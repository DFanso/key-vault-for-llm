# kv self-update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** kv finds out when a newer GitHub release is out. It tells the user (in the tray on macOS/Windows; through `kv update --check`, `kv status` and `kv tui` elsewhere). After a yes, it downloads, checks the sha256, swaps its own binary and restarts the daemon and tray.

**Architecture:** A new `kv::update` module holds everything that doesn't touch the UI, in small files:
- checking the GitHub API;
- the state file;
- archive extraction and checksum;
- the binary swap;
- the install orchestration.

`kv update` in `cli.rs` and the tray worker both call it. The tray reaches it through an `Updater` trait, so `tray_worker` tests can use a fake. The tray restarts by starting its successor (`kv tray --after-update <version>`) and handing over the tray lock.

**Tech Stack:**
- Rust 2024, MSRV 1.90;
- reqwest 0.13 (rustls), already used;
- `semver`;
- pure-Rust `.tar.xz` and `.zip` readers;
- `wiremock` for tests, already a dev-dependency;
- tao/wry tray, already used.

**Spec:** `docs/superpowers/specs/2026-11-16-kv-self-update-design.md`

## Global Constraints

- MSRV `rust-version = "1.90"`. Every new crate must build on it, and CI's `msrv` job checks this.
- Archive readers must be pure Rust, with no system liblzma or zlib. Releases cross-build five targets.
- Build only what each platform needs: `.tar.xz` support on unix, `.zip` support on Windows.
- Release targets and asset names:
  - `kv-aarch64-apple-darwin.tar.xz`
  - `kv-x86_64-apple-darwin.tar.xz`
  - `kv-aarch64-unknown-linux-gnu.tar.xz`
  - `kv-x86_64-unknown-linux-gnu.tar.xz`
  - `kv-x86_64-pc-windows-msvc.zip`
  - each with `<archive>.sha256` beside it.
- The latest-release URL is the constant `https://api.github.com/repos/DFanso/key-vault-for-llm/releases/latest`. **No environment variable, flag or config may change it.** Tests pass a wiremock URL to the library functions, which take the URL as a parameter; the CLI and tray only ever pass the constant.
- Downloads use HTTPS only. Redirects are followed (at most 5) only to `github.com`, `api.github.com`, or hosts ending in `.githubusercontent.com`. Proxy settings are ignored (`no_proxy()`), as in `broker/http.rs`. The User-Agent is `kv/<CARGO_PKG_VERSION>` and nothing else identifies the user.
- Size caps: API reply 1 MiB, `.sha256` 4 KiB, archive 64 MiB, the extracted binary 256 MiB.
- Cadence: the tray first checks 3 minutes after start, then every 12 h. `kv status` and `kv tui` check at most every 24 h, with a 3 s timeout, and only when the tray isn't running.
- `KV_UPDATE_CHECK=off` (any of kv's boolean "off" words) turns off automatic checks. An explicit `kv update` or `kv update --check` still checks.
- Only a strictly newer, non-prerelease semver is offered. A tag must be `v<semver>`; anything else counts as no update.
- Only builds with the `release-build` Cargo feature update themselves. `dist-workspace.toml` enables it for release builds; `cargo install --path` and source builds never do.
- Fixed text:
  - menu line: `Update to kv {version}…`
  - after an update: `Updated to kv {version}. Unlock to continue.`
  - macOS addition: `macOS will ask for your login password once before Touch ID works again; choose Always Allow.`
  - confirmation warning: `Updating locks the vault and stops anything agents have running now: waiting approvals, programs, MCP servers and database connections.`
- Commits are authored by DFanso <leogavin123@outlook.com>, with no AI attribution (no Co-Authored-By, no "Generated with" line).
- Each task ends with `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo test --workspace --locked` green.

## Review Focus

1. **The installed `kv` is a symlink** (e.g. `~/.cargo/bin/kv` → another folder). The update must replace the real file the link points to, and the link keeps working. Test in Task 5.
2. **GitHub rate-limits or returns junk** (403/429 with `x-ratelimit-remaining: 0`, an HTML error page, truncated JSON). The tray stays silent and retries at the next interval; `kv update --check` prints one clear sentence, never a raw serde error. Test in Task 2.
3. **The latest release is a pre-release version** (`v1.9.0-rc.1` published without the pre-release box ticked). It's never offered. Test in Task 2.
4. **The folder isn't writable, or a step fails mid-swap.** The old binary is byte-for-byte unchanged and the error names the folder. Test in Task 5.
5. **Two updates start at once** (two terminals, or a terminal while the tray's install runs). The second gets "another kv update is running", not a corrupted install. Test in Task 5.

---

### Task 1: Foundation: release-build marker, target, version, paths, opt-out

**Files:**
- Create: `crates/kv/src/update.rs` (module root: shared types, `UpdateError`, small helpers)
- Modify: `crates/kv/src/lib.rs` (add `pub mod update;`)
- Modify: `crates/kv/src/paths.rs` (two path helpers)
- Modify: `crates/kv/Cargo.toml` (feature `release-build = []`; dependency `semver = "1"`)
- Modify: `dist-workspace.toml` (`features = ["release-build"]` under `[dist]`)
- Test: `crates/kv/tests/update_basics.rs`

**Interfaces:**
- Produces, in `kv::update`:
  - `pub const LATEST_URL: &str` (the constant above)
  - `pub fn current_version() -> semver::Version`, parsed from `CARGO_PKG_VERSION`
  - `pub fn target() -> Option<&'static str>`: one of the five triples from `cfg!(target_os, target_arch)`; `None` elsewhere
  - `pub fn archive_name(target: &str) -> String`: `kv-<target>.zip` for the Windows triple, `kv-<target>.tar.xz` otherwise
  - `pub fn is_release_build() -> bool`: `cfg!(feature = "release-build")`
  - `pub fn checks_enabled(value: Option<&std::ffi::OsStr>) -> bool`
  - `pub fn parse_tag(tag: &str) -> Option<semver::Version>`: requires a leading `v`; returns `None` for a pre-release
  - `pub struct Asset { pub name: String, pub url: url::Url, pub size: u64 }`
  - `pub struct Offer { pub version: semver::Version, pub notes_url: String, pub archive: Asset, pub checksum: Asset }`
  - `pub enum UpdateError { Network(String), Malformed(String), RateLimited, NotReleaseBuild, NotWritable(PathBuf), NoAssetForTarget(String), ChecksumMismatch, TooLarge(&'static str), WrongVersion { expected: String, found: String }, Busy, TrayRunning, Swap(String) }`, with `Display` giving one plain sentence each (e.g. `Busy` → "another kv update is running")
- Produces, in `Paths`:
  - `pub fn update_state_file(&self) -> PathBuf`: `self.audit.with_file_name("update.json")`
  - `pub fn update_lock_file(&self) -> PathBuf`: `self.runtime.join("update.lock")`

- [ ] **Step 1: Write the failing tests** in `crates/kv/tests/update_basics.rs`:
  - `parse_tag("v1.9.0") == Some(1.9.0)`
  - `parse_tag("1.9.0") == None`
  - `parse_tag("v1.9.0-rc.1") == None`
  - `parse_tag("vX") == None`
  - `archive_name("x86_64-pc-windows-msvc") == "kv-x86_64-pc-windows-msvc.zip"`
  - `archive_name("aarch64-apple-darwin") == "kv-aarch64-apple-darwin.tar.xz"`
  - `target()` is `Some` on the three CI platforms
  - `checks_enabled(None)` is true
  - `checks_enabled(Some("off".as_ref()))` and `checks_enabled(Some("0".as_ref()))` are false
  - `current_version() == Version::parse(env!("CARGO_PKG_VERSION"))`
  - `is_release_build()` is false under `cargo test`
  - the two `Paths::under(tmp)` paths end in `update.json` and `run/update.lock`
- [ ] **Step 2: Run them to see them fail.** Run `cargo test -p kv --test update_basics`. Expected: compile errors, because `kv::update` doesn't exist.
- [ ] **Step 3: Implement the module root.** Add the items above. For `checks_enabled`, accept the same off words `notify::or_default` uses for `KV_NOTIFY`.
- [ ] **Step 4: Run the tests again.** Run `cargo test -p kv --test update_basics`. Expected: all pass.
- [ ] **Step 5: Check the dist config** (if `dist` is installed). Run `dist plan`. Expected: the same five targets as before and no error about `features`. Otherwise this is checked by the PR's `plan` job.
- [ ] **Step 6: Commit** with the message `Add the update module's basics and a release-build feature`.

### Task 2: Checking GitHub for a newer release

**Files:**
- Create: `crates/kv/src/update/check.rs`
- Test: `crates/kv/tests/update_check.rs` (wiremock)

**Interfaces:**
- Consumes: Task 1's `Offer`, `Asset`, `parse_tag`, `archive_name`, `UpdateError`.
- Produces:
  - `pub fn client() -> reqwest::Result<reqwest::Client>`: `no_proxy()`, timeouts (connect 10 s, total 120 s), User-Agent `kv/<version>`, and a custom redirect policy (https only, allowed hosts, at most 5)
  - `pub fn offer_from(json: &[u8], current: &semver::Version, target: &str) -> Result<Option<Offer>, UpdateError>`: pure. It reads `tag_name`, `html_url`, `draft`, `prerelease` and `assets[].{name, browser_download_url, size}`. It returns `None` when:
    - the release is a draft or a prerelease;
    - the tag isn't newer;
    - the archive or its `.sha256` asset is missing.
    It returns `Err(Malformed)` for bad JSON, and also when an asset URL isn't https on an allowed host.
  - `pub async fn latest(client: &reqwest::Client, url: &str, current: &semver::Version, target: &str) -> Result<Option<Offer>, UpdateError>`: GETs `url` with `Accept: application/vnd.github+json`, enforces the 1 MiB cap, then calls `offer_from`.
    - 403/429 with `x-ratelimit-remaining: 0` → `RateLimited`
    - another non-2xx → `Network`

- [ ] **Step 1: Write the failing tests** with wiremock, from a minimal release JSON built in the test (`tag_name`, `html_url`, `assets` with the platform archive and its `.sha256`):
  - `offers_a_newer_release`: `Some(offer)` with `offer.version == 99.0.0`, and the archive name equal to `archive_name(target)`
  - `same_or_older_is_no_update`: tags `v<current>` and `v0.1.0` give `None`
  - `prerelease_version_is_not_offered`: `v99.0.0-rc.1`, with `prerelease: false`, gives `None` (Review Focus 3)
  - `missing_sha256_is_no_update`
  - `foreign_asset_host_is_refused`: `browser_download_url` on `https://evil.example/kv.tar.xz` gives `Err(Malformed)`
  - `rate_limit_and_junk`: a 403 with `x-ratelimit-remaining: 0` gives `Err(RateLimited)`; a 200 with an HTML body gives `Err(Malformed)`; the `Display` of both is one line with no `{` or `serde` in it (Review Focus 2)
  - `oversized_reply_is_refused`: a 2 MiB body gives `Err(TooLarge(_))`
- [ ] **Step 2: Run them to see them fail.** Run `cargo test -p kv --test update_check`. Expected: FAIL (functions missing).
- [ ] **Step 3: Implement `check.rs`** with the signatures above. Read the body in chunks so the cap applies before parsing.
- [ ] **Step 4: Run the tests again.** Run `cargo test -p kv --test update_check`. Expected: PASS.
- [ ] **Step 5: Commit** with the message `Check GitHub for a newer kv release`.

### Task 3: Remembering checks (state file and cadence)

**Files:**
- Create: `crates/kv/src/update/state.rs`
- Test: `crates/kv/tests/update_state.rs`

**Interfaces:**
- Produces:
  - `#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)] pub struct UpdateState { pub last_check: Option<u64>, pub latest: Option<String>, pub announced: Option<String> }`. Times are unix seconds; versions are strings without the `v`.
  - `pub fn load(path: &Path) -> UpdateState`: missing or corrupt → `Default`
  - `pub fn save(path: &Path, state: &UpdateState) -> io::Result<()>`: write a temp file, then rename
  - `pub fn due(state: &UpdateState, now: u64, every: Duration) -> bool`
  - `pub const TRAY_FIRST: Duration` (3 min)
  - `pub const TRAY_EVERY: Duration` (12 h)
  - `pub const CLI_EVERY: Duration` (24 h)
  - `pub fn newer_known(state: &UpdateState, current: &semver::Version) -> Option<semver::Version>`

- [ ] **Step 1: Write the failing tests:**
  - a save → load round trip
  - a corrupt file loads as default
  - `due` is true with no `last_check`, false 1 h after a check with `CLI_EVERY`, and true 25 h after
  - `newer_known` returns `Some` only when `latest` is newer than the current version
- [ ] **Step 2: Run them to see them fail.** Run `cargo test -p kv --test update_state`. Expected: FAIL.
- [ ] **Step 3: Implement `state.rs`.**
- [ ] **Step 4: Run the tests again.** Run `cargo test -p kv --test update_state`. Expected: PASS.
- [ ] **Step 5: Commit** with the message `Remember when kv last checked for an update`.

### Task 4: Checksum and archive extraction

**Files:**
- Create: `crates/kv/src/update/archive.rs`
- Modify: `crates/kv/Cargo.toml`: pure-Rust tar + xz reader under `[target.'cfg(unix)'.dependencies]`, and a zip reader (deflate only, default features off) under `[target.'cfg(windows)'.dependencies]`. The same crates go in `[dev-dependencies]` so tests can build archives.
- Test: `crates/kv/tests/update_archive.rs`

**Interfaces:**
- Produces:
  - `pub fn parse_sha256(text: &str) -> Result<[u8; 32], UpdateError>`: accepts `<64 hex>`, `<64 hex> *name` and `<64 hex>  name`, with surrounding whitespace allowed; anything else is `Malformed`
  - `pub fn verify_sha256(file: &Path, expected: &[u8; 32]) -> Result<(), UpdateError>`: streams the file; a mismatch is `ChecksumMismatch`
  - `pub fn extract_binary(archive: &Path, out: &Path) -> Result<(), UpdateError>`: writes only the entry whose file name is `kv` (unix) or `kv.exe` (Windows), at depth ≤ 2, e.g. `kv-<target>/kv`. It rejects symlink, hardlink and device entries, `..` and absolute paths, a missing binary (`Malformed`), and more than 256 MiB (`TooLarge`). On unix it sets mode 0755.

- [ ] **Step 1: Write the failing tests.** Build archives in a tempdir with the dev-dependency writers:
  - `extracts_only_the_binary`: an archive holding `kv-t/kv`, `kv-t/README.md` and `../evil` writes only `out`; `../evil` doesn't exist anywhere
  - `symlink_entry_is_refused`
  - `archive_without_binary_is_malformed`
  - `parse_sha256_forms`: the three accepted forms parse; `"xyz"` and a 63-character hex string give `Malformed`
  - `checksum_mismatch`
- [ ] **Step 2: Run them to see them fail.** Run `cargo test -p kv --test update_archive`. Expected: FAIL.
- [ ] **Step 3: Implement `archive.rs`.** Gate the tar.xz code with `#[cfg(unix)]` and the zip code with `#[cfg(windows)]`, so each CI OS tests its own format.
- [ ] **Step 4: Run the tests again** on macOS locally. Run `cargo test -p kv --test update_archive`. Expected: PASS. The Windows half runs in CI.
- [ ] **Step 5: Check the MSRV.** Run `cargo +1.90 check -p kv --all-targets --locked`. Expected: it builds.
- [ ] **Step 6: Commit** with the message `Verify and unpack a kv release archive`.

### Task 5: Swap the binary and install

**Files:**
- Create: `crates/kv/src/update/swap.rs`
- Create: `crates/kv/src/update/install.rs`
- Test: `crates/kv/tests/update_install.rs`

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces:
  - `pub struct Swapped { pub installed: PathBuf, pub backup: PathBuf }`
  - `pub fn swap(installed: &Path, new_binary: &Path) -> Result<Swapped, UpdateError>`. `new_binary` must sit in the same folder as `installed`.
    - unix: hard-link or copy `installed` to `kv.previous` (replacing an old one), then `rename(new_binary, installed)`.
    - Windows: `rename(installed, "kv.exe.old")`, then `rename(new_binary, installed)`; if the second rename fails, rename back.
    - On any error the original is unchanged, and the error is `Swap(..)`, or `NotWritable(folder)` for a permission denial.
  - `pub fn clean_old(installed: &Path)`: Windows tries to remove `kv.exe.old` and ignores failure (an old process may still be running it); unix does nothing. It's called at the start of every kv command (Task 6), so the first command run by the new binary clears it. The old binary never calls it after a swap.
  - `pub fn installed_exe() -> io::Result<PathBuf>`: `std::env::current_exe()?.canonicalize()`, so a symlink resolves to the real file (Review Focus 1)
  - `pub fn update_lock(paths: &Paths) -> Result<std::fs::File, UpdateError>`: `try_lock` on `paths.update_lock_file()`; if it's held → `Busy`
  - `pub struct InstallOptions { pub installed: PathBuf, pub release_build: bool }`
  - `pub struct Installed { pub version: semver::Version, pub swapped: Swapped }`
  - `pub async fn install(client: &reqwest::Client, offer: &Offer, opts: &InstallOptions, paths: &Paths) -> Result<Installed, UpdateError>`. Order:
    1. `release_build` false → `NotReleaseBuild`
    2. take `update_lock`
    3. create a temp folder beside `opts.installed` (unwritable → `NotWritable`)
    4. download the `.sha256` (4 KiB cap) and the archive (64 MiB cap, also refusing more than `offer.archive.size`)
    5. `verify_sha256`
    6. `extract_binary`
    7. run the extracted binary with `--version`; it must print `kv <offer.version>`, else `WrongVersion`
    8. `swap`
    9. remove the temp folder whatever the outcome

- [ ] **Step 1: Write the failing tests.** Serve a fake release from wiremock: a real archive built in-test holding a small script or binary that prints `kv 99.0.0` to `--version`. On unix, a `#!/bin/sh` script; on Windows, a copy of a tiny test helper binary built by the test crate is acceptable, or skip that one test on Windows with a comment. Tests:
  - `installs_and_keeps_a_backup` (unix): afterwards `installed` prints `kv 99.0.0` and `kv.previous` holds the old bytes
  - `checksum_mismatch_leaves_old_binary`: the old bytes are unchanged and no temp folder is left behind
  - `wrong_version_inside_archive`: the binary prints `kv 98.0.0` → `WrongVersion`, and the old file is unchanged
  - `not_release_build_refused`: `release_build: false` → `NotReleaseBuild` before any HTTP request (wiremock `expect(0)`)
  - `unwritable_folder` (unix, skipped when running as root): a 0555 folder → `NotWritable(folder)`, the old file is unchanged (Review Focus 4)
  - `symlinked_install_replaces_target` (unix): with `installed_exe`-style resolution, the real file is updated and the link still resolves to the new version (Review Focus 1)
  - `second_install_is_busy`: while `update_lock` is held → `Busy` (Review Focus 5)
- [ ] **Step 2: Run them to see them fail.** Run `cargo test -p kv --test update_install`. Expected: FAIL.
- [ ] **Step 3: Implement `swap.rs` and `install.rs`.**
- [ ] **Step 4: Run the tests again.** Run `cargo test -p kv --test update_install`. Expected: PASS.
- [ ] **Step 5: Commit** with the message `Install a kv release over the running binary`.

### Task 6: `kv update`, and notices in `kv status` and `kv tui`

**Files:**
- Modify: `crates/kv/src/cli.rs`:
  - `Command::Update`;
  - handling in `main`'s match;
  - the notice in `Command::Status`;
  - the TUI start-up notice.
- Modify: `crates/kv/src/tray.rs`: `pub fn is_running(paths: &Paths) -> bool`, which returns true when `tray_lock_file` is locked by someone else and false when this process can take and release it.
- Test: `crates/kv/tests/cli.rs` (additions)

**Interfaces:**
- Consumes: Tasks 1–5; `stop_or_lock(paths, ControlCommand::Stop)` (existing, `cli.rs`).
- Produces:
  - `Command::Update { #[arg(long)] check: bool, #[arg(long)] yes: bool }`, with help text "Check for a newer kv and install it after asking".
  - `pub async fn update_notice(paths: &Paths, now: u64) -> Option<String>`, in `kv::update` (`update.rs`). It returns `"kv {v} is out: run `kv update`."`. It does nothing (returns `None`) when checks are off, when the tray is running, or when not `due(…, CLI_EVERY)`. Otherwise it checks with a 3 s timeout, saves the state, and uses `newer_known`. It never errors.

Behaviour of `kv update`:
1. `--check`: check now, save the state, and print `kv {v} is out.` plus the release notes URL, or `kv {current} is the latest.`. Errors print `UpdateError`'s sentence and exit 1.
2. Without `--check`:
   - On macOS and Windows, if `tray::is_running` → `TrayRunning`. Message: "kv tray is running: update from its menu (Update to kv X.Y.Z…) so it restarts on the new version."
   - Not a release build → `NotReleaseBuild`. Message: "this kv wasn't installed from a release; reinstall it from https://github.com/DFanso/key-vault-for-llm/releases".
   - Check. Nothing newer → say so and exit 0.
   - Print the version, the notes URL and the confirmation warning (Global Constraints).
   - Ask `Update to kv {v}? [y/N]` on a terminal. With no terminal, require `--yes`, else refuse with a hint to pass it.
   - `install` with `installed_exe()`, then `stop_or_lock(Stop)`.
   - Print the "Updated to kv …" text, and the macOS addition on macOS.

- [ ] **Step 1: Write the failing tests** in `tests/cli.rs`, using the existing `Kv` harness:
  - `update_check_reports`: `kv update --check` exits 0 or 1, and its output contains either "is the latest" / "is out", or one plain error line. The test must not depend on the network result: it asserts only the shape, and is `#[ignore]`d if no network.
  - `update_refuses_non_release_build`: `kv update --yes` (stdin not a tty) prints "wasn't installed from a release" and exits non-zero, without touching the binary
  - `status_has_no_update_line_when_checks_off`: with `KV_UPDATE_CHECK=off`, `kv status` output has no "kv update"
- [ ] **Step 2: Run them to see them fail.** Run `cargo test -p kv --test cli update_ status_has_no_update`. Expected: FAIL.
- [ ] **Step 3: Implement `Command::Update`, `update_notice` and `tray::is_running`.** At the top of `cli::main`, call `update::swap::clean_old(&installed_exe)` when `installed_exe()` succeeds, on every command. Wire `update_notice` into `kv status` (printed after the status) and into `kv tui`'s first frame footer, or as a line printed before the TUI starts.
- [ ] **Step 4: Run the tests again.** Run `cargo test -p kv --test cli`. Expected: PASS.
- [ ] **Step 5: Commit** with the message `Add kv update, and a line in kv status and kv tui when one is out`.

### Task 7: Tray: check, tell, confirm, install, restart

**Files:**
- Create: `crates/kv/src/tray/update.rs`: the `Updater` trait and its real implementation, plus `restart_after_update`.
- Modify: `crates/kv/src/tray/worker.rs`:
  - take a `Box<dyn Updater>` in `Worker::new`;
  - hold `offer: Option<Offer>` and `next_check: Instant`;
  - add the check scheduling, notifications and actions.
- Modify: `crates/kv/src/tray/model.rs`: `View.update: Option<&'a semver::Version>`, and the menu line in both locked and unlocked menus, just above "Quit kv tray".
- Modify: `crates/kv/src/tray/window.rs`:
  - `ToPage::State` gains `version: String` and `update: Option<String>`;
  - new `ToPage::UpdateAsk { version: String, notes_url: String }` and `ToPage::UpdateResult { ok: bool, message: String }`;
  - new `FromPage::OfferUpdate`, `FromPage::CheckUpdates` and `FromPage::InstallUpdate`.
- Modify: `crates/kv/src/tray/page/index.html`, `app.js`, `app.css`:
  - a line in the flyout menu;
  - "kv {version}" and a **Check for updates** button with result text in Settings;
  - a confirmation dialog with the warning, a release-notes link, **Update** and **Not now**;
  - built with `el()` (no innerHTML), CSP unchanged.
- Modify: `crates/kv/src/tray.rs` and `crates/kv/src/cli.rs`:
  - hidden `--after-update <VERSION>` on `Command::Tray`;
  - `pub fn lock_single_retry(paths: &Paths, wait: Duration) -> io::Result<File>`;
  - on start with `--after-update`, show the after-update text (`clean_old` already ran in `cli::main`).
- Modify: `crates/kv/src/tray/ui.rs`: hold the tray lock as `Arc<Mutex<Option<File>>>`, so `restart_after_update` can release it and take it back.
- Test: `crates/kv/tests/tray_worker.rs`, `tray_model.rs`, `tray_page.rs` (additions)

**Interfaces:**
- Consumes: Tasks 1–6.
- Produces:
  - `pub trait Updater: Send + Sync { fn check(&self) -> BoxFuture<'static, Result<Option<Offer>, UpdateError>>; fn install(&self, offer: Offer) -> BoxFuture<'static, Result<Installed, UpdateError>>; fn restart(&self, version: &semver::Version) -> Result<(), String>; }`, using `futures_util::future::BoxFuture`
  - `Action::UpdateChecked(Result<Option<Offer>, String>)` (never on a menu) and `Action::OfferUpdate` (the menu line)
  - `pub fn restart_after_update(lock: &Arc<Mutex<Option<File>>>, exe: &Path, version: &semver::Version, paths: &Paths) -> Result<(), String>`. It drops the lock, then, up to 3 times:
    - spawn `exe tray --after-update <version>`;
    - wait up to 5 s;
    - succeed when `tray::is_running(paths)` and the child hasn't exited.
    If all three fail, it takes the lock back and returns `Err` with "kv {v} is installed, but the new tray didn't start. Run `kv tray`, or log out and back in."

Worker behaviour:
- **Scheduling.** `next_check = start + TRAY_FIRST`, then `+ TRAY_EVERY`. When it's due and checks are enabled, spawn `updater.check()` and post its result back as `Action::UpdateChecked` through the existing action channel. Save `UpdateState`. Check errors are silent.
- **New version found.** When a check returns `Some(offer)` whose version ≠ `state.announced`, notify once:
  - macOS: `Desktop::post` a `Notice` with key `update-<version>`, no answer buttons, title `kv {v} is out`, body `Open kv's menu to update.`; `Action::Notice { key: "update-…", verdict: None }` opens the confirmation;
  - elsewhere: `Desktop::notify` with the same text.
  Then set `announced`.
- **Offering.** `Action::OfferUpdate` / `FromPage::OfferUpdate` → `show_window(Tab::Home)` and `ToPage::UpdateAsk`.
- **Checking by hand.** `FromPage::CheckUpdates` → check now; reply with `UpdateResult` ("kv X is out" or "kv X is the latest") or the error sentence.
- **Installing.** `FromPage::InstallUpdate` → `updater.install(offer)`. On `Ok`:
  - stop the daemon (the driver's existing stop path; it locks the vault);
  - `updater.restart(version)`;
  - on `Ok`, return `Next::Quit`;
  - on `Err(msg)`, `UpdateResult { ok: false, message: msg }` and a notification.
  On an install `Err`, `UpdateResult { ok: false, message: e.to_string() }`, and the old tray keeps running.

- [ ] **Step 1: Write the failing tests.**
  - `tray_model.rs` — `update_line_in_both_menus`: with `View.update = Some(1.9.0)`, the locked and unlocked menus both contain `Update to kv 1.9.0…` mapped to `Action::OfferUpdate`, placed before "Quit kv tray"; with `None`, neither does.
  - `tray_worker.rs`, using the existing fake `Desktop` plus a `FakeUpdater` that returns scripted results:
    - `announces_a_new_version_once`: two checks returning the same offer → exactly one notification
    - `install_failure_keeps_tray`: install `Err(ChecksumMismatch)` → the page gets `UpdateResult { ok: false }`; the loop doesn't quit; `restart` is never called
    - `install_success_stops_daemon_and_restarts`: install `Ok` → `restart` called once with the version, then the worker returns
    - `restart_failure_reports`: `restart` `Err(..)` → `UpdateResult { ok: false }` holding that text, and the worker keeps running
  - `tray_page.rs`: the page still uses no innerHTML and keeps its CSP (existing test); the new dialog's text contains the exact warning from Global Constraints.
- [ ] **Step 2: Run them to see them fail.** Run `cargo test -p kv --test tray_model --test tray_worker --test tray_page`. Expected: FAIL.
- [ ] **Step 3: Implement the worker, model, window message, page and restart changes** as specified.
- [ ] **Step 4: Run the tests again.** Run `cargo test -p kv --test tray_model --test tray_worker --test tray_page`. Expected: PASS.
- [ ] **Step 5: Check by hand on macOS.**
  - Build a release-build binary: `cargo build --release -p kv --features release-build`.
  - Run it as a demo tray under a throwaway `KV_HOME` with `KV_TRAY_APP=off`.
  - Confirm that Settings shows the version and that **Check for updates** reports `kv 1.8.0 is the latest` (or a newer version).
  - Leave the real install alone; the swap was covered in Task 5.
- [ ] **Step 6: Commit** with the message `Tray: tell when a new kv is out, and update after asking`.

### Task 8: README and release check

**Files:**
- Modify: `README.md`. Add a new `## Updating kv` section before `## What kv protects against`, covering:
  - the tray checks a few minutes after start and every 12 h, and `kv status`/`kv tui` once a day when the tray isn't running;
  - `KV_UPDATE_CHECK=off`;
  - `kv update`, `kv update --check` and `--yes`;
  - kv trusts the latest GitHub release, checks its sha256 against the published file, and always asks first;
  - what happens after: the vault is locked, the macOS login-password prompt (choose Always Allow), `kv.previous` / `kv.exe.old` for going back by hand;
  - source builds don't update themselves.
- Test: none new. The existing suite plus the PR's `plan` job checks that `features = ["release-build"]` is valid for dist.

- [ ] **Step 1: Write the README section.**
- [ ] **Step 2: Run the full checks.** Run `cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked`. Expected: all green.
- [ ] **Step 3: Commit** with the message `README: updating kv`.
- [ ] **Step 4: Open the PR** with the title `kv update: check for a new release, ask, install`. Confirm CI is green on macos-15, ubuntu-24.04 and windows-2025, and that the Release workflow's `plan` job passes with the new dist feature.
