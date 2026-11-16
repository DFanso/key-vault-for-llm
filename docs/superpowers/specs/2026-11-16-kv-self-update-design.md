# kv self-update: check for a new release, ask, install

Date: 2026-11-16. Status: draft for Leo's review.

## Why

Installing a new kv today is a manual job. For 1.8.0 that meant:
- download the archive for the platform and check its checksum;
- swap `~/.cargo/bin/kv` without breaking the running `kv mcp` processes;
- stop the daemon and restart the tray;
- restart the tray a second time, because the first restart failed with `OS_REASON_CODESIGNING`.

Nobody finds out a new version exists unless they look. And mixed versions cause real breakage: a 1.6.1 vault couldn't open a 1.7.0 `login` share. Leo wants kv to tell him when there's a new release and install it when he says yes, on macOS, Windows and Linux.

## What Leo decided

- **The tray tells and asks.** Nothing installs until he agrees.
- **It works on all three platforms:** macOS, Windows and Linux.
- **No signing key.** kv trusts the latest GitHub release and checks each download against the checksum published with it. Leo chose this knowing the trade-off: whoever can publish a release on the repo (Leo, anyone with write access, or someone who takes over his GitHub account) can put a build in front of every kv user. The user still has to say yes to it.
- **How the tray tells:** a line in the tray menu, plus one notification per new version. (Proposed by the assistant; Leo answered "approve".)

## Goals

1. kv finds out on its own when a newer release is out:
   - the tray on macOS and Windows checks in the background;
   - on Linux, which has no tray, `kv update --check` and a short notice from `kv status` and `kv tui` do the same job.
2. One yes installs the update completely: download, verify, swap the binary, restart the daemon and tray. There are no manual steps.
3. kv installs only the latest published GitHub release, only when it's newer than the one running, and only after the download matches its published checksum.
4. Agent sessions running when the update happens keep their connection to kv (their `kv mcp` stays the old binary until they restart). They get `vault_locked` until the user unlocks. Anything the daemon was running for them stops: waiting approvals, `exec` programs, MCP servers it started and database connections. The confirmation says so (see 3).
5. Afterwards, the user is told what to expect: the vault is locked, and on a Mac the one-time login-password prompt before Touch ID works again.

## Non-goals

- Installing without asking, or on a schedule.
- Downgrades or picking a version. `kv update` only goes to the latest release.
- Updating kv installed by a package manager, or kv built from source.
- A tray on Linux.
- Fixing mixed-version compatibility (unknown kinds, "daemon unavailable" when an older client can't read a newer daemon's reply). That's a separate fix. Updates make mixed versions more common for a while, though, which makes that fix more urgent.

## Anti-goals (a failure even if it "works")

- **An update path that's easier to abuse than publishing a GitHub release.** Without signing, the release on GitHub is the trust root. Nothing else may widen it: no update URL override, no plain HTTP, no other source, no following links off GitHub.
- **A half-replaced binary.** If anything fails, the old kv must stay exactly as it was.
- **The daemon and the tray left on different versions.** kv only sends the Touch ID key to a daemon running the same `kv` binary, so a mismatch silently breaks Touch ID unlock.
- **Nagging.** One notification per version, never repeated.
- **Leaking anything about the user to GitHub** beyond what a request to a public URL must carry.

## Design

### 1. Release side: nothing new

- cargo-dist already publishes what the updater needs:
  - an archive per target: `kv-<target>.tar.xz`, or `kv-x86_64-pc-windows-msvc.zip` on Windows;
  - a `.sha256` file beside each archive (plus `sha256.sum` and `dist-manifest.json`).
- The release workflow doesn't change, and there's no key to manage.
- Every release from 1.8.0 on already has these files, so the first kv with the updater can update to any later release.

### 2. Checking

- **Request.** Get the latest release from the GitHub API: `GET https://api.github.com/repos/DFanso/key-vault-for-llm/releases/latest`, which leaves out drafts and prereleases.
  - Unauthenticated.
  - User-Agent `kv/<version>` (GitHub requires one); nothing else about the user.
- **Newer?** Compare the tag (`vX.Y.Z`) to the running version as semver. A release that's missing this platform's archive or its `.sha256` counts as "no update yet".
- **The tray:**
  - checks a few minutes after it starts, then about every 12 hours;
  - remembers the last check and the last version it announced in a small state file in kv's data folder, so a restart doesn't re-notify.
- **Linux, and macOS or Windows without the tray:**
  - `kv update --check` checks now and prints the result.
  - `kv status` and `kv tui` check at most once a day, using the same state file, and add one line when an update is waiting.
- **Opt-out.** `KV_UPDATE_CHECK=off` turns off every automatic check. An explicit `kv update` or `kv update --check` still works.
- **Failures are quiet.** A check that fails (offline, rate-limited, GitHub down) says nothing and tries again at the next interval. GitHub allows 60 unauthenticated requests an hour, so the cadence above stays far below that.

### 3. Telling the user

- **Tray menu.** When a newer release exists, the menu shows "Update to kv X.Y.Z…". Choosing it opens a short confirmation in kv's window:
  - the version;
  - a link to the release notes on GitHub;
  - a warning that updating locks the vault and stops anything agents have running now (waiting approvals, programs, MCP servers, database connections);
  - Update and Not now.
- **Notification.** One per new version, never repeated for that version.
  - On macOS, clicking it opens the same confirmation, through kv.app as other notices do today.
  - On Windows the notification only informs, and the menu line is how to update. kv has no click handling for Windows toasts, and adding it isn't worth it for this. (Assistant's call.)
- **Settings.** The window's Settings shows the running version and a **Check for updates** button.
- **CLI.**
  - `kv update` checks, shows the version, asks `y/N` on the terminal, then installs.
  - When stdin isn't a terminal it needs `--yes`. This is so a stray agent can't trigger an update by accident.
  - `kv update --check` only reports.
  - **While the tray is running (macOS, Windows):** `kv update` doesn't install. It says to use the tray's "Update to kv X.Y.Z…", because the CLI has no way to restart the tray, and leaving the old tray running would put the tray and daemon on different versions. `kv update --check` still works. (Assistant's call.)
  - The CLI warns about stopping running work, as the confirmation does.

### 4. Installing (one code path, used by the tray and the CLI)

1. **Find the installed kv.** Use `current_exe()`, canonicalized. Refuse with a clear message (what to do instead) if:
   - the build isn't a release build (e.g. built from source; how a release build marks itself is left to the builder);
   - the folder isn't writable by the user;
   - the release has no archive for this platform's target triple.
2. **Download** the platform's archive and its `.sha256`, by the asset URLs the GitHub API returned for that release, into a new temporary folder in the same folder as the installed binary. Being on the same filesystem lets the final swap be a rename. Cap the sizes.
3. **Verify, and stop at the first failure:**
   - the release's version is newer than the running one;
   - the archive's sha256 matches its published `.sha256`.
   - This catches a damaged or cut-off download. It doesn't prove who made the release; see section 5.
4. **Extract only the `kv` binary** (`kv.exe` on Windows), with no other paths, then run it with `--version` and check it reports the expected version.
5. **Swap:**
   - **macOS and Linux:**
     - keep the current binary as `kv.previous` beside it (one backup, for a manual rollback);
     - rename the new file over `kv`.
     - The rename gives `kv` a new inode, so running `kv mcp` processes keep their old, valid code. Don't write into the existing file: that's what invalidates running processes on macOS.
   - **Windows:**
     - rename the running `kv.exe` to `kv.exe.old` (Windows allows renaming a running exe);
     - move the new one into place;
     - delete leftover `.old` files the next time kv starts.
   - If any step fails, put the old binary back and report the error. Never leave a half-replaced install.
6. **Restart:**
   - Stop the daemon, as `kv stop` does; this locks the vault.
   - The tray starts the new binary as `kv tray` and exits. The new tray retries taking the tray lock for a few seconds while the old one releases it.
     - The old tray exits only once the new one says it is up: the old tray passes it a file path (the hidden `--ready-file` argument), and the new tray creates that file after its icon is up. The old tray waits a bounded time (10 seconds) for the file while the new process is still running. Holding the tray lock alone doesn't count, since the new tray takes the lock before it builds its icon and could still fail after that. The old tray removes the file afterwards.
     - On macOS the tray runs from a LaunchAgent without KeepAlive, so the tray has to start its successor itself.
     - The manual 1.8.0 install saw one `OS_REASON_CODESIGNING` spawn failure right after the swap. The restart must check the new tray actually came up, retry, and tell the user if it didn't.
   - The next command starts the daemon on demand, now on the new binary.
   - **If the new tray doesn't come up after the retries, kv reports it and doesn't roll back.** The old tray keeps running, takes its lock back (it retries for a few seconds, and says so in the message if it can't), and stays on the old binary. The new binary stays in place, and kv says how to start the tray (`kv tray`, or log out and in) and how to go back by hand, naming the file the old kv was kept as. Because the next command starts the daemon from the new binary, and kv only sends the Touch ID (or Windows Hello) key to a daemon running the same binary, the message also says that Touch ID unlock won't work until kv tray is quit and started again, and that unlocking with the passphrase works meanwhile. (Leo's call.) On macOS and Linux that's `kv.previous`. On Windows, `kv.exe.old` is kept until a new kv has started successfully once, instead of being deleted at the next start. Automatic rollback would need the old tray to stay alive until the new one proves healthy, which clashes with the tray lock, and it isn't worth that for a failure that a retry fixed on 1.8.0. (Assistant's call.)
   - `kv.app` (the macOS notification helper) is rebuilt from the new binary when the new tray starts, as it is today.
7. **Afterwards:**
   - The new tray says "Updated to kv X.Y.Z. Unlock to continue."
   - On macOS it adds that macOS will ask for the login password once before Touch ID works, and to choose Always Allow. The README already documents this.
   - `kv update` on the CLI prints the same.

### 5. Security notes

- **Trust root.** The trust root is the GitHub release itself: the repo, and Leo's GitHub account. The checksum guards against a damaged download, not a bad release. The protection against a bad release is that nothing installs without the user saying yes. Leo accepted this in place of a signing key.
- **No server override.** There's no environment variable or flag in release builds that changes where kv looks for updates. Downloads go to github.com and its asset hosts over HTTPS only. Tests get their own seam, compiled only into test builds.
- **Downgrades.** Only strictly newer versions install, so an old release can't be pushed back as an update.
- **Downloads.** Downloads use the HTTPS client kv already ships with (reqwest with the platform verifier), with size limits on every file.
- **Possible later step.** If signing is wanted later, a signature check fits in at step 3 without changing the rest. Repo hygiene that helps now: 2FA or a passkey on Leo's GitHub account, and a tag protection rule so only Leo can push `v*` tags.
- **README.** Add a short "Updating kv" section covering:
  - what gets checked and how often;
  - the opt-out;
  - that kv trusts the GitHub release and always asks first;
  - what to expect after an update.

## Testing expectations

- Unit tests:
  - version comparison;
  - picking the platform's archive from a release's asset list;
  - checksum verification (good, mismatched, missing or malformed `.sha256`);
  - refusing an older or equal version;
  - extracting only the binary from an archive that also holds other paths.
- Swap tests in a temp folder on all three CI platforms, including the failure path: a mid-swap failure leaves the old binary in place.
- An end-to-end test against a local HTTP server serving a fake release. The test seam exists only under `cfg(test)` or a test-only feature.

## Left to the builder

- Exact UI text, the check interval and jitter, and the state file's format and location.
- How a release build marks itself, as long as builds from source and `cargo install --path` builds never self-update.
- Crate choices (e.g. `semver`, and archive readers for `.tar.xz` and `.zip`), within the repo's MSRV.
