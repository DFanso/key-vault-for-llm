# kv run and MCP servers through kv Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `env` handles pin a `run` command that the daemon launches with the handle's variables, relayed and scrubbed, so `kv run <handle>` and four new `kv mcp` tools replace servers-hub and its plaintext `servers.json`.

**Architecture:** A handle's policy gains `run: Option<Vec<String>>`. An agent-socket `Run` request is authorized like `exec` (policy, approval, a place in a book of at most 32 runs that ends on lock or handle change), then `broker::run` starts the program in the user's home directory and relays stdin, stdout and stderr as `RunInput`/`RunOutput` frames on the same connection, scrubbing output with a `StreamScrubber` that now holds back only bytes that could start a secret. `client::run_stream` turns that connection into byte streams; `kv run` pipes them to its own terminal, and `kv mcp` runs an rmcp client on them per server.

**Tech Stack:** Rust 2024 (MSRV 1.89), tokio 1.53 (`io-util`, `io-std`, `process`, `sync`), rmcp 3.5 (`client` feature added to the main dependency), serde/serde_json, base64 (kv-core), Bun for the one-off migration script.

**Spec:** `docs/superpowers/specs/2026-10-09-kv-run-design.md`, with the main design `docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md`.

## Decisions this plan makes

The spec leaves these open or states them loosely. Task 9 writes them into the spec.

- **`kv stop` ends runs as a lock.** `kv stop` locks the vault before the daemon exits, so its programs end with `Ended { reason: "the vault locked" }` and audit outcome `locked`. "kv stopped" is what `kv run` and the gateway say when the daemon connection breaks without an `Ended` frame (`RunEnd::Lost`).
- **`kv run` approvals read "an agent with no session".** `kv run` sends no `Hello`, and the Approvals tab already words a request without a session that way; no new client field is added.
- **A missing program is `upstream_error`**, as the spec says, even though `exec` reports the same case as `bad_request`.
- **Whether the program exists is checked at launch, after any approval.** `exec` does the same, so the daemon never touches the disk while holding its lock. The spec's "all checks happen before approval" covers policy, mode, the run command and the limit.
- **tokio's `io-std` feature is listed explicitly** for `kv run`'s terminal pumps. It was compiled in only through rmcp's `transport-io`.
- **The shared book keeps the name `Leases`.** It gains a limit and end reasons; `kv run` uses a second instance with a limit of 32.

## Global Constraints

- Edition 2024, `rust-version = "1.89"`: no language or library features newer than Rust 1.89.
- No new crates. The only manifest changes: rmcp's `client` feature on the main `rmcp` dependency, and tokio's `io-std` feature.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` pass after every task, on macOS, Linux and Windows: `cfg(unix)` code has a `cfg(not(unix))` counterpart where needed.
- No agent-socket message type has a field that holds a secret value. `RunOutput` carries only scrubbed bytes; `RunInput` carries what the client writes to the program.
- Every byte a launched program writes to stdout or stderr passes through a `StreamScrubber` before it leaves the daemon. Output cut by a kill, or written by anything the program left running, drops the held-back tail instead of flushing it.
- The pinned arguments never appear in messages, `list_handles`, `kv list`, `list_servers`, approvals or the audit log: only `program_name(argv[0])`, the file name of the program.
- The daemon mutex is never held across a launch, a relay or an approval wait.
- A launched program runs in the user's home directory, with the daemon's environment plus the handle's variables; a bare argv[0] resolves through `exec::resolve` on the daemon's PATH.
- Limits: at most 32 runs at once (counting those waiting for approval), `run` commands of at most 128 arguments of at most 4096 bytes, `RunInput`/`RunOutput` data of at most 64 KiB per frame, 120 s for a gateway server to finish MCP `initialize`, 60 s approval wait.
- Secret values and passphrases are never accepted as command-line arguments.
- Commit messages are one plain sentence saying what changed and why, with no conventional-commit prefix and no AI attribution or `Co-Authored-By` trailer.
- servers-hub's secret values must never be printed: the migration script and every command touching `servers.json` mask them.
- Use `bun` for the migration script.

## Review Focus

- **A program that writes more than 64 KiB in one write** (Dokploy's tool list is several hundred KiB): it must arrive whole, in order and scrubbed, split across frames. Test: Task 5, `a_large_write_arrives_whole_and_scrubbed`.
- **A program that exits when its stdin closes**: the client closing stdin must reach it as EOF, and its exit code must come back. Tests: Task 5, `output_is_scrubbed_and_each_reply_arrives_at_once` (exit 3 after EOF); Task 6, `add_a_server_list_it_and_run_it`.
- **A missing or unstartable program**: refused with an error that names only the program's file name, never the pinned arguments. Test: Task 5, `a_missing_program_is_refused_without_its_arguments`.
- **A server that exits on its own**: the next gateway call must start it again rather than fail forever. Test: Task 7, `a_server_that_quits_or_is_stopped_starts_again`.
- **A policy edit that does not mention `run`** (every `kv tui` policy edit): it must keep the run command. Test: Task 2, `policy_patch_without_run_keeps_the_run_command`.

---

### Task 1: Scrubber holds back only what could start a secret

**Files:**
- Modify: `crates/kv-core/src/scrub.rs`
- Test: `crates/kv-core/tests/scrub.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `Scrubber::resume(&self, pending: Vec<u8>) -> StreamScrubber<'_>`; `StreamScrubber::into_pending(self) -> Vec<u8>`. `StreamScrubber::push` now emits everything except the longest tail that is a proper prefix of a pattern.

- [ ] **Step 1: Write the failing tests**

Add to `crates/kv-core/tests/scrub.rs`, after `stream_without_secrets_passes_through`:

```rust
#[test]
fn stream_emits_a_complete_line_at_once() {
    let s = Scrubber::new([("openrouter", KEY)]);
    let mut stream = s.stream();
    let line = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n";
    assert_eq!(stream.push(line), line);
}

#[test]
fn stream_holds_back_only_a_possible_start_of_a_secret() {
    let s = Scrubber::new([("openrouter", KEY)]);
    let mut stream = s.stream();
    assert_eq!(stream.push(b"token: sk-or"), b"token: ");
    let mut out = b"token: ".to_vec();
    out.extend(stream.push(b"-v1-0123456789abcdef done\n"));
    out.extend(stream.finish());
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "token: [kv:openrouter] done\n"
    );
}

#[test]
fn a_secret_split_at_every_position_is_still_caught() {
    let s = Scrubber::new([("openrouter", KEY)]);
    let input = format!("a {KEY} b {} c\n", hex::encode(KEY));
    let bytes = input.as_bytes();
    for cut in 0..=bytes.len() {
        let mut stream = s.stream();
        let mut out = stream.push(&bytes[..cut]);
        out.extend(stream.push(&bytes[cut..]));
        out.extend(stream.finish());
        assert_eq!(out, s.scrub(bytes), "cut at {cut}");
    }
}

#[test]
fn a_stream_can_move_to_a_newer_scrubber() {
    const OTHER: &str = "pw-0123456789-abcdef";
    let old = Scrubber::new([("openrouter", KEY)]);
    let new = Scrubber::new([("openrouter", KEY), ("db", OTHER)]);
    let mut stream = old.stream();
    let mut out = stream.push(b"x sk-or");
    let mut stream = new.resume(stream.into_pending());
    out.extend(stream.push(format!("-v1-0123456789abcdef and {OTHER}\n").as_bytes()));
    out.extend(stream.finish());
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "x [kv:openrouter] and [kv:db]\n"
    );
}

#[test]
fn resuming_on_a_scrubber_without_secrets_keeps_the_held_bytes() {
    let old = Scrubber::new([("openrouter", KEY)]);
    let empty = Scrubber::new(std::iter::empty::<(&str, &str)>());
    let mut stream = old.stream();
    assert_eq!(stream.push(b"sk-or"), b"");
    let mut stream = empty.resume(stream.into_pending());
    assert_eq!(stream.push(b"-v1"), b"sk-or-v1");
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p kv-core --test scrub`
Expected: compile errors for `resume` and `into_pending`. After stubbing them, `stream_emits_a_complete_line_at_once` and `stream_holds_back_only_a_possible_start_of_a_secret` would fail, because today the last `longest − 1` bytes are always held.

- [ ] **Step 3: Implement**

In `crates/kv-core/src/scrub.rs`:

1. Add `use std::collections::HashSet;` at the top.
2. Add a field to `Scrubber`:

```rust
pub struct Scrubber {
    matcher: Option<AhoCorasick>,
    /// `replacements[i]` replaces pattern `i`.
    replacements: Vec<Vec<u8>>,
    max_pattern_len: usize,
    /// Every proper prefix of every pattern, in ASCII lowercase: the tails a
    /// stream must hold back, because more input could complete a secret.
    prefixes: HashSet<Vec<u8>>,
}
```

3. In `Scrubber::new`, after `let max_pattern_len = ...;`, build the prefixes and store them:

```rust
        let mut prefixes = HashSet::new();
        for pattern in &patterns {
            let lower = pattern.to_ascii_lowercase();
            for end in 1..lower.len() {
                prefixes.insert(lower[..end].to_vec());
            }
        }
```

and end the function with:

```rust
        Self {
            matcher,
            replacements,
            max_pattern_len,
            prefixes,
        }
```

4. Add to `impl Scrubber`, after `stream`:

```rust
    /// A stream that starts with `pending`, the bytes another stream held
    /// back (`StreamScrubber::into_pending`), so a long-running stream can
    /// move to a scrubber with newer secrets without losing them.
    pub fn resume(&self, pending: Vec<u8>) -> StreamScrubber<'_> {
        StreamScrubber {
            scrubber: self,
            pending,
        }
    }

    /// Where the tail that could still grow into a secret starts: the
    /// longest suffix of `pending` that is a proper prefix of a pattern, or
    /// `pending.len()` when none is.
    fn held_from(&self, pending: &[u8]) -> usize {
        let longest = self.max_pattern_len.saturating_sub(1).min(pending.len());
        let tail = pending[pending.len() - longest..].to_ascii_lowercase();
        (1..=longest)
            .rev()
            .find(|&len| self.prefixes.contains(&tail[longest - len..]))
            .map_or(pending.len(), |len| pending.len() - len)
    }
```

5. Replace the `StreamScrubber` doc comment and `push`, and add `into_pending`:

```rust
/// Scrubs output that arrives in chunks. Holds back only a tail that could
/// still grow into a secret, so a secret split across chunks is caught and
/// everything else goes out at once. The concatenated output equals
/// `Scrubber::scrub` on the whole input.
pub struct StreamScrubber<'s> {
    scrubber: &'s Scrubber,
    pending: Vec<u8>,
}

impl StreamScrubber<'_> {
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let Some(ac) = &self.scrubber.matcher else {
            let mut out = std::mem::take(&mut self.pending);
            out.extend_from_slice(chunk);
            return out;
        };
        self.pending.extend_from_slice(chunk);
        // A match starting before `cut` lies entirely inside `pending` and
        // cannot grow into a longer one: that would make the bytes from its
        // start a proper prefix of a pattern, and so part of the held tail.
        let cut = self.scrubber.held_from(&self.pending);
        let mut out = Vec::new();
        let mut last = 0;
        for m in ac.find_iter(&self.pending) {
            if m.start() >= cut {
                break;
            }
            out.extend_from_slice(&self.pending[last..m.start()]);
            out.extend_from_slice(&self.scrubber.replacements[m.pattern().as_usize()]);
            last = m.end();
        }
        let emit_to = cut.max(last);
        out.extend_from_slice(&self.pending[last..emit_to]);
        self.pending.drain(..emit_to);
        out
    }

    pub fn finish(self) -> Vec<u8> {
        self.scrubber.scrub(&self.pending)
    }

    /// The bytes held back so far, neither scrubbed nor emitted.
    pub fn into_pending(self) -> Vec<u8> {
        self.pending
    }
}
```

- [ ] **Step 4: Run the tests and see them pass**

Run: `cargo test -p kv-core --test scrub`
Expected: PASS, including the two property tests (`stream_output_equals_one_shot_output`, `no_encoding_of_a_secret_survives`).

- [ ] **Step 5: Check the workspace and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: all clean. `exec` tests still pass because the concatenated output is unchanged.

```bash
git add crates/kv-core/src/scrub.rs crates/kv-core/tests/scrub.rs
git commit -m "Hold back only a tail that could start a secret, so a waiting program's reply goes out at once"
```

---

### Task 2: The `run` command in policy, policy patches and handle info

**Files:**
- Modify: `crates/kv-core/src/policy.rs`
- Modify: `crates/kv-core/src/proto.rs` (`PolicyPatch` only)
- Modify: `crates/kv-core/src/secret.rs`
- Modify (add `runs: None,` to every `HandleInfo { .. }` literal): `crates/kv/tests/tui.rs`, `crates/kv/tests/tui_edit.rs`, `crates/kv/tests/tui_requests.rs`
- Test: `crates/kv-core/tests/policy.rs`, `crates/kv-core/tests/proto.rs`, `crates/kv-core/tests/secret.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `Policy.run: Option<Vec<String>>`.
  - `Operation::Run`.
  - `DenyReason::NoRunCommand`.
  - `pub const MAX_RUN_ARGS: usize = 128`, `pub const MAX_RUN_ARG_LEN: usize = 4096`.
  - `pub fn validate_run(argv: &[String]) -> Result<(), String>`.
  - `pub fn program_name(program: &str) -> String`.
  - `PolicyPatch.run: Option<Vec<String>>`, where `Some(vec![])` clears.
  - `HandleInfo.runs: Option<String>`.

- [ ] **Step 1: Write the failing tests**

Append to `crates/kv-core/tests/policy.rs`, and add `program_name, validate_run, MAX_RUN_ARGS, MAX_RUN_ARG_LEN` to its `use kv_core::policy::{...}` line:

```rust
fn runner(mode: Mode, run: Option<&[&str]>) -> Secret {
    env(Policy {
        mode,
        run: run.map(|argv| argv.iter().map(|a| a.to_string()).collect()),
        ..Policy::default()
    })
}

#[test]
fn run_needs_a_run_command() {
    assert_eq!(
        evaluate(&runner(Mode::Auto, None), &Operation::Run),
        Decision::Deny(DenyReason::NoRunCommand)
    );
    assert_eq!(
        evaluate(&runner(Mode::Auto, Some(&[])), &Operation::Run),
        Decision::Deny(DenyReason::NoRunCommand)
    );
}

#[test]
fn run_follows_the_mode() {
    let argv: &[&str] = &["/usr/local/bin/bunx", "-y", "ssh-mcp"];
    assert_eq!(
        evaluate(&runner(Mode::Auto, Some(argv)), &Operation::Run),
        Decision::Allow
    );
    assert_eq!(
        evaluate(&runner(Mode::Ask, Some(argv)), &Operation::Run),
        Decision::Ask
    );
    assert_eq!(
        evaluate(&runner(Mode::Deny, Some(argv)), &Operation::Run),
        Decision::Deny(DenyReason::ModeDeny)
    );
}

#[test]
fn run_is_only_for_env_handles() {
    let s = http(Policy {
        mode: Mode::Auto,
        run: Some(vec!["/bin/tool".into()]),
        ..Policy::default()
    });
    assert!(matches!(
        evaluate(&s, &Operation::Run),
        Decision::Deny(DenyReason::WrongKind { .. })
    ));
}

#[test]
fn exec_ignores_the_run_command() {
    let s = runner(Mode::Auto, Some(&["/bin/tool"]));
    assert!(matches!(
        evaluate(&s, &Operation::Exec { program: "/bin/tool" }),
        Decision::Deny(DenyReason::CommandNotAllowed { .. })
    ));
}

#[test]
fn run_commands_are_checked_before_they_are_stored() {
    let argv = |args: &[&str]| args.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    assert!(validate_run(&argv(&["bunx", "-y", "ssh-mcp@1.2.3"])).is_ok());
    assert!(validate_run(&[]).is_err());
    assert!(validate_run(&argv(&["", "x"])).is_err());
    assert!(validate_run(&argv(&["tool", "a\0b"])).is_err());
    assert!(validate_run(&vec!["x".to_string(); MAX_RUN_ARGS + 1]).is_err());
    assert!(validate_run(&["x".to_string(), "y".repeat(MAX_RUN_ARG_LEN + 1)]).is_err());
}

#[test]
fn program_name_is_the_file_name_only() {
    assert_eq!(program_name("/opt/homebrew/bin/bunx"), "bunx");
    assert_eq!(program_name("bunx"), "bunx");
}
```

Append to `crates/kv-core/tests/proto.rs`:

```rust
#[test]
fn policy_patch_sets_and_clears_the_run_command() {
    let mut policy = Policy::default();
    PolicyPatch {
        run: Some(vec!["bunx".into(), "-y".into(), "ssh-mcp".into()]),
        ..PolicyPatch::default()
    }
    .apply(&mut policy);
    assert_eq!(
        policy.run,
        Some(vec!["bunx".into(), "-y".into(), "ssh-mcp".into()])
    );
    PolicyPatch {
        run: Some(Vec::new()),
        ..PolicyPatch::default()
    }
    .apply(&mut policy);
    assert_eq!(policy.run, None);
}

#[test]
fn policy_patch_without_run_keeps_the_run_command() {
    let mut policy = Policy {
        run: Some(vec!["bunx".into()]),
        ..Policy::default()
    };
    // What `kv tui` sends when the user edits a handle's policy.
    PolicyPatch {
        mode: Some(Mode::Ask),
        allowed_cmds: Some(Vec::new()),
        ..PolicyPatch::default()
    }
    .apply(&mut policy);
    assert_eq!(policy.run, Some(vec!["bunx".into()]));
}

#[test]
fn a_policy_without_run_still_parses() {
    let policy: Policy = serde_json::from_str(r#"{"mode":"auto"}"#).unwrap();
    assert_eq!(policy.run, None);
    assert!(!serde_json::to_string(&policy).unwrap().contains("run"));
}
```

Append to `crates/kv-core/tests/secret.rs`, adding to its imports whatever is missing of `std::collections::BTreeMap`, `kv_core::policy::Policy` and `kv_core::secret::{Secret, SecretText, SecretValue}`:

```rust
#[test]
fn handle_info_shows_only_the_program_a_handle_runs() {
    let secret = Secret {
        name: "ssh-kycdev".into(),
        description: String::new(),
        value: SecretValue::Env {
            vars: BTreeMap::from([(
                "SSH_MCP_PASSWORD".to_string(),
                SecretText::new("hunter2-hunter2"),
            )]),
        },
        policy: Policy {
            run: Some(vec![
                "/usr/local/bin/bunx".into(),
                "-y".into(),
                "ssh-mcp@1.2.3".into(),
                "--host=10.0.0.5".into(),
            ]),
            ..Policy::default()
        },
        created_at: 0,
        updated_at: 0,
    };
    let info = secret.info();
    assert_eq!(info.runs.as_deref(), Some("bunx"));
    let json = serde_json::to_string(&info).unwrap();
    assert!(!json.contains("10.0.0.5"), "{json}");
    assert!(!json.contains("ssh-mcp"), "{json}");
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p kv-core --test policy --test proto --test secret`
Expected: compile errors: no field `run` on `Policy`/`PolicyPatch`, no `Operation::Run`, `validate_run`, `program_name`, `HandleInfo.runs`.

- [ ] **Step 3: Implement**

In `crates/kv-core/src/policy.rs`:

```rust
    /// `env`: the exact command `kv run` and `kv mcp` start with the
    /// variables set, program first. `None` launches nothing; `exec` never
    /// looks at it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<Vec<String>>,
```

Add the field above to `Policy` after `allowed_cmds`, and `run: None,` to `impl Default for Policy`. Then add these after `Policy`'s `Default` impl:

```rust
/// Longest `run` command, in arguments.
pub const MAX_RUN_ARGS: usize = 128;
/// Longest argument of a `run` command, in bytes.
pub const MAX_RUN_ARG_LEN: usize = 4096;

/// Checks a `run` command before it is stored: a program, at most
/// `MAX_RUN_ARGS` arguments of at most `MAX_RUN_ARG_LEN` bytes, and no NUL,
/// which no program can receive.
pub fn validate_run(argv: &[String]) -> Result<(), String> {
    match argv.first() {
        None => return Err("the run command is empty".into()),
        Some(program) if program.is_empty() => {
            return Err("the run command's program is empty".into());
        }
        Some(_) => {}
    }
    if argv.len() > MAX_RUN_ARGS {
        return Err(format!(
            "the run command has more than {MAX_RUN_ARGS} arguments"
        ));
    }
    if argv.iter().any(|arg| arg.len() > MAX_RUN_ARG_LEN) {
        return Err(format!(
            "an argument of the run command is longer than {MAX_RUN_ARG_LEN} bytes"
        ));
    }
    if argv.iter().any(|arg| arg.contains('\0')) {
        return Err("the run command cannot contain NUL characters".into());
    }
    Ok(())
}

/// The file name of a `run` command's program, which is all kv shows of
/// the command: the arguments may hold an address the user wants hidden.
pub fn program_name(program: &str) -> String {
    std::path::Path::new(program)
        .file_name()
        .map_or_else(|| program.to_owned(), |name| name.to_string_lossy().into_owned())
}
```

Add `Run` to `Operation`, and `"run"` to its `name`:

```rust
    /// Start the handle's `run` command.
    Run,
```

```rust
            Self::Run => "run",
```

Add to `DenyReason`:

```rust
    #[error("this handle has no run command; the user adds one with `kv policy <handle> --run -- <command>`")]
    NoRunCommand,
```

In `evaluate`, add `| (Operation::Run, SecretKind::Env)` to the `kind_ok` pattern, and to the `check` match:

```rust
        Operation::Run => check_run(policy),
```

Add next to `check_exec`:

```rust
fn check_run(policy: &Policy) -> Result<(), DenyReason> {
    match &policy.run {
        Some(argv) if !argv.is_empty() => Ok(()),
        _ => Err(DenyReason::NoRunCommand),
    }
}
```

In `crates/kv-core/src/proto.rs`, add to `PolicyPatch` after `allowed_cmds`:

```rust
    /// `env`: a new `run` command; an empty list clears it.
    #[serde(default)]
    pub run: Option<Vec<String>>,
```

and to `PolicyPatch::apply`, after the `allowed_cmds` branch:

```rust
        if let Some(argv) = &self.run {
            policy.run = (!argv.is_empty()).then(|| argv.clone());
        }
```

In `crates/kv-core/src/secret.rs`, add to `HandleInfo` after `auth`:

```rust
    /// `env`: the file name of the program the handle's `run` command
    /// starts, never its arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runs: Option<String>,
```

and to the `HandleInfo { .. }` literal in `Secret::info`, after `auth,`:

```rust
            runs: self
                .policy
                .run
                .as_ref()
                .and_then(|argv| argv.first())
                .map(|program| crate::policy::program_name(program)),
```

Then add `runs: None,` after the `auth: ...,` line of each complete `HandleInfo { .. }` literal:
- `crates/kv/tests/tui.rs`: `fn handle` (line 47).
- `crates/kv/tests/tui_edit.rs`: `fn http_handle` (line 75) and `fn env_handle` (line 96). The literals at lines 494 and 660 end in `..http_handle(..)`, so they need nothing.
- `crates/kv/tests/tui_requests.rs`: `fn handle` (line 85).

Leave `HandleRequest { .. }` literals alone; they have an `auth` field too.

- [ ] **Step 4: Run the tests and see them pass**

Run: `cargo test -p kv-core --test policy --test proto --test secret`
Expected: PASS.

- [ ] **Step 5: Check the workspace and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: all clean.

```bash
git add crates/kv-core crates/kv/tests/tui.rs crates/kv/tests/tui_edit.rs crates/kv/tests/tui_requests.rs
git commit -m "Let an env handle pin a run command, shown to agents only as its program name"
```

---

### Task 3: The lease book takes a limit and says why an entry ended

**Files:**
- Modify: `crates/kv/src/broker/lease.rs`
- Test: `crates/kv/tests/lease.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `pub enum EndReason { Locked, HandleChanged }`, with `message(self) -> &'static str` and `outcome(self) -> &'static str`.
  - `Leases::with_limit(limit: usize) -> Leases`.
  - `LeaseTicket::ended(&self) -> impl Future<Output = EndReason>`.
  - `end_handle` sends `HandleChanged`; `end_all` sends `Locked`.
  - `Leases::default()` keeps `MAX_LEASES`.

- [ ] **Step 1: Write the failing tests**

Append to `crates/kv/tests/lease.rs`, adding `use kv::broker::lease::EndReason;` and `use kv::broker::Leases;` if missing:

```rust
#[tokio::test]
async fn a_book_holds_at_most_its_limit() {
    let book = Leases::with_limit(2);
    let first = book.open("a").unwrap();
    let _second = book.open("b").unwrap();
    assert!(book.open("c").is_none());
    drop(first);
    assert!(book.open("c").is_some());
}

#[tokio::test]
async fn an_ended_entry_says_why() {
    let book = Leases::with_limit(4);
    let changed = book.open("a").unwrap();
    let locked = book.open("b").unwrap();
    book.end_handle("a");
    assert!(changed.has_ended());
    assert!(!locked.has_ended());
    assert_eq!(changed.ended().await, EndReason::HandleChanged);
    book.end_all();
    assert_eq!(locked.ended().await, EndReason::Locked);
    assert_eq!(EndReason::Locked.message(), "the vault locked");
    assert_eq!(EndReason::HandleChanged.outcome(), "handle_changed");
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p kv --test lease`
Expected: compile errors: no `with_limit`, `EndReason` or `ended`.

- [ ] **Step 3: Implement**

In `crates/kv/src/broker/lease.rs`:

```rust
/// Why the daemon ended a lease or a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    Locked,
    HandleChanged,
}

impl EndReason {
    /// Told to the client.
    pub fn message(self) -> &'static str {
        match self {
            Self::Locked => "the vault locked",
            Self::HandleChanged => "the handle changed",
        }
    }

    /// For the audit log.
    pub fn outcome(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::HandleChanged => "handle_changed",
        }
    }
}
```

Change `Leases`, `Book` and their impls as below. The scrubber field and methods stay as they are.

```rust
/// Open entries the daemon ends when the vault locks or a handle changes,
/// with the scrubber they follow. `db_connect` leases and `kv run`'s
/// programs each keep one book.
#[derive(Clone)]
pub struct Leases {
    book: Arc<Mutex<Book>>,
    scrubber: Arc<watch::Sender<Arc<Scrubber>>>,
    limit: usize,
}

#[derive(Default)]
struct Book {
    next: u64,
    /// Ending an entry sends its reason, then drops its sender.
    live: Vec<(u64, String, watch::Sender<Option<EndReason>>)>,
}

impl Default for Leases {
    fn default() -> Self {
        Self::with_limit(MAX_LEASES)
    }
}

impl Leases {
    /// A book that holds at most `limit` entries at once.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            book: Arc::default(),
            scrubber: Arc::new(watch::Sender::new(Arc::new(Scrubber::new([])))),
            limit,
        }
    }

    fn book(&self) -> std::sync::MutexGuard<'_, Book> {
        self.book.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A place for a new entry on `handle`; `None` when the book is full.
    pub fn open(&self, handle: &str) -> Option<LeaseTicket> {
        let mut book = self.book();
        if book.live.len() >= self.limit {
            return None;
        }
        book.next += 1;
        let id = book.next;
        let (sender, end) = watch::channel(None);
        book.live.push((id, handle.to_owned(), sender));
        Some(LeaseTicket {
            id,
            leases: self.clone(),
            end,
        })
    }

    pub fn end_handle(&self, handle: &str) {
        self.end_where(EndReason::HandleChanged, |h| h == handle);
    }

    pub fn end_all(&self) {
        self.end_where(EndReason::Locked, |_| true);
    }

    fn end_where(&self, reason: EndReason, matches: impl Fn(&str) -> bool) {
        self.book().live.retain(|(_, handle, sender)| {
            if !matches(handle) {
                return true;
            }
            sender.send_replace(Some(reason));
            false
        });
    }

    // `count`, `subscribe` and `set_scrubber` stay unchanged.
}
```

Change `LeaseTicket`'s `end` field type to `watch::Receiver<Option<EndReason>>`, and add to `impl LeaseTicket`:

```rust
    /// Waits until the daemon ends this entry, and says why.
    pub async fn ended(&self) -> EndReason {
        let mut end = self.end.clone();
        while end.changed().await.is_ok() {}
        let reason = *end.borrow();
        reason.unwrap_or(EndReason::Locked)
    }
```

Change the free function `ended` and the `connection` parameter types from `watch::Receiver<()>` to `watch::Receiver<Option<EndReason>>`. Do the same for every `end: watch::Receiver<()>` parameter in `broker/lease/postgres.rs` and `broker/lease/redis.rs`, which only wait on `changed()`. Run `grep -rn "Receiver<()>" crates/kv/src/broker` and change each hit.

- [ ] **Step 4: Run the tests and see them pass**

Run: `cargo test -p kv --test lease`
Expected: PASS.

- [ ] **Step 5: Check the workspace and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`

```bash
git add crates/kv/src/broker crates/kv/tests/lease.rs
git commit -m "Give the lease book a limit and an end reason, so kv run can share it"
```

---

### Task 4: The daemon authorizes `run`

**Files:**
- Modify: `crates/kv-core/src/proto.rs`
- Modify: `crates/kv/src/broker.rs`
- Modify: `crates/kv/src/daemon/state.rs`
- Modify: `crates/kv/src/daemon/server.rs`
- Modify: `crates/kv/tests/common/mod.rs`
- Modify: `crates/kv/tests/state.rs`
- Test: `crates/kv-core/tests/proto.rs`
- Test: `crates/kv/tests/run_policy.rs` (new)

**Interfaces:**
- Consumes:
  - `Policy.run`, `Operation::Run`, `program_name`, `validate_run` (Task 2).
  - `Leases::with_limit`, `EndReason`, `LeaseTicket::ended` (Task 3).
- Produces:
  - `RunCall { handle: String }`.
  - `AgentRequest::Run(RunCall)`.
  - `AgentResponse::Started`.
  - `RunInput::{Stdin { data: Vec<u8> }, CloseStdin}`.
  - `RunOutput::{Stdout { data }, Stderr { data }, Exited { code: Option<i32>, signal: Option<i32> }, Ended { reason: String }}`.
  - `pub const MAX_RUN_CHUNK: usize = 64 * 1024`.
  - `kv::broker::RunJob { handle, argv, env, ticket, scrubber, audit, started, decision }`.
  - `Prepared::Run(Box<RunJob>)`.
  - Test helpers `common::run_secret(name, vars, argv, mode) -> Secret`, `common::launch(handle) -> RunCall` and `Fixture::run_job(call) -> Result<RunJob, (AgentErrorCode, String)>`.

- [ ] **Step 1: Write the failing tests**

Append to `crates/kv-core/tests/proto.rs`, adding `RunCall, RunInput, RunOutput, MAX_RUN_CHUNK` to its `use kv_core::proto::{...}`:

```rust
#[test]
fn run_messages_are_tagged_and_carry_bytes_as_base64() {
    let request = AgentRequest::Run(RunCall {
        handle: "ssh-kycdev".into(),
    });
    let json = serde_json::to_string(&request).unwrap();
    assert_eq!(json, r#"{"type":"run","handle":"ssh-kycdev"}"#);
    assert_eq!(
        serde_json::from_str::<AgentRequest>(&json).unwrap(),
        request
    );
    assert_eq!(
        serde_json::to_string(&AgentResponse::Started).unwrap(),
        r#"{"type":"started"}"#
    );
    let input = RunInput::Stdin {
        data: b"{\"id\":1}\n\x00\xff".to_vec(),
    };
    let json = serde_json::to_string(&input).unwrap();
    assert!(json.contains("\"type\":\"stdin\""), "{json}");
    assert_eq!(serde_json::from_str::<RunInput>(&json).unwrap(), input);
    for output in [
        RunOutput::Stdout { data: vec![1, 2, 3] },
        RunOutput::Stderr { data: Vec::new() },
        RunOutput::Exited {
            code: Some(3),
            signal: None,
        },
        RunOutput::Ended {
            reason: "the vault locked".into(),
        },
    ] {
        let json = serde_json::to_string(&output).unwrap();
        assert_eq!(serde_json::from_str::<RunOutput>(&json).unwrap(), output);
    }
}

#[test]
fn a_full_run_chunk_fits_in_a_frame() {
    let output = RunOutput::Stdout {
        data: vec![0xff; MAX_RUN_CHUNK * 2],
    };
    assert!(serde_json::to_vec(&output).unwrap().len() < MAX_FRAME_LEN);
}
```

Add to `crates/kv/tests/common/mod.rs`. Add `RunJob` to the `kv::broker::{...}` import and `RunCall` to the `kv_core::proto::{...}` import; then add `| Prepared::Run(_)` to each of the five `panic!` arms in `http`, `exec`, `db`, `connect` and `wait`, and add:

```rust
    pub fn run_job(&mut self, call: RunCall) -> Result<RunJob, (AgentErrorCode, String)> {
        match self.prepare(AgentRequest::Run(call)) {
            Prepared::Run(job) => Ok(*job),
            Prepared::Reply(AgentResponse::Error { code, message }) => Err((code, message)),
            Prepared::Reply(other) => panic!("unexpected reply {other:?}"),
            Prepared::Http(_) | Prepared::Exec(_) | Prepared::Db(_) | Prepared::Connect(_) => {
                panic!("unexpected job")
            }
            Prepared::Wait(_) => panic!("unexpected wait for approval"),
        }
    }
```

inside `impl Fixture`, and at module level:

```rust
/// An env handle whose `run` command is `argv`.
pub fn run_secret(name: &str, vars: &[(&str, &str)], argv: &[&str], mode: Mode) -> Secret {
    let mut secret = env_secret(name, vars, &[], mode);
    secret.policy.run = Some(argv.iter().map(|a| a.to_string()).collect());
    secret
}

pub fn launch(handle: &str) -> RunCall {
    RunCall {
        handle: handle.into(),
    }
}
```

In `crates/kv/tests/state.rs`, add `| Prepared::Run(_)` to the arm in `agent_at` that panics with "expected a reply, got a job".

Create `crates/kv/tests/run_policy.rs`:

```rust
//! Authorizing `run`: which handles may start their command, approval,
//! the limit, validation of run commands, and what ends a run.

mod common;

use common::*;
use kv::broker::lease::EndReason;
use kv_core::policy::Mode;
use kv_core::proto::{
    AgentErrorCode, AgentRequest, ControlCommand, ControlErrorCode, ControlResponse, PolicyPatch,
    Verdict,
};

const SECRET: &str = "hunter2-hunter2-0123";
const HOST: &str = "10.0.0.5";

fn add_server(f: &mut Fixture, name: &str, mode: Mode) {
    f.add(run_secret(
        name,
        &[("SSH_MCP_PASSWORD", SECRET)],
        &["/usr/local/bin/bunx", "-y", "ssh-mcp@1.2.3", "--host=10.0.0.5"],
        mode,
    ));
}

#[test]
fn run_is_refused_while_the_vault_is_locked() {
    let mut f = Fixture::new();
    add_server(&mut f, "srv", Mode::Auto);
    f.control(ControlCommand::Lock);
    let (code, _) = f.run_job(launch("srv")).unwrap_err();
    assert_eq!(code, AgentErrorCode::VaultLocked);
}

#[test]
fn run_needs_a_known_env_handle_with_a_run_command() {
    let mut f = Fixture::new();
    f.add(env_secret("plain", &[("A", SECRET)], &["tool"], Mode::Auto));
    f.add(openrouter(Mode::Auto));
    assert_eq!(
        f.run_job(launch("nope")).unwrap_err().0,
        AgentErrorCode::UnknownHandle
    );
    let (code, message) = f.run_job(launch("plain")).unwrap_err();
    assert_eq!(code, AgentErrorCode::PolicyDenied);
    assert!(message.contains("no run command"), "{message}");
    assert_eq!(
        f.run_job(launch("openrouter")).unwrap_err().0,
        AgentErrorCode::PolicyDenied
    );
}

#[test]
fn an_auto_server_gets_its_command_and_variables() {
    let mut f = Fixture::new();
    add_server(&mut f, "srv", Mode::Auto);
    let job = f.run_job(launch("srv")).unwrap();
    assert_eq!(job.handle, "srv");
    assert_eq!(job.argv[0], "/usr/local/bin/bunx");
    assert_eq!(job.argv[3], "--host=10.0.0.5");
    assert_eq!(job.env.len(), 1);
    assert_eq!(job.env[0].0, "SSH_MCP_PASSWORD");
    assert_eq!(job.env[0].1.expose(), SECRET);
    assert_eq!(job.decision, "auto");
    assert!(!format!("{job:?}").contains(HOST));
}

#[test]
fn a_deny_server_is_refused() {
    let mut f = Fixture::new();
    add_server(&mut f, "srv", Mode::Deny);
    assert_eq!(
        f.run_job(launch("srv")).unwrap_err().0,
        AgentErrorCode::PolicyDenied
    );
}

#[test]
fn an_ask_server_waits_and_a_session_grant_covers_the_next_start() {
    let mut f = Fixture::new();
    add_server(&mut f, "srv", Mode::Ask);
    let agent = session("s1");
    let waiting = f.wait(Some(&agent), AgentRequest::Run(launch("srv")), f.t0);
    let token = f.token();
    let approval = f.overview(&token).approvals.remove(0);
    assert_eq!(approval.tool, "run");
    assert_eq!(approval.detail, "starts bunx");
    assert!(approval.can_grant);
    assert!(!format!("{approval:?}").contains(HOST));
    assert!(matches!(
        f.decide(&token, waiting.id, Verdict::AllowSession),
        ControlResponse::Done { .. }
    ));
    match f
        .daemon
        .prepare_in(Some(&agent), AgentRequest::Run(launch("srv")), f.t0)
    {
        kv::daemon::Prepared::Run(job) => assert_eq!(job.decision, "approved"),
        _ => panic!("expected the grant to cover the second start"),
    }
    let other = session("s2");
    f.wait(Some(&other), AgentRequest::Run(launch("srv")), f.t0);
}

#[test]
fn at_most_32_programs_run_at_once() {
    let mut f = Fixture::new();
    add_server(&mut f, "srv", Mode::Auto);
    let jobs: Vec<_> = (0..32).map(|_| f.run_job(launch("srv")).unwrap()).collect();
    let (code, message) = f.run_job(launch("srv")).unwrap_err();
    assert_eq!(code, AgentErrorCode::PolicyDenied);
    assert!(message.contains("32 programs"), "{message}");
    drop(jobs);
    assert!(f.run_job(launch("srv")).is_ok());
}

#[tokio::test]
async fn changing_the_handle_and_locking_end_runs() {
    let mut f = Fixture::new();
    add_server(&mut f, "srv", Mode::Auto);
    add_server(&mut f, "other", Mode::Auto);
    let changed = f.run_job(launch("srv")).unwrap();
    let locked = f.run_job(launch("other")).unwrap();
    f.control(ControlCommand::SetPolicy {
        name: "srv".into(),
        patch: PolicyPatch {
            grant_ttl: Some(std::time::Duration::from_secs(60)),
            ..PolicyPatch::default()
        },
    });
    assert_eq!(changed.ticket.ended().await, EndReason::HandleChanged);
    assert!(!locked.ticket.has_ended());
    f.control(ControlCommand::Lock);
    assert_eq!(locked.ticket.ended().await, EndReason::Locked);
}

#[test]
fn run_commands_are_validated_when_stored() {
    let mut f = Fixture::new();
    let refused = |f: &mut Fixture, secret| match f.send(
        Some(PASS),
        None,
        ControlCommand::Add {
            secret,
            replace: false,
        },
    ) {
        ControlResponse::Error {
            code: ControlErrorCode::Invalid,
            message,
        } => message,
        other => panic!("expected invalid, got {other:?}"),
    };
    let mut web = openrouter(Mode::Auto);
    web.policy.run = Some(vec!["/bin/tool".into()]);
    assert!(refused(&mut f, web).contains("only env handles"));
    let empty = env_secret("empty", &[], &[], Mode::Auto);
    assert!(refused(&mut f, empty).contains("at least one variable"));
    let mut blank = env_secret("blank", &[], &[], Mode::Auto);
    blank.policy.run = Some(vec![String::new()]);
    assert!(refused(&mut f, blank).contains("program is empty"));

    // A run-only handle: a command and no variables.
    f.add(run_secret("bare", &[], &["/usr/bin/true"], Mode::Auto));
    match f.send(
        Some(PASS),
        None,
        ControlCommand::SetPolicy {
            name: "bare".into(),
            patch: PolicyPatch {
                run: Some(Vec::new()),
                ..PolicyPatch::default()
            },
        },
    ) {
        ControlResponse::Error { message, .. } => {
            assert!(message.contains("at least one variable"), "{message}")
        }
        other => panic!("expected an error, got {other:?}"),
    }
    let job = f.run_job(launch("bare")).unwrap();
    assert!(job.env.is_empty());
}

#[test]
fn the_audit_log_names_the_program_but_not_its_arguments() {
    let mut f = Fixture::new();
    add_server(&mut f, "srv", Mode::Deny);
    let _ = f.run_job(launch("srv"));
    let lines = f.audit_lines();
    let run = lines
        .iter()
        .find(|line| line["action"] == "run")
        .expect("a run entry");
    assert_eq!(run["handle"], "srv");
    assert_eq!(run["summary"], "bunx");
    assert_eq!(run["decision"], "policy");
    for line in &lines {
        assert!(!line.to_string().contains(HOST), "{line}");
        assert!(!line.to_string().contains(SECRET), "{line}");
    }
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p kv-core --test proto && cargo test -p kv --test run_policy`
Expected: compile errors: no `RunCall`, `RunInput`, `RunOutput`, `AgentResponse::Started`, `Prepared::Run`, `RunJob`.

- [ ] **Step 3: Implement the protocol (kv-core)**

In `crates/kv-core/src/proto.rs`, add `Run(RunCall),` to `AgentRequest` after `RequestHandle`, and this to `AgentResponse` before `Error`:

```rust
    /// The handle's program is running. From here on the connection
    /// carries `RunInput` frames to the daemon and `RunOutput` frames back.
    Started,
```

Add after `MAX_OUTPUT_LEN`:

```rust
/// Largest `data` in one `RunInput` or `RunOutput` frame, in bytes. Larger
/// output is split across frames.
pub const MAX_RUN_CHUNK: usize = 64 * 1024;
```

Add near the other call types:

```rust
/// Starts the handle's `run` command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunCall {
    pub handle: String,
}

/// From the client to a running program.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RunInput {
    Stdin {
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
    /// The client has nothing more to write; the program sees end of input.
    CloseStdin,
}

/// From a running program to the client, scrubbed. Ends with exactly one
/// `Exited` or `Ended`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RunOutput {
    Stdout {
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
    Stderr {
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
    /// The program ended by itself. `signal` is set on Unix when a signal
    /// ended it.
    Exited {
        code: Option<i32>,
        signal: Option<i32>,
    },
    /// kv ended the program, for `reason`.
    Ended { reason: String },
}

/// Bytes as a base64 string, so program output that is not UTF-8 survives
/// the JSON frame.
mod base64_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}
```

- [ ] **Step 4: Implement the job type and the daemon (kv)**

In `crates/kv/src/broker.rs`, add `use kv_core::policy::program_name;` and:

```rust
/// A `run` that passed every check.
pub struct RunJob {
    pub handle: String,
    /// The handle's `run` command, program first.
    pub argv: Vec<String>,
    pub env: Vec<(String, SecretText)>,
    /// The run's place among the open runs, taken when it was authorized,
    /// so a lock or a change to the handle ends it even before it starts.
    pub ticket: LeaseTicket,
    /// The scrubber for every unlocked secret, kept current while it runs.
    pub scrubber: tokio::sync::watch::Receiver<Arc<Scrubber>>,
    pub audit: Audit,
    pub started: Instant,
    /// `auto`, or `approved` after a decision in `kv tui`, for the audit log.
    pub decision: &'static str,
}

/// The program's name only: its arguments may hold a hidden address, and
/// the job holds values.
impl std::fmt::Debug for RunJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunJob")
            .field("handle", &self.handle)
            .field("program", &self.argv.first().map(|p| program_name(p)))
            .finish_non_exhaustive()
    }
}
```

In `crates/kv/src/daemon/state.rs`:

1. Imports:
   - Add `program_name` and `validate_run` to `kv_core::policy::{...}`.
   - Add `RunCall` to `kv_core::proto::{...}`.
   - Add `RunJob` to `crate::broker::{...}`.
2. Constant, after `MAX_PENDING`:

```rust
/// Programs started through `run` at once, counting those waiting for
/// approval.
const MAX_RUNS: usize = 32;
```

3. Field on `Daemon`, after `leases`:

```rust
    /// Programs started through `run`. All end when the vault locks; a
    /// handle's end when it changes.
    runs: Leases,
```

   and in `Daemon::new`: `runs: Leases::with_limit(MAX_RUNS),`.

4. `Prepared` gains `Run(Box<RunJob>),` after `Connect`.

5. In `prepare_in`, add the arm `AgentRequest::Run(call) => self.prepare_run(call, session, now),` after `DbConnect`.

6. Add after `prepare_connect`:

```rust
    fn prepare_run(
        &mut self,
        call: RunCall,
        session: Option<&SessionInfo>,
        now: Instant,
    ) -> Prepared {
        let handle = call.handle;
        let refuse = |daemon: &Self, summary: &str, decision, response| {
            daemon.refuse("run", &handle, summary, decision, response)
        };
        let Some(vault) = &self.vault else {
            return refuse(self, "", "locked", self.locked_error());
        };
        let Some(secret) = vault.get(&handle).cloned() else {
            return refuse(self, "", "invalid", unknown_handle(vault, &handle));
        };
        let program = secret
            .policy
            .run
            .as_ref()
            .and_then(|argv| argv.first())
            .map(|p| program_name(p))
            .unwrap_or_default();
        let decision = evaluate(&secret, &Operation::Run);
        if let Decision::Deny(reason) = decision {
            return refuse(
                self,
                &program,
                "policy",
                agent_error(AgentErrorCode::PolicyDenied, reason),
            );
        }
        let ask = decision == Decision::Ask && !self.granted(session, &handle, now);
        if ask && self.approvals.len() >= MAX_PENDING {
            return refuse(self, &program, "denied", too_many_waiting());
        }
        let Some(ticket) = self.runs.open(&handle) else {
            let message = format!(
                "{MAX_RUNS} programs are running through kv already; stop one, or ask the user \
                 to lock the vault"
            );
            return refuse(
                self,
                &program,
                "denied",
                agent_error(AgentErrorCode::PolicyDenied, message),
            );
        };
        self.touch(now);
        let scrubber = self.scrubber();
        self.runs.set_scrubber(scrubber);
        let env = match &secret.value {
            SecretValue::Env { vars } => vars
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            _ => Vec::new(),
        };
        let job = Prepared::Run(Box::new(RunJob {
            handle: handle.clone(),
            argv: secret.policy.run.clone().unwrap_or_default(),
            env,
            ticket,
            scrubber: self.runs.subscribe(),
            audit: self.audit.clone(),
            started: now,
            decision: if decision == Decision::Ask {
                "approved"
            } else {
                "auto"
            },
        }));
        if !ask {
            return job;
        }
        let ask = Ask {
            tool: "run",
            ask: vec![handle.clone()],
            handles: handle,
            summary: program.clone(),
            detail: format!("starts {program}"),
            cwd: None,
        };
        self.queue(ask, job, session, now)
    }
```

7. In `handle_changed`, after `self.leases.end_handle(name);`, add `self.runs.end_handle(name);`. In `lock_vault`, after `self.leases.end_all();`, add `self.runs.end_all();`. In `handle_control`, replace the lease scrubber refresh with:

```rust
                        // Open leases and runs scrub with the secrets as they are now.
                        if self.leases.count() > 0 || self.runs.count() > 0 {
                            let scrubber = self.scrubber();
                            self.leases.set_scrubber(scrubber.clone());
                            self.runs.set_scrubber(scrubber);
                        }
```

8. Validation:
   - Remove the `if vars.is_empty() { ... }` check from the `SecretValue::Env` branch of `validate_value`. Keep the variable-name check.
   - Add the function below.
   - Call `validate_secret(&secret)?;` in `add`, right after `validate_value(&secret.value)?;`.
   - Call `validate_secret(&updated)?;` in `set_policy`, right after `patch.apply(&mut updated.policy);`.
   - Call `validate_secret(&updated)?;` in `update`, right before `let warnings = warnings_for(&updated);`.

```rust
/// Checks what `validate_value` cannot see alone: a `run` command needs an
/// env handle and a valid argv, and only a handle with one may have no
/// variables.
fn validate_secret(secret: &Secret) -> Result<(), Failure> {
    let invalid = |message: String| Err(fail(ControlErrorCode::Invalid, message));
    if let Some(argv) = &secret.policy.run {
        if secret.kind() != SecretKind::Env {
            return invalid("only env handles can have a run command".into());
        }
        if let Err(why) = validate_run(argv) {
            return invalid(why);
        }
    }
    if let SecretValue::Env { vars } = &secret.value
        && vars.is_empty()
        && secret.policy.run.is_none()
    {
        return invalid("an env handle needs at least one variable, or a run command".into());
    }
    Ok(())
}
```

In `crates/kv/src/daemon/server.rs`, add this arm to `run_job`, after `Prepared::Wait(_)`:

```rust
        // `serve_agent` gives a run its connection before this point.
        Prepared::Run(_) => AgentResponse::Error {
            code: AgentErrorCode::UpstreamError,
            message: "internal error: a run reached the reply path".into(),
        },
```

- [ ] **Step 5: Run the tests and see them pass**

Run: `cargo test -p kv-core --test proto && cargo test -p kv --test run_policy --test state`
Expected: PASS.

- [ ] **Step 6: Check the workspace and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`

```bash
git add crates/kv-core crates/kv/src crates/kv/tests
git commit -m "Authorize run requests: policy, approval, a book of 32 runs, and stored run commands checked"
```

---

### Task 5: Launch and relay the program, and the client side of a run

**Files:**
- Create: `crates/kv/src/broker/run.rs`
- Modify: `crates/kv/src/broker.rs` (`pub mod run;`)
- Modify: `crates/kv/src/daemon/server.rs`
- Modify: `crates/kv/src/client.rs`
- Test: `crates/kv/tests/run.rs` (new)

**Interfaces:**
- Consumes:
  - `RunJob`, `RunInput`, `RunOutput`, `MAX_RUN_CHUNK`, `AgentResponse::Started` (Task 4).
  - `Scrubber::resume`, `StreamScrubber::into_pending` (Task 1).
  - `LeaseTicket::ended`, `EndReason` (Task 3).
  - `exec::resolve`, `process::{isolate, ProcessTree}`.
- Produces:
  - `kv::broker::run::serve<S: AsyncRead + AsyncWrite + Send + 'static>(stream: S, job: RunJob)`.
  - `kv::client::run_stream(paths: &Paths, session: Option<&SessionInfo>, handle: &str) -> io::Result<Result<RunStream, AgentResponse>>`.
  - `pub struct RunStream { pub stdin: WriteHalf<SimplexStream>, pub stdout: ReadHalf<SimplexStream>, pub stderr: mpsc::Receiver<Vec<u8>>, pub ended: oneshot::Receiver<RunEnd>, pub guard: RunGuard }`.
  - `pub enum RunEnd { Exited { code: Option<i32>, signal: Option<i32> }, Ended(String), Lost }`.
  - `pub struct RunGuard`, which closes the connection when dropped.

- [ ] **Step 1: Write the failing tests**

Create `crates/kv/tests/run.rs`:

```rust
//! Programs started through `run`, end to end: a daemon in this process,
//! reached through its real sockets, starts this test binary, whose
//! `helper` test acts as the program when `KV_RUN_HELPER` is set.

mod common;
mod live;

use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use kv::client::{self, RunEnd, RunStream};
use kv_core::policy::Mode;
use kv_core::proto::{AgentErrorCode, AgentResponse, ControlCommand, SessionInfo, Verdict};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

const SECRET: &str = "s3cr3t-run-value-0123456789";
const MODE_VAR: &str = "KV_RUN_HELPER";

/// Not a real test. Started by kv with `KV_RUN_HELPER` set, it behaves as
/// the program under test and exits without letting the harness print more.
#[test]
fn helper() {
    let Ok(mode) = std::env::var(MODE_VAR) else {
        return;
    };
    let secret = std::env::var("SECRET_VALUE").unwrap_or_default();
    let mut out = std::io::stdout();
    match mode.as_str() {
        // One reply per line, then exit 3 at end of input.
        "echo" => {
            for line in std::io::stdin().lock().lines() {
                writeln!(out, "got {} secret={secret}", line.unwrap()).unwrap();
                out.flush().unwrap();
            }
            std::process::exit(3);
        }
        // More than a frame's worth in one write.
        "big" => {
            let mut text = "x".repeat(1 << 20);
            text.push_str(&format!(" secret={secret}\n"));
            out.write_all(text.as_bytes()).unwrap();
            out.flush().unwrap();
            std::process::exit(0);
        }
        "sleep" => {
            writeln!(out, "ready pid={} end", std::process::id()).unwrap();
            out.flush().unwrap();
            std::thread::sleep(Duration::from_secs(60));
            std::process::exit(0);
        }
        #[cfg(unix)]
        "signal" => {
            writeln!(out, "ready").unwrap();
            out.flush().unwrap();
            let me = rustix::process::getpid();
            let _ = rustix::process::kill_process(me, rustix::process::Signal::TERM);
            std::thread::sleep(Duration::from_secs(60));
            std::process::exit(0);
        }
        other => panic!("unknown helper mode {other}"),
    }
}

fn helper_argv() -> Vec<String> {
    let exe = std::env::current_exe().unwrap();
    [
        exe.to_str().unwrap(),
        "helper",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]
    .map(String::from)
    .to_vec()
}

async fn add_server(daemon: &live::Daemon, name: &str, mode: &str, policy_mode: Mode) {
    let argv = helper_argv();
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let secret = common::run_secret(
        name,
        &[("SECRET_VALUE", SECRET), (MODE_VAR, mode)],
        &argv,
        policy_mode,
    );
    daemon
        .control(
            Some(live::PASS),
            ControlCommand::Add {
                secret,
                replace: false,
            },
        )
        .await;
}

async fn start(daemon: &live::Daemon, name: &str) -> RunStream {
    match client::run_stream(&daemon.paths, None, name).await.unwrap() {
        Ok(stream) => stream,
        Err(refusal) => panic!("refused: {refusal:?}"),
    }
}

/// Reads until `text` appears, without sending anything more.
async fn read_until(stdout: &mut (impl AsyncRead + Unpin), text: &str) -> String {
    let mut seen = Vec::new();
    let mut buffer = [0u8; 4096];
    tokio::time::timeout(Duration::from_secs(20), async {
        while !String::from_utf8_lossy(&seen).contains(text) {
            let n = stdout.read(&mut buffer).await.unwrap();
            assert!(
                n > 0,
                "output ended before {text:?}: {}",
                String::from_utf8_lossy(&seen)
            );
            seen.extend_from_slice(&buffer[..n]);
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {text:?}"));
    String::from_utf8_lossy(&seen).into_owned()
}

fn audit_has(daemon: &live::Daemon, outcome: &str) -> bool {
    std::fs::read_to_string(&daemon.paths.audit)
        .unwrap_or_default()
        .lines()
        .any(|line| line.contains("\"action\":\"run\"") && line.contains(outcome))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn output_is_scrubbed_and_each_reply_arrives_at_once() {
    let daemon = live::Daemon::start().await;
    add_server(&daemon, "echo", "echo", Mode::Auto).await;
    let mut run = start(&daemon, "echo").await;
    run.stdin.write_all(b"hello\n").await.unwrap();
    // The whole reply arrives while the program waits for more input.
    let seen = read_until(&mut run.stdout, "got hello secret=[kv:echo]\n").await;
    assert!(!seen.contains(SECRET), "{seen}");
    run.stdin.write_all(b"again\n").await.unwrap();
    read_until(&mut run.stdout, "got again").await;
    run.stdin.shutdown().await.unwrap();
    let end = tokio::time::timeout(Duration::from_secs(20), run.ended)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        end,
        RunEnd::Exited {
            code: Some(3),
            signal: None
        }
    );
    assert!(audit_has(&daemon, "exited:3"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_write_arrives_whole_and_scrubbed() {
    let daemon = live::Daemon::start().await;
    add_server(&daemon, "big", "big", Mode::Auto).await;
    let mut run = start(&daemon, "big").await;
    let mut all = String::new();
    tokio::time::timeout(Duration::from_secs(30), run.stdout.read_to_string(&mut all))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(all.matches('x').count(), 1 << 20);
    assert!(all.contains("secret=[kv:big]"));
    assert!(!all.contains(SECRET));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locking_ends_the_program() {
    let daemon = live::Daemon::start().await;
    add_server(&daemon, "sleeper", "sleep", Mode::Auto).await;
    let mut run = start(&daemon, "sleeper").await;
    read_until(&mut run.stdout, "ready").await;
    daemon.control(None, ControlCommand::Lock).await;
    let end = tokio::time::timeout(Duration::from_secs(20), run.ended)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(end, RunEnd::Ended("the vault locked".into()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changing_the_handle_ends_the_program() {
    let daemon = live::Daemon::start().await;
    add_server(&daemon, "sleeper", "sleep", Mode::Auto).await;
    let mut run = start(&daemon, "sleeper").await;
    read_until(&mut run.stdout, "ready").await;
    daemon
        .control(
            Some(live::PASS),
            ControlCommand::SetPolicy {
                name: "sleeper".into(),
                patch: kv_core::proto::PolicyPatch {
                    grant_ttl: Some(Duration::from_secs(60)),
                    ..Default::default()
                },
            },
        )
        .await;
    let end = tokio::time::timeout(Duration::from_secs(20), run.ended)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(end, RunEnd::Ended("the handle changed".into()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnecting_kills_the_program() {
    let daemon = live::Daemon::start().await;
    add_server(&daemon, "sleeper", "sleep", Mode::Auto).await;
    let mut run = start(&daemon, "sleeper").await;
    let seen = read_until(&mut run.stdout, " end").await;
    let pid: i32 = seen
        .split("pid=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    drop(run);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !audit_has(&daemon, "client_closed") {
        assert!(Instant::now() < deadline, "the run was not ended");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    #[cfg(unix)]
    {
        let pid = rustix::process::Pid::from_raw(pid).unwrap();
        while rustix::process::test_kill_process(pid).is_ok() {
            assert!(Instant::now() < deadline, "the program is still running");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let _ = pid;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signal_is_reported() {
    let daemon = live::Daemon::start().await;
    add_server(&daemon, "signal", "signal", Mode::Auto).await;
    let run = start(&daemon, "signal").await;
    let end = tokio::time::timeout(Duration::from_secs(20), run.ended)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        end,
        RunEnd::Exited {
            code: None,
            signal: Some(15)
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_program_is_refused_without_its_arguments() {
    let daemon = live::Daemon::start().await;
    let secret = common::run_secret(
        "missing",
        &[("SECRET_VALUE", SECRET)],
        &["/nonexistent-kv-test/tool", "--host=10.9.8.7"],
        Mode::Auto,
    );
    daemon
        .control(
            Some(live::PASS),
            ControlCommand::Add {
                secret,
                replace: false,
            },
        )
        .await;
    match client::run_stream(&daemon.paths, None, "missing")
        .await
        .unwrap()
    {
        Err(AgentResponse::Error { code, message }) => {
            assert_eq!(code, AgentErrorCode::UpstreamError);
            assert!(message.contains("tool"), "{message}");
            assert!(!message.contains("10.9.8.7"), "{message}");
            assert!(!message.contains("nonexistent"), "{message}");
        }
        Ok(_) => panic!("a missing program started"),
        Err(other) => panic!("unexpected reply {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ask_server_starts_once_approved() {
    let daemon = live::Daemon::start().await;
    add_server(&daemon, "asker", "echo", Mode::Ask).await;
    let paths = daemon.paths.clone();
    let pending = tokio::spawn(async move {
        let session = SessionInfo {
            id: "session-1".into(),
            client: "approval test".into(),
        };
        client::run_stream(&paths, Some(&session), "asker")
            .await
            .unwrap()
    });
    let id = daemon.waiting_id().await;
    daemon
        .with_token(ControlCommand::Decide {
            id,
            verdict: Verdict::AllowOnce,
        })
        .await;
    let Ok(mut run) = pending.await.unwrap() else {
        panic!("the approved run was refused");
    };
    run.stdin.write_all(b"hi\n").await.unwrap();
    read_until(&mut run.stdout, "got hi").await;
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p kv --test run`
Expected: compile errors: no `client::run_stream`, `RunEnd` or `RunStream`.

- [ ] **Step 3: Implement the daemon side**

Add `pub mod run;` to `crates/kv/src/broker.rs` next to the other modules. Create `crates/kv/src/broker/run.rs`:

```rust
//! `run`: starts a handle's `run` command with its variables set, in the
//! user's home directory, and relays its stdin, stdout and stderr over the
//! connection that asked, scrubbing what comes out. The program ends when
//! it exits, when the client goes away, when the vault locks or when the
//! handle changes.

use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use kv_core::policy::program_name;
use kv_core::proto::{AgentErrorCode, AgentResponse, MAX_RUN_CHUNK, RunInput, RunOutput};
use kv_core::scrub::Scrubber;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, watch};

use super::RunJob;
use super::exec::resolve;
use super::lease::EndReason;
use super::process::{ProcessTree, isolate};
use crate::audit::Use;
use crate::frame::{read_frame, write_frame};

/// How long to wait for the output pipes once the program has ended and
/// anything it left running has been killed.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
enum Pipe {
    Stdout,
    Stderr,
}

enum End {
    Exited(Option<ExitStatus>),
    Ended(EndReason),
    ClientClosed,
}

/// Starts the program and relays it over `stream` until it ends. Records
/// the launch, or the refusal, and the end in the audit log.
pub async fn serve<S>(stream: S, job: RunJob)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let program = program_name(&job.argv[0]);
    let (mut child, tree) = match launch(&job, &program) {
        Ok(started) => started,
        Err(response) => {
            let outcome = match &response {
                AgentResponse::Error { code, .. } => code.as_str(),
                _ => "error",
            };
            record(&job, &program, outcome, job.started.elapsed());
            let _ = write_frame(&mut writer, &response).await;
            return;
        }
    };
    record(&job, &program, "started", job.started.elapsed());
    let running = Instant::now();
    if write_frame(&mut writer, &AgentResponse::Started)
        .await
        .is_err()
    {
        tree.kill();
        let _ = child.wait().await;
        record(&job, &program, "client_closed", running.elapsed());
        return;
    }
    let cut = Arc::new(AtomicBool::new(false));
    let (queue, outbox) = mpsc::channel(16);
    let delivery = tokio::spawn(deliver(writer, outbox));
    let stdout = tokio::spawn(pump(
        child.stdout.take(),
        job.scrubber.clone(),
        queue.clone(),
        cut.clone(),
        Pipe::Stdout,
    ));
    let stderr = tokio::spawn(pump(
        child.stderr.take(),
        job.scrubber.clone(),
        queue.clone(),
        cut.clone(),
        Pipe::Stderr,
    ));
    let mut input = tokio::spawn(feed(reader, child.stdin.take()));
    let end = tokio::select! {
        status = child.wait() => End::Exited(status.ok()),
        reason = job.ticket.ended() => End::Ended(reason),
        _ = &mut input => End::ClientClosed,
    };
    // Output cut by a kill may end inside a secret, and so may output from
    // anything the program left running: the held-back tail is dropped.
    if !matches!(end, End::Exited(_)) || tree.running() {
        cut.store(true, Ordering::SeqCst);
    }
    tree.kill();
    let status = match &end {
        End::Exited(status) => *status,
        _ => child.wait().await.ok(),
    };
    input.abort();
    let (stdout_abort, stderr_abort) = (stdout.abort_handle(), stderr.abort_handle());
    let drained = tokio::time::timeout(DRAIN_GRACE, async {
        let _ = stdout.await;
        let _ = stderr.await;
    })
    .await;
    if drained.is_err() {
        stdout_abort.abort();
        stderr_abort.abort();
    }
    let (last, outcome) = match end {
        End::Exited(_) => {
            let (code, signal) = exit_parts(status);
            let outcome = match (code, signal) {
                (Some(code), _) => format!("exited:{code}"),
                (None, Some(signal)) => format!("signal:{signal}"),
                (None, None) => "exited".to_owned(),
            };
            (Some(RunOutput::Exited { code, signal }), outcome)
        }
        End::Ended(reason) => (
            Some(RunOutput::Ended {
                reason: reason.message().to_owned(),
            }),
            reason.outcome().to_owned(),
        ),
        End::ClientClosed => (None, "client_closed".to_owned()),
    };
    if let Some(last) = last {
        let _ = queue.send(last).await;
    }
    drop(queue);
    let _ = delivery.await;
    record(&job, &program, &outcome, running.elapsed());
}

fn launch(job: &RunJob, program: &str) -> Result<(Child, ProcessTree), AgentResponse> {
    if job.ticket.has_ended() {
        return Err(error(
            AgentErrorCode::PolicyDenied,
            "the vault locked or the handle changed before the program started; try again",
        ));
    }
    let path = resolve(&job.argv[0], std::env::var_os("PATH").as_deref()).ok_or_else(|| {
        error(
            AgentErrorCode::UpstreamError,
            format!("{program} was not found, or is not a program kv can start"),
        )
    })?;
    let home = dirs::home_dir().ok_or_else(|| {
        error(
            AgentErrorCode::UpstreamError,
            "kv cannot find the home directory to start the program in",
        )
    })?;
    let mut command = Command::new(&path);
    command
        .args(&job.argv[1..])
        .current_dir(&home)
        .envs(job.env.iter().map(|(name, value)| (name, value.expose())))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    isolate(&mut command);
    let child = command.spawn().map_err(|e| {
        error(
            AgentErrorCode::UpstreamError,
            format!("could not start {program}: {e}"),
        )
    })?;
    let tree = ProcessTree::adopt(&child).map_err(|e| {
        error(
            AgentErrorCode::UpstreamError,
            format!("could not track {program}: {e}"),
        )
    })?;
    Ok((child, tree))
}

/// Passes what the client writes to the program until the client goes
/// away, which is when this returns.
async fn feed<R: AsyncRead + Unpin>(mut reader: R, mut stdin: Option<ChildStdin>) {
    loop {
        match read_frame::<_, RunInput>(&mut reader).await {
            Ok(Some(RunInput::Stdin { data })) => {
                if let Some(pipe) = &mut stdin
                    && pipe.write_all(&data).await.is_err()
                {
                    // The program closed its stdin; keep reading, so a client
                    // that goes away is still noticed.
                    stdin = None;
                }
            }
            Ok(Some(RunInput::CloseStdin)) => stdin = None,
            Ok(None) | Err(_) => return,
        }
    }
}

/// Reads one output pipe through the scrubber, following the scrubber as
/// secrets change, and queues it for the client.
async fn pump(
    reader: Option<impl AsyncRead + Unpin>,
    mut scrubber: watch::Receiver<Arc<Scrubber>>,
    queue: mpsc::Sender<RunOutput>,
    cut: Arc<AtomicBool>,
    pipe: Pipe,
) {
    let Some(mut reader) = reader else {
        return;
    };
    let mut held = Vec::new();
    let mut buffer = vec![0; MAX_RUN_CHUNK];
    loop {
        let n = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let current = scrubber.borrow_and_update().clone();
        let mut stream = current.resume(std::mem::take(&mut held));
        let scrubbed = stream.push(&buffer[..n]);
        held = stream.into_pending();
        if !send(&queue, pipe, scrubbed).await {
            return;
        }
    }
    if !cut.load(Ordering::SeqCst) {
        let current = scrubber.borrow().clone();
        let rest = current.resume(held).finish();
        send(&queue, pipe, rest).await;
    }
}

/// Queues `bytes` in frames of at most `MAX_RUN_CHUNK`. False once the
/// client is gone.
async fn send(queue: &mpsc::Sender<RunOutput>, pipe: Pipe, bytes: Vec<u8>) -> bool {
    for piece in bytes.chunks(MAX_RUN_CHUNK) {
        let data = piece.to_vec();
        let message = match pipe {
            Pipe::Stdout => RunOutput::Stdout { data },
            Pipe::Stderr => RunOutput::Stderr { data },
        };
        if queue.send(message).await.is_err() {
            return false;
        }
    }
    true
}

/// Writes queued output to the client, in order, until the queue closes or
/// the client goes away.
async fn deliver<W: AsyncWrite + Unpin>(mut writer: W, mut outbox: mpsc::Receiver<RunOutput>) {
    while let Some(message) = outbox.recv().await {
        if write_frame(&mut writer, &message).await.is_err() {
            return;
        }
    }
    let _ = writer.flush().await;
}

fn exit_parts(status: Option<ExitStatus>) -> (Option<i32>, Option<i32>) {
    let Some(status) = status else {
        return (None, None);
    };
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        (status.code(), status.signal())
    }
    #[cfg(not(unix))]
    {
        (status.code(), None)
    }
}

fn record(job: &RunJob, program: &str, outcome: &str, duration: Duration) {
    job.audit.record_use(&Use {
        action: "run",
        handle: &job.handle,
        decision: job.decision,
        summary: program,
        outcome,
        duration,
    });
}

fn error(code: AgentErrorCode, message: impl Into<String>) -> AgentResponse {
    AgentResponse::Error {
        code,
        message: message.into(),
    }
}
```

In `crates/kv/src/daemon/server.rs`:

1. Rename `wait_then_run` to `wait_for_decision` and give it the signature below. It no longer runs the job: it returns it, or a `Prepared::Reply` explaining why not. Drop the `http` parameter.

```rust
/// Waits for the user's decision without holding the daemon lock. Returns
/// the job to run, or a reply saying why not; `None` when the agent hung
/// up while it waited, and the request is withdrawn.
async fn wait_for_decision(
    daemon: &Shared,
    stream: &mut ServerStream,
    waiting: Waiting,
) -> Option<Prepared> {
```

   Inside it:
   - The expired branch's `return Some(response);` becomes `return Some(Prepared::Reply(response));`.
   - The final `Some(match decided { ... })` becomes:

```rust
    Some(match decided {
        Some(Verdict::AllowOnce | Verdict::AllowSession) => then,
        Some(Verdict::Deny | Verdict::DenyAlways) => Prepared::Reply(AgentResponse::Error {
            code: AgentErrorCode::ApprovalDenied,
            message: "the user denied the request".into(),
        }),
        None => {
            let shared = daemon.clone();
            let ended = tokio::task::spawn_blocking(move || lock(&shared).take_ended(id)).await;
            Prepared::Reply(ended.ok().flatten().unwrap_or_else(|| AgentResponse::Error {
                code: AgentErrorCode::VaultLocked,
                message:
                    "the vault was locked before the request was approved; ask the user to unlock it"
                        .into(),
            }))
        }
    })
```

2. In `serve_agent`, replace everything from `let response = match prepared {` to just before `if write_frame(&mut stream, &response)` with:

```rust
        let prepared = match prepared {
            Prepared::Wait(waiting) => {
                if notify {
                    notify::approval_needed(waiting.notice.clone());
                }
                match wait_for_decision(&daemon, &mut stream, *waiting).await {
                    Some(prepared) => prepared,
                    None => return,
                }
            }
            prepared => prepared,
        };
        // A run keeps the connection: from here on it carries the program's
        // input and output.
        if let Prepared::Run(job) = prepared {
            broker::run::serve(stream, *job).await;
            return;
        }
        let response = run_job(prepared, &http).await;
```

- [ ] **Step 4: Implement the client side**

In `crates/kv/src/client.rs`, add these imports:
- `kv_core::proto::{MAX_RUN_CHUNK, RunCall, RunInput, RunOutput}` (merged into the existing `kv_core::proto` import);
- `tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, SimplexStream, WriteHalf}`;
- `tokio::sync::{mpsc, oneshot}`.

Then add:

```rust
/// How a program started with `run_stream` ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunEnd {
    /// It ended by itself; `signal` is set on Unix when a signal ended it.
    Exited {
        code: Option<i32>,
        signal: Option<i32>,
    },
    /// kv ended it, for this reason.
    Ended(String),
    /// The connection to the daemon broke first.
    Lost,
}

/// A program the daemon started for this client. Write its input to
/// `stdin` (shutting it down closes the program's stdin), read its
/// scrubbed output from `stdout` and `stderr`, and learn from `ended` how
/// it ended. Dropping `guard` closes the connection, which makes the daemon
/// end the program.
pub struct RunStream {
    pub stdin: WriteHalf<SimplexStream>,
    pub stdout: ReadHalf<SimplexStream>,
    pub stderr: mpsc::Receiver<Vec<u8>>,
    pub ended: oneshot::Receiver<RunEnd>,
    pub guard: RunGuard,
}

/// Stops the relay tasks, and so closes the connection, when dropped.
pub struct RunGuard(Vec<tokio::task::JoinHandle<()>>);

impl Drop for RunGuard {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// Asks the daemon to start `handle`'s run command, starting the daemon
/// if needed. `Ok(Err(reply))` is the daemon's refusal.
pub async fn run_stream(
    paths: &Paths,
    session: Option<&SessionInfo>,
    handle: &str,
) -> io::Result<Result<RunStream, AgentResponse>> {
    let mut stream = connect(&paths.agent_endpoint(), true).await?;
    if let Some(session) = session {
        write_frame(&mut stream, &AgentRequest::Hello(session.clone())).await?;
    }
    let request = AgentRequest::Run(RunCall {
        handle: handle.to_owned(),
    });
    match exchange(&mut stream, &request).await? {
        AgentResponse::Started => {}
        refusal => return Ok(Err(refusal)),
    }
    let (mut from_daemon, mut to_daemon) = tokio::io::split(stream);
    let (mut input_reader, stdin) = tokio::io::simplex(MAX_RUN_CHUNK);
    let (stdout, mut output_writer) = tokio::io::simplex(MAX_RUN_CHUNK);
    let (stderr_sender, stderr) = mpsc::channel(16);
    let (end_sender, ended) = oneshot::channel();
    let input = tokio::spawn(async move {
        let mut buffer = vec![0; MAX_RUN_CHUNK];
        loop {
            let message = match input_reader.read(&mut buffer).await {
                Ok(0) | Err(_) => RunInput::CloseStdin,
                Ok(n) => RunInput::Stdin {
                    data: buffer[..n].to_vec(),
                },
            };
            let closing = message == RunInput::CloseStdin;
            if write_frame(&mut to_daemon, &message).await.is_err() || closing {
                return;
            }
        }
    });
    let output = tokio::spawn(async move {
        let end = loop {
            match read_frame::<_, RunOutput>(&mut from_daemon).await {
                Ok(Some(RunOutput::Stdout { data })) => {
                    let _ = output_writer.write_all(&data).await;
                }
                Ok(Some(RunOutput::Stderr { data })) => {
                    let _ = stderr_sender.send(data).await;
                }
                Ok(Some(RunOutput::Exited { code, signal })) => {
                    break RunEnd::Exited { code, signal };
                }
                Ok(Some(RunOutput::Ended { reason })) => break RunEnd::Ended(reason),
                Ok(None) | Err(_) => break RunEnd::Lost,
            }
        };
        let _ = output_writer.shutdown().await;
        let _ = end_sender.send(end);
    });
    Ok(Ok(RunStream {
        stdin,
        stdout,
        stderr,
        ended,
        guard: RunGuard(vec![input, output]),
    }))
}
```

- [ ] **Step 5: Run the tests and see them pass**

Run: `cargo test -p kv --test run`
Expected: PASS. On Windows, `a_signal_is_reported` is compiled out.

- [ ] **Step 6: Check the workspace and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`

```bash
git add crates/kv/src crates/kv/tests/run.rs
git commit -m "Start a handle's run command in the daemon and relay its scrubbed input and output"
```

---

### Task 6: `kv run`, and `--run` / `--no-run` in the CLI

**Files:**
- Modify: `crates/kv/Cargo.toml` (tokio feature `io-std`)
- Modify: `crates/kv/src/cli.rs`
- Test: `crates/kv/src/cli.rs` (`mod tests`)
- Test: `crates/kv/tests/cli.rs`

**Interfaces:**
- Consumes: `client::{run_stream, RunStream, RunEnd}` (Task 5); `PolicyPatch.run`, `HandleInfo.runs` (Task 2).
- Produces: the `kv run <handle>` subcommand. `PolicyArgs` gains `run: bool`, `no_run: bool` and `run_argv: Vec<String>` (the arguments after `--`). `kv add --kind env` accepts no `--var` when `--run` is given. `kv list` shows `runs=<program>`.

- [ ] **Step 1: Write the failing tests**

In `crates/kv/src/cli.rs` `mod tests`, add these fields to the `PolicyArgs { .. }` literal in `policy_flags_build_a_patch_and_empty_string_clears_a_list`:

```rust
            run: false,
            no_run: false,
            run_argv: Vec::new(),
```

and add:

```rust
    #[test]
    fn run_takes_everything_after_the_double_dash() {
        let policy = |args: &[&str]| match Cli::try_parse_from([&["kv", "policy", "srv"], args].concat()) {
            Ok(Cli {
                command: Command::Policy { policy, .. },
            }) => Ok(policy.patch().run),
            Ok(_) => unreachable!(),
            Err(e) => Err(e.to_string()),
        };
        assert_eq!(
            policy(&["--run", "--", "bunx", "-y", "ssh-mcp@1.2.3", "--host=10.0.0.5"]),
            Ok(Some(vec![
                "bunx".into(),
                "-y".into(),
                "ssh-mcp@1.2.3".into(),
                "--host=10.0.0.5".into()
            ]))
        );
        assert_eq!(policy(&["--no-run"]), Ok(Some(Vec::new())));
        assert_eq!(policy(&["--mode", "auto"]).unwrap(), None);
        assert!(policy(&["--run"]).is_err());
        assert!(policy(&["--", "bunx"]).is_err());
        assert!(policy(&["--run", "--no-run", "--", "bunx"]).is_err());
    }
```

Append to `crates/kv/tests/cli.rs`:

```rust
const RUN_SECRET: &str = "s3cr3t-cli-run-0123456789";

/// Not a real test. Started by `kv run` with `KV_CLI_HELPER` set, it echoes
/// each input line with its secret, and exits 3 at end of input.
#[test]
fn helper() {
    if std::env::var("KV_CLI_HELPER").is_err() {
        return;
    }
    let secret = std::env::var("SECRET_VALUE").unwrap_or_default();
    let mut out = std::io::stdout();
    for line in std::io::stdin().lines() {
        writeln!(out, "got {} secret={secret}", line.unwrap()).unwrap();
        out.flush().unwrap();
    }
    std::process::exit(3);
}

#[test]
fn add_a_server_list_it_and_run_it() {
    let kv = Kv::initialized();
    let exe = std::env::current_exe().unwrap();
    let exe = exe.to_str().unwrap();
    kv.ok(
        &[
            "add", "srv", "--kind", "env", "--var", "SECRET_VALUE", "--var", "KV_CLI_HELPER",
            "--mode", "auto", "--run", "--", exe, "helper", "--exact", "--nocapture",
            "--test-threads=1",
        ],
        &format!("{PASS}\n{RUN_SECRET}\necho-mode\n"),
    );
    let listed = kv.ok(&["list"], "");
    let program = std::path::Path::new(exe).file_name().unwrap().to_str().unwrap();
    assert!(listed.contains(&format!("runs={program}")), "{listed}");
    assert!(!listed.contains("--nocapture"), "{listed}");

    let output = kv.run(&["run", "srv"], "hello\n");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("got hello secret=[kv:srv]"), "{stdout}");
    assert!(!stdout.contains(RUN_SECRET), "{stdout}");
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn a_run_only_handle_needs_no_variables() {
    let kv = Kv::initialized();
    kv.ok(
        &["add", "bare", "--kind", "env", "--mode", "auto", "--run", "--", "/bin/echo", "hi"],
        &format!("{PASS}\n"),
    );
    assert!(kv.ok(&["list"], "").contains("runs=echo"));
    let refused = kv.fails(
        &["add", "novars", "--kind", "env", "--mode", "auto"],
        &format!("{PASS}\n"),
    );
    assert!(refused.contains("--var"), "{refused}");
    kv.ok(&["policy", "bare", "--run", "--", "/bin/echo", "bye"], &format!("{PASS}\n"));
    let refused = kv.fails(&["policy", "bare", "--no-run"], &format!("{PASS}\n"));
    assert!(refused.contains("at least one variable"), "{refused}");
}

#[test]
fn only_env_handles_take_a_run_command() {
    let kv = Kv::initialized();
    let refused = kv.fails(
        &["add", "web", "--kind", "http", "--host", "example.com", "--run", "--", "/bin/true"],
        &format!("{PASS}\n{TOKEN}\n"),
    );
    assert!(refused.contains("only env handles"), "{refused}");
}

#[test]
fn kv_run_reports_a_refusal_and_fails() {
    let kv = Kv::initialized();
    let output = kv.run(&["run", "missing"], "");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("kv run: unknown_handle"), "{stderr}");
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p kv --lib cli:: && cargo test -p kv --test cli`
Expected: compile errors for the new `PolicyArgs` fields, then failures: no `run` subcommand, `--run` unknown.

- [ ] **Step 3: Implement**

In `crates/kv/Cargo.toml`, add `"io-std"` to the tokio features list.

In `crates/kv/src/cli.rs`:

1. Imports:
   - `use crate::client::{RunEnd, RunStream};`
   - `use tokio::io::AsyncWriteExt;`
   - `Paths` is already imported.
2. In `enum Command`, after `Tui`:

```rust
    /// Start a handle's run command with its variables set, on this
    /// process's stdin and stdout (for an MCP client that should talk to
    /// one server directly)
    Run {
        /// An env handle with a run command
        handle: String,
    },
```

3. In `PolicyArgs`, after `grant_ttl`:

```rust
    /// env: the exact command kv run and kv mcp start, given after `--`,
    /// e.g. --run -- bunx -y ssh-mcp@1.2.3 --host=10.0.0.5
    #[arg(long, requires = "run_argv")]
    run: bool,
    /// env: remove the handle's run command
    #[arg(long, conflicts_with = "run")]
    no_run: bool,
    #[arg(last = true, value_name = "COMMAND", requires = "run")]
    run_argv: Vec<String>,
```

   and in `PolicyArgs::patch`, add to the `PolicyPatch { .. }`:

```rust
            run: if self.no_run {
                Some(Vec::new())
            } else if self.run {
                Some(self.run_argv.clone())
            } else {
                None
            },
```

4. In `read_value`'s `Kind::Env` branch, change the empty-vars check to:

```rust
            if args.vars.is_empty() && !args.policy.run {
                return Err(CliError(
                    "an env secret needs at least one --var NAME, or a --run command".into(),
                ));
            }
```

5. In `constraints`, after the `env_vars` part:

```rust
    if let Some(program) = &handle.runs {
        parts.push(format!("runs={program}"));
    }
```

6. In `main`, between building the runtime and `match runtime.block_on(run(cli))`:

```rust
    if let Command::Run { handle } = &cli.command {
        let code = runtime.block_on(run_handle(handle));
        // Exit at once: a read blocked on this terminal's stdin would keep the
        // runtime from shutting down.
        std::process::exit(code);
    }
```

7. In `run`'s `match cli.command`, add:

```rust
        Command::Run { .. } => unreachable!("main runs kv run before this"),
```

8. Add:

```rust
/// `kv run`: relays this process's stdin, stdout and stderr to the
/// handle's program, and returns the exit status to use: the program's,
/// 128 + the signal that ended it, or 1 when kv refused or ended it.
async fn run_handle(handle: &str) -> i32 {
    let paths = match Paths::from_env() {
        Ok(paths) => paths,
        Err(e) => {
            eprintln!("kv run: {e}");
            return 1;
        }
    };
    let started = match client::run_stream(&paths, None, handle).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(AgentResponse::Error { code, message })) => {
            eprintln!("kv run: {}: {message}", code.as_str());
            return 1;
        }
        Ok(Err(other)) => {
            eprintln!("kv run: unexpected reply from the daemon: {other:?}");
            return 1;
        }
        Err(e) => {
            eprintln!("kv run: daemon_unavailable: {e}");
            return 1;
        }
    };
    let RunStream {
        mut stdin,
        mut stdout,
        mut stderr,
        ended,
        guard,
    } = started;
    let input = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut stdin).await;
        let _ = stdin.shutdown().await;
    });
    let output = tokio::spawn(async move {
        let mut out = tokio::io::stdout();
        let _ = tokio::io::copy(&mut stdout, &mut out).await;
        let _ = out.flush().await;
    });
    let errors = tokio::spawn(async move {
        let mut err = tokio::io::stderr();
        while let Some(chunk) = stderr.recv().await {
            let _ = err.write_all(&chunk).await;
            let _ = err.flush().await;
        }
    });
    let end = ended.await.unwrap_or(RunEnd::Lost);
    let _ = output.await;
    let _ = errors.await;
    input.abort();
    drop(guard);
    match end {
        RunEnd::Exited {
            code: Some(code), ..
        } => code,
        RunEnd::Exited {
            signal: Some(signal),
            ..
        } => 128 + signal,
        RunEnd::Exited { .. } => 1,
        RunEnd::Ended(reason) => {
            eprintln!("kv run: {reason}");
            1
        }
        RunEnd::Lost => {
            eprintln!("kv run: kv stopped");
            1
        }
    }
}
```

- [ ] **Step 4: Run the tests and see them pass**

Run: `cargo test -p kv --lib cli:: && cargo test -p kv --test cli`
Expected: PASS.

- [ ] **Step 5: Check the workspace and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`

```bash
git add crates/kv/Cargo.toml Cargo.lock crates/kv/src/cli.rs crates/kv/tests/cli.rs
git commit -m "Add kv run and the --run and --no-run flags, so a handle's command can be set and started"
```

---

### Task 7: The servers gateway in `kv mcp`

**Files:**
- Modify: `crates/kv/Cargo.toml` (rmcp feature `client`)
- Create: `crates/kv/src/mcp/servers.rs`
- Modify: `crates/kv/src/mcp.rs`
- Test: `crates/kv/tests/servers.rs` (new)

**Interfaces:**
- Consumes: `client::{run_stream, agent, RunStream, RunEnd, RunGuard}` (Task 5); `HandleInfo.runs` (Task 2).
- Produces: the MCP tools `list_servers`, `list_server_tools(server, filter?, schemas?)`, `call_server_tool(server, tool, arguments?)` and `stop_server(server)`. Errors are tool results whose text starts with a code: the daemon's codes, plus `server_stopped` and `daemon_unavailable`.

- [ ] **Step 1: Write the failing tests**

Create `crates/kv/tests/servers.rs`:

```rust
//! `kv mcp`'s servers end to end: an MCP client drives the `kv` binary,
//! whose daemon starts this test binary as an MCP server; the `helper` test
//! is that server when `KV_SERVERS_HELPER` is set.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kv::client;
use kv::paths::Paths;
use kv_core::proto::{
    Approval, ControlCommand, ControlRequest, ControlResponse, Verdict,
};
use kv_core::secret::SecretText;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock};
use rmcp::service::{RoleClient, RunningService};
use rmcp::transport::TokioChildProcess;
use rmcp::{ErrorData, ServerHandler, ServiceExt, schemars, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "correct horse battery";
const SECRET: &str = "s3cr3t-server-value-0123456789";
const MODE_VAR: &str = "KV_SERVERS_HELPER";

#[derive(Clone)]
struct Helper;

#[derive(Deserialize, schemars::JsonSchema)]
struct EchoArgs {
    text: String,
}

#[tool_router]
impl Helper {
    #[tool(description = "Returns the secret from the environment.")]
    async fn reveal(&self) -> Result<CallToolResult, ErrorData> {
        let secret = std::env::var("SECRET_VALUE").unwrap_or_default();
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "secret={secret}"
        ))]))
    }

    #[tool(description = "Echoes its text.\nA second line that list_server_tools leaves out.")]
    async fn echo(&self, Parameters(args): Parameters<EchoArgs>) -> Result<CallToolResult, ErrorData> {
        Ok(CallToolResult::success(vec![ContentBlock::text(args.text)]))
    }

    #[tool(description = "Exits the server at once.")]
    async fn quit(&self) -> Result<CallToolResult, ErrorData> {
        std::process::exit(0)
    }
}

#[tool_handler(name = "helper")]
impl ServerHandler for Helper {}

/// Not a real test. Started by kv with `KV_SERVERS_HELPER` set, it serves
/// MCP on stdin and stdout until its client goes away.
#[test]
fn helper() {
    if std::env::var(MODE_VAR).is_err() {
        return;
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let running = Helper.serve(rmcp::transport::stdio()).await.unwrap();
        let _ = running.waiting().await;
    });
    std::process::exit(0);
}

struct Home {
    dir: TempDir,
}

impl Home {
    fn new() -> Self {
        let home = Self {
            dir: TempDir::new().unwrap(),
        };
        home.kv(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
        home
    }

    fn paths(&self) -> Paths {
        Paths::under(self.dir.path())
    }

    fn kv(&self, args: &[&str], stdin: &str) -> String {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kv"))
            .args(args)
            .env("KV_HOME", self.dir.path())
            .env("KV_NOTIFY", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "kv {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn add_server(&self, name: &str, mode: &str) {
        let exe = std::env::current_exe().unwrap();
        self.kv(
            &[
                "add", name, "--kind", "env", "--var", "SECRET_VALUE", "--var", MODE_VAR,
                "--mode", mode, "--run", "--", exe.to_str().unwrap(), "helper", "--exact",
                "--nocapture", "--test-threads=1",
            ],
            &format!("{PASS}\n{SECRET}\non\n"),
        );
    }

    async fn mcp(&self) -> RunningService<RoleClient, ()> {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_kv"));
        command
            .arg("mcp")
            .env("KV_HOME", self.dir.path())
            .env("KV_NOTIFY", "off")
            .current_dir(self.dir.path());
        ().serve(TokioChildProcess::new(command).unwrap())
            .await
            .unwrap()
    }

    /// Audit entries for runs of `handle` that ended with `outcome`.
    fn runs(&self, handle: &str, outcome: &str) -> usize {
        std::fs::read_to_string(&self.paths().audit)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|e| e["action"] == "run" && e["handle"] == handle && e["outcome"] == outcome)
            .count()
    }

    fn starts(&self, handle: &str) -> usize {
        self.runs(handle, "started")
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = Command::new(env!("CARGO_BIN_EXE_kv"))
            .arg("stop")
            .env("KV_HOME", self.dir.path())
            .stdin(Stdio::null())
            .output();
    }
}

async fn call(client: &RunningService<RoleClient, ()>, tool: &'static str, args: Value) -> (bool, String) {
    let mut params = CallToolRequestParams::new(tool);
    if let Value::Object(map) = args {
        params = params.with_arguments(map);
    }
    let result = client.call_tool(params).await.unwrap();
    let text = result
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Text(text) => Some(text.text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    (result.is_error.unwrap_or(false), text)
}

fn json_of(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {text}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_servers_shows_servers_and_whether_they_run() {
    let home = Home::new();
    home.add_server("srv", "auto");
    home.kv(
        &["add", "plain", "--kind", "env", "--var", "A", "--cmd", "tool"],
        &format!("{PASS}\nvalue-0123456789\n"),
    );
    let client = home.mcp().await;
    let (error, text) = call(&client, "list_servers", json!({})).await;
    assert!(!error, "{text}");
    let servers = json_of(&text);
    let servers = servers.as_array().unwrap();
    assert_eq!(servers.len(), 1, "{text}");
    assert_eq!(servers[0]["name"], "srv");
    assert_eq!(servers[0]["running"], false);
    assert!(!text.contains("--nocapture"), "{text}");
    let (error, text) = call(&client, "list_server_tools", json!({"server": "srv"})).await;
    assert!(!error, "{text}");
    let (_, text) = call(&client, "list_servers", json!({})).await;
    assert_eq!(json_of(&text)[0]["running"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_server_tools_filters_and_shows_schemas() {
    let home = Home::new();
    home.add_server("srv", "auto");
    let client = home.mcp().await;
    let (_, text) = call(&client, "list_server_tools", json!({"server": "srv"})).await;
    let listed = json_of(&text);
    assert_eq!(listed["total"], 3);
    assert!(!text.contains("second line"), "{text}");
    assert!(!text.contains("inputSchema"), "{text}");
    let (_, text) = call(
        &client,
        "list_server_tools",
        json!({"server": "srv", "filter": "ECHO", "schemas": true}),
    )
    .await;
    let listed = json_of(&text);
    assert_eq!(listed["matched"], 1);
    assert_eq!(listed["tools"][0]["name"], "echo");
    assert!(text.contains("inputSchema"), "{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn call_server_tool_returns_the_result_scrubbed() {
    let home = Home::new();
    home.add_server("srv", "auto");
    let client = home.mcp().await;
    let (error, text) = call(&client, "call_server_tool", json!({"server": "srv", "tool": "reveal"})).await;
    assert!(!error, "{text}");
    assert_eq!(text, "secret=[kv:srv]");
    let (error, text) = call(
        &client,
        "call_server_tool",
        json!({"server": "srv", "tool": "echo", "arguments": {"text": "hi"}}),
    )
    .await;
    assert!(!error, "{text}");
    assert_eq!(text, "hi");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_first_calls_start_the_server_once() {
    let home = Home::new();
    home.add_server("srv", "auto");
    let client = home.mcp().await;
    let args = json!({"server": "srv", "tool": "reveal"});
    let (a, b) = tokio::join!(
        call(&client, "call_server_tool", args.clone()),
        call(&client, "call_server_tool", args)
    );
    assert!(!a.0 && !b.0, "{a:?} {b:?}");
    assert_eq!(home.starts("srv"), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_that_quits_or_is_stopped_starts_again() {
    let home = Home::new();
    home.add_server("srv", "auto");
    let client = home.mcp().await;
    let reveal = json!({"server": "srv", "tool": "reveal"});
    assert!(!call(&client, "call_server_tool", reveal.clone()).await.0);
    let (error, text) = call(&client, "call_server_tool", json!({"server": "srv", "tool": "quit"})).await;
    assert!(error, "{text}");
    assert!(text.starts_with("server_stopped"), "{text}");
    let (error, text) = call(&client, "call_server_tool", reveal.clone()).await;
    assert!(!error, "{text}");
    assert_eq!(home.starts("srv"), 2);
    let (error, text) = call(&client, "stop_server", json!({"server": "srv"})).await;
    assert!(!error, "{text}");
    let (_, text) = call(&client, "list_servers", json!({})).await;
    assert_eq!(json_of(&text)[0]["running"], false);
    assert!(!call(&client, "call_server_tool", reveal).await.0);
    assert_eq!(home.starts("srv"), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locking_stops_servers_and_the_next_call_says_vault_locked() {
    let home = Home::new();
    home.add_server("srv", "auto");
    let client = home.mcp().await;
    let reveal = json!({"server": "srv", "tool": "reveal"});
    assert!(!call(&client, "call_server_tool", reveal.clone()).await.0);
    home.kv(&["lock"], "");
    // The daemon records the end once it has told kv mcp.
    let deadline = Instant::now() + Duration::from_secs(20);
    while home.runs("srv", "locked") == 0 {
        assert!(Instant::now() < deadline, "the lock did not end the server");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // A call that reaches the old server learns why it stopped; the call
    // after that tries to start it again, on a locked vault.
    let (error, text) = call(&client, "call_server_tool", reveal.clone()).await;
    assert!(error, "{text}");
    let text = if text.starts_with("server_stopped") {
        assert!(text.contains("the vault locked"), "{text}");
        let (error, text) = call(&client, "call_server_tool", reveal).await;
        assert!(error, "{text}");
        text
    } else {
        text
    };
    assert!(text.starts_with("vault_locked"), "{text}");
}

async fn waiting_approval(paths: &Paths, token: &SecretText) -> Approval {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let request = ControlRequest {
            passphrase: None,
            device: None,
            token: Some(token.clone()),
            command: ControlCommand::Overview,
        };
        if let ControlResponse::Overview { overview } = client::control(paths, &request, false).await.unwrap()
            && let Some(approval) = overview.approvals.into_iter().next()
        {
            return approval;
        }
        assert!(Instant::now() < deadline, "nothing is waiting");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ask_server_can_be_allowed_for_the_session() {
    let home = Home::new();
    home.add_server("prod", "ask");
    let paths = home.paths();
    let open = ControlRequest {
        passphrase: Some(SecretText::new(PASS)),
        device: None,
        token: None,
        command: ControlCommand::OpenSession,
    };
    let ControlResponse::Session { token } = client::control(&paths, &open, false).await.unwrap() else {
        panic!("no session");
    };
    let client = home.mcp().await;
    let peer = client.peer().clone();
    let reveal = || {
        let mut params = CallToolRequestParams::new("call_server_tool");
        if let Value::Object(map) = json!({"server": "prod", "tool": "reveal"}) {
            params = params.with_arguments(map);
        }
        params
    };
    let pending = tokio::spawn({
        let peer = peer.clone();
        let params = reveal();
        async move { peer.call_tool(params).await.unwrap() }
    });
    let approval = waiting_approval(&paths, &token).await;
    assert_eq!(approval.tool, "run");
    assert!(approval.can_grant);
    assert!(approval.detail.starts_with("starts "), "{}", approval.detail);
    let decide = ControlRequest {
        passphrase: None,
        device: None,
        token: Some(token.clone()),
        command: ControlCommand::Decide {
            id: approval.id,
            verdict: Verdict::AllowSession,
        },
    };
    client::control(&paths, &decide, false).await.unwrap();
    assert_ne!(pending.await.unwrap().is_error, Some(true));
    call(&client, "stop_server", json!({"server": "prod"})).await;
    // The grant covers the next start: no approval is needed.
    let again = tokio::time::timeout(Duration::from_secs(20), peer.call_tool(reveal()))
        .await
        .expect("the second start waited for approval")
        .unwrap();
    assert_ne!(again.is_error, Some(true));
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p kv --test servers`
Expected: FAIL. `kv mcp` has no `list_servers`, so the calls return MCP errors and `unwrap` panics.

- [ ] **Step 3: Implement**

In `crates/kv/Cargo.toml`, add `"client"` to the main `rmcp` dependency's features: `["macros", "server", "transport-io", "client"]`.

Create `crates/kv/src/mcp/servers.rs`:

```rust
//! The servers `kv mcp` reaches for an agent: handles with a `run` command,
//! started through the daemon on first use and kept for this process. Each
//! is an MCP client on the program's relayed stdin and stdout, so this
//! process sees only scrubbed output and never a secret.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kv_core::proto::{AgentRequest, AgentResponse, SessionInfo};
use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, ClientInfo, ContentBlock,
    Implementation,
};
use rmcp::service::{RoleClient, RunningService};
use serde_json::{Map, Value, json};
use tokio::io::AsyncWriteExt;
use tokio::sync::{OnceCell, watch};

use crate::client::{self, RunEnd, RunGuard, RunStream};
use crate::paths::Paths;

/// How long a started server has to finish MCP initialization: room for a
/// launcher such as bunx to download a pinned version the first time.
const INIT_TIMEOUT: Duration = Duration::from_secs(120);

/// Characters of a tool's first description line shown without `schemas`.
const SHORT_DESCRIPTION: usize = 160;

type Table = BTreeMap<String, Arc<OnceCell<Arc<Server>>>>;

pub struct Servers {
    paths: Paths,
    /// One entry per server started or starting in this process.
    running: Arc<Mutex<Table>>,
}

/// A running server: the MCP client on its relay, why it ended once it
/// has, and the connection that keeps it alive.
struct Server {
    client: RunningService<RoleClient, ClientInfo>,
    end: watch::Receiver<Option<String>>,
    guard: Mutex<Option<RunGuard>>,
}

impl Servers {
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            running: Arc::default(),
        }
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub async fn list(&self) -> CallToolResult {
        let handles = match client::agent(&self.paths, None, &AgentRequest::ListHandles).await {
            Ok(AgentResponse::Handles { handles }) => handles,
            Ok(AgentResponse::Error { code, message }) => {
                return failure(format!("{}: {message}", code.as_str()));
            }
            Ok(other) => return failure(format!("upstream_error: unexpected reply {other:?}")),
            Err(e) => return failure(unreachable_daemon(e)),
        };
        let running: Vec<String> = self
            .table()
            .iter()
            .filter(|(_, cell)| cell.initialized())
            .map(|(name, _)| name.clone())
            .collect();
        let servers: Vec<Value> = handles
            .iter()
            .filter_map(|handle| {
                let program = handle.runs.as_ref()?;
                Some(json!({
                    "name": handle.name,
                    "description": handle.description,
                    "runs": program,
                    "mode": handle.mode,
                    "running": running.contains(&handle.name),
                }))
            })
            .collect();
        success(&Value::Array(servers))
    }

    pub async fn list_tools(
        &self,
        name: &str,
        session: SessionInfo,
        filter: Option<&str>,
        schemas: bool,
    ) -> CallToolResult {
        let server = match self.get(name, session).await {
            Ok(server) => server,
            Err(message) => return failure(message),
        };
        let tools = match server.client.list_all_tools().await {
            Ok(tools) => tools,
            Err(e) => return failure(self.lost(name, &server, e).await),
        };
        let needle = filter.unwrap_or_default().to_lowercase();
        let matches: Vec<Value> = tools
            .iter()
            .filter(|tool| {
                let text = format!("{} {}", tool.name, tool.description.as_deref().unwrap_or_default());
                needle.is_empty() || text.to_lowercase().contains(&needle)
            })
            .map(|tool| {
                if schemas {
                    json!({
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": Value::Object((*tool.input_schema).clone()),
                    })
                } else {
                    json!({
                        "name": tool.name,
                        "description": first_line(tool.description.as_deref().unwrap_or_default()),
                    })
                }
            })
            .collect();
        success(&json!({
            "total": tools.len(),
            "matched": matches.len(),
            "tools": matches,
        }))
    }

    pub async fn call(
        &self,
        name: &str,
        session: SessionInfo,
        tool: String,
        arguments: Map<String, Value>,
    ) -> CallToolResult {
        let server = match self.get(name, session).await {
            Ok(server) => server,
            Err(message) => return failure(message),
        };
        let params = CallToolRequestParams::new(tool).with_arguments(arguments);
        match server.client.call_tool(params).await {
            Ok(result) => result,
            Err(e) => failure(self.lost(name, &server, e).await),
        }
    }

    pub async fn stop(&self, name: &str) -> CallToolResult {
        let cell = self.table().remove(name);
        let Some(server) = cell.as_ref().and_then(|cell| cell.get()).cloned() else {
            return text(format!("{name} is not running in this session."));
        };
        // Closing the connection makes the daemon end the program.
        drop(server.guard.lock().unwrap_or_else(PoisonError::into_inner).take());
        text(format!("Stopped {name}."))
    }

    /// The running server, starting it first if needed. Calls that arrive
    /// while it starts wait for that one start.
    async fn get(&self, name: &str, session: SessionInfo) -> Result<Arc<Server>, String> {
        let cell = self.table().entry(name.to_owned()).or_default().clone();
        let started = cell
            .get_or_try_init(|| self.start(name, session))
            .await
            .cloned();
        if started.is_err() {
            // Forget the failed start, so the next call tries again.
            let mut table = self.table();
            if table
                .get(name)
                .is_some_and(|c| Arc::ptr_eq(c, &cell) && !c.initialized())
            {
                table.remove(name);
            }
        }
        started
    }

    async fn start(&self, name: &str, session: SessionInfo) -> Result<Arc<Server>, String> {
        let stream = match client::run_stream(&self.paths, Some(&session), name).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(AgentResponse::Error { code, message })) => {
                return Err(format!("{}: {message}", code.as_str()));
            }
            Ok(Err(other)) => {
                return Err(format!("upstream_error: unexpected reply from the daemon: {other:?}"));
            }
            Err(e) => return Err(unreachable_daemon(e)),
        };
        let RunStream {
            stdin,
            stdout,
            mut stderr,
            ended,
            guard,
        } = stream;
        // The program's stderr, already scrubbed, goes where MCP clients keep
        // a server's logs.
        tokio::spawn(async move {
            let mut err = tokio::io::stderr();
            while let Some(chunk) = stderr.recv().await {
                let _ = err.write_all(&chunk).await;
            }
        });
        let info = ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new(format!("kv/{name}"), env!("CARGO_PKG_VERSION")),
        );
        let client = match tokio::time::timeout(INIT_TIMEOUT, info.serve((stdout, stdin))).await {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                return Err(format!("upstream_error: {name} did not start as an MCP server: {e}"));
            }
            Err(_) => {
                return Err(format!(
                    "upstream_error: {name} did not finish starting within {}s",
                    INIT_TIMEOUT.as_secs()
                ));
            }
        };
        let (end_sender, end) = watch::channel(None);
        let server = Arc::new(Server {
            client,
            end,
            guard: Mutex::new(Some(guard)),
        });
        let running = self.running.clone();
        let key = name.to_owned();
        let watched = Arc::downgrade(&server);
        tokio::spawn(async move {
            let reason = match ended.await {
                Ok(RunEnd::Exited {
                    code: Some(code), ..
                }) => format!("the server exited with code {code}"),
                Ok(RunEnd::Exited { .. }) => "the server was killed".to_owned(),
                Ok(RunEnd::Ended(reason)) => reason,
                Ok(RunEnd::Lost) | Err(_) => "kv stopped".to_owned(),
            };
            let _ = end_sender.send(Some(reason));
            // Forget it, so the next call starts it again.
            let mut table = running.lock().unwrap_or_else(PoisonError::into_inner);
            let same = table
                .get(&key)
                .and_then(|cell| cell.get())
                .is_some_and(|s| std::ptr::eq(Arc::as_ptr(s), watched.as_ptr()));
            if same {
                table.remove(&key);
            }
        });
        Ok(server)
    }

    /// The error for a call that failed: `server_stopped` with the reason
    /// once the server has ended, which also forgets it.
    async fn lost(&self, name: &str, server: &Arc<Server>, error: impl std::fmt::Display) -> String {
        let mut end = server.end.clone();
        // The client can notice the end a moment before the reason arrives.
        let _ = tokio::time::timeout(Duration::from_secs(1), end.wait_for(Option::is_some)).await;
        let reason = end.borrow().clone();
        let stopped = reason.is_some() || server.client.is_closed();
        if stopped {
            self.forget(name, server);
        }
        match reason {
            Some(reason) => format!("server_stopped: {reason}"),
            None if stopped => format!("server_stopped: {error}"),
            None => format!("upstream_error: {error}"),
        }
    }

    fn forget(&self, name: &str, server: &Arc<Server>) {
        let mut table = self.table();
        if table
            .get(name)
            .and_then(|cell| cell.get())
            .is_some_and(|s| Arc::ptr_eq(s, server))
        {
            table.remove(name);
        }
    }
}

fn first_line(text: &str) -> String {
    text.lines()
        .next()
        .unwrap_or_default()
        .chars()
        .take(SHORT_DESCRIPTION)
        .collect()
}

fn success(value: &Value) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).unwrap_or_default(),
    )])
}

fn text(message: String) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(message)])
}

fn failure(message: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}

fn unreachable_daemon(e: std::io::Error) -> String {
    format!("daemon_unavailable: the kv daemon could not be started or reached: {e}")
}
```

In `crates/kv/src/mcp.rs`:

1. Add `mod servers;` after the `use` block, and `use std::sync::Arc;`.
2. Add the argument types:

```rust
#[derive(Deserialize, schemars::JsonSchema)]
pub struct ServerArgs {
    /// A server name from list_servers.
    server: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ListServerToolsArgs {
    /// A server name from list_servers.
    server: String,
    /// Case-insensitive text to look for in tool names and descriptions.
    #[serde(default)]
    filter: Option<String>,
    /// Include each matching tool's full description and input schema.
    #[serde(default)]
    schemas: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct CallServerToolArgs {
    /// A server name from list_servers.
    server: String,
    /// A tool name from list_server_tools.
    tool: String,
    /// Arguments matching the tool's input schema.
    #[serde(default)]
    arguments: Option<serde_json::Map<String, serde_json::Value>>,
}
```

3. Add the field `servers: Arc<servers::Servers>,` to `KvServer`, and in `serve` construct it with `servers: Arc::new(servers::Servers::new(paths.clone())),` before `paths` is moved.
4. Add to the `#[tool_router] impl KvServer` block:

```rust
    #[tool(
        description = "List the MCP servers kv can start for you, such as SSH or Dokploy servers that need the user's secrets, with their descriptions and whether each is running in this session. Starts nothing."
    )]
    async fn list_servers(&self) -> Result<CallToolResult, ErrorData> {
        Ok(self.servers.list().await)
    }

    #[tool(
        description = "Start a server from list_servers if it is not running, and list its tools: names and the first line of each description. Narrow big servers with filter, then pass schemas: true to get the input schemas of the matches. If the server's handle is in ask mode, starting it waits up to 60 s for the user to approve it in kv tui."
    )]
    async fn list_server_tools(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<ListServerToolsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = self.session(&peer);
        Ok(self
            .servers
            .list_tools(&args.server, session, args.filter.as_deref(), args.schemas)
            .await)
    }

    #[tool(
        description = "Call a tool on a server from list_servers, starting the server if needed. Returns the tool's own result, with secrets replaced by [kv:<handle>]. Check the tool's input schema with list_server_tools first."
    )]
    async fn call_server_tool(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<CallServerToolArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = self.session(&peer);
        Ok(self
            .servers
            .call(&args.server, session, args.tool, args.arguments.unwrap_or_default())
            .await)
    }

    #[tool(description = "Stop a server started in this session.")]
    async fn stop_server(
        &self,
        Parameters(args): Parameters<ServerArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.servers.stop(&args.server).await)
    }
```

5. In the `#[tool_handler(...)]` instructions, before "Handles in ask mode", add this sentence: `MCP servers that hold the user's secrets, such as SSH or Dokploy servers, are reached with list_servers, then list_server_tools, then call_server_tool; start one only when the user asks for that server.`

- [ ] **Step 4: Run the tests and see them pass**

Run: `cargo test -p kv --test servers && cargo test -p kv --test mcp`
Expected: PASS. The existing `mcp` tests still pass with the new tools listed.

- [ ] **Step 5: Check the workspace and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`

```bash
git add crates/kv/Cargo.toml Cargo.lock crates/kv/src/mcp.rs crates/kv/src/mcp crates/kv/tests/servers.rs
git commit -m "Reach MCP servers that hold secrets through kv mcp, started on demand with their handle's variables"
```

---

### Task 8: Show what a server runs in `kv tui`

**Files:**
- Modify: `crates/kv/src/tui/view.rs`
- Test: `crates/kv/tests/tui.rs`

**Interfaces:**
- Consumes: `HandleInfo.runs` (Task 2); `run` approvals from the daemon (Task 4), whose `detail` is `starts <program>`.
- Produces: the Handles tab shows `runs <program>` on a server's line.

- [ ] **Step 1: Write the failing tests**

Append to `crates/kv/tests/tui.rs`, adding `SecretKind` to its `kv_core::secret` import if missing:

```rust
#[test]
fn the_handles_tab_shows_what_a_server_runs_but_not_its_arguments() {
    let mut app = unlocked(Vec::new());
    let mut server = handle("ssh-kycdev", Mode::Auto);
    server.kind = SecretKind::Env;
    server.allowed_hosts = Vec::new();
    server.description = String::new();
    server.runs = Some("bunx".into());
    let mut o = overview(Vec::new());
    o.handles.push(server);
    app.apply(Outcome::Overview(o));
    key(&mut app, '2');
    let drawn = screen(&app);
    assert!(drawn.contains("runs bunx"), "{drawn}");
}

#[test]
fn a_run_approval_names_the_program() {
    let mut run = approval(7, false);
    run.client = None;
    run.tool = "run".into();
    run.handles = vec!["ssh-kyclive".into()];
    run.detail = "starts bunx".into();
    // A lone waiting request is selected as it arrives.
    let app = unlocked(vec![run]);
    let drawn = screen(&app);
    assert!(drawn.contains("run · ssh-kyclive"), "{drawn}");
    assert!(drawn.contains("starts bunx"), "{drawn}");
    assert!(drawn.contains("a allow once"), "{drawn}");
    assert!(!drawn.contains("allow for session"), "{drawn}");
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p kv --test tui`
Expected: `the_handles_tab_shows_what_a_server_runs_but_not_its_arguments` fails, because "runs bunx" is not drawn. `a_run_approval_names_the_program` passes already: it pins today's generic approval rendering for `run`.

- [ ] **Step 3: Implement**

In `crates/kv/src/tui/view.rs` `handle_line`, after `let mut text = format!(...);`:

```rust
    if let Some(program) = &handle.runs {
        text.push_str(&format!(" runs {program}"));
    }
```

- [ ] **Step 4: Run the tests and see them pass**

Run: `cargo test -p kv --test tui`
Expected: PASS.

- [ ] **Step 5: Check the workspace and commit**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`

```bash
git add crates/kv/src/tui/view.rs crates/kv/tests/tui.rs
git commit -m "Show the program a server runs on the Handles tab of kv tui"
```

---

### Task 9: Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md`
- Modify: `docs/superpowers/specs/2026-10-09-kv-run-design.md`
- Modify (local only, untracked): `CLAUDE.md`

**Interfaces:** none.

- [ ] **Step 1: README**

In `README.md`:
- Replace `The agent then sees seven tools:` with `The agent then sees these tools:`.
- Add this bullet after the `status` bullet:

```markdown
- `list_servers`, `list_server_tools`, `call_server_tool` and `stop_server`:
  MCP servers that need your secrets (see below).
```

Add this section after "### Keeping a service's address hidden":

````markdown
### MCP servers with secrets

Some MCP servers need a secret of their own, such as an SSH password or a
Dokploy API key. Instead of writing it into an MCP config file, make the
server a kv handle: an `env` handle with a `run` command, the exact command
that starts it.

```sh
kv add ssh-dev --kind env --var SSH_MCP_PASSWORD --mode auto \
  --description "dev box over SSH" \
  --run -- /path/to/bunx -y ssh-mcp@1.2.3 --host=10.0.0.5 --user=root
kv add dokploy-prod --kind env --var DOKPLOY_URL --var DOKPLOY_API_KEY \
  --run -- /path/to/bunx -y @dokploy/mcp@0.3.0
```

The agent finds them with `list_servers`, lists a server's tools with
`list_server_tools` (narrow big servers with `filter`) and calls one with
`call_server_tool`. kv starts a server the first time one of its tools is
needed and keeps it for the agent's session; `stop_server` stops it.

- The server runs in your home directory with the handle's variables set.
  What it writes is scrubbed, so results show `[kv:<handle>]` where a secret
  would be.
- Nothing can change the command or its arguments without your passphrase,
  and agents see only the program's name (`runs: bunx`), never the arguments.
- A handle in `--mode ask` waits for you in `kv tui` when the server starts;
  `s` allows it for the rest of that agent session, until the handle's
  `grant_ttl`.
- Locking the vault stops every server; the next call says the vault is
  locked.
- A server that needs no secret, such as one that logs in with a key file,
  can be a handle with a `run` command and no `--var`.
- The server itself holds the secret, so run only programs you trust, and pin
  package versions (`ssh-mcp@1.2.3`), since an unpinned `bunx` command runs
  whatever the registry serves that day.

`kv run <handle>` starts the same command on its own stdin and stdout, for an
MCP client that should talk to one server directly:
`claude mcp add ssh-dev -- kv run ssh-dev`. Change a server's command with
`kv policy <handle> --run -- <command>`.
````

- [ ] **Step 2: Main design spec**

In `docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md`:
- In the section 3 policy block, add this line after `allowed_cmds:`:
  `run:             [bunx, -y, ssh-mcp@1.2.3, ...] # env: the exact command kv run and kv mcp start`
- In the section 4 tools table, add these four rows after `status`:

```markdown
| `list_servers` | — | handles with a `run` command, their descriptions, whether each runs in this session |
| `list_server_tools` | server, filter?, schemas? | the server's tools, first description lines or full schemas; starts the server |
| `call_server_tool` | server, tool, arguments? | the tool's own result, scrubbed; starts the server |
| `stop_server` | server | confirmation |
```

- In section 5's scrubber bullets, replace the "Streaming: hold back `longest pattern − 1` bytes between chunks so secrets split across chunks are caught." bullet with: "Streaming: hold back only the longest tail that is a proper prefix of a pattern, so secrets split across chunks are caught and a program waiting for input gets its whole reply out."
- In the agent-facing errors table, add: `| \`server_stopped\` | A server reached through \`kv mcp\` ended (lock, handle change, exit); the next call starts it again. |`.
- In section 8, remove `; \`kv run --env <handle>... -- <command>\` to launch long-running tools ... does hold the secret` from the v1.1 bullet, so it ends after `printenv`. Add a new bullet before it: `- Done after v1.0: \`kv run\` and servers reached through \`kv mcp\`, with the command pinned in the handle; see \`2026-10-09-kv-run-design.md\`.`

- [ ] **Step 3: kv run spec, decisions from this plan**

In `docs/superpowers/specs/2026-10-09-kv-run-design.md`:
- Change `Status:` to `Status: implemented on feat/run`.
- In section 2, "Approval": replace "`kv run` names no session; the client shows as `kv run`, and only" with "`kv run` names no session, so the approval reads as from an agent with no session, and only".
- In section 3, "Ends" table: replace the "The daemon stops" row with:

```markdown
| `kv stop` (it locks first) | tree killed | `Ended { reason: "the vault locked" }` | `locked` |
| The daemon dies | tree killed with the daemon's process group or job | the connection closes; `kv run` says "kv stopped" | — |
```

- [ ] **Step 4: CLAUDE.md (local)**

In `CLAUDE.md`'s request flow list, change the `Prepared` bullet list to include `Run`. Then add after the protocol-layers paragraph: "`broker/run.rs` starts a handle's pinned `run` command and relays its stdin/stdout/stderr as `RunInput`/`RunOutput` frames on the agent connection that asked; `client::run_stream` is the client side, used by `kv run` and by `mcp/servers.rs`, which runs an rmcp client per server for `kv mcp`'s server tools." This file is untracked; do not commit it.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/superpowers/specs
git commit -m "Document MCP servers through kv and record the run decisions in the specs"
```

---

### Task 10: Move servers-hub into kv and remove it

This task runs outside the repository and touches the user's real vault and configuration. Every step that changes something waits for the user's go-ahead. The user runs `--apply` themselves, because it asks for their passphrase.

**Files:**
- Create (scratch, never committed): `/Volumes/storage/tmp/kv-migrate/migrate.ts`

**Interfaces:**
- Consumes: the `kv add ... --run --`, `kv list --json` and `runs` behavior from Tasks 2 to 7, installed as the user's `kv`.
- Produces: one kv handle per `servers.json` entry. Afterwards, servers-hub's registration and directory are removed.

- [ ] **Step 1: Install the new kv**

Run: `cd /Volumes/storage/Codes/key-vault-for-llm && cargo install --locked --path crates/kv && kv --version`
Expected: it prints `kv 1.0.0`. Then ask the user to run `! kv stop` and `! kv unlock`, so the daemon runs the new binary.

- [ ] **Step 2: Write the migration script**

Create `/Volumes/storage/tmp/kv-migrate/migrate.ts`:

```ts
#!/usr/bin/env bun
// One-off: moves servers-hub's servers.json into kv as server handles.
// Values reach `kv add` only on stdin; nothing this prints contains them.
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

type Entry = {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  description?: string;
};

const argv = process.argv.slice(2);
const apply = argv.includes("--apply");
const option = (name: string) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const askPattern = new RegExp(option("--ask") ?? "kyclive|vllm");
const configPath =
  option("--config") ?? `${process.env.HOME}/Codes/mcp/servers-hub/servers.json`;
const servers: Record<string, Entry> =
  JSON.parse(readFileSync(configPath, "utf8")).servers ?? {};

const handleName = /^[a-z0-9][a-z0-9_-]{0,62}$/;

// The package argument of a launcher command: the first non-flag argument.
const packageIndex = (args: string[]) => args.findIndex((a) => !a.startsWith("-"));

async function pin(spec: string): Promise<string> {
  const at = spec.lastIndexOf("@");
  if (at > 0) return spec; // already versioned; scoped names start with @
  const res = await fetch(`https://registry.npmjs.org/${spec.replace("/", "%2F")}/latest`);
  if (!res.ok) throw new Error(`npm has no latest version for ${spec}`);
  const { version } = (await res.json()) as { version: string };
  return `${spec}@${version}`;
}

function absolute(program: string): string {
  if (program.startsWith("/")) return program;
  const found = Bun.which(program);
  if (!found) throw new Error(`${program} is not on PATH`);
  return found;
}

function masked(args: string[], pkg: number): string {
  return args
    .map((a, i) => {
      if (i === pkg) return a;
      if (/^--?[\w-]+=/.test(a)) return a.replace(/=.*/, "=<masked>");
      if (a.startsWith("-")) return a;
      return "<masked>";
    })
    .join(" ");
}

async function hidden(prompt: string): Promise<string> {
  process.stderr.write(prompt);
  const stdin = process.stdin;
  stdin.setRawMode(true);
  stdin.resume();
  let value = "";
  for await (const chunk of stdin) {
    for (const ch of chunk.toString("utf8")) {
      if (ch === "\r" || ch === "\n") {
        stdin.setRawMode(false);
        stdin.pause();
        process.stderr.write("\n");
        return value;
      }
      if (ch === "\u0003") {
        stdin.setRawMode(false);
        process.exit(130);
      }
      if (ch === "\u007f") value = value.slice(0, -1);
      else value += ch;
    }
  }
  return value;
}

function kvJson(args: string[]): any {
  const out = spawnSync("kv", args, { encoding: "utf8" });
  if (out.status !== 0) throw new Error(`kv ${args.join(" ")} failed: ${out.stderr}`);
  return JSON.parse(out.stdout);
}

const existing = new Set<string>(kvJson(["list", "--json"]).map((h: any) => h.name));
const plans: { name: string; mode: string; vars: string[]; argv: string[]; entry: Entry }[] = [];
for (const [name, entry] of Object.entries(servers)) {
  if (entry.command === "kv") continue; // already migrated
  if (!handleName.test(name)) throw new Error(`${name} is not a valid kv handle name`);
  if (existing.has(name)) throw new Error(`kv already has a handle named ${name}; remove or rename it first`);
  if (entry.cwd) throw new Error(`${name} sets cwd, which kv run does not support`);
  const args = [...(entry.args ?? [])];
  const pkg = packageIndex(args);
  if (/^bunx$|^npx$/.test(entry.command) && pkg >= 0) args[pkg] = await pin(args[pkg]);
  const vars = Object.keys(entry.env ?? {});
  for (const v of vars) {
    if (/[\r\n]/.test(entry.env![v])) throw new Error(`${name}: ${v} contains a newline`);
  }
  plans.push({
    name,
    mode: askPattern.test(name) ? "ask" : "auto",
    vars,
    argv: [absolute(entry.command), ...args],
    entry,
  });
}

for (const p of plans) {
  const pkg = packageIndex(p.argv.slice(1));
  console.log(
    `${p.name}: mode ${p.mode}; vars ${p.vars.join(", ") || "(none)"}; runs ${p.argv[0].split("/").pop()} ${masked(p.argv.slice(1), pkg)}`,
  );
}
if (!apply) {
  console.log(`\n${plans.length} servers would be added. Nothing changed; pass --apply to add them.`);
  process.exit(0);
}

const passphrase = await hidden("kv passphrase: ");
for (const p of plans) {
  const args = [
    "add", p.name, "--kind", "env", "--mode", p.mode,
    ...(p.entry.description ? ["--description", p.entry.description] : []),
    ...p.vars.flatMap((v) => ["--var", v]),
    "--run", "--", ...p.argv,
  ];
  const input = [passphrase, ...p.vars.map((v) => p.entry.env![v])].join("\n") + "\n";
  const out = spawnSync("kv", args, { input, encoding: "utf8" });
  if (out.status !== 0) {
    console.error(`${p.name}: kv add failed: ${out.stderr.trim()}`);
    process.exit(1);
  }
  console.log(`${p.name}: added`);
}

const listed = new Map<string, any>(kvJson(["list", "--json"]).map((h: any) => [h.name, h]));
const missing = plans.filter((p) => !listed.get(p.name)?.runs);
if (missing.length) {
  console.error(`not confirmed: ${missing.map((p) => p.name).join(", ")}`);
  process.exit(1);
}
console.log(`\nAll ${plans.length} servers are in kv. servers-hub can be removed.`);
```

- [ ] **Step 3: Dry run and the user's review**

Run: `bun /Volumes/storage/tmp/kv-migrate/migrate.ts`
Expected: 19 lines. Each shows a handle, its mode (`ask` for `*kyclive*` and `ssh-vllm-gpu`), its variable names, and a pinned, masked command. No values or hosts appear. Show this to the user and wait for their go-ahead.

- [ ] **Step 4: The user applies it**

Ask the user to run: `! bun /Volumes/storage/tmp/kv-migrate/migrate.ts --apply`
Expected: 19 `added` lines and "All 19 servers are in kv."

- [ ] **Step 5: Check through kv mcp**

In a new Claude Code session, call:
- `list_servers`: 19 servers, none running.
- `list_server_tools` on a dev SSH server, such as `ssh-kycdev`: it starts with no prompt.
- `list_server_tools` on one prod server, such as `ssh-kyclive-cpu-1-api`: it waits in `kv tui`; allow it for the session.
- `call_server_tool` on a Dokploy server with a read-only tool found through `filter`.

- [ ] **Step 6: Remove servers-hub, one confirmed step at a time**

1. Run `claude mcp get servers-hub` and `claude mcp get mcp-hub`, and show the user which entries start servers-hub. After their OK, run `claude mcp remove servers-hub -s user`, and the same for `mcp-hub` if it starts the same hub.
2. Run `git -C ~/Codes/mcp/servers-hub status -sb` and `git -C ~/Codes/mcp/servers-hub log --branches --not --remotes --oneline` to check for unpushed work. Show the result. After the user's OK, run `rm -rf ~/Codes/mcp/servers-hub`. That also deletes the plaintext `servers.json`. The GitHub repository is left alone.
3. Run `rm -rf /Volumes/storage/tmp/kv-migrate`.

- [ ] **Step 7: Recommend rotation**

Tell the user that the 18 migrated passwords and API keys sat in a plaintext file. Rotating them, with `kv add <name> ... --replace` or `e` in `kv tui`, closes that exposure.
