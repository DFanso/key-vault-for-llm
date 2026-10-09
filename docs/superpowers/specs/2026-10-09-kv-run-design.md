# kv run: launching long-running programs with a handle's secrets — design

Date: 2026-10-09
Status: design agreed in conversation, written spec pending review

## 1. Goal

Let long-running programs the user trusts, such as MCP servers started by an
MCP gateway, receive secrets from kv instead of from plaintext config files.
This replaces the "`kv run --env <handle>... -- <command>`" item planned for
v1.1 in the main design (`2026-10-08-kv-llm-secrets-broker-design.md`,
section 8) with a stricter form: the handle pins the exact command.

The first user is servers-hub, a gateway that starts stdio MCP servers on
demand from a `servers.json` file. Today that file holds 10 SSH passwords
(`SSH_MCP_PASSWORD` for `ssh-mcp`) and 8 Dokploy URLs and API keys
(`DOKPLOY_URL`, `DOKPLOY_API_KEY` for `@dokploy/mcp`) in plaintext, where an
agent with a shell can read them.

Success means:

- `servers.json` holds no passwords, API keys or host addresses for the
  migrated servers; each entry is `{"command": "kv", "args": ["run", "<handle>"]}`.
- servers-hub needs no code change, and every server starts and works through
  it as before.
- Nothing that can reach kv (an agent through MCP `exec`, an agent running
  `kv run` in a shell, any other process running as the user) can use a
  handle to launch a different program, or the same program with different
  arguments, without the passphrase.
- Development servers start without a prompt while the vault is unlocked;
  production servers wait for approval in `kv tui`.
- Locking the vault stops every program launched this way.

### Threat model

As in the main design. In addition:

- The launched program holds the secret, by design. kv cannot stop a
  launched program from leaking it; pinning the command is what limits which
  programs get it.
- A pinned command that fetches code at launch (`bunx -y pkg`) trusts the
  package registry. The migration pins package versions to narrow this.

### Not in scope

- An MCP tool for `run`. Agents do not launch these programs; a gateway the
  user configured does.
- Editing the `run` command in `kv tui`. It is set with the CLI.
- SSH key handling (`ssh_exec`), which stays in the v1.1 list.
- Passing the caller's environment or working directory to the program.

## 2. User-facing behavior

### The `run` command on a handle

An `env` handle may carry a `run` command: the exact argv to launch, stored
in the handle's policy inside the encrypted vault.

```sh
kv add ssh-kycdev --kind env --var SSH_MCP_PASSWORD --mode auto \
  --run -- /path/to/bunx -y ssh-mcp@1.2.3 --host=10.0.0.5 --port=22 \
  --user=root --timeout=30000 --disableApproval
kv policy ssh-kycdev --run -- /path/to/bunx -y ssh-mcp@1.2.4 ...   # replace
kv policy ssh-kycdev --no-run                                        # clear
```

- `--run` takes every argument after `--`. `--run` and `--no-run` cannot be
  combined, and `--run` with no arguments is an error.
- Only `env` handles may have a `run` command. The daemon refuses it on other
  kinds with the control error `invalid`, which `kv add` and `kv policy`
  print.
- The argv has at most 128 entries of at most 4096 bytes each, and argv[0]
  must not be empty.
- Changing or clearing `run` is a policy change: it needs the passphrase (or
  Touch ID / Windows Hello, or an unlocked `kv tui` session), and it ends the
  handle's running programs, grants and waiting requests like any other
  change to a handle.

`run` and `allowed_cmds` are independent. `exec` keeps using `allowed_cmds`
and never looks at `run`; `kv run` uses only `run`. A handle meant only for
launching keeps `allowed_cmds` empty, so `exec` refuses it.

### `kv run <handle>`

Takes the handle name and nothing else. It starts the daemon if none is
running, asks it to launch the handle's command, then acts as the program:
its own stdin goes to the program, and the program's stdout and stderr come
out of its own stdout and stderr, scrubbed.

Exit status:

- the program's exit code when it exits;
- 128 + the signal number when a signal ends the program (Unix);
- 1 when kv refuses the launch (`vault_locked`, `policy_denied`,
  `approval_denied`, `approval_timeout`, `unknown_handle`, a missing
  program) or ends the program (lock, handle changed, daemon stopped). The
  reason is printed to stderr as one line starting with `kv run:`.

Messages never include the pinned arguments, only the program's file name,
since the arguments may hold an address the user wants hidden.

### What agents and `kv list` see

`list_handles`, `kv list` and `kv list --json` show `runs: <file name of
argv[0]>` (for example `runs: bunx`) for a handle with a `run` command, and
nothing about its arguments.

### Approval

A `kv run` on a handle in `mode: ask` waits for a decision in `kv tui` like
any other request (60 s, then `approval_timeout`). The Approvals tab shows the
client as `kv run`, the tool `run`, the handle and the program's file name.
`kv run` names no agent session, so only "allow once" (`a`), deny (`d`) and
deny-and-set-to-deny (`D`) apply; "allow for session" is not offered. Once
allowed, the program runs until one of the ends in section 3.

## 3. Daemon

### Request

`AgentRequest::Run(RunCall { handle })` on the agent socket. The pipeline is
the usual one:

1. Vault locked → `vault_locked`.
2. Unknown handle → `unknown_handle`.
3. Policy: `Operation::Run` is allowed only on `env` handles with a `run`
   command ("this handle has no run command" otherwise); `mode: deny`
   refuses; `mode: ask` waits for approval; `mode: auto` proceeds.
4. A place among the open runs is taken (at most 32, counting those waiting
   for approval); when none is free → `policy_denied` "too many programs are
   running through kv run".
5. Launch, reply `AgentResponse::Started`, relay.

All checks happen before approval, so the user is never asked about a launch
that would be refused.

### Launch

- argv is the handle's `run` command. A bare argv[0] is resolved with
  `exec::resolve` through the PATH the daemon started with, skipping relative
  entries; an absolute argv[0] must exist and be executable. A program that
  cannot be found or started → `upstream_error` naming only its file name.
- Environment: the daemon's own, plus the handle's variables (the same rule
  as `exec`).
- Working directory: the user's home directory (`dirs::home_dir`), never one
  the caller chooses, so a directory with its own `bunfig.toml`, `.npmrc` or
  `package.json` cannot change what a launcher fetches.
- The program starts isolated with `process::isolate` and is adopted into a
  `ProcessTree` (process group on Unix, job object on Windows), so ending it
  ends everything it started.
- stdin, stdout and stderr are pipes.

### Relay

After `Started`, the connection carries stream frames instead of
request/response pairs:

- `kv run` → daemon: `RunInput::Stdin { data }`, `RunInput::CloseStdin`.
- daemon → `kv run`: `RunOutput::Stdout { data }`, `RunOutput::Stderr { data }`,
  then exactly one of `RunOutput::Exited { code, signal }` or
  `RunOutput::Ended { reason }`.

`data` is bytes, base64 in the JSON frame, at most 64 KiB per frame. stdin is
passed to the program unchanged. stdout and stderr each go through their own
`StreamScrubber`. Each direction applies backpressure: when `kv run` stops
reading, the daemon stops reading the program's output, and the program
blocks on its next write.

Like leases, a run follows the current scrubber (`Leases::subscribe` today),
so a secret added while it runs is scrubbed from then on. On a change, the
held-back bytes of each stream are moved into a stream on the new scrubber.

### Scrubber change: hold back only a possible secret

`StreamScrubber::push` today holds back the last `longest pattern − 1` bytes
until more input arrives. A long-running program that writes a reply and
then waits for the next request, as every stdio MCP server does, would never
see the end of its reply delivered.

The new rule changes only where the cut falls. Instead of
`pending.len() − (longest pattern − 1)`, the cut is the start of the longest
tail of the pending bytes that is a proper prefix of some pattern (compared
ignoring ASCII case, as matching is), or the end of the pending bytes when no
tail is. Matches that start before the cut are replaced and emitted as they
are today; everything from the cut on is held back.

A tail that cannot start a secret cannot become one, and a match that could
still grow into a longer pattern starts a tail that is a proper prefix of
that pattern, so it stays held back. The guarantee is unchanged: the
concatenated output still equals `Scrubber::scrub` on the whole input. All
proper prefixes of all patterns are precomputed, lowercased, into a set when
the scrubber is built. `exec` and leases use the same `StreamScrubber` and
get the same behavior.

### Ends

A run ends at the first of:

| Cause | Program | `kv run` gets | Audit outcome |
|---|---|---|---|
| The program exits | already gone; its tree is killed | `Exited { code, signal }` | `exited:<code>` or `signal:<n>` |
| `kv run` disconnects | tree killed | — | `client_closed` |
| The vault locks (`kv lock`, idle lock, `L` in the TUI) | tree killed | `Ended { reason: "the vault locked" }` | `locked` |
| The handle is changed or removed | tree killed | `Ended { reason: "the handle changed" }` | `handle_changed` |
| The daemon stops | tree killed | `Ended { reason: "kv stopped" }`, or the connection closes | `daemon_stopped` |

After the program exits, the daemon finishes reading what is left of its
stdout and stderr (until both close or the tree is killed), so the last
output is not lost, then sends `Exited`.

### Bookkeeping

Runs use the same mechanism that ends leases: a book of live entries, each
with a ticket whose end signal fires when its entry is removed. The book
becomes generic over its limit; `db_connect` keeps a book of 16, `run` gets
its own book of 32. `end_handle` and `end_all` are called on both books
wherever they are called for leases today.

A running program does not count as use of the vault for the idle lock;
only requests do.

### Audit

Two records per run, never with values or arguments:

- at launch: tool `run`, the handle, the program's file name as the summary,
  the decision (`auto`, `approved`, `denied`, `policy`, `locked`, `invalid`),
  outcome `started` or the refusal's error code;
- at the end: tool `run`, the handle, outcome from the table above, and how
  long the program ran.

## 4. Code layout

kv-core:

- `policy.rs`: `Policy.run: Option<Vec<String>>` (`#[serde(default,
  skip_serializing_if = "Option::is_none")]`); `Operation::Run`;
  `DenyReason::NoRunCommand`.
- `proto.rs`: `AgentRequest::Run(RunCall)`, `AgentResponse::Started`,
  `RunInput`, `RunOutput`; `PolicyPatch.run: Option<Vec<String>>`, where an
  empty list clears it.
- `secret.rs`: `HandleInfo.runs: Option<String>`.
- `scrub.rs`: the hold-back change above.

kv:

- `broker/run.rs` (new): launch, relay, scrub and end a run.
- `broker/lease.rs`: the book made generic over its limit and shared with
  `run`.
- `daemon/state.rs`: `prepare_run`, `Prepared::Run`, the runs book ended on
  lock and handle change, `run` validated on `add` and `set_policy`.
- `daemon/server.rs`: on `Prepared::Run` (directly or after approval),
  `serve_agent` hands the connection to `broker::run` and stops reading
  requests from it.
- `cli.rs`, `client.rs`: `kv run`, `--run` / `--no-run`, `runs` in `kv list`.
- `tui/view.rs`: `runs` on the Handles tab; `run` approvals.

## 5. Testing

Test-first, in the existing layout:

- kv-core: policy table tests for `Operation::Run`; scrubber tests that a
  complete line is emitted at once, that a secret split across chunks at
  every position is still caught, and the existing property test (streaming
  equals whole-input scrubbing) extended to random chunkings with the new
  rule; proto round trips for the new messages; `PolicyPatch` clearing.
- `Fixture` tests for `prepare_run`: locked, unknown handle, wrong kind, no
  `run`, deny, ask, auto, the 32-run limit, handle change and lock ending a
  ticket, audit lines.
- End to end through a real daemon (`live`): the test binary acts as the
  launched program (the `KV_EXEC_HELPER` pattern) and echoes each stdin line
  back with the secret in it. Asserts: output scrubbed; each reply arrives
  without further input; exit code and signal passthrough; the program dies
  on lock, on handle change and when `kv run` disconnects; `Ended` reasons.
- `kv run` through `CARGO_BIN_EXE_kv`, and one rmcp client talking to the
  existing `KV_MCP_HELPER` server through `kv run`, which is the servers-hub
  path.
- CLI: `--run`, `--no-run`, refusal on non-`env` kinds, `runs` in `kv list`.

CI stays as it is: fmt, clippy with `-D warnings` and tests on macOS, Linux
and Windows, and the MSRV check.

## 6. servers-hub migration

A Bun script in servers-hub, `scripts/migrate-to-kv.ts`:

- Default `--dry-run`: prints, per `servers.json` entry, the handle it
  becomes, its variable names, its mode and its pinned command with argument
  values masked. Changes nothing.
- `--apply`:
  1. Reads the kv passphrase once from a hidden prompt.
  2. Resolves `bunx` to an absolute path, and pins each package argument
     without a version to the version the npm registry reports as latest
     (`ssh-mcp` → `ssh-mcp@x.y.z`).
  3. Migrates every entry that has an `env` block, and skips the rest (such
     as `ssh-kyc-migration-dev`, which uses a key file). Each migrated
     entry's whole `env` block becomes the handle's variables, including
     non-secret ones such as `DOKPLOY_REDACT_ENV`.
  4. Mode: `ask` for names matching `kyclive` or `vllm`, `auto` otherwise
     (`--ask <regex>` overrides).
  5. Runs `kv add <name> --kind env --var ... --mode ... --run -- <argv>`,
     writing the passphrase and then each value, one per line, to its stdin.
     Values never appear in arguments or output.
  6. Confirms with `kv list --json` that each handle exists with `runs`.
  7. Rewrites `servers.json` atomically (temp file with mode 600, rename),
     replacing only the confirmed entries with `{"command": "kv", "args":
     ["run", "<name>"]}` and keeping each `description`.
- Safe to re-run: entries already using `kv run` are skipped; an existing
  handle with the same name stops the script with a message instead of being
  replaced.
- No backup of the old file is kept, since it would still hold the secrets.

servers-hub's README and `servers.example.json` change to show a `kv run`
entry and how to add a server with `kv add ... --run`.

## 7. Rollout

1. Implement on `feat/run` in key-vault-for-llm; update the main design's
   section 8 and the README ("Launching MCP servers with secrets").
2. Install the new kv; `kv stop`, then `kv unlock`.
3. Dry-run the migration, then the user runs `--apply` themselves.
4. Check one dev server (starts without a prompt) and one prod server (asks
   in `kv tui`) through servers-hub.

Recommended afterwards, outside this work: rotate the migrated passwords
and keys, since they were readable in plaintext.

## 8. Known limits

- An older kv that rewrites the vault drops `run`, since unknown policy
  fields are ignored when read.
- The launched program holds its secrets and can leak them; kv scrubs only
  what it writes to stdout and stderr.
- A pinned `bunx` command still downloads the pinned version from the
  registry when it is not cached.
