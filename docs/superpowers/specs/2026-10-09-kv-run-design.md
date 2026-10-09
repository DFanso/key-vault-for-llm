# kv run and MCP servers through kv — design

Date: 2026-10-09
Status: design agreed in conversation, written spec pending review

## 1. Goal

Let stdio MCP servers that need secrets (SSH and Dokploy servers, for
example) run on demand through kv, which launches them with a handle's
secrets and passes tool calls to them, instead of a separate gateway that
reads the secrets from a plaintext file. This replaces the "`kv run --env
<handle>... -- <command>`" item planned for v1.1 in the main design
(`2026-10-08-kv-llm-secrets-broker-design.md`, section 8) with a stricter
form, where the handle pins the exact command, and adds a gateway to `kv mcp`.

The first user replaces servers-hub, a gateway that starts stdio MCP servers
on demand from a `servers.json` file. That file holds 10 SSH passwords
(`SSH_MCP_PASSWORD` for `ssh-mcp`), 8 Dokploy URLs and API keys
(`DOKPLOY_URL`, `DOKPLOY_API_KEY` for `@dokploy/mcp`) and one SSH server that
logs in with a key file, all where an agent with a shell can read them.

Success means:

- All 19 servers are kv handles, reachable through `kv mcp`'s
  `list_servers`, `list_server_tools`, `call_server_tool` and `stop_server`,
  and servers-hub and its `servers.json` are gone.
- Nothing that can reach kv (an agent through MCP, an agent running `kv run`
  in a shell, any other process running as the user) can use a handle to
  launch a different program, or the same program with different arguments,
  without the passphrase.
- Development servers start without a prompt while the vault is unlocked;
  production servers wait for approval in `kv tui`, once per agent session.
- Locking the vault stops every server launched through kv.

### Threat model

As in the main design. In addition:

- The launched program holds the secret, by design. kv cannot stop a
  launched program from leaking it; pinning the command is what limits which
  programs get it.
- A pinned command that fetches code at launch (`bunx -y pkg`) trusts the
  package registry. The migration pins package versions to narrow this.

### Not in scope

- Sharing one running server between agent sessions. Each `kv mcp` process
  starts its own, as servers-hub did.
- Editing the `run` command in `kv tui`. It is set with the CLI.
- SSH key handling (`ssh_exec`), which stays in the v1.1 list. A server that
  logs in with a key file keeps the file on disk.
- Passing the caller's environment or working directory to the program.
- A permanent import command; the move from servers-hub is a one-off script.

## 2. User-facing behavior

### Servers are handles with a `run` command

An `env` handle may carry a `run` command: the exact argv to launch, stored
in the handle's policy inside the encrypted vault. A handle with a `run`
command is a *server*.

```sh
kv add ssh-kycdev --kind env --var SSH_MCP_PASSWORD --mode auto \
  --description "kycdev box over SSH" \
  --run -- /path/to/bunx -y ssh-mcp@1.2.3 --host=10.0.0.5 --port=22 \
  --user=root --timeout=30000 --disableApproval
kv add ssh-migration --kind env --mode auto \
  --run -- /path/to/bunx -y ssh-mcp@1.2.3 --host=10.0.0.9 --key=/path/to/id
kv policy ssh-kycdev --run -- /path/to/bunx -y ssh-mcp@1.2.4 ...   # replace
kv policy ssh-kycdev --no-run                                        # clear
```

- `--run` takes every argument after `--`. `--run` and `--no-run` cannot be
  combined, and `--run` with no arguments is an error.
- Only `env` handles may have a `run` command. The daemon refuses it on other
  kinds with the control error `invalid`, which `kv add` and `kv policy`
  print.
- An `env` handle needs at least one variable, unless it has a `run` command
  (a *run-only* handle). `kv add` asks for no values then; clearing `run` on
  a handle without variables is refused.
- The argv has at most 128 entries of at most 4096 bytes each, and argv[0]
  must not be empty.
- Changing or clearing `run` is a policy change: it needs the passphrase (or
  Touch ID / Windows Hello, or an unlocked `kv tui` session), and it ends the
  handle's running programs, grants and waiting requests like any other
  change to a handle.

`run` and `allowed_cmds` are independent. `exec` keeps using `allowed_cmds`
and never looks at `run`; launching uses only `run`. A server keeps
`allowed_cmds` empty, so `exec` refuses it.

### `kv mcp` tools for servers

Four tools join the existing seven:

- `list_servers`: every handle with a `run` command, with its description
  and whether it is running in this `kv mcp` process. Starts nothing.
- `list_server_tools(server, filter?, schemas?)`: starts the server if it is
  not running, and lists its tools. `filter` is a case-insensitive substring
  matched against each tool's name and description. Without `schemas`, each
  tool is its name and the first line of its description cut to 160
  characters; with `schemas: true`, its full description and input schema.
  The result also gives the total number of tools and how many matched.
- `call_server_tool(server, tool, arguments?)`: starts the server if needed
  and calls the tool with `arguments` (an object, `{}` when omitted). The
  result is the server's own result, with secrets replaced by
  `[kv:<handle>]`; an error result stays an error.
- `stop_server(server)`: stops it if it is running in this process.

The `kv mcp` instructions gain one sentence: servers are reached with
`list_servers`, then `list_server_tools`, then `call_server_tool`, and are
started only when the user asks for that server.

### `kv run <handle>`

Takes the handle name and nothing else. It starts the daemon if none is
running, asks it to launch the handle's command, then acts as the program:
its own stdin goes to the program, and the program's stdout and stderr come
out of its own stdout and stderr, scrubbed. It lets any MCP client use one
server directly (`claude mcp add ssh-kycdev -- kv run ssh-kycdev`).

Exit status:

- the program's exit code when it exits;
- 128 + the signal number when a signal ends the program (Unix);
- 1 when kv refuses the launch (`vault_locked`, `policy_denied`,
  `approval_denied`, `approval_timeout`, `unknown_handle`, a missing
  program) or ends the program (lock, handle changed, daemon stopped). The
  reason is printed to stderr as one line starting with `kv run:`.

### Never showing the arguments

Messages, `list_handles`, `list_servers`, `kv list`, approvals and the audit
log never include the pinned arguments, only the program's file name,
since the arguments may hold an address the user wants hidden.
`list_handles`, `kv list` and `kv list --json` show `runs: <file name of
argv[0]>` (for example `runs: bunx`) for a server.

### Approval

Launching a server in `mode: ask` waits for a decision in `kv tui` like any
other request (60 s, then `approval_timeout`). The Approvals tab shows the
client, the tool `run`, the handle and the program's file name.

- Through `kv mcp`, the launch names the agent session, so "allow for
  session" (`s`) is offered as for other tools: later launches of that
  handle from the same session within `grant_ttl` need no approval.
- `kv run` names no session; the client shows as `kv run`, and only "allow
  once" (`a`), deny (`d`) and deny-and-set-to-deny (`D`) apply.

Approval is asked only at launch. A running server keeps running after a
grant expires, until one of the ends in section 3.

## 3. Daemon

### Request

`AgentRequest::Run(RunCall { handle })` on the agent socket, after an
optional `Hello`. The pipeline is the usual one:

1. Vault locked → `vault_locked`.
2. Unknown handle → `unknown_handle`.
3. Policy: `Operation::Run` is allowed only on `env` handles with a `run`
   command ("this handle has no run command" otherwise); `mode: deny`
   refuses; `mode: ask` waits for approval unless the session holds a grant;
   `mode: auto` proceeds.
4. A place among the open runs is taken (at most 32, counting those waiting
   for approval); when none is free → `policy_denied` "32 programs are
   running through kv already; stop one, or ask the user to lock the vault".
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

- client → daemon: `RunInput::Stdin { data }`, `RunInput::CloseStdin`.
- daemon → client: `RunOutput::Stdout { data }`, `RunOutput::Stderr { data }`,
  then exactly one of `RunOutput::Exited { code, signal }` or
  `RunOutput::Ended { reason }`.

`data` is bytes, base64 in the JSON frame, at most 64 KiB per frame. stdin is
passed to the program unchanged. stdout and stderr each go through their own
`StreamScrubber`. Each direction applies backpressure: when the client stops
reading, the daemon stops reading the program's output, and the program
blocks on its next write.

Like leases, a run follows the current scrubber, so a secret added while it
runs is scrubbed from then on. On a change, the held-back bytes of each
stream are moved into a stream on the new scrubber.

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

| Cause | Program | Client gets | Audit outcome |
|---|---|---|---|
| The program exits | already gone; its tree is killed | `Exited { code, signal }` | `exited:<code>` or `signal:<n>` |
| The client disconnects | tree killed | — | `client_closed` |
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
its own book of 32. Both are ended wherever leases are ended today (lock,
handle change), and both follow the same scrubber.

A running program does not count as use of the vault for the idle lock;
only requests do.

### Audit

Two records per run, never with values or arguments:

- at launch: tool `run`, the handle, the program's file name as the summary,
  the decision (`auto`, `approved`, `denied`, `policy`, `locked`, `invalid`),
  outcome `started` or the refusal's error code;
- at the end: tool `run`, the handle, outcome from the table above, and how
  long the program ran.

## 4. The gateway in `kv mcp`

- **Starting.** The first `list_server_tools` or `call_server_tool` for a
  server opens a new agent-socket connection, sends `Hello` with this
  process's session and `Run { handle }`, and waits for `Started` or a
  refusal (a refusal becomes the tool's error, with its code). On `Started`
  it runs an rmcp client named `kv/<handle>` over the relay (stdin chunks
  out, scrubbed stdout chunks in) and performs MCP `initialize`.
- **One start per server.** Running servers are kept per server name as a
  shared start; calls that arrive while a server starts wait for that start,
  so a server is never launched twice by one `kv mcp`. A failed start is
  forgotten, so the next call tries again.
- **Time limits.** Approval keeps the daemon's 60 s wait. After `Started`,
  `initialize` must finish within 120 s, room for `bunx` to download a
  pinned version the first time; otherwise the connection is dropped, which
  kills the program, and the call fails with `upstream_error`.
- **stderr.** The program's scrubbed stderr is written to `kv mcp`'s own
  stderr, which MCP clients keep in their logs.
- **Calls.** `arguments` pass through unchanged; results come back as the
  server sent them, after the daemon's scrubbing. Results are not capped.
- **Ends.** When the relay closes (lock, handle change, the program exiting,
  `stop_server`, the daemon stopping), the server's entry is removed. A call
  that was in progress fails with `server_stopped: <reason>`. The next call
  starts the server again, which on a locked vault fails at once with
  `vault_locked`.
- **Exit.** When the MCP client goes away, `kv mcp` exits, its connections
  close, and the daemon kills every program it started for that process.
- **`list_servers`** reads `list_handles` (keeping handles with `runs`) and
  this process's set of running servers.

## 5. Code layout

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
  lock and handle change, `run` and run-only handles validated on `add` and
  `set_policy`.
- `daemon/server.rs`: on `Prepared::Run` (directly or after approval),
  `serve_agent` hands the connection to `broker::run` and stops reading
  requests from it.
- `client.rs`: `run_stream(paths, session, handle)`, which opens the
  connection, sends `Hello` and `Run`, and on `Started` returns a
  `RunStream`: an `AsyncWrite` for stdin, an `AsyncRead` for stdout, a
  receiver for stderr chunks and the run's end. Used by `kv run` and the
  gateway.
- `mcp/servers.rs` (new): the gateway's book of running servers and the
  four tools' logic. `mcp.rs` declares the tools and calls into it.
- `cli.rs`: `kv run`, `--run` / `--no-run`, run-only `env` handles, `runs`
  in `kv list`.
- `tui/view.rs`: `runs` on the Handles tab; `run` approvals.
- `Cargo.toml`: rmcp's `client` feature on the main dependency (already
  used by the tests).

## 6. Testing

Test-first, in the existing layout:

- kv-core: policy table tests for `Operation::Run`; scrubber tests that a
  complete line is emitted at once, that a secret split across chunks at
  every position is still caught, and the existing property test (streaming
  equals whole-input scrubbing) extended to random chunkings with the new
  rule; proto round trips for the new messages; `PolicyPatch` clearing.
- `Fixture` tests for `prepare_run`: locked, unknown handle, wrong kind, no
  `run`, run-only handle, deny, ask with and without a session grant, auto,
  the 32-run limit, lock and handle change ending a ticket, audit lines.
- `kv run` end to end: the test binary acts as the launched program (the
  `KV_EXEC_HELPER` pattern) and echoes each stdin line back with the secret
  in it. Asserts: output scrubbed; each reply arrives without further input;
  exit code and signal passthrough; the program dies when `kv run`
  disconnects, on lock and on handle change; `Ended` reasons.
- Gateway end to end: an rmcp client drives `kv mcp`; the test binary acts
  as a small rmcp MCP server with a `reveal` tool returning its secret and a
  `slow` tool. Asserts: `list_servers` before and after a start;
  `list_server_tools` with `filter` and `schemas`; `call_server_tool`
  returns the secret as `[kv:<handle>]`; concurrent first calls launch once;
  `stop_server`; a lock gives `server_stopped`, then `vault_locked`.
- CLI: `--run`, `--no-run`, run-only handles, refusal on non-`env` kinds,
  `runs` in `kv list`.

CI stays as it is: fmt, clippy with `-D warnings` and tests on macOS, Linux
and Windows, and the MSRV check.

## 7. Moving off servers-hub

A one-off Bun script, written to a scratch directory and committed nowhere:

- Default `--dry-run`: prints, per `servers.json` entry, the handle it
  becomes, its variable names, its mode and its pinned command with argument
  values masked. Changes nothing.
- `--apply`:
  1. Reads the kv passphrase once from a hidden prompt.
  2. Resolves `bunx` to an absolute path, and pins each package argument
     without a version to the version the npm registry reports as latest
     (`ssh-mcp` → `ssh-mcp@x.y.z`).
  3. Migrates every entry: its whole `env` block (including non-secret
     variables such as `DOKPLOY_REDACT_ENV`) becomes the handle's variables,
     and an entry without `env` becomes a run-only handle. Its
     `description`, if any, becomes the handle's.
  4. Mode: `ask` for names matching `kyclive` or `vllm`, `auto` otherwise
     (`--ask <regex>` overrides).
  5. Runs `kv add <name> --kind env [--var ...] --mode ... --run -- <argv>`,
     writing the passphrase and then each value, one per line, to its stdin.
     Values never appear in arguments or output.
  6. Confirms with `kv list --json` that each handle exists with `runs`.
- An existing handle with the same name stops the script with a message
  instead of being replaced.

Then, each step confirmed with the user: remove the `servers-hub` MCP
registration (`claude mcp remove servers-hub -s user`, and `mcp-hub` if it
starts the same hub), and delete `~/Codes/mcp/servers-hub` with its
`servers.json`. Its GitHub repository is left alone.

## 8. Rollout

1. Implement on `feat/run` in key-vault-for-llm; update the main design's
   section 8 and the README ("MCP servers with secrets").
2. Install the new kv; `kv stop`, then `kv unlock`.
3. Dry-run the migration, then the user runs `--apply` themselves.
4. Check `list_servers`, one dev server (starts without a prompt) and one
   prod server (asks in `kv tui`, once per session) through `kv mcp`.
5. Remove servers-hub as in section 7.

Recommended afterwards, outside this work: rotate the migrated passwords
and keys, since they were readable in plaintext.

## 9. Known limits

- An older kv that rewrites the vault drops `run`, since unknown policy
  fields are ignored when read.
- The launched program holds its secrets and can leak them; kv scrubs only
  what it writes to stdout and stderr.
- A pinned `bunx` command still downloads the pinned version from the
  registry when it is not cached.
- Each agent session starts its own copy of a server.
