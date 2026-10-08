# kv: a local secrets broker for LLM agents — design

Date: 2026-10-08
Status: approved design, pending implementation plan

## 1. Goal

Let AI coding agents (Claude Code, Cursor, any MCP client) *use* API keys,
database credentials and other secrets without ever *holding* them. The agent
works with named handles (`prod-db`, `openrouter`); a local daemon performs the
authenticated work and returns scrubbed results.

Success means:

- Secret values never appear in the model's context, chat transcripts, or
  agent tool output under normal operation.
- Casual or prompt-injected misuse of a handle is stopped by per-secret policy
  and human approval.
- The tool runs on macOS, Linux and Windows.

### Users

Single user on their own machine (v1). No multi-user, sync or server mode.

### Threat model

In scope:

- Secrets leaking into model context, transcripts, logs and provider-side
  storage.
- An agent (possibly prompt-injected) using a handle for something the user
  did not intend: wrong host, write instead of read, unexpected command.
- An agent trying to approve its own requests or unlock the vault without the
  user.

Out of scope:

- A determined malicious process running as the same OS user (reading daemon
  memory, keylogging the passphrase, attaching a debugger). kv is not a
  sandbox. The README states this plainly.
- Transformations of a secret the scrubber cannot recognise (reversed, split,
  encrypted). Policy and approval are the controls for that.

## 2. Architecture

```
 Claude Code / Cursor / any MCP agent
        │ stdio (MCP)
   ┌────▼─────┐   agent socket     ┌──────────────────────────────┐
   │  kv mcp  ├───────────────────►│          kv daemon           │
   └──────────┘  use handles only  │  vault (key held in memory)  │
                                   │  policy engine               │
   ┌──────────┐  control socket    │  approval queue              │
   │  kv tui  ├───────────────────►│  audit log                   │
   └──────────┘  needs unlock      │  ├ HTTP proxy                │
   ┌──────────┐                    │  ├ DB proxies (pg, redis)    │
   │ kv <cli> ├───────────────────►│  └ exec runner + scrubber    │
   └──────────┘                    └──────────────┬───────────────┘
                                                  ▼
                                upstream APIs / DBs / child processes
```

### Crates

Cargo workspace, Rust stable:

- `kv-core` (library, no network code): vault format and crypto, secret types,
  policy evaluation, output scrubber, IPC message types.
- `kv` (single binary): subcommands `daemon`, `mcp`, `tui`, and CLI commands
  `add`, `list`, `rm`, `lock`, `status`.

Key dependencies: `tokio`, `rmcp` (MCP), `ratatui` + `crossterm` (TUI),
`clap`, `serde`, `chacha20poly1305`, `argon2`, `zeroize`, `secrecy`,
`aho-corasick`, `reqwest` (rustls), `tokio-postgres`, `redis`,
`interprocess` (local sockets / named pipes), `keyring` and
`security-framework` (biometric unlock), `notify-rust`, `dirs`.

### IPC

Length-prefixed JSON frames over local sockets: Unix domain sockets in the
per-user runtime dir on macOS/Linux, named pipes ACL'd to the current user SID
on Windows. Both sockets verify the peer runs as the same OS user
(`SO_PEERCRED` / `getpeereid` / pipe ACL).

- **Agent socket**: `list_handles`, `http_request`, `db_query`, `db_connect`,
  `exec`, `request_handle`, `status`. No message type on this socket can carry a secret value;
  this is enforced by the types in `kv-core`, not by runtime checks. A
  connection may open with a `hello` frame naming its agent session (a random
  id `kv mcp` picks per MCP connection, at most 128 bytes) and client (the MCP
  `clientInfo` name, self-reported, at most 1024 bytes). It gets no reply;
  approvals use it to scope grants and to tell the user who is asking.
- **Control socket**: `init`, `unlock`, `lock`, `stop`, `open_session`,
  `overview`, `decide`, `dismiss_request`, secret and policy CRUD (`add`, `update`, `remove`,
  `set_policy`), passphrase change. Every command except `lock` and `stop`
  must prove the user is present:
  - CLI commands (`kv add`, `kv rm`, `kv policy`, `kv passwd`, `kv unlock`)
    carry the vault passphrase, checked per command. Nothing reusable outlives
    the command, so an agent running commands as the user has nothing to
    replay. Wrong passphrases count toward the unlock backoff.
  - `kv tui` sends the passphrase once with `open_session`, which unlocks the
    vault if needed and returns a random 256-bit token (64 hex characters)
    held only in TUI memory. The token stands in for the passphrase on every
    command except `init`, `open_session` and `passphrase change`. Tokens are
    compared in constant time, at most 16 are open at once (the oldest is
    dropped), and every lock and passphrase change ends them all. A wrong or
    ended token gets `session_ended`; it does not count toward the unlock
    backoff, since 256 bits cannot be guessed.
  - `overview` (status, handles and waiting requests) needs a token, is not
    audited and does not count as use of the vault, so a TUI left open does
    not keep the vault from locking.
- Malformed frames get a `bad_request` reply and the connection is closed;
  control-socket replies never echo request content, which may include the
  passphrase. Frames are capped at 4 MiB, so a reply with 256 KiB of stdout
  and 256 KiB of stderr still fits when every byte is JSON-escaped.

### Daemon lifecycle

- Every `kv` command except `lock` and `stop` connects to the daemon and, if
  none is running, spawns `kv daemon` detached and waits for it. A lock file
  prevents two daemons starting at once; the loser exits quietly. Stale socket
  files from a crashed daemon are replaced once the lock is held.
- `kv stop` locks and shuts the daemon down. `KV_HOME` puts the vault, audit
  log and sockets under one directory instead of the platform defaults.
- The daemon starts locked and exits after an idle period while locked. No
  launchd/systemd/Windows service install is required.
- If the daemon crashes, the key is gone with it. `kv mcp` respawns it, and it
  comes back locked.

## 3. Vault

### File format

Path: `<config dir>/kv/vault.kv` (from `dirs::config_dir()`).

- A random 256-bit **vault key** encrypts the payload with
  XChaCha20-Poly1305.
- The vault key is stored wrapped once per unlock method:
  - **Passphrase** (always present, the only method on Linux): wrapping key
    from Argon2id.
  - **Touch ID** (macOS): wrapping key stored as a Keychain item with
    `kSecAccessControlBiometryCurrentSet`.
  - **Windows Hello**: wrapping key derived via HKDF from a
    `KeyCredentialManager` signature over a fixed per-vault challenge.
- Layout: header (magic, format version, KDF params, list of wrapped keys),
  then nonce + AEAD ciphertext of the serialized secrets.
- Writes are atomic (temp file, fsync, rename) and keep one `.bak` holding
  the previous version.
- Changing the passphrase generates a new vault key, re-encrypts everything
  and writes the new version to `.bak` as well, so the old passphrase opens
  no file kv leaves behind, and an old copy plus the old passphrase reveals
  nothing about later versions. Other unlock methods (Touch ID, Windows
  Hello) are dropped and must be enrolled again. Copies made by other tools
  (Time Machine, cloud sync) before the change still open with the old
  passphrase.

The OS keyring never holds anything that can decrypt the vault without user
presence. On Windows and Linux any same-user process can read keyring items,
which would let an agent bypass kv entirely.

### Secret model

```
name:         prod-db                 # handle shown to the agent
kind:         postgres                # http | postgres | redis | env
description:  "Prod Postgres (Azure)" # shown to the agent
value:        <kind-specific>         # never leaves the daemon
policy:       { ... }
created_at, updated_at
```

Kind-specific values:

- `http`: token plus placement — header with a template (`Authorization:
  Bearer {}`, `x-api-key: {}`) or a query parameter. Optional `base_url`
  (e.g. `https://dokploy.example.com/api`) for services whose address should
  stay hidden too; see `http_request` in section 4.
- `postgres`, `redis`: full connection URL.
- `env`: one or more `NAME=value` pairs for `exec`.

### Policy

```
mode:            auto | ask | deny
allowed_hosts:   [api.openrouter.ai]   # http: host (default port) or host:port
allow_plain_http: false                # http
allowed_methods: [GET, POST]           # http, optional
read_only:       true                  # postgres, redis
allowed_cmds:    [terraform, psql]     # env: bare name (PATH) or absolute path
grant_ttl:       15m                   # duration of a session grant
```

New secrets default to `mode: ask` with empty allow-lists.

`allowed_hosts` entries are `host` (the scheme's default port only) or
`host:port`. `allowed_cmds` entries are either a bare name, which matches only
a bare argv[0] that the runner resolves through PATH, or an absolute path,
which matches only that exact path. Case and a `.exe` suffix are ignored only
on Windows. An `http` secret with a `base_url` needs no `allowed_hosts`: the
base URL's origin is the only destination.

`list_handles` returns name, kind, description, mode and constraints. It never
returns values, the hostname inside a DB URL, or a secret's `base_url`.

## 4. MCP tools and request flow

| Tool | Input | Output |
|---|---|---|
| `list_handles` | — | handles with kind, description, constraints |
| `http_request` | handle, method, url, headers?, body? | status, headers, body (scrubbed, body capped at 256 KB) |
| `db_query` | handle, query (SQL or Redis command) | rows as JSON (scrubbed, capped) |
| `db_connect` | handle, ttl? | local connection URL with a lease token |
| `exec` | handles[], argv[], cwd?, timeout? | exit code, stdout, stderr (scrubbed) |
| `request_handle` | name, kind, description?, reason?, header?/template?/query_param?, base_url?, allowed_hosts?, env_vars?, allowed_cmds? | confirmation that the request waits in `kv tui` |
| `status` | — | locked/unlocked, pending approvals |

`request_handle` lets an agent ask for a handle it lacks without ever
carrying a value: unknown arguments such as `token` are refused, and the
request type has no field for one. The daemon refuses a name that is invalid
or already a handle, keeps at most 16 requests (asking again for a name
replaces the earlier request), cleans the agent's text as for approvals, and
drops fields that do not belong to the kind. Requests live in memory, survive
a lock, appear in `overview`, and leave when a handle with that name is added
or the user dismisses them (`dismiss_request`, audited). The TUI lists them
first on the Handles tab; `Enter` opens the New handle form filled in from the
request with mode `ask` and the focus on the secret field, and `x` dismisses.
A notification announces each request.

### Request pipeline (daemon)

1. Vault locked → `vault_locked`.
2. Policy check → `policy_denied` with the failing rule.
3. `mode: ask` and no matching grant → enqueue approval, send OS notification,
   wait up to 60 s → `approval_denied` / `approval_timeout` on failure. The
   wait happens outside the daemon lock, so other requests keep flowing. At
   most 32 requests wait at once; more get `approval_timeout` at once. Locking
   answers every waiting request with `vault_locked` and drops all grants.
4. Execute.
5. Scrub output.
6. Write audit record.
7. Return.

### Per tool

- **`http_request`**: URL host and port must match `allowed_hosts`; HTTPS
  only unless `allow_plain_http`. The daemon attaches auth and sends via
  `reqwest` with rustls. Redirects are followed only to allowed hosts, and
  auth is stripped on any cross-host hop. The response is scrubbed, since
  some APIs echo the key in errors.
  - System proxy settings are ignored, so neither the credential nor the
    address passes through a proxy. Requests time out after 60 s.
  - Redirects are followed by kv, at most 5. The credential goes only to the
    original origin; a query-parameter credential is removed from the next
    URL, and a `Location` that contains the token is not followed. 303, and
    301/302 after a POST, become a GET without a body. A redirect to a
    target the policy does not allow is returned to the agent as the 3xx
    response instead of being followed.
  - Transport errors are reported without the URL and then scrubbed.
  - The agent may not set `Accept-Encoding`, `Range` or `If-Range`, and a
    response with a `Content-Encoding` other than `identity` is an
    `upstream_error`: a compressed body or a byte range could carry a secret
    past the scrubber.
  - When `allowed_methods` is set, method-override headers
    (`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`) are
    refused. A framework's `_method` body field cannot be policed.
  - With a `base_url`, the agent sends a path (`/project.all`) instead of a
    URL. The daemon appends it to the base URL's path; the result must keep
    the base URL's origin and path prefix, so absolute URLs, `//host` and
    `..` segments that escape the prefix are rejected. Redirects may only
    stay on that origin. The base URL and its host are added to the
    scrubber, so responses and errors never reveal the address.
- **`db_query`**: the daemon connects itself (`tokio-postgres` / `redis`) and
  returns rows. Preferred path for agents.
- **`db_connect`**: starts a loopback proxy on a random port and returns e.g.
  `postgres://kv:<lease-token>@127.0.0.1:41823/app`. The lease token is
  random, single-lease and expires with the TTL. The proxy authenticates the
  client with the token, connects upstream with the real credentials, then
  passes traffic through.
- **`exec`**: argv array only, never a shell string. `sh`, `bash`, `cmd`,
  `powershell` are not allowed unless listed in `allowed_cmds`. Env vars from
  all listed handles are injected; output streams through the scrubber; the
  process group is killed on timeout.
  - `cwd` must be an absolute path to an existing directory. The daemon
    checks only that it is absolute while authorizing; the runner checks it
    exists, so a stalled network mount cannot block the daemon's lock. `kv mcp`
    fills in its own working directory (the agent's project) when the
    agent omits it.
  - The timeout defaults to 60 s and may be at most 600 s.
  - Two handles setting the same variable is a `bad_request` (names compare
    case-insensitively on Windows).
  - A bare argv[0] is resolved through the PATH the daemon started with,
    skipping relative entries, not through the agent's environment.
  - The program runs in its own process group (Unix) or job object
    (Windows). Whatever it leaves running is killed when it exits, as well
    as on timeout.
  - stdout and stderr are each capped at 256 KiB. When output is cut by the
    cap or by a kill, the scrubber's held-back tail is dropped rather than
    flushed, so a partial secret at the cut never escapes.

### Read-only enforcement

- **Redis**: enforced. RESP is parsed and only an allow-list of read commands
  is forwarded.
- **Postgres**: best effort. Sessions are opened with
  `default_transaction_read_only=on`, and statements that change it
  (`SET ... transaction_read_only`, `BEGIN READ WRITE`, `SET SESSION
  CHARACTERISTICS`) are rejected in the simple query protocol and in `db_query`.
  The real guarantee is a read-only role: kv checks the role's privileges when
  the secret is added (via the unlocked daemon) and again on first use after
  each unlock, and warns in the `kv add` output and the TUI when a `read_only`
  secret uses a role with write access.

## 5. Scrubbing, unlock, approval, audit, errors

### Scrubber

- Patterns: every unlocked secret value as raw, base64 (standard and URL-safe,
  at all three byte alignments), hex (lower and upper), URL-encoded and
  JSON-escaped. Connection URLs also contribute their password alone.
- One Aho-Corasick automaton over all patterns, rebuilt on unlock and on
  secret changes.
- Streaming: hold back `longest pattern − 1` bytes between chunks so secrets
  split across chunks are caught.
- Matches are replaced with `[kv:<handle>]`.
- Values shorter than 8 characters are not scrubbed (false positives);
  `kv add` warns about them.

### Unlock

- `kv unlock` (or any control command) and, from Plan 4, `kv tui` prompt for
  the passphrase, or a biometric from Plan 6. The daemon unwraps the vault key
  and holds it in memory-locked (`mlock`/`VirtualLock`, best effort), zeroized
  memory. The TUI additionally receives a random 256-bit control session token
  held only in TUI memory.
- The daemon disables core dumps and, on Linux, marks itself non-dumpable so
  other processes running as the same user cannot attach a debugger or read
  its memory through `/proc`.
- After 5 failed attempts, unlock backs off exponentially.
- v1 lock triggers: idle timeout (default 8 h, `kv daemon --idle-lock`),
  `kv lock`, `kv stop`, `L` in the TUI, daemon exit. Only use of the vault
  resets the idle timer; `status` polls do not.

### Approval (TUI)

- Shows: client name from MCP `clientInfo` (labelled as self-reported),
  handle, tool, key arguments (method + URL, argv, first 200 characters of a
  query), working directory, seconds left to answer. The URL shown is the one
  that will be sent (for a `base_url` handle, the agent's path). Agent-supplied
  text has control characters replaced with U+FFFD, invisible format
  characters (bidi overrides, zero-width spaces) dropped and whitespace runs
  collapsed, and is cut to 64 characters (client) or 300 (arguments, working
  directory), so it can neither drive the terminal nor pose as extra lines.
- Decision keys act on the selected request by id. If it stops waiting,
  nothing is selected until the user picks again with the arrow keys, so a
  list that shifts never turns a key press into a decision on a request the
  user has not read. Pastes arrive as one input (bracketed paste) and are
  never read as commands; Ctrl and Alt letters do nothing.
- A request whose agent hangs up is withdrawn at once and audited with
  outcome `cancelled`; it can no longer be approved.
- Actions: `a` allow once; `s` allow for `grant_ttl`, scoped to that MCP
  session + handle (only offered when the request named a session); `d` deny;
  `D` deny and set the secret to `mode: deny`. Decisions are audited as
  `decide`; the request itself is audited with decision `approved` or
  `denied`, and an unanswered one as `denied` with outcome `approval_timeout`.
- OS notification via `notify-rust` when a request is queued, naming the
  client and handles but no arguments. On by default; `KV_NOTIFY=off` (or
  `kv daemon --notify off`) turns it off.
- Handles tab: add, edit (description, or a new value of the same kind;
  blank secret fields keep the old value, and an http value without a base
  URL keeps the handle's), change policy, remove after a yes. Secret fields
  are drawn as dots.
- Audit tab: the newest 200 entries, read from the end of `audit.jsonl` by
  the TUI itself, with control characters replaced.

### Audit log

- JSONL at `<data dir>/kv/audit.jsonl`: timestamp, handle, tool, scrubbed
  argument summary, decision
  (`auto|approved|denied|policy|locked|invalid`; `invalid` covers malformed
  requests and unknown handles), outcome (HTTP status / exit code /
  error code), duration. Recording the MCP session id and client name is
  planned, not yet done.
- Never contains secret values. Rotates at 10 MB, keeps 5 files. Viewable in
  the TUI.
- Not tamper-proof against the same OS user.

### Agent-facing errors

Stable codes with actionable messages:

| Code | Message |
|---|---|
| `no_vault` | Ask the user to create one with `kv init`. |
| `vault_locked` | Ask the user to unlock with `kv tui`. |
| `bad_request` | Names the field that is wrong. |
| `policy_denied` | Names the failing rule and the allowed values. |
| `approval_denied` | The user denied the request. |
| `approval_timeout` | No decision within 60 s. |
| `unknown_handle` | Lists available handles. |
| `upstream_error` | Upstream message, scrubbed. |
| `daemon_unavailable` | The daemon could not be started or reached. |

All failures are closed: no partial results, no fallback to unauthenticated
or unscrubbed paths.

## 6. Testing

- **`kv-core` unit tests**: vault round trip, wrong passphrase, tampered
  ciphertext, multiple wrapped keys, atomic write; table-driven policy tests;
  `proptest` scrubber tests — a secret at random positions, in every supported
  encoding, split at random chunk boundaries, never survives.
- **Daemon integration tests** (real daemon, temp dirs, low-cost Argon2
  params):
  - HTTP: local TLS test server with a self-signed cert. Asserts auth reaches
    upstream, host allow-list, redirect auth stripping, echoed key scrubbed.
  - Exec: test helper binary prints the injected secret raw, base64 and hex;
    output must be scrubbed.
  - Postgres and Redis via `testcontainers` (Linux CI only), including
    read-only enforcement.
  - Security: agent socket rejects control messages; control messages without
    token rejected; unlock backoff; decoder fuzzing; approval timeout fails
    closed.
- **MCP end to end**: `rmcp` client drives `kv mcp`. Manual check with
  `claude mcp add kv -- kv mcp`.
- **CI**: GitHub Actions matrix (macOS, Ubuntu, Windows): `cargo fmt --check`,
  `cargo clippy -- -D warnings`, `cargo test`.
- **Manual per release**: Touch ID and Windows Hello unlock.

## 7. Distribution

`cargo install` first; prebuilt binaries for macOS, Linux and Windows via
`cargo-dist` as the final v1 milestone.

## 8. Out of scope for v1

- v1.1: SSH (key-holding agent, `ssh_exec`); Claude Code guard hooks that
  block reads of `.env`, `~/.ssh/id_*`, `printenv`; `kv run --env <handle>...
  -- <command>` to launch long-running tools the user trusts, such as MCP
  servers (a Dokploy MCP, for example), with `env` secrets injected, so
  their keys leave plaintext config files like `settings.local.json`. The
  same policy and approval as `exec` apply at launch, stdout and stderr pass
  through the streaming scrubber, and the launched process does hold the
  secret.
- Later: lock on sleep / screen lock; pluggable backends (1Password,
  Bitwarden, Infisical); MySQL, Mongo and other DB proxies.
- Not planned: team sharing or sync; sandboxing a same-user agent.
