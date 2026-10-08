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
  `exec`, `status`. No message type on this socket can carry a secret value;
  this is enforced by the types in `kv-core`, not by runtime checks.
- **Control socket**: `unlock`, `lock`, `approve`, `deny`, secret and policy
  CRUD, audit log reads. Every message except `unlock` must carry the control
  session token issued at unlock.

### Daemon lifecycle

- `kv mcp` and `kv tui` connect to the daemon; if none is running they spawn
  `kv daemon` detached. A lock file prevents two daemons starting at once.
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
| `status` | — | locked/unlocked, pending approvals |

### Request pipeline (daemon)

1. Vault locked → `vault_locked`.
2. Policy check → `policy_denied` with the failing rule.
3. `mode: ask` and no matching grant → enqueue approval, send OS notification,
   wait up to 60 s → `approval_denied` / `approval_timeout` on failure.
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

- `kv tui` prompts for passphrase or biometric. The daemon unwraps the vault
  key, holds it in locked (`mlock`/`VirtualLock`), zeroized memory, and
  returns a random 256-bit control session token held only in TUI memory.
- After 5 failed attempts, unlock backs off exponentially.
- v1 lock triggers: idle timeout (default 8 h, configurable), `kv lock`, `L`
  in the TUI, daemon exit.

### Approval (TUI)

- Shows: client name from MCP `clientInfo` (labelled as self-reported),
  handle, tool, key arguments (method + URL, argv, first 200 characters of a
  query), working directory.
- Actions: `a` allow once; `s` allow for `grant_ttl`, scoped to that MCP
  session + handle; `d` deny; `D` deny and set the secret to `mode: deny`.
- OS notification via `notify-rust` when a request is queued.

### Audit log

- JSONL at `<data dir>/kv/audit.jsonl`: timestamp, MCP session id, client
  name, handle, tool, scrubbed argument summary, decision
  (`auto|approved|denied|policy|locked`), outcome (HTTP status / exit code /
  error code), duration.
- Never contains secret values. Rotates at 10 MB, keeps 5 files. Viewable in
  the TUI.
- Not tamper-proof against the same OS user.

### Agent-facing errors

Stable codes with actionable messages:

| Code | Message |
|---|---|
| `vault_locked` | Ask the user to unlock with `kv tui`. |
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
