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
`interprocess` (local sockets / named pipes), `objc2-local-authentication`
and `security-framework` (Touch ID), `windows` (Windows Hello),
`notify-rust`, `dirs`.

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
  - **Touch ID** (macOS): a random wrapping key in a login keychain item
    (service `kv vault`, account the slot id), read only after
    `LAContext` confirms a fingerprint. The slot keeps the Mac's
    `evaluatedPolicyDomainState`, and kv refuses the key once the enrolled
    fingerprints change, as `kSecAccessControlBiometryCurrentSet` would.
    That access control, and the data-protection keychain, need an
    entitlement only a signed binary can carry (`errSecMissingEntitlement`,
    -34018, for `cargo install` builds), hence the legacy keychain. The
    item's ACL lets only the `kv` binary that saved it read it without the
    login password, so a new build asks for it once.
  - **Windows Hello**: wrapping key derived with HKDF-SHA256 (salt
    `kv-windows-hello-v1`, info `vault wrapping key`) from a
    `KeyCredentialManager` RSA signature over a random 32-byte challenge
    kept in the slot. PKCS#1 v1.5 signatures are deterministic, so the same
    credential and challenge give the same key.
- Layout: header (magic, format version, KDF params, list of wrapped keys),
  then nonce + AEAD ciphertext of the serialized secrets. A header with more
  than 8 wrapped keys, more than 2 passphrase keys, or KDF parameters above
  1 GiB of memory, 16 passes or 8 lanes is corrupt and refused before any
  key derivation. A wrapped key of a method (or device kind) this version
  does not know is kept on save and skipped on unlock, so a vault set up by
  a newer kv still opens with the passphrase; one with no method is corrupt.
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
which would let an agent bypass kv entirely. On macOS the Touch ID key is
readable without a prompt only by the `kv` binary that saved it, which reads
it only after a fingerprint. Code that loads itself into that binary (for
example with `DYLD_INSERT_LIBRARIES`, which binaries without the hardened
runtime honor) skips the fingerprint; that is the same-user process of the
threat model, which can attack the daemon the same way.

An agent can start a device prompt itself, by running `kv unlock` or `kv
tui` under a pseudo-terminal. Two things keep that from handing it the
vault: the client sends a device key only to a daemon running the same
program (the control socket's peer process, `LOCAL_PEERPID` and
`proc_pidpath` on macOS, `SO_PEERCRED` and `/proc/<pid>/exe` on Linux,
`GetNamedPipeServerProcessId` on Windows, against `current_exe`), so a
listener the agent put at the socket gets nothing; and each Touch ID prompt
names the change ("remove the handle prod-db from the kv vault", "open kv
tui, where you approve agent requests"), so the user can cancel one they did
not start. Windows Hello cannot show such text, and nothing ties its
credential to kv, so another program the user lets pass a Hello prompt can
derive the same key; the README says to cancel Hello prompts you did not
start and to prefer the passphrase where agents run unattended.

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
| `db_query` | handle, query (SQL or Redis command), timeout? | Postgres: one result per statement, values as text; Redis: the reply as JSON (scrubbed, capped at 256 KB) |
| `db_connect` | handle, ttl_secs? | loopback connection URL with a lease token, its lifetime, warnings |
| `exec` | handles[], argv[], cwd?, timeout? | exit code, stdout, stderr (scrubbed) |
| `request_handle` | name, kind, description?, reason?, header?/template?/query_param?, base_url?, allowed_hosts?, env_vars?, allowed_cmds? | confirmation that the request waits in `kv tui` |
| `status` | — | locked/unlocked, pending approvals |

`request_handle` lets an agent ask for a handle it lacks without ever
carrying a value: unknown arguments such as `token` are refused, and the
request type has no field for one. The daemon refuses a name that is invalid
or already a handle, and more than 4 hosts or a host that is not a plain-ASCII
`host` or `host:port` (so lookalike letters cannot pose as a known host). It
keeps at most 16 requests (asking again for a name replaces the earlier request
and is not announced again), cleans the agent's text as for approvals, and
drops fields that do not belong to the kind. Requests live in memory, survive
a lock, appear in `overview`, and leave when a handle with that name is added
or the user dismisses them (`dismiss_request`, audited). The TUI lists them
first on the Handles tab, selected by identity so rows arriving above never
move the cursor; `Enter` opens the New handle form filled in from the request
with mode `ask` and the focus on the secret field, and `x` dismisses. Requested
programs are a hint, not a prefilled policy, because one could be a shell. The
form scrolls by wrapped rows so the focused field is always in view.
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
  - One connection per query. Postgres uses the simple query protocol, so a
    query may hold several statements and every value comes back as text
    (`null` for NULL), one result per statement with its row count. Redis
    takes one command line, split as `redis-cli` splits it, and returns the
    reply as JSON (maps as `[key, value]` pairs; a number that matches a
    secret comes back as the scrubbed string).
  - The timeout defaults to 30 s and may be at most 300 s; Postgres also gets
    it as `statement_timeout`, so the server stops an abandoned query.
    Results are cut at 256 KB and marked `truncated`. One Postgres row is
    held in memory whole before it is cut; kv speaks RESP itself and reads a
    Redis reply only as far as the cap.
  - Commands that hold or change the connection (`SUBSCRIBE` and friends,
    `MONITOR`, `AUTH`, `HELLO`, `QUIT`, `RESET`, `SYNC`) are refused for every
    Redis handle. `#insecure` in a `rediss://` URL is refused, since kv always
    checks certificates.
  - TLS certificates are always verified against the platform trust store,
    whatever `sslmode` says (`sslmode=disable` still turns TLS off). A
    Postgres URL that names no `sslmode` and a host other than loopback or a
    Unix socket gets `sslmode=require`, since `prefer` can be downgraded to
    plain text by an attacker on the network.
  - Connection URLs must use `postgres://`/`postgresql://` or
    `redis://`/`rediss://`. Every host is scrubbed like the password unless it
    is loopback, and errors are scrubbed, since they can quote the query. A
    Postgres URL may list several hosts (`h1:5432,h2`) and name more in
    `host=` and `hostaddr=`, and a password in `password=`; kv reads all of
    them, though the `url` crate cannot parse such URLs.
- **`db_connect`**: starts a loopback proxy on a random port and returns e.g.
  `postgres://kv:<lease-token>@127.0.0.1:41823/app?sslmode=disable` (or
  `redis://kv:<lease-token>@127.0.0.1:41823/0`). The lease token is 256
  random bits, belongs to one lease and is compared in constant time. The
  proxy authenticates the client with the token (Postgres: a cleartext
  password over loopback, after answering `N` to TLS requests; Redis: `AUTH`
  or `HELLO ... AUTH`), connects upstream with the real credentials (TLS as
  for `db_query`; Postgres logs in with SCRAM-SHA-256, MD5 or a password),
  then relays traffic both ways, scrubbing what comes back. It is not a plain
  pass-through: every message from the server is scrubbed in place (Postgres
  row values, column names, error and notice fields, notifications,
  parameter values, command tags, COPY data; Redis strings, errors, and any
  number that matches a secret, which becomes a string).
  - The TTL defaults to 900 s and may be at most 3600 s. A lease ends at its
    expiry, when the vault locks, or when its handle is added, changed or
    removed (as grants do); its listener closes and its connections are cut
    (Postgres clients get `57P01`). The lease's place is taken when the
    request is authorized, so a lock while it waits for approval ends it too.
  - At most 16 leases are open at once (counting those waiting for
    approval), with at most 16 connections each. A client has 30 s to log in,
    and the server 20 s. Any single message larger than 16 MiB ends the
    connection, since each is held whole while it is scrubbed.
  - Leases follow the current scrubber, so a secret added while one is open
    is scrubbed from then on.
  - Postgres: the client must ask for the lease's database; `user` is
    ignored, replication connections and query cancellation are not passed
    on, and `_pq_.` protocol options are declined. Other startup parameters
    pass through.
  - Redis: commands must arrive as RESP arrays of strings. Replies are
    written in the order of the commands, with kv's own errors in their
    place; RESP3 push messages pass through. `AUTH`, `HELLO` with options,
    `RESET`, subscriptions, `MONITOR`, `CLIENT REPLY` and replication
    commands are refused on every lease.
  - Each connection is audited when it closes, with how it ended (`closed`,
    `wrong_token`, `policy_denied`, `lease_ended`, ...); the lease itself is
    audited like other requests.
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
  is forwarded, in `db_query` and through `db_connect`.
- **Postgres**: best effort. Sessions are opened with
  `default_transaction_read_only=on`, and statements that change it
  (`SET ... transaction_read_only`, `BEGIN READ WRITE`, `SET SESSION
  CHARACTERISTICS`) are rejected in the simple query protocol and in `db_query`.
  In `db_query` the check reads comments as spaces and keeps quoted text, and
  refuses any query mentioning `read_only`, `read write`, `characteristics`,
  `set_config`, `default_transaction` or `U&` escapes, and `DO` blocks, which
  can build such a statement at run time. It also refuses statements that end
  the transaction (`COMMIT`, `END`, `ROLLBACK`, `ABORT`, `PREPARE
  TRANSACTION`) and `CALL`: a function such as `query_to_xml` can run a
  `set_config` built from string pieces, which only takes effect in the next
  transaction. The checks run before approval.
  The real guarantee is a read-only role: kv checks the role's privileges
  (superuser; membership in `pg_write_server_files` or
  `pg_execute_server_program`; INSERT or UPDATE on any column, or DELETE or
  TRUNCATE, of any table, view or foreign table; or CREATE on any schema;
  outside the system schemas) when the secret is added and again on
  first use after each unlock, and warns in the `kv add` output, the query
  result and the TUI when a `read_only` secret uses a role with write access.
  `kv add` runs the check itself, with the URL it just read, so a slow
  database never holds up the daemon; `kv tui` relies on the first-use
  check. `db_connect` runs it before returning the URL and returns the
  warning with it.
- **Postgres through `db_connect`**: a session lasts many transactions, so
  the proxy also watches the server. It needs PostgreSQL 14 or later, which
  reports `default_transaction_read_only` at login and whenever it changes;
  a read-only lease on an older server is refused at login. The proxy:
  - adds `-c default_transaction_read_only=on` to the session's options and
    refuses startup parameters that mention a way to change it;
  - checks each simple query and each statement the client prepares as
    `db_query` does, except that a statement ending the transaction is
    allowed as the last one of a batch (a simple query, or the extended
    protocol up to `Sync`); `DO`, `CALL` and `PREPARE TRANSACTION` are
    refused, and so are fast-path function calls;
  - passes one batch on at a time, waiting for the server's
    `ReadyForQuery` before the next, and closes the session (`25006`) if the
    server reports `default_transaction_read_only` other than `on` or starts
    a COPY from the client. So a switch built at run time is caught before
    any later batch runs, and nothing can follow the transaction it was
    made in within the same batch.

## 5. Scrubbing, unlock, approval, audit, errors

### Scrubber

- Patterns: every unlocked secret value as raw, base64 (standard and URL-safe,
  at all three byte alignments), hex (lower and upper), URL-encoded and
  JSON-escaped. Connection URLs also contribute their password alone.
- One Aho-Corasick automaton over all patterns, rebuilt on unlock and on
  secret changes.
- Streaming: hold back `longest pattern − 1` bytes between chunks so secrets
  split across chunks are caught.
- Matches are replaced with `[kv:<handle>]`. Matching ignores ASCII case:
  host names are case-insensitive, and a secret in another case is still a
  secret.
- Values shorter than 8 characters are not scrubbed (false positives);
  `kv add` warns about them.

### Unlock

- `kv unlock` (or any control command) and, from Plan 4, `kv tui` prompt for
  the passphrase. From Plan 6, once `kv biometric enable` has added a slot
  for this platform's device, `kv unlock`, `add`, `rm`, `policy` and
  `biometric disable` ask Touch ID or Windows Hello first when stdin is a
  terminal, and fall back to the passphrase if the user cancels or the
  daemon turns the key down; `kv tui` asks at start and on Ctrl-T. The
  client asks the platform and sends the daemon the slot id and key in place
  of the passphrase (`DeviceCredential`), so the daemon never talks to the
  platform, and only to a daemon running the same program (section 3); a
  wrong key counts toward the unlock backoff like a wrong passphrase. The
  TUI shows the prompt on a thread of its own and keeps taking keys, so Esc
  still quits; a prompt unanswered for 120 seconds is cancelled. Enrolling a device and changing the passphrase always take the
  passphrase. `KV_BIOMETRIC=off` turns device unlock off. The daemon unwraps the vault key
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
  are drawn as dots. A read-only handle whose role can write is marked.
- Adding, changing or removing a handle ends its "allow for session" grants
  and its role check, and withdraws requests waiting on it, since they hold
  its old value and policy; the agent gets `policy_denied` saying the handle
  changed, and the request is audited as `withdrawn` / `handle_changed`.
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
  - Postgres and Redis on real servers (Linux CI only, as GitHub Actions
    service containers), including read-only enforcement, and `db_connect`
    leases driven by ordinary clients (`tokio-postgres`, `redis`). The tests read
    `KV_TEST_POSTGRES_URL` and `KV_TEST_REDIS_URL` and skip without them,
    unless `KV_REQUIRE_DB_TESTS` is set, as CI sets it; locally any server
    will do.
  - Security: agent socket rejects control messages; control messages without
    token rejected; unlock backoff; decoder fuzzing; approval timeout fails
    closed.
- **MCP end to end**: `rmcp` client drives `kv mcp`. Manual check with
  `claude mcp add kv -- kv mcp`.
- **CI**: GitHub Actions matrix (macOS, Ubuntu, Windows): `cargo fmt --check`,
  `cargo clippy -- -D warnings`, `cargo test`; `cargo check --locked` on the
  MSRV (1.89). Every action is pinned to a commit.
- **Manual per release**: Touch ID and Windows Hello unlock.

## 7. Distribution

`cargo install --path crates/kv`, or prebuilt binaries built by
`cargo-dist` (0.33) on GitHub Releases when a version tag (`v1.0.0`) is
pushed: macOS (arm64, x86_64), Linux (x86_64, arm64, glibc) and Windows
(x86_64, MSVC), with shell and PowerShell installers that put `kv` in
`~/.cargo/bin` and no updater. The binaries are not code-signed or
notarized; installers fetch with `curl`/`irm`, which macOS does not
quarantine.

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
