# key-vault-for-llm

A local secrets broker for AI coding agents. Agents get named handles to
secrets (`prod-db`, `openrouter`, `github`) and the broker does the
authenticated work, so API keys, database URLs and other credentials never
show up in a chat transcript or in the model's context.

Status: the vault, daemon and CLI work. Agents cannot use handles yet; the MCP
server, HTTP requests and secret-injecting `exec` come next.

## What works today

```sh
cargo install --path crates/kv

kv init                       # create the vault and choose a passphrase
kv add openrouter --kind http --host openrouter.ai --mode auto
kv add prod-db --kind postgres --read-only true
kv add aws --kind env --var AWS_ACCESS_KEY_ID --var AWS_SECRET_ACCESS_KEY --cmd terraform
kv list                       # names and policies, never values
kv policy openrouter --method GET --method POST
kv lock                       # agents get "vault locked" until you unlock
kv unlock
kv passwd                     # also rotates the vault key
kv stop                       # lock and stop the daemon
```

Secret values and passphrases are read from a hidden prompt, or one per line
from stdin when stdin is not a terminal. They are never taken as command-line
arguments, where they would end up in shell history.

Every command that changes the vault asks for the passphrase, so an agent
running commands as you cannot add, remove or loosen secrets. The vault locks
itself after 8 hours without use. To change that, set `KV_IDLE_LOCK=2h` (any
duration) in your shell profile and run `kv stop` so the next command picks it
up.

Set `KV_HOME` to keep the vault, audit log and sockets in one directory
instead of the platform defaults.

## Planned for v1

- HTTP API proxy that adds auth headers for allow-listed hosts
- Local database proxy (Postgres, Redis) that connects upstream with the real
  credentials, with optional read-only enforcement
- Running CLI tools with secrets injected as env vars, with output scrubbed
- Exposed to agents over MCP

## What kv protects against

kv keeps secrets out of the model's context and transcripts, and limits what
an agent can do with a handle through per-secret policy and approvals. It is
not a sandbox: a malicious process running as your own user can still attack
it (for example by reading process memory on platforms that allow it).

Single-user, for macOS, Linux and Windows, written in Rust.
