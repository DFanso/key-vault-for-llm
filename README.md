# key-vault-for-llm

A local secrets broker for AI coding agents. Agents get named handles to
secrets (`prod-db`, `openrouter`, `github`) and the broker does the
authenticated work, so API keys, database URLs and other credentials never
show up in a chat transcript or in the model's context.

Status: agents can make HTTP requests and run programs with your secrets over
MCP. Approval prompts (`--mode ask`) arrive with `kv tui`; until then only
handles set to `--mode auto` can be used. Database access comes after that.

## Setup

```sh
cargo install --path crates/kv

kv init                       # create the vault and choose a passphrase
kv add openrouter --kind http --host openrouter.ai --mode auto
kv add aws --kind env --var AWS_ACCESS_KEY_ID --var AWS_SECRET_ACCESS_KEY \
  --cmd terraform --mode auto

claude mcp add kv -- kv mcp   # or add `kv mcp` as a stdio server in any MCP client
```

The agent then sees four tools:

- `list_handles`: names, kinds and policies, never values.
- `http_request`: sends a request with the handle's credential attached.
- `exec`: runs a program (never a shell) with an `env` handle's variables set.
- `status`: whether the vault is unlocked.

Wherever a secret would appear in a response or in program output, the agent
sees `[kv:<handle>]` instead, including base64, hex, URL-encoded and
JSON-escaped forms.

### Keeping a service's address hidden

For self-hosted services such as Dokploy, the address can be as sensitive as
the key. Add the handle with `--base-url` and kv prompts for it; the agent
then sends only paths such as `/project.all`, and the address is scrubbed
from everything it gets back:

```sh
kv add dokploy --kind http --base-url --header x-api-key --template '{}' --mode auto
```

## Day to day

```sh
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

`exec` looks bare program names up on the PATH the daemon started with,
skipping relative entries. Anything that can write to a directory on that
PATH can stand in for the program, so for the strongest guarantee list
programs by absolute path (`--cmd /usr/local/bin/terraform`).

Set `KV_HOME` to keep the vault, audit log and sockets in one directory
instead of the platform defaults. Every use of a handle is recorded in the
audit log (`audit.jsonl`), without values.

## Planned for v1

- `kv tui`: approval prompts for `--mode ask` handles, editing and the audit
  log in a terminal UI
- Local database proxy (Postgres, Redis) that connects upstream with the real
  credentials, with optional read-only enforcement
- Touch ID and Windows Hello unlock, and prebuilt binaries

## What kv protects against

kv keeps secrets out of the model's context and transcripts, and limits what
an agent can do with a handle through per-secret policy and approvals. It is
not a sandbox: a malicious process running as your own user can still attack
it (for example by reading process memory on platforms that allow it). A
program you let a handle run does receive the secret.

Single-user, for macOS, Linux and Windows, written in Rust.
