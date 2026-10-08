# key-vault-for-llm

A local secrets broker for AI coding agents. Agents get named handles to
secrets (`prod-db`, `openrouter`, `github`) and the broker does the
authenticated work, so API keys, database URLs and other credentials never
show up in a chat transcript or in the model's context.

Status: design phase.

## Planned for v1

- HTTP API proxy that adds auth headers for allow-listed hosts
- Local database proxy (Postgres, Redis) that connects upstream with the real
  credentials, with optional read-only enforcement
- Running CLI tools with secrets injected as env vars, with output scrubbed
- Exposed to agents over MCP

Single-user, macOS first, written in Rust.
