# Security model

kv keeps secrets out of the model's context and transcripts, and limits what
an agent can do with a handle through per-handle policy and approvals. It
assumes the agent runs as you, on your machine, and can run commands. It is
not a sandbox.

What kv does:

- No tool returns a secret or takes one. Values appear in results only as
  `[kv:<handle>]`, and every command that changes the vault asks for the
  passphrase (or Touch ID or Windows Hello), or runs inside an unlocked
  `kv tui`.
- The vault file is encrypted with XChaCha20-Poly1305 under a key derived
  from your passphrase with Argon2id. While unlocked, the daemon holds the
  key in memory it locks against swapping (best effort) and keeps out of core
  dumps. On Linux it also makes itself non-dumpable, so other processes of
  your user cannot read its memory through `/proc` or attach a debugger to
  it.
- kv's clients (the CLI, `kv tui` and `kv tray`) send the passphrase,
  session tokens, Touch ID or Windows Hello keys and secret values only to the
  kv daemon for your own vault. Before sending, they check that the process
  at the socket runs as you and runs the same `kv` program. On Linux and
  macOS they also check that it runs as the daemon for your runtime
  directory and is the process actually serving the connection. A process
  that takes the daemon's socket first, or puts its own in place of it, gets
  nothing.

What it cannot stop. These all need a process already running as you, and
some need more than that:

- A program you let a handle run receives the secret. That is the point of
  `exec` and `run`, so allow only programs you trust.
- Code running inside a real kv daemon can do what the daemon does. On
  Linux that takes only `LD_PRELOAD`. On macOS, release binaries from 1.9.2
  on are signed (ad hoc) with the hardened runtime, so macOS ignores
  `DYLD_INSERT_LIBRARIES` for them and refuses to let a debugger attach. A kv
  you build yourself is not signed that way unless you do it:
  `codesign --force --options runtime --sign - "$(command -v kv)"`.
- kv's binary sits in a folder you can write to (`~/.cargo/bin` by
  default), so a process running as you could replace it. An ad hoc
  signature names no developer, so nothing checks who built the kv that
  runs.
- On Linux, a process can start a real kv daemon as its own traced child and
  control it, which the default `kernel.yama.ptrace_scope=1` allows. With
  `ptrace_scope` 0, any process of yours can attach to `kv tui` and read the
  passphrase as you type it. Where agents run unattended, set it to 2, which
  leaves debugging other processes to root (so `gdb -p` and `strace -p` then
  need `sudo`):

  ```sh
  echo 'kernel.yama.ptrace_scope = 2' | sudo tee /etc/sysctl.d/60-kv-ptrace.conf
  sudo sysctl --system
  ```

- On Windows, kv checks the program of the process that created the
  daemon's pipe. A determined process of yours could arrange for that
  process id to be reused by a kv process, so the check is weaker there than
  on Linux and macOS.
- An unlocked `kv tui` or `kv tray` answers requests for whoever drives it. A
  program running as you that can control other programs' windows can type
  into the TUI or click Allow in the tray's menu, window or notifications: on
  macOS only programs you have given the Accessibility permission, on Windows
  any program at the same integrity level. Lock the vault, or quit both, when
  agents run unattended.
- While kv's window shows a value, a program you have given the Screen
  Recording or Accessibility permission can read it off the screen, and while
  a copied value is on the clipboard any program can read it.

If kv refuses to talk to the process at its socket and `kv stop` does not
clear it, find out what that process is before you do anything else.

To report a security problem, use GitHub's private reporting (the Security
tab, then Report a vulnerability) rather than a public issue.
