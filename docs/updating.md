# Updating kv

```sh
kv update --check             # say whether a newer kv is out, install nothing
kv update                     # show the release notes, ask, then install
kv update --yes               # answer yes when there is no terminal to ask on
```

`kv update` shows a link to the release notes and asks `Update to kv X.Y.Z?
[y/N]` before it installs anything. When stdin is not a terminal (a script, for
example) there is nothing to ask on, so it refuses unless you pass `--yes`,
which answers yes for you. Updating locks the vault and stops anything agents
have running now: waiting approvals, programs, MCP servers and database
connections. When it finishes it says
`Updated to kv X.Y.Z. Unlock to continue.`

kv looks for a new release on its own, only in a build installed from a
release:

- The tray checks 3 minutes after it starts and then every 12 hours. It tells
  you with a notification and an `Update to kv X.Y.Z…` item in its menu.
- `kv status` and `kv tui` ask GitHub at most once a day, and only when the
  tray is not running. Once a newer kv is known, every run prints
  ``kv X.Y.Z is out: run `kv update`.`` until you update.

To turn these off, set `KV_UPDATE_CHECK=off`:

- For `kv status` and `kv tui`, set it in your shell profile.
- A tray started at login does not see your shell profile. On macOS, run
  `KV_UPDATE_CHECK=off kv tray --login on` to carry it into the login item.
  On Windows, set it as a user environment variable with
  `setx KV_UPDATE_CHECK off`, which covers both.

`kv update` and `kv update --check` still check when you run them.

On macOS and Windows, `kv update` will not run while the tray is running. It
points you to the tray's menu instead, so the tray restarts on the new
version. On Linux there is no tray; `kv update` installs directly.

kv trusts the latest release on GitHub (`DFanso/key-vault-for-llm`) and
nothing else: no setting changes where it looks. It downloads the archive for
your platform, checks its sha256 against the `.sha256` file published beside
it, and only installs a version newer than the one you have. It never installs
without asking, and a pre-release is never offered.

After an update the vault is locked, so run `kv unlock`. On macOS, the new
kv binary can no longer read the Touch ID key until you allow it once; see
[Touch ID and Windows Hello](touch-id.md) and choose Always
Allow.

## Upgrading from 1.9.4 or earlier

An agent's call that finds the vault locked now waits up to 30 seconds for
you to unlock it, after a notification saying so, instead of failing at
once. Set `KV_UNLOCK_WAIT=off` (and run `kv stop`) to keep the old behaviour;
see [When something waits on you](approvals.md#when-something-waits-on-you).

## Upgrading from 1.9.0 or earlier

1.9.1 fixes a security issue
([GHSA-xcr2-9r88-r8f2](https://github.com/DFanso/key-vault-for-llm/security/advisories/GHSA-xcr2-9r88-r8f2)):
kv's clients now check that the process at the daemon's socket is the kv
daemon for your vault before they send it anything secret. `kv update` stops
the old daemon for you. If you installed 1.9.1 another way (the installer
script, `cargo install`) while an older daemon was still running, commands
that unlock or use the vault refuse to talk to it:

```text
kv: the process at the kv socket (...) is not this kv's daemon: ...; kv sent it nothing. If it is an older kv, run `kv stop`, otherwise stop that process, and try again
```

Run `kv stop` (it still works with an old daemon) and try again; the next
command starts the new daemon. You see the same refusal, for the same
reason, when the daemon was started from a different kv binary than the one
you run, such as a second install elsewhere on your PATH. If `kv stop` does
not clear it, something else is holding the socket: find and stop that
process rather than working around the message.

The old kv is kept so you can go back by hand. On macOS and Linux it is
`kv.previous`, next to `kv`. To go back, stop kv and move the old file over
`kv` (if `kv` is a link, use the folder of the file it points to):

```sh
kv stop
mv /path/to/kv.previous /path/to/kv
```

On Windows it is `kv.exe.old`, next to `kv.exe`. If a `kv.exe.old` from an
earlier update is still running (an agent session's `kv mcp` started before
that update, say), Windows will not let kv remove it, so the old kv is kept
under the first free numbered name instead: `kv.exe.1.old`, then
`kv.exe.2.old`, and so on. The number is the first one free, not a count, so
it does not tell you which file is newest: use the file named in kv's message
about the update. kv removes all of them once the new kv has worked: after a
kv command succeeds, or the tray has started. So they are the way back when
the new kv does not work.

To go back, first close every kv that is running: quit kv tray and close the
agent sessions, since each runs its own `kv mcp`. Windows will not replace
`kv.exe` while a kv runs from it. The update already stopped the daemon. Then,
in PowerShell, move the old file over `kv.exe`, with the name the update kept
it under:

```powershell
Move-Item -Force C:\path\to\kv.exe.old C:\path\to\kv.exe
```

A kv built from source (`cargo install`, `cargo build`) does not update
itself: `kv update` tells you to install from a release instead. Update it by
building again.
