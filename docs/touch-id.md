# Touch ID and Windows Hello

```sh
kv biometric enable           # asks for the passphrase, then a fingerprint or Hello
kv biometric disable
```

Once it is on, `kv unlock`, `kv add`, `kv rm`, `kv policy` and `kv tui` ask
for a fingerprint or Hello instead of the passphrase (Ctrl-T asks again on
the TUI's unlock screen). Cancel the prompt to type the passphrase instead;
commands that read stdin from a pipe always read the passphrase. `kv status`
says which is on. `kv passwd` turns it off, since the new vault key has no
copy for the device; run `kv biometric enable` again. Adding or removing a
fingerprint on the Mac also turns Touch ID off until you enable it again.

kv keeps the Touch ID key in your login keychain, where only the `kv` binary
that saved it can read it without your login password. After you install a
new kv, macOS asks for that password once; choose Always Allow. Set
`KV_BIOMETRIC=off` to never use either method.

An agent running commands as you can start a prompt too, by running one of
these commands itself. The Touch ID prompt says what kv is trying to do,
such as "remove the handle prod-db from the kv vault" or "open kv tui, where
you approve agent requests": cancel any you did not start. kv sends the key,
like the passphrase, only to the kv daemon for your own vault (see
[Security model](security.md)). Windows Hello's dialog
cannot say what it is for, and Windows does not keep other programs from
using kv's Hello credential, so a Hello prompt you approve for another
program can give it a lasting key to the vault. On Windows, cancel every
Hello prompt you did not start, and keep using the passphrase where agents
run unattended.
