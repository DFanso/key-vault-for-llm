# Sharing a secret

When a colleague needs one of your secrets, or you need one of theirs, don't
paste it into Telegram or Slack, where anyone who gets into the chat can
read it. Let both agents pass it between the two vaults instead:

1. The person who needs it asks their agent. It calls `request_share` and
   gets a request code (`kv-request:v1:…`) to post in the chat. The code
   holds only a public key; the private half stays in their vault.
2. The person who has it asks their agent to answer. It calls `send_share`
   with the code and a handle, and kv waits for that person to approve on
   the Approvals tab, every time, whatever the handle's mode. Once they
   allow it, the agent gets a share (`kv-share:v1:…`) to post back: the
   handle's value, sealed so that only the requesting vault can open it
   (X25519, HKDF-SHA256 and XChaCha20-Poly1305).
3. The requester's agent calls `receive_share`. kv opens the share and saves
   it as a new handle. The agent sees the handle's name and policy, never
   the value.

A received handle starts in ask mode and keeps only the hosts, methods and
read-only setting it was sent with, never a `run` command or programs it may
be given to. Add those with Policy if it needs them. A share never replaces a
handle: pick another name if the suggested one is taken. Each request answers
one share and expires after 7 days.

kv refuses a share that sets environment variables which change how a program
runs or where it connects, such as `PATH`, `LD_PRELOAD`, `DYLD_*`,
`NODE_OPTIONS`, `GIT_SSH_COMMAND`, package-manager settings (`npm_config_*`,
`PIP_*`, `UV_*`) or `*_PROXY`: every program kv starts with the handle would
get them. It won't send a handle that sets them either. A handle you add
yourself may set them, with a warning. A handle kv saved from a share that
sets one, such as one received by an older kv, starts no program until you
take those variables out of it (Edit, then Remove variables, which needs none
of its values) or add it again as your own; forgetting the share on the
Shares tab doesn't change that.

kv also refuses a value, token or URL longer than 4096 bytes, an env handle
with more than 8 KiB of values, and a value that would take the whole vault
past what kv's output scrubber takes: about 256 KiB of ordinary tokens, less
of values full of punctuation, whose encodings it also looks for. A change
that makes the vault smaller always goes through. These limits are checked
whenever a value is saved (add, update, a share sent or received), not when
a vault is opened or a program starts, so a handle saved by an older kv keeps
working; you can only change its value to one within them.

You don't need an agent for any of it. The same three steps are buttons on the
Shares tab of kv's window, and each shows its code or share with a Copy
button, ready to paste into whatever chat you use:

1. **Request a secret** makes the request code. Say what you need and who you
   are if you like; both go in the code, which anyone in the chat can read.
2. **Send a secret**: paste their request code and pick a handle. kv seals it
   at once, without the Approvals tab, since you are the one asking. kv
   doesn't keep the sealed text, so copy it before you close the dialog. A
   handle set to deny can't be sent.
3. **Receive a share**: paste the share they sent back, and a name to save it
   under if the suggested one is taken.

Either side can use an agent or the window; the codes are the same.

The Shares tab also lists open requests (with their codes and a Copy button),
what you received and what you sent. **View** shows a received value as long
as the handle still holds what arrived, never a value you typed in yourself.
**Cancel request** throws away a request's key, so a share sealed to it can no
longer be opened.

Anyone who can read the chat can seal something to a request code, so kv
cannot tell who a share came from; the sender's name is whatever they typed.
Each request has a safety code such as `7KQ2-M9XD`, shown to both people: the
requester when the code is made, the sender on the approval or with the sealed
share. For anything sensitive, compare the two over a call or another channel
before you send the share or use the handle.

A share of a token, or of an env handle with a few variables, fits in one
chat message. When a share is longer than one Telegram message, kv says so:
send it as a text file rather than splitting it.

## Sharing the variables of a `.env` or settings file

To pass on what a project's `.env` or JSON settings file holds, import it
into a handle, then share that handle as above:

```sh
kv import .env                      # tick the variables to keep, then save
kv import appsettings.Development.json --name demo-app
kv import .env --keep API_TOKEN,DB_URL --yes
```

kv reads the file, lists the variables it found by name (never their
values) and saves the ones you tick as one env handle, in ask mode unless
you pass `--mode`. It asks for your passphrase or Touch ID as `kv add` does.
A JSON file's nested keys become names joined with `__`, as .NET reads them
(`ConnectionStrings__Db`).
Variables that change how a program runs or where it connects, such as
`PATH` or `NODE_OPTIONS`, start unticked; kv will not send them in a share
anyway. `kv import` notes what it skipped or could not read, such as `${VAR}`
references, which it keeps as written. In the window, **New handle**, then
**Import a .env or settings file**, does the same (on a Mac, press
Command-Shift-Period in the file panel to see `.env`).

Don't share a handle made from a settings file such as `appsettings.json`
yet. Besides secrets, those files set addresses (a database host, an API's
base URL), and kv cannot yet show the receiver a code for what a share
holds: someone who forges a share could point their app at a server of
theirs. The same goes for a `.env` variable that holds an address, such as
`DATABASE_URL`. Tokens and passwords are fine to share, with the safety code
checked as above.

## Sharing any file

A `file` handle keeps any file as it is, up to 1 MiB: a list of passwords, a
key, a certificate, a keystore. kv stores the bytes, never reads them as
text, and never shows them to an agent.

```sh
kv add passwords --kind file --file ./passwords.txt --cmd hydra --mode ask
```

A program uses the file through `exec`. List the handle with the others, and
put `{file:passwords}` in an argument where the file's path goes (or read the
path from `KV_FILE_PASSWORDS`). kv writes the file to a folder only you can
read, under its own name, and removes it when the program ends (if the
daemon stops first, the next one to start removes the folder once it is an
hour old). If the file is text, each line of eight characters or more is
scrubbed from the program's output like any other secret; a binary file is
not scrubbed, and `kv add` says so. A text file whose lines add up to more than the scrubber takes
(about 250 KiB of text) is refused for the same reason.

Sharing works as above, with two differences. The sealed share of a file is
too long for a chat message, so `send_share` saves it as a `.kvshare` file
and gives the agent its path to send as an attachment (with Telegram,
`telegram_send_file`). The person's agent passes the path it saved the
attachment to as `receive_share`'s `file`. The file is encrypted to the
receiver's vault and nobody else's, and it arrives byte for byte or not at
all: the share carries the file's SHA-256, which the receiver's kv checks
before saving, on top of the encryption refusing anything changed on the
way. Your approval names the file, its size and a short fingerprint, so you
can read it out to the receiver to confirm it is the same one. A received
file starts in ask mode, like any share.

The window does the same without the terminal. On the Handles screen, **New
handle** and then **Give a program a file** picks a file and asks for a name
and the programs that may use it. When
you send a file on the Shares screen, kv saves the sealed share as a
`.kvshare` file in your Downloads folder and offers **Show in folder**; to
receive one, choose it with **Choose a .kvshare file** in the Receive dialog.
The download icon beside a received file saves it to Downloads exactly as it
arrived, under a name that is safe to create, and never over a file already
there.
