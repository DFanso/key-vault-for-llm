# kv tray: approve agent requests from the menu bar — design

Date: 2026-10-12
Status: implemented on feat/tray

## 1. Goal

Answer `--mode ask` requests without opening a terminal. Today they wait in
`kv tui` for up to 60 seconds, with a desktop notification to say one
arrived; if `kv tui` is not open and unlocked, the request times out. A
status icon in the macOS menu bar and the Windows notification area shows
how many requests are waiting and lets the user allow or deny each from its
menu.

Success means:

- With `kv tray` running and the vault unlocked in it, every waiting request
  appears in the menu within about a second, and choosing Allow once, Allow
  for this session, Deny, or Deny and block answers it exactly as the same
  key does in `kv tui`.
- The icon shows locked, unlocked, or a waiting count without any unlock,
  so it is right before the user has unlocked the tray.
- The tray unlocks only with Touch ID or Windows Hello. The passphrase is
  never typed into it.
- `kv tray --login on` makes it start at login; `--login off` undoes that.

The main design (`2026-10-08-kv-llm-secrets-broker-design.md`) is the
authority for sessions, approvals, device unlock and the threat model; this
document adds a client, not new daemon behaviour.

## 2. Decisions

- **Inside the `kv` binary, as `kv tray`.** Built with `tray-icon` (0.26),
  `muda` (0.21) and `tao` (0.37), the crates Tauri uses, so the tray reuses
  the TUI's daemon client, device unlock and peer check rather than
  reimplementing them in Swift and C#. Built for macOS and Windows only;
  on Linux `kv tray` says the platform has no tray support.
- **MSRV rises from 1.89 to 1.90**, which `tray-icon` 0.26 and `muda` 0.21
  need. CI's `msrv` job and the README badge move with it.
- **Answers from the menu.** Each waiting request is a menu entry whose
  submenu shows what it asked for and offers the four answers the TUI's
  Approvals tab offers (`a`, `s`, `d`, `D`). "Allow for this session" is shown
  only when the request can be granted (`Approval.can_grant`).
- **Touch ID or Windows Hello only.** Unlocking opens a control session with
  a device credential (main design, section 5 "Unlock"). Without a device
  slot for this platform the menu offers "Unlock in kv tui" instead, which
  opens a terminal running `kv tui`. No password field: a passphrase is only
  ever typed into a terminal.
- **Started by the user.** `kv tray` runs it; `kv tray --login on|off` adds or
  removes a login item. Neither the daemon nor `kv mcp` ever starts it.
- **One tray at a time**, enforced with a lock file next to the daemon's.
- **No new daemon commands.** The tray uses `Status` (agent socket, no
  session), `OpenSession`, `Overview`, `Decide` and `Lock`, as `kv tui` does.

## 3. What the user sees

### Icon

| State | macOS menu bar | Windows notification area |
|-------|----------------|---------------------------|
| Daemon not running, or no vault | grey icon | grey icon, tooltip "kv: not running" or "kv: no vault yet" |
| Locked | grey icon | grey icon, tooltip "kv: locked" |
| Unlocked, nothing waiting | normal icon | normal icon, tooltip "kv: unlocked" |
| N requests waiting | normal icon and the title "N" | badge icon, tooltip "kv: N requests waiting" |

The count comes from `Status.pending_approvals`, which needs no session, so
a locked tray still shows that something is waiting. Status reads never
start the daemon (a new `client::agent_if_running`, like
`control_if_running`), so a tray left running does not keep a daemon alive
or start one after `kv stop`; only Unlock starts it.

Icons are drawn as small RGBA images in code (a key shape, a grey variant,
and a badge variant), so the binary carries no image files. On macOS the
icon is a template image so it follows the menu bar's light or dark style.

### Menu when the tray has no session

- "Unlock with Touch ID" (macOS) or "Unlock with Windows Hello" when the
  vault has a slot for this platform's device; otherwise "Unlock in kv tui".
- "Open kv tui"
- "Start at login" (checkbox, mirrors the login item)
- "Quit kv tray"

When the daemon is not running the unlock item reads "Unlock with Touch ID"
still: unlocking starts the daemon, as every client does.

### Menu when the tray has a session

- One entry per waiting request, oldest first, labelled
  `<client> · <tool> · <handles>` (for example
  `claude-code · http_request · openrouter`), "agent" when the client gave no
  name. Its submenu:
  - the request's detail (`Approval.detail`) and, when present, its working
    directory, as disabled items;
  - "Expires in Ns", refreshed with the menu;
  - "Allow once", "Allow for this session" (only if `can_grant`), "Deny",
    "Deny and block <handles>".
- "No requests waiting" (disabled) when there are none.
- "N handle requests: open kv tui" when agents have asked for handles
  (`Overview.handle_requests`); it opens `kv tui`, where they are answered.
- "Lock vault"
- "Open kv tui"
- "Start at login"
- "Quit kv tray"

When the daemon has no vault yet, the menu says "No vault yet: run `kv init`"
in place of the unlock item.

The menu is replaced only when its items change. When only the countdowns
("Expires in Ns") change, their text is updated in place, so a menu the user
has open is not swapped for a new one every second.

Labels are made single-line (control characters and line breaks become
spaces, runs of whitespace collapse) and cut to 60 characters with "…";
detail lines are cut to 100. The daemon has already made agent text safe to
show (main design, section 5 "Approval"); the tray only shortens it.

## 4. Architecture

New module `crates/kv/src/tray/`, compiled on macOS and Windows:

- **`model`** — pure state. `Model::new(View { status, overview, device,
  login })` gives the icon state, the tooltip and title, and the menu as a
  list of `Item`s (actions, the login checkbox, disabled text lines,
  separators, and a submenu per request). Item ids are derived from the
  action (`decide:<approval id>:<verdict>`, `unlock`, `lock`, `tui`,
  `handle-requests`, `login:on`, `login:off`, `quit`), so a click maps back
  to the same request and answer however the list moved. No UI or daemon
  code; unit-tested.
- **`ui`** — the main thread. Runs the `tao` event loop (macOS requires the
  status item on the main thread), owns the `TrayIcon` and the `muda` menu,
  rebuilds the menu when a new `Model` arrives through the event loop's
  proxy, and sends each click's `Action` to the worker. The only part that
  touches platform UI; not unit-tested.
- **`worker`** — a tokio runtime on a background thread. Holds a
  `tui::Driver` (session token, device, daemon client) and loops:
  1. every second, read `Status` from the agent socket without starting the
     daemon and, with a session, `Overview` through the driver; build a
     `Model`; send it to the UI;
  2. on an `Action` from the UI, carry it out:
     - `Unlock`: `Driver::ask_device`, then `finish_device`; the device
       prompt reads "open kv tray, where you approve agent requests";
     - `Decide(id, verdict)`: `ControlCommand::Decide` through the driver;
     - `Lock`: the driver's lock, which also drops the session;
     - `OpenTui`: open a terminal running `<current exe> tui` (macOS:
       `osascript` telling Terminal to `do script`; Windows: `cmd /c start`,
       which opens the user's default terminal, Windows Terminal included);
     - `Login(on)`: `login::set(on)`;
     - `Quit`: end the loop and the event loop.
- **`login`** — the login item.
  - macOS: `~/Library/LaunchAgents/dev.dfanso.kv.tray.plist` with
    `ProgramArguments` = [current exe, `tray`], `RunAtLoad` true,
    `ProcessType` `Interactive`. `--login off` deletes it. kv does not call
    `launchctl`; the item takes effect at the next login, and the current
    tray keeps running.
  - Windows: the value `kv tray` under
    `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, set to
    `"<current exe>" tray`; `--login off` deletes it.
  - `is_on()` reads the same place, for the checkbox.
  - `kv tray --login on|off` changes the item, prints what it did and exits;
    it does not start a tray.
  - Started from the Run key, Windows gives `kv.exe` (a console program) a
    console window of its own. The tray frees a console no other process
    shares, so only a brief flash remains at login; started from a terminal
    it keeps that terminal's console.

`Driver::with_device`, `ask_device`, `finish_device` and the `DEVICE_REASON`
constant become parameters where the tray needs a different prompt text:
`Driver::with_device(paths, device)` gains a `reason: &'static str` field
set by a builder method, defaulting to the TUI's text.

### Single instance

`kv tray` takes an exclusive lock on `Paths::tray_lock_file()`
(`<runtime dir>/tray.lock`) with `File::try_lock`, as the daemon does with
`daemon.lock`, and exits with "kv tray is already running" when it cannot.

## 5. Errors

A native menu cannot show a message, so failures become desktop
notifications through `notify-rust`, which kv already uses:

- a decision on a request that is no longer waiting: "That request is no
  longer waiting";
- a device prompt cancelled or refused: the device's reason, as `kv tui`
  shows it;
- a daemon that stopped: the session ends and the menu returns to the
  locked state; the icon shows "not running" until the next status read
  succeeds;
- an unexpected reply: the reply's message.

The worker never panics on a daemon reply; a model it cannot build is
replaced by the locked model.

## 6. Security

- **The session lives only in the tray's memory**, as in `kv tui`, and ends
  when the vault locks: `kv lock`, the idle lock, "Lock vault", or the daemon
  stopping.
- **Unlock goes through the existing device path**: the device key is sent
  only to a daemon running this same program (main design, section 3), and
  the Touch ID prompt names the tray, so a prompt the user did not start
  says so.
- **Decisions name the request id**, never a position. A click on a request
  that has gone is refused by the daemon. A menu rebuilt while open cannot
  move a click onto another request because every item's id encodes its
  request.
- **Same exposure as `kv tui`.** A program running as the user that can
  drive other programs' UI can open the menu and click Allow, just as it
  can type into a terminal running an unlocked `kv tui`. On macOS that needs
  the Accessibility permission for the program doing it; on Windows any
  program at the same integrity level can. The README's "What kv protects
  against" says so.
- **The tray shows nothing the TUI does not**: no secret values, only the
  daemon's already-made-safe request text.

## 7. Testing

- `model` unit tests (`crates/kv/tests/tray_model.rs`, the module made
  public like `tui::app`): icon state and tooltip for not running, locked,
  idle and waiting; the locked menu with and without a device slot; one
  entry per request, oldest first, with "Allow for this session" only when
  `can_grant`; label shortening (line breaks, control characters, 60/100
  character cuts); item ids mapping back to the right request and verdict;
  the login checkbox state.
- `worker` tests (`crates/kv/tests/tray_worker.rs`) against a daemon running
  in the test process with the fake device from `tests/fake`: unlocking
  yields the unlocked model; allowing a waiting request lets the agent's
  call return 200; denying returns the agent's denial; locking elsewhere
  returns the model to locked; a decision on a request that has gone becomes
  a notification-worthy error. The worker takes a `Desktop` trait
  (notifications, opening `kv tui`, the login item) so tests record what it
  asked for instead of doing it.
- `login` tests on macOS: `set(true)` writes the plist under a temporary
  home with the current exe and `tray`, `is_on()` sees it, `set(false)`
  removes it. The Windows registry code is compiled by CI on windows-latest.
- Manual checks before release: the icon and menu on macOS (light and dark
  menu bar) and Windows; a Touch ID and a Hello prompt from the tray;
  answering a real request from the menu; the login item after logging out
  and in; "Open kv tui" opening a terminal; a second `kv tray` refusing to
  start.

## 8. Out of scope

- Linux trays (AppIndicator, StatusNotifierItem).
- Answering handle requests (`request_handle`) from the tray; the menu only
  points to `kv tui` for them (section 3).
- Editing handles or policies from the tray.
- A passphrase dialog in the tray.
- Code signing or a `.app` bundle; `kv tray` runs as the plain `kv` binary.
