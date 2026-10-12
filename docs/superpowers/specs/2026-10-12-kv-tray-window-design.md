# kv tray window: unlock and manage kv without the TUI — design

Date: 2026-10-12
Status: implemented on feat/tray-window

## 1. Goal

`kv tray` (`2026-10-12-kv-tray-design.md`) answers agent requests from its
menu, but leans on `kv tui` for everything else: unlocking with the
passphrase, agents' handle requests, and editing handles. This change gives
the tray a window of its own, so the tray works without `kv tui`:

- The tray unlocks the vault itself: Touch ID or Windows Hello first, and
  the passphrase typed into kv's window when there is no device slot or the
  prompt is cancelled.
- "Open kv…" in the menu opens a window with three tabs, as `kv tui` has:
  Approvals, Handles and Audit, with the same actions.
- The tray never starts `kv tui`. `kv tui` stays for terminal users.

Success means a user who never opens a terminal after `kv init` can unlock,
answer requests, fill in agents' handle requests, add, edit, re-police and
remove handles, read the audit log, and lock, all from the tray.

The tray spec stays the authority for the icon, the menu's quick answers,
the worker and the login item; this document changes only what it says
below. The main design (`2026-10-08-kv-llm-secrets-broker-design.md`)
stays the authority for sessions, approvals, device unlock and the threat
model. No daemon command or protocol message is added.

## 2. Decisions

- **A webview window (wry 0.57)** on the tray's existing tao event loop:
  the system's web engine (WKWebView on macOS, WebView2 on Windows) draws
  one built-in HTML page. Chosen over egui (its own event loop, a custom
  look) and native AppKit/Win32 code (the UI twice).
- **The passphrase may now be typed into kv's window.** This reverses the
  tray spec's "no password field". Touch ID or Hello is still tried first;
  the window is the fallback.
- **The menu keeps its quick answers** and gains "Open kv…". The window
  never opens by itself; a waiting request still shows a notification.
- **One session for the menu and the window**, held by the worker's
  `tui::Driver`.
- **The TUI's forms are shared, not copied.** `tui::edit` and `tui::form`'s
  data model move to `kv::forms`, used by the TUI and the window, so both
  validate a handle the same way.
- **macOS and Windows only**, like the tray.

## 3. What the user sees

### Menu changes

- "Unlock in kv tui" becomes "Unlock…", which opens the window on its
  unlock screen.
- "Open kv tui" becomes "Open kv…", which opens the window (on the unlock
  screen while locked, on the Approvals tab while unlocked).
- "N handle requests: open kv tui" becomes "N handle requests: open kv…",
  which opens the window on the Handles tab.
- "Unlock with Touch ID" / "Unlock with Windows Hello", the quick answers,
  "Lock vault", "Start at login" and "Quit kv tray" are unchanged.
- When the window is already open, these items bring it to the front and
  switch its screen or tab.

### The window

One window, about 760×520 points, resizable, titled "kv", following the
system's light or dark appearance. Closing it destroys the window; the tray
keeps running and the session stays open. Only Lock (window or menu), the
idle lock, `kv lock`, or the daemon stopping ends the session.

**Unlock screen** (whenever there is no session):

- With a device slot for this platform, opening the window starts the
  device prompt at once and shows "Waiting for Touch ID…" ("…for Windows
  Hello…"). If the prompt fails or is cancelled, the screen shows the
  reason and the passphrase field; "Use Touch ID" asks again.
- Without a slot, the passphrase field is shown at once.
- Enter submits the passphrase. The page clears the field as soon as it
  sends it, whatever the result. The daemon's answer (wrong passphrase,
  the backoff wait, no vault yet: run `kv init`) shows under the field.

**Header** (with a session): "Unlocked · locks in 7h 52m" from
`Status.locks_in_secs`, and a Lock button.

**Approvals tab**, labelled "Approvals (N)" while requests wait:

- One card per waiting request, oldest first: the agent (or "agent"), the
  tool, the handles, the full detail and working directory as the daemon
  gives them (wrapped, not cut), and "Expires in Ns".
- Buttons: Allow once, Allow for this session (only when `can_grant`),
  Deny, Deny and block <handles>. Each acts on the card's request id.
- A request that stopped waiting disappears on the next refresh; a click on
  it in the meantime shows the daemon's "no longer waiting" message on the
  card.
- "No requests waiting" when there are none.

**Handles tab**:

- Agents' handle requests first, each with what it asked for, "Fill in"
  and "Dismiss". "Fill in" opens the New handle form filled in from the
  request with the secret field focused, as `kv tui` does.
- A table of handles: name, kind, mode, hosts or commands, and the role
  warning for a read-only handle whose role can write.
- Add, Edit (description or a new value), Policy, and Remove (after a
  confirm inside the page).
- Forms are the shared `kv::forms` forms, drawn from their field
  descriptions: text fields, password fields for secrets, select menus for
  choices, fields shown or hidden by the same conditions as in the TUI, the
  same hints. A blank secret field in an edit keeps the old value. Rust
  validates; its error shows beside the form. A saved form closes and its
  inputs are wiped.

**Audit tab**: the newest 200 entries of the audit log, newest first, read
by the worker while this tab is the one shown.

**Ending a session** takes the window back to the unlock screen and drops
any open form and what was typed into it.

**Keyboard**: Tab between fields, Enter submits, Esc closes a form. No
single-letter shortcuts.

## 4. Architecture

All in the `kv tray` process.

- **`kv::forms`** (moved from `tui::edit` and the data part of `tui::form`):
  the form builders (`new_handle`, `requested_handle`, `edit_handle`,
  `edit_policy`), `Purpose`, `submit(&Purpose, &Form) -> Result<Effect,
  String>`, plus two new functions for the window: `describe(&Form) ->
  FormView` (serializable: title, fields with key, label, kind, options,
  condition, hint, and the text of non-secret fields only) and
  `fill(&mut Form, values)` (sets each field the page sent, ignoring keys
  the form does not have). `tui::form` keeps the key handling and drawing.
- **`tray::window`** (pure, all platforms): the page protocol.
  - `FromPage` (serde, tagged): `Ready` (the page has loaded),
    `Unlock { passphrase }`, `DeviceUnlock`, `Decide { id, verdict }`,
    `OpenForm { form }` where `form` is `New`, `Request { id }`,
    `Edit { name }` or `Policy { name }`, `SubmitForm { values }`,
    `CloseForm`, `Dismiss { id }`, `Remove { name }`, `Lock`,
    `Tab { tab }`.
  - `ToPage` (serde, tagged): `State { locked, device, waiting_for_device,
    overview }`, `Form { view }`, `FormError { message }`, `FormDone`,
    `Audit { entries }`, `Message { text, request }` (`request` names the
    card it belongs on), `Show { tab }`. The unlock screen is not a tab:
    the page shows it whenever `State.locked` is true.
  - Passphrases and secret values arrive as plain strings and are turned
    into `SecretText` before anything else touches them.
- **`tray::worker`** gains the window's state: whether it is open, its
  active tab, the open form and its `Purpose`, and who is waiting on a
  device prompt. The menu's `OpenTui` and `HandleRequests` become
  `Action::Open(Tab)`, and `Action` gains `Window(FromPage)` and
  `WindowClosed`. Its `Desktop` swaps `open_tui` for `show_window(Tab)` and
  `page(ToPage)`. Every tick it sends the menu's `Model` as today and,
  while the window is open, a `State` (and `Audit` on the Audit tab).
- **`tray::ui`** creates the wry `WebView` in a tao window when the worker
  asks to show the window, raises it if it exists, serves the page under the custom
  protocol `kv`, forwards IPC strings to the worker as `FromPage` (dropping
  any that do not parse or that come from another URL), and runs
  `kv.receive(<json>)` for each `ToPage`. Closing the window sends
  `WindowClosed`.
- **`tray/page/`**: `index.html`, `app.js`, `app.css`, embedded with
  `include_str!`. Vanilla JS, no framework, no build step.

## 5. Security

- **Only kv's page.** Assets come from the binary through `kv://app/`;
  navigation to anything else and new windows are refused; the page's
  Content-Security-Policy is `default-src 'none'; script-src 'self';
  style-src 'self'; img-src 'self' data:; connect-src 'none'` (no inline
  script, no `eval`, no network). Developer tools are off (wry's `devtools`
  feature is not enabled). The webview is incognito; on Windows its data
  folder is under the system's temporary directory.
- **Agent text stays text.** Request details, client names, handle names
  and handle requests are agent-supplied. The page inserts text only with
  `textContent`, never `innerHTML` or `insertAdjacentHTML`; a test fails
  if the embedded page contains either, an inline script, or `eval`.
- **Secrets go one way.** The passphrase and secret values travel from the
  page to Rust, become `SecretText` (zeroized on drop), and the inputs are
  cleared after each submit. The session token, device keys and stored
  secret values are never sent to the page; `describe` sends no text for
  hidden fields. The webview's own process may briefly hold what was typed,
  like a terminal emulator does.
- **Secure input.** On macOS a focused password field turns on Secure Event
  Input, so other programs cannot read those keystrokes.
- **Same exposure as `kv tui`, plus a look-alike risk.** A program running
  as the user that can drive other programs' UI can click Allow or read the
  window, as it can with a terminal. A program can also draw a window that
  looks like kv's and ask for the passphrase. kv's window only opens when
  the user picks a menu item, never by itself; the README says to treat an
  unexpected kv window as fake.
- Device unlock and the daemon peer check are unchanged.

## 6. Errors

- An action from the window reports in the window (beside the form, on the
  card, or under the passphrase field). An action from the menu reports as
  a notification, as today.
- If the webview cannot be created (on Windows, no WebView2 runtime), kv
  shows the notification "kv's window needs the Microsoft Edge WebView2
  Runtime" and the menu keeps working.
- A message from the page that does not parse is dropped. The worker never
  panics on page input.

## 7. Testing

- `kv::forms`: the existing TUI form tests keep passing after the move;
  new tests show `describe` sends no secret text, `fill` then `submit`
  gives the same `Effect` as typing the same values in the TUI, and
  unknown keys are ignored.
- `tray::window`: every `FromPage` and `ToPage` round-trips through JSON;
  malformed and unknown messages are rejected.
- `tray::worker`, against a daemon in the test process with the fake device
  and a fake desktop that records what it sends to the page: passphrase
  unlock and a wrong passphrase; device unlock and a cancelled prompt;
  Decide from the window; Add, Edit, Policy and Remove through form
  messages, including a validation error; Fill in and Dismiss of a handle
  request; Audit only while its tab is shown; a lock elsewhere sending the
  locked `State` and dropping the open form.
- The page: a test reads the embedded files and fails on `innerHTML`,
  `insertAdjacentHTML`, `eval`, `new Function`, inline `<script>` bodies or
  a missing CSP. Its behaviour is checked by hand.
- Manual checks before release: the window in light and dark mode on macOS
  and Windows; Touch ID, Hello and passphrase unlock from the window; each
  form, including Fill in from a real `request_handle`; answering from a
  card; Lock from the window and from elsewhere; Windows without WebView2.

## 8. Out of scope

- Linux.
- Clicking the icon to open the window directly; more than one window.
- A settings tab (the login item stays in the menu).
- New daemon commands.
- The `bus error` when `kv tray` is started from the cmux terminal (an
  environment variable sets it off inside macOS's PNG decoder); fixed
  separately.
