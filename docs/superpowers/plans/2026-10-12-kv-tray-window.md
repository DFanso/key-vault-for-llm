# kv Plan 8: kv's window in `kv tray` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `kv tray` works without `kv tui`. It unlocks with Touch ID or Windows Hello, or with the passphrase typed into kv's own window. Its menu's "Open kv…" opens that window, with Approvals, Handles and Audit tabs that do what the TUI's tabs do.

**Architecture:**
- **Forms.** The TUI's handle forms move to `kv::forms`, so the TUI and the window build, validate and save a handle the same way. `describe` turns a form into a serializable view with no secret text in it, and `fill` puts the page's values back.
- **Protocol.** A pure `tray::window` defines the JSON the page and the tray exchange (`FromPage`, `ToPage`), and carries the page itself (`tray/page/`, embedded).
- **Worker.** `tray::worker` holds one session for the menu and the window, the window's tab and open form, and answers each failure where the user asked: in the window, or as a notification for the menu.
- **UI.** `tray::ui` draws the window as a wry webview in a tao window, serves the page under its own `kv` protocol with a strict CSP, and passes page messages to the worker only from that page.

**Tech Stack:** Rust 2024 (MSRV 1.90), wry 0.57 (no default features), tao 0.37, tray-icon 0.26 (muda 0.21 as `tray_icon::menu`), serde/serde_json, vanilla HTML/CSS/JS (no framework, no build step).

**Spec:** `docs/superpowers/specs/2026-10-12-kv-tray-window-design.md`. The tray spec `docs/superpowers/specs/2026-10-12-kv-tray-design.md` stays the authority for the icon, the menu's quick answers, the worker loop and the login item, and the main design `docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md` for sessions, approvals and device unlock. Task 6 brings the window spec's protocol names (`Ready`, `Show { tab }`, `Message { text, request }`, `Action::Open(Tab)`) in line with this plan.

## Decisions this plan makes

Each is a choice for you to confirm or change.

- **Tabs, not screens.** The spec's `Show { screen }` and `OpenWindow(Screen)` become `ToPage::Show { tab }` and the menu's `Action::Open(Tab)`. The unlock screen is not a tab: the page shows it whenever `State.locked` is true.
- **The page says when it has loaded** (`FromPage::Ready`). The worker answers with the tab, the state, the open form and, on the Audit tab, the log, because messages sent before the page loaded are lost.
- **`ToPage::Message` names its request** (`request: Option<u64>`), so "that request is no longer waiting" shows on the card that was clicked.
- **Unknown fields on a message with no data** (such as `{"type":"lock","extra":1}`) are accepted, since serde ignores them on internally tagged unit variants. Messages that carry data reject unknown fields (`deny_unknown_fields`).
- **Opening the window while locked asks for Touch ID or Hello at once**, but only when the window was closed. "Open kv…" on an open window, or after a cancelled prompt, raises it without a second prompt; "Use Touch ID" asks again. A prompt already running for the menu is not doubled; the window shows "Waiting for Touch ID…" while it runs.
- **A form stays open with its error** until the daemon accepts it. A rejected or failed save keeps what was typed (the secret too), as in the TUI. A save, Cancel, Esc, a lock from anywhere, or closing the window drops the form and wipes its inputs.
- **The New handle form needs only a session**. Fill in, Edit and Policy open from the last overview, because the page only shows those buttons for things in it.
- **When a session ends at a tick** (idle lock, `kv lock`, daemon stopped), the window shows the daemon's reason; the menu still shows none, as before.
- **"Open kv…" also shows when there is no vault yet**: the window's unlock screen then shows the daemon's "no vault yet: run `kv init`".
- **On Windows any failure to create the webview** shows the spec's "kv's window needs the Microsoft Edge WebView2 Runtime" (the error itself goes to stderr). Asking wry for the runtime version needs its `os-webview` feature, which is Linux's.
- **WebView2's data folder is `%TEMP%\kv-webview`**: by default it would sit next to `kv.exe`, which may not be writable. On Windows the page is `https://kv.app/index.html` (`with_https_scheme`); on macOS it is `kv://app/index.html`.
- **macOS gets a hidden Edit menu.** An accessory app shows no menu bar, but Cmd+C, Cmd+V, Cmd+X, Cmd+A and Cmd+Z only work in the window's fields when the app menu has those items. `tray::ui` installs one with `Menu::init_for_nsapp`.
- **`kv tray` no longer opens a terminal at all.** `tray::tui_command` and its two tests are removed in Task 4.
- **Tasks 3 and 4 pass through a stub.** In Task 3, "Open kv…" still calls the old `open_tui`, so the build stays green. In Task 4, `System::show_window` and `System::page` do nothing until Task 5 draws the window.

## Global Constraints

- Every cargo command runs with `export DEVELOPER_DIR=/Library/Developer/CommandLineTools` set (this Mac's linker). The live database tests are unaffected and skip without `KV_TEST_POSTGRES_URL` / `KV_TEST_REDIS_URL`.
- Rust 1.90 stays the minimum supported version.
- No new daemon command or protocol message: the window uses what `kv tui` uses (`Status`, `OpenSession`, `Overview`, `Decide`, `Add`, `Update`, `SetPolicy`, `Remove`, `DismissRequest`, `Lock`).
- The page inserts text only through text nodes and `textContent`: never `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, an inline script or an inline event handler.
- The page's Content-Security-Policy is exactly `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'`, as a response header on every file and as a `<meta>` in `index.html`.
- Passphrases and secret values from the page are `SecretText` from the moment they are parsed, and the IPC body is zeroized. `describe` sends no text for secret or pairs fields. The session token, device keys and stored secret values never reach the page.
- Messages from the page count only when the IPC request's URL is the page's (`is_page_url`). Navigation away and new windows are refused, the webview is incognito, and wry's `devtools` feature stays off.
- The worker never panics on page input: no `unwrap`, `expect` or `unreachable!` on anything that came from the page.
- wry, tao and tray-icon are dependencies for `cfg(any(target_os = "macos", windows))` only. `tray::window`, `tray::worker` and `kv::forms` build everywhere, so their tests run in all three CI jobs.
- Copy, verbatim:
  - Menu: "Unlock…", "Open kv…", "1 handle request: open kv…", "N handle requests: open kv…".
  - Window: "kv is locked", "Waiting for Touch ID…" ("…for Windows Hello…"), "Use Touch ID", "Unlocked · locks in 7h 52m", "Approvals (N)", "No requests waiting", "Expires in Ns", "Allow once", "Allow for this session", "Deny", "Deny and block <handles>".
  - Windows notification: "kv's window needs the Microsoft Edge WebView2 Runtime".
- Commits as DFanso <leogavin123@outlook.com>, no AI attribution.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` stay clean after every task. kv cannot be cross-checked from macOS (aws-lc-sys does not cross-compile), so Windows-only code is compiled by CI's windows-latest job. Task 5 also gives a small probe crate that checks `webview.rs` for Windows from macOS.

## Review Focus

These five involve a real webview, a keyboard or a Windows machine, so no test in this plan exercises them. Each is a manual check before release (Task 5, Step 7).

- **Pasting a token on macOS.** Cmd+V into the token field of the New handle form, from a tray that is an accessory app with no menu bar. The token pastes, and Cmd+C, Cmd+X, Cmd+A and Cmd+Z work in every field.
- **Typing while the tray ticks.** With a form open, or a passphrase half typed, for over a minute while requests arrive and expire: focus and typed text stay, a card's buttons do not move under the pointer, and only "Expires in Ns" changes each second.
- **The window coming forward.** "Open kv…" and "N handle requests: open kv…" bring the window in front of other apps on macOS (an accessory app) and on Windows, never open a second one, and switch to the right tab. Closing the window and choosing "Open kv…" again opens it on the same session.
- **Hostile agent text.** A request whose client name, detail and working directory hold `<img src=x onerror=alert(1)>`, a 4,000-character line, line breaks and right-to-left marks. It shows as literal text, wraps inside the card, and leaves the buttons usable.
- **Windows without the WebView2 Runtime, and with it.**
  - Without it: "Open kv…" shows the notification and the menu keeps answering requests.
  - With it: the window opens, its data folder is under `%TEMP%\kv-webview`, and Windows Hello comes to the front from the window's "Use Windows Hello".

---
### Task 1: Share the handle forms: `kv::forms`

**Files:**
- Create: `crates/kv/tests/forms.rs`
- Create: `crates/kv/src/forms.rs`
- Move: `crates/kv/src/tui/edit.rs` → `crates/kv/src/forms/handles.rs`
- Modify: `crates/kv/src/lib.rs`
- Modify: `crates/kv/src/tui.rs`
- Modify: `crates/kv/src/tui/app.rs`
- Modify: `crates/kv/src/tui/form.rs`

**Interfaces:**
- Consumes:
  - `tui::edit`: `Purpose`, `new_handle`, `requested_handle`, `edit_handle`, `edit_policy`, `submit`.
  - `tui::form`: `Form`, `Field`, `Input`, `is_variable_name`.
  - `tui::app::Effect`.
- Produces `kv::forms` (a `pub mod`):
  - Moved from the TUI:
    - `Form`, `Field`, `Input`, `is_variable_name`;
    - `Purpose { Add, Edit(HandleInfo), Policy(HandleInfo) }`;
    - `new_handle() -> Form`, `requested_handle(&RequestedHandle) -> Form`, `edit_handle(&HandleInfo) -> Form`, `edit_policy(&HandleInfo) -> Form`;
    - `submit(&Purpose, &Form) -> Result<Effect, String>`.
  - New:
    - `describe(&Form) -> FormView`. Secret and pairs fields carry an empty `value`.
    - `fill(&mut Form, &BTreeMap<String, SecretText>) -> Result<(), String>`. It sets text, a choice (which must be one of its options, else `"<Label>: choose one of …"`), or pairs (one `NAME=value` per line). It ignores unknown keys, and on an error it changes nothing.
    - `FormView { title: String, fields: Vec<FieldView>, focus: Option<String> }` (Serialize + Deserialize).
    - `FieldView { key, label, kind: FieldKind, options: Vec<String>, value, hint, when: Option<When> }`.
    - `FieldKind { Text, Secret, Choice, Pairs }` (snake_case) and `When { key: String, options: Vec<String> }`.
  - `tui::form` keeps `Reply` and the key handling (`handle_key`, `paste`), and re-exports `Field, Form, Input, is_variable_name`.

The TUI keeps its behaviour exactly; only where the code lives changes. Every existing TUI suite is part of this task's test run.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv/tests/forms.rs b/crates/kv/tests/forms.rs
new file mode 100644
index 0000000000000000000000000000000000000000..6ca0bcd11c449a709389afb4f8b9b8846ccd2050
--- /dev/null
+++ b/crates/kv/tests/forms.rs
@@ -0,0 +1,190 @@
+//! The handle forms `kv tui` and the `kv tray` window share: a form turned
+//! into what the window draws, and what the window sends back turned into
+//! the same effect as typing it into the TUI.
+
+use std::collections::BTreeMap;
+
+use kv::forms::{self, FieldKind, FormView, Purpose};
+use kv::tui::app::{App, Effect};
+use kv_core::policy::Mode;
+use kv_core::proto::{Overview, RequestedHandle, Status};
+use kv_core::secret::{AuthPlacement, SecretText, SecretValue};
+use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
+
+const TOKEN: &str = "sk-or-v1-0123456789abcdef";
+
+fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, SecretText> {
+    pairs
+        .iter()
+        .map(|(k, v)| ((*k).to_owned(), SecretText::new(*v)))
+        .collect()
+}
+
+fn field<'a>(view: &'a FormView, key: &str) -> &'a forms::FieldView {
+    view.fields
+        .iter()
+        .find(|f| f.key == key)
+        .unwrap_or_else(|| panic!("no field {key} in {view:?}"))
+}
+
+#[test]
+fn a_described_form_never_carries_a_secret() {
+    let mut form = forms::new_handle();
+    forms::fill(
+        &mut form,
+        &values(&[("name", "openrouter"), ("token", TOKEN)]),
+    )
+    .unwrap();
+    let view = forms::describe(&form);
+    assert_eq!(view.title, "New handle");
+    let token = field(&view, "token");
+    assert_eq!(token.kind, FieldKind::Secret);
+    assert_eq!(token.value, "");
+    assert_eq!(field(&view, "name").value, "openrouter");
+    assert!(!serde_json::to_string(&view).unwrap().contains("0123456789"));
+
+    let kind = field(&view, "kind");
+    assert_eq!(kind.kind, FieldKind::Choice);
+    assert_eq!(kind.options, ["http", "env", "postgres", "redis"]);
+    assert_eq!(kind.value, "http");
+    let header = field(&view, "header");
+    assert_eq!(header.value, "Authorization");
+    let when = header.when.as_ref().unwrap();
+    assert_eq!(
+        (when.key.as_str(), when.options.as_slice()),
+        ("placement", &["header".to_owned()][..])
+    );
+    assert_eq!(field(&view, "vars").kind, FieldKind::Pairs);
+}
+
+/// What the window sends gives the same effect as the same values typed
+/// into `kv tui`.
+#[test]
+fn filled_values_save_as_the_tui_would() {
+    let mut form = forms::new_handle();
+    forms::fill(
+        &mut form,
+        &values(&[
+            ("name", "openrouter"),
+            ("description", "Models"),
+            ("token", TOKEN),
+            ("hosts", "openrouter.ai, api.openrouter.ai"),
+        ]),
+    )
+    .unwrap();
+    let from_window = forms::submit(&Purpose::Add, &form).unwrap();
+
+    let mut app = App::new();
+    app.apply(kv::tui::app::Outcome::Opened);
+    app.apply(kv::tui::app::Outcome::Overview(Overview {
+        status: Status {
+            vault_exists: true,
+            locked: false,
+            handle_count: Some(0),
+            locks_in_secs: None,
+            pending_approvals: 0,
+            devices: Vec::new(),
+        },
+        handles: Vec::new(),
+        approvals: Vec::new(),
+        handle_requests: Vec::new(),
+        role_warnings: Default::default(),
+    }));
+    let press = |app: &mut App, code| app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
+    press(&mut app, KeyCode::Char('2'));
+    press(&mut app, KeyCode::Char('n'));
+    let type_into = |app: &mut App, key: &str, text: &str| {
+        while app.form().unwrap().focused() != Some(key) {
+            press(app, KeyCode::Tab);
+        }
+        for c in text.chars() {
+            press(app, KeyCode::Char(c));
+        }
+    };
+    type_into(&mut app, "name", "openrouter");
+    type_into(&mut app, "description", "Models");
+    type_into(&mut app, "token", TOKEN);
+    type_into(&mut app, "hosts", "openrouter.ai, api.openrouter.ai");
+    while app.form().unwrap().focused().is_some() {
+        press(&mut app, KeyCode::Tab);
+    }
+    let from_tui = press(&mut app, KeyCode::Enter).unwrap();
+    assert_eq!(from_window, from_tui);
+    let Effect::Add(secret) = from_window else {
+        panic!("{from_window:?}");
+    };
+    assert_eq!(secret.policy.mode, Mode::Ask);
+    assert_eq!(
+        secret.value,
+        SecretValue::Http {
+            token: SecretText::new(TOKEN),
+            placement: AuthPlacement::Header {
+                name: "Authorization".into(),
+                template: "Bearer {}".into(),
+            },
+            base_url: None,
+        }
+    );
+}
+
+#[test]
+fn variables_come_one_per_line() {
+    let mut form = forms::new_handle();
+    forms::fill(
+        &mut form,
+        &values(&[
+            ("kind", "env"),
+            ("name", "aws"),
+            (
+                "vars",
+                "AWS_ACCESS_KEY_ID=AKIA0\n\n  AWS_SECRET_ACCESS_KEY=s3cret  \n",
+            ),
+            ("cmds", "terraform"),
+        ]),
+    )
+    .unwrap();
+    let Effect::Add(secret) = forms::submit(&Purpose::Add, &form).unwrap() else {
+        panic!();
+    };
+    let SecretValue::Env { vars } = secret.value else {
+        panic!();
+    };
+    assert_eq!(
+        vars.keys().collect::<Vec<_>>(),
+        ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
+    );
+    assert_eq!(vars["AWS_SECRET_ACCESS_KEY"], SecretText::new("s3cret"));
+
+    let error = forms::fill(&mut form, &values(&[("vars", "not a pair")])).unwrap_err();
+    assert!(error.contains("NAME=value"), "{error}");
+}
+
+#[test]
+fn unknown_keys_are_ignored_and_unknown_options_refused() {
+    let mut form = forms::new_handle();
+    forms::fill(&mut form, &values(&[("no_such_field", "x"), ("name", "a")])).unwrap();
+    assert_eq!(form.text("name"), "a");
+    let error = forms::fill(&mut form, &values(&[("kind", "ftp")])).unwrap_err();
+    assert!(error.contains("Kind"), "{error}");
+    assert_eq!(
+        form.chosen("kind"),
+        "http",
+        "a refused value changes nothing"
+    );
+}
+
+#[test]
+fn a_requested_handle_puts_the_cursor_on_its_secret() {
+    let requested = RequestedHandle {
+        id: 3,
+        client: None,
+        request: serde_json::from_str(
+            r#"{"name":"github","kind":"http","allowed_hosts":["api.github.com"]}"#,
+        )
+        .unwrap(),
+    };
+    let view = forms::describe(&forms::requested_handle(&requested));
+    assert_eq!(view.focus.as_deref(), Some("token"));
+    assert_eq!(field(&view, "name").value, "github");
+    assert_eq!(field(&view, "hosts").value, "api.github.com");
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv --test forms --test tui --test tui_edit --test tui_requests --test tui_session --test tui_audit --test tui_device`
Expected: `forms` fails to compile with `error[E0432]: unresolved import kv::forms`, so nothing runs.

- [ ] **Step 3: Implement**

The diff moves `crates/kv/src/tui/edit.rs` to `crates/kv/src/forms/handles.rs` (a rename with a two-line change; `git apply` performs the move). It also moves the data half of `tui/form.rs` into `forms.rs`.

Apply with `git apply`:

```diff
diff --git a/crates/kv/src/forms.rs b/crates/kv/src/forms.rs
new file mode 100644
index 0000000000000000000000000000000000000000..f2a479c30cea473b573237f81c22d97a778e6961
--- /dev/null
+++ b/crates/kv/src/forms.rs
@@ -0,0 +1,385 @@
+//! The handle forms `kv tui` and the `kv tray` window share: their fields,
+//! the effect each saves as (`handles`), and, for the window, a form as
+//! data (`describe`) and the window's answers put back into it (`fill`).
+
+mod handles;
+
+use std::collections::BTreeMap;
+
+use kv_core::secret::SecretText;
+use serde::{Deserialize, Serialize};
+use zeroize::Zeroizing;
+
+pub use handles::{Purpose, edit_handle, edit_policy, new_handle, requested_handle, submit};
+
+pub enum Input {
+    Text,
+    /// Typed like text, drawn as dots.
+    Hidden,
+    Choice(&'static [&'static str]),
+    /// NAME=value pairs: Enter adds the typed pair; only names are drawn.
+    Pairs,
+}
+
+pub struct Field {
+    pub key: &'static str,
+    pub label: &'static str,
+    pub input: Input,
+    pub text: Zeroizing<String>,
+    pub choice: usize,
+    pub pairs: Vec<(String, SecretText)>,
+    /// Drawn dimmed after the field, e.g. what leaving it blank means.
+    pub hint: String,
+    /// Shown only while the choice field `.0` is set to one of `.1`.
+    pub(crate) when: Option<(&'static str, &'static [&'static str])>,
+}
+
+impl Field {
+    fn new(key: &'static str, label: &'static str, input: Input) -> Self {
+        Self {
+            key,
+            label,
+            input,
+            text: Zeroizing::new(String::new()),
+            choice: 0,
+            pairs: Vec::new(),
+            hint: String::new(),
+            when: None,
+        }
+    }
+
+    pub fn text(key: &'static str, label: &'static str) -> Self {
+        Self::new(key, label, Input::Text)
+    }
+
+    pub fn hidden(key: &'static str, label: &'static str) -> Self {
+        Self::new(key, label, Input::Hidden)
+    }
+
+    pub fn choice(
+        key: &'static str,
+        label: &'static str,
+        options: &'static [&'static str],
+    ) -> Self {
+        Self::new(key, label, Input::Choice(options))
+    }
+
+    pub fn pairs(key: &'static str, label: &'static str) -> Self {
+        Self::new(key, label, Input::Pairs)
+    }
+
+    pub fn with_text(mut self, text: &str) -> Self {
+        self.text = Zeroizing::new(text.to_owned());
+        self
+    }
+
+    pub fn with_choice(mut self, option: &str) -> Self {
+        self.set_choice(option);
+        self
+    }
+
+    /// Selects `option` in a choice field, or the first one if it has no
+    /// such option.
+    pub fn set_choice(&mut self, option: &str) {
+        if let Input::Choice(options) = self.input {
+            self.choice = options.iter().position(|o| *o == option).unwrap_or(0);
+        }
+    }
+
+    pub fn hint(mut self, hint: impl Into<String>) -> Self {
+        self.hint = hint.into();
+        self
+    }
+
+    pub fn when(mut self, key: &'static str, options: &'static [&'static str]) -> Self {
+        self.when = Some((key, options));
+        self
+    }
+
+    pub fn depends_on(&self) -> Option<(&'static str, &'static [&'static str])> {
+        self.when
+    }
+
+    pub fn without_condition(mut self) -> Self {
+        self.when = None;
+        self
+    }
+
+    /// The selected option of a choice field.
+    pub fn chosen(&self) -> &'static str {
+        match self.input {
+            Input::Choice(options) => options[self.choice],
+            _ => "",
+        }
+    }
+}
+
+pub struct Form {
+    title: String,
+    pub(crate) fields: Vec<Field>,
+    /// `fields.len()` is the Save row.
+    pub(crate) focus: usize,
+}
+
+impl Form {
+    pub fn new(title: impl Into<String>, fields: Vec<Field>) -> Self {
+        let mut form = Self {
+            title: title.into(),
+            fields,
+            focus: 0,
+        };
+        if !form.is_shown(0) {
+            form.move_focus(1);
+        }
+        form
+    }
+
+    pub fn title(&self) -> &str {
+        &self.title
+    }
+
+    /// The key of the focused field, or `None` on the Save row.
+    pub fn focused(&self) -> Option<&str> {
+        self.fields.get(self.focus).map(|f| f.key)
+    }
+
+    /// The fields on screen, with whether each has the focus.
+    pub fn shown(&self) -> impl Iterator<Item = (&Field, bool)> {
+        self.fields
+            .iter()
+            .enumerate()
+            .filter(|(i, _)| self.is_shown(*i))
+            .map(|(i, f)| (f, i == self.focus))
+    }
+
+    pub fn save_focused(&self) -> bool {
+        self.focus == self.fields.len()
+    }
+
+    pub fn field(&self, key: &str) -> &Field {
+        self.fields
+            .iter()
+            .find(|f| f.key == key)
+            .unwrap_or_else(|| panic!("the form has no field {key}"))
+    }
+
+    pub fn field_mut(&mut self, key: &str) -> &mut Field {
+        self.fields
+            .iter_mut()
+            .find(|f| f.key == key)
+            .unwrap_or_else(|| panic!("the form has no field {key}"))
+    }
+
+    /// Puts the focus on a field, if it is shown.
+    pub fn focus_on(&mut self, key: &str) {
+        if let Some(index) = self.fields.iter().position(|f| f.key == key)
+            && self.is_shown(index)
+        {
+            self.focus = index;
+        }
+    }
+
+    pub fn has(&self, key: &str) -> bool {
+        self.fields.iter().any(|f| f.key == key)
+    }
+
+    /// The trimmed text of a field, or "" if the form has no such field.
+    pub fn text(&self, key: &str) -> &str {
+        self.fields
+            .iter()
+            .find(|f| f.key == key)
+            .map_or("", |f| f.text.trim())
+    }
+
+    pub fn chosen(&self, key: &str) -> &'static str {
+        self.field(key).chosen()
+    }
+
+    pub fn is_shown_key(&self, key: &str) -> bool {
+        self.fields
+            .iter()
+            .position(|f| f.key == key)
+            .is_some_and(|i| self.is_shown(i))
+    }
+
+    pub(crate) fn is_shown(&self, index: usize) -> bool {
+        let Some(field) = self.fields.get(index) else {
+            return true;
+        };
+        let Some((key, options)) = field.when else {
+            return true;
+        };
+        self.fields
+            .iter()
+            .position(|f| f.key == key)
+            .is_some_and(|i| self.is_shown(i) && options.contains(&self.fields[i].chosen()))
+    }
+
+    /// Steps to the next or previous shown row, wrapping past Save.
+    pub(crate) fn move_focus(&mut self, step: isize) {
+        let rows = self.fields.len() + 1;
+        let mut next = self.focus;
+        for _ in 0..rows {
+            next = (next as isize + step).rem_euclid(rows as isize) as usize;
+            if self.is_shown(next) {
+                break;
+            }
+        }
+        self.focus = next;
+    }
+}
+
+pub(crate) const PAIR_HELP: &str =
+    "type a variable as NAME=value (letters, digits and _ in the name), then press Enter";
+
+/// `NAME=value` with a variable name and a value, or `None`.
+pub(crate) fn parse_pair(text: &str) -> Option<(String, SecretText)> {
+    let (name, value) = text.split_once('=')?;
+    let name = name.trim();
+    (is_variable_name(name) && !value.is_empty()).then(|| (name.to_owned(), SecretText::new(value)))
+}
+
+/// Letters, digits and `_`, not starting with a digit: what shells accept,
+/// and what the TUI is willing to draw before the value.
+pub fn is_variable_name(name: &str) -> bool {
+    let mut chars = name.chars();
+    chars
+        .next()
+        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
+        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
+}
+
+/// A form as the `kv tray` window draws it. Secret fields carry no text.
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
+pub struct FormView {
+    pub title: String,
+    pub fields: Vec<FieldView>,
+    /// The field to put the cursor in.
+    pub focus: Option<String>,
+}
+
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
+pub struct FieldView {
+    pub key: String,
+    pub label: String,
+    pub kind: FieldKind,
+    /// A choice field's options.
+    pub options: Vec<String>,
+    /// The text of a text field or the option of a choice field; empty for
+    /// secrets and variables.
+    pub value: String,
+    pub hint: String,
+    /// Shown only while another choice field has one of these options.
+    pub when: Option<When>,
+}
+
+#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
+#[serde(rename_all = "snake_case")]
+pub enum FieldKind {
+    Text,
+    Secret,
+    Choice,
+    /// `NAME=value` lines.
+    Pairs,
+}
+
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
+pub struct When {
+    pub key: String,
+    pub options: Vec<String>,
+}
+
+pub fn describe(form: &Form) -> FormView {
+    FormView {
+        title: form.title().to_owned(),
+        focus: form.focused().map(str::to_owned),
+        fields: form
+            .fields
+            .iter()
+            .map(|field| {
+                let (kind, options, value) = match field.input {
+                    Input::Text => (FieldKind::Text, Vec::new(), field.text.to_string()),
+                    Input::Hidden => (FieldKind::Secret, Vec::new(), String::new()),
+                    Input::Pairs => (FieldKind::Pairs, Vec::new(), String::new()),
+                    Input::Choice(options) => (
+                        FieldKind::Choice,
+                        options.iter().map(|o| (*o).to_owned()).collect(),
+                        field.chosen().to_owned(),
+                    ),
+                };
+                FieldView {
+                    key: field.key.to_owned(),
+                    label: field.label.to_owned(),
+                    kind,
+                    options,
+                    value,
+                    hint: field.hint.clone(),
+                    when: field.when.map(|(key, options)| When {
+                        key: key.to_owned(),
+                        options: options.iter().map(|o| (*o).to_owned()).collect(),
+                    }),
+                }
+            })
+            .collect(),
+    }
+}
+
+/// Puts what the window sent into `form`: text as typed, a choice by its
+/// option, and variables one `NAME=value` per line, replacing the ones the
+/// form had. Keys the form does not have are ignored. On an error the form
+/// is left as it was.
+pub fn fill(form: &mut Form, values: &BTreeMap<String, SecretText>) -> Result<(), String> {
+    let mut updates = Vec::new();
+    for (key, value) in values {
+        let Some(index) = form.fields.iter().position(|f| f.key == key) else {
+            continue;
+        };
+        let field = &form.fields[index];
+        let update = match field.input {
+            Input::Text | Input::Hidden => Update::Text(Zeroizing::new(value.expose().to_owned())),
+            Input::Choice(options) => {
+                let choice = options
+                    .iter()
+                    .position(|o| *o == value.expose())
+                    .ok_or_else(|| {
+                        format!("{}: choose one of {}", field.label, options.join(", "))
+                    })?;
+                Update::Choice(choice)
+            }
+            Input::Pairs => {
+                let mut pairs: Vec<(String, SecretText)> = Vec::new();
+                for line in value
+                    .expose()
+                    .lines()
+                    .map(str::trim)
+                    .filter(|l| !l.is_empty())
+                {
+                    let (name, value) = parse_pair(line)
+                        .ok_or_else(|| format!("{}: one NAME=value per line", field.label))?;
+                    pairs.retain(|(n, _)| *n != name);
+                    pairs.push((name, value));
+                }
+                Update::Pairs(pairs)
+            }
+        };
+        updates.push((index, update));
+    }
+    for (index, update) in updates {
+        let field = &mut form.fields[index];
+        match update {
+            Update::Text(text) => field.text = text,
+            Update::Choice(choice) => field.choice = choice,
+            Update::Pairs(pairs) => {
+                field.text = Zeroizing::new(String::new());
+                field.pairs = pairs;
+            }
+        }
+    }
+    Ok(())
+}
+
+enum Update {
+    Text(Zeroizing<String>),
+    Choice(usize),
+    Pairs(Vec<(String, SecretText)>),
+}
diff --git a/crates/kv/src/tui/edit.rs b/crates/kv/src/forms/handles.rs
similarity index 99%
rename from crates/kv/src/tui/edit.rs
rename to crates/kv/src/forms/handles.rs
index 48e90ba8d3a886e2dfda56b6900c9b312a700b08..844dcd2ebbff54f68819f86783b4840705881924 100644
--- a/crates/kv/src/tui/edit.rs
+++ b/crates/kv/src/forms/handles.rs
@@ -7,8 +7,8 @@ use kv_core::policy::{Mode, Policy};
 use kv_core::proto::{PolicyPatch, RequestedHandle};
 use kv_core::secret::{AuthPlacement, HandleInfo, Secret, SecretKind, SecretText, SecretValue};
 
-use super::app::Effect;
-use super::form::{Field, Form};
+use super::{Field, Form};
+use crate::tui::app::Effect;
 
 const KINDS: &[&str] = &["http", "env", "postgres", "redis"];
 const MODES: &[&str] = &["ask", "auto", "deny"];
diff --git a/crates/kv/src/lib.rs b/crates/kv/src/lib.rs
index 69709056807aa205a979f90d7809676e6f3941d1..4f8b3c7518456117a52eb4576555eeb9526e7ca9 100644
--- a/crates/kv/src/lib.rs
+++ b/crates/kv/src/lib.rs
@@ -6,6 +6,7 @@ pub mod cli;
 pub mod client;
 pub mod daemon;
 pub mod device;
+pub mod forms;
 pub mod frame;
 pub mod ipc;
 pub mod mcp;
diff --git a/crates/kv/src/tui.rs b/crates/kv/src/tui.rs
index eb8c7057d2b9d8b631c7c8f239b688262d8935e4..96f88bb75fb6dbe635fe622978f683573f5fc77a 100644
--- a/crates/kv/src/tui.rs
+++ b/crates/kv/src/tui.rs
@@ -4,7 +4,6 @@
 //! the token.
 
 pub mod app;
-mod edit;
 pub mod form;
 pub mod view;
 
diff --git a/crates/kv/src/tui/app.rs b/crates/kv/src/tui/app.rs
index ce62377de343c9350b4aa2f321f504de1fe9c120..178b46577216fc2c5fcc44e416b85cb12b42b96d 100644
--- a/crates/kv/src/tui/app.rs
+++ b/crates/kv/src/tui/app.rs
@@ -10,8 +10,8 @@ use kv_core::vault::DeviceKind;
 use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
 use zeroize::Zeroizing;
 
-use super::edit::{self, Purpose};
 use super::form::{Form, Reply};
+use crate::forms::{self, Purpose};
 
 #[derive(Clone, Copy, Debug, PartialEq, Eq)]
 pub enum Screen {
@@ -409,16 +409,16 @@ impl App {
                 self.selected_handle = (self.selected_handle + 1).min(rows.saturating_sub(1));
                 return None;
             }
-            (KeyCode::Char('n'), ..) => (edit::new_handle(), Purpose::Add),
+            (KeyCode::Char('n'), ..) => (forms::new_handle(), Purpose::Add),
             (KeyCode::Enter | KeyCode::Char('e'), Some(request), _) => {
-                (edit::requested_handle(request), Purpose::Add)
+                (forms::requested_handle(request), Purpose::Add)
             }
             (KeyCode::Char('x'), Some(request), _) => return Some(Effect::Dismiss(request.id)),
             (KeyCode::Char('e'), _, Some(handle)) => {
-                (edit::edit_handle(handle), Purpose::Edit(handle.clone()))
+                (forms::edit_handle(handle), Purpose::Edit(handle.clone()))
             }
             (KeyCode::Char('p'), _, Some(handle)) => {
-                (edit::edit_policy(handle), Purpose::Policy(handle.clone()))
+                (forms::edit_policy(handle), Purpose::Policy(handle.clone()))
             }
             (KeyCode::Char('x'), _, Some(handle)) => {
                 self.removing = Some(handle.name.clone());
@@ -451,7 +451,7 @@ impl App {
                 self.message = Some(message);
                 None
             }
-            Reply::Submit => match edit::submit(&editor.purpose, &editor.form) {
+            Reply::Submit => match forms::submit(&editor.purpose, &editor.form) {
                 Ok(effect) => {
                     editor.saving = true;
                     self.message = Some("saving…".into());
diff --git a/crates/kv/src/tui/form.rs b/crates/kv/src/tui/form.rs
index 11dbdfa13ad3098ec5220c04f13ecb77d3f614d3..f5b24466f659bbda050cde27b3deecbaf2c55b5c 100644
--- a/crates/kv/src/tui/form.rs
+++ b/crates/kv/src/tui/form.rs
@@ -1,111 +1,10 @@
-//! A small form: text, hidden and choice fields, and a list of NAME=value
-//! pairs, followed by a Save row.
+//! Typing into a form in `kv tui`: what each key does. The form itself is
+//! `kv::forms`, shared with the `kv tray` window.
 
-use kv_core::secret::SecretText;
 use ratatui::crossterm::event::{KeyCode, KeyEvent};
-use zeroize::Zeroizing;
 
-pub enum Input {
-    Text,
-    /// Typed like text, drawn as dots.
-    Hidden,
-    Choice(&'static [&'static str]),
-    /// NAME=value pairs: Enter adds the typed pair; only names are drawn.
-    Pairs,
-}
-
-pub struct Field {
-    pub key: &'static str,
-    pub label: &'static str,
-    pub input: Input,
-    pub text: Zeroizing<String>,
-    pub choice: usize,
-    pub pairs: Vec<(String, SecretText)>,
-    /// Drawn dimmed after the field, e.g. what leaving it blank means.
-    pub hint: String,
-    /// Shown only while the choice field `.0` is set to one of `.1`.
-    when: Option<(&'static str, &'static [&'static str])>,
-}
-
-impl Field {
-    fn new(key: &'static str, label: &'static str, input: Input) -> Self {
-        Self {
-            key,
-            label,
-            input,
-            text: Zeroizing::new(String::new()),
-            choice: 0,
-            pairs: Vec::new(),
-            hint: String::new(),
-            when: None,
-        }
-    }
-
-    pub fn text(key: &'static str, label: &'static str) -> Self {
-        Self::new(key, label, Input::Text)
-    }
-
-    pub fn hidden(key: &'static str, label: &'static str) -> Self {
-        Self::new(key, label, Input::Hidden)
-    }
-
-    pub fn choice(
-        key: &'static str,
-        label: &'static str,
-        options: &'static [&'static str],
-    ) -> Self {
-        Self::new(key, label, Input::Choice(options))
-    }
-
-    pub fn pairs(key: &'static str, label: &'static str) -> Self {
-        Self::new(key, label, Input::Pairs)
-    }
-
-    pub fn with_text(mut self, text: &str) -> Self {
-        self.text = Zeroizing::new(text.to_owned());
-        self
-    }
-
-    pub fn with_choice(mut self, option: &str) -> Self {
-        self.set_choice(option);
-        self
-    }
-
-    /// Selects `option` in a choice field, or the first one if it has no
-    /// such option.
-    pub fn set_choice(&mut self, option: &str) {
-        if let Input::Choice(options) = self.input {
-            self.choice = options.iter().position(|o| *o == option).unwrap_or(0);
-        }
-    }
-
-    pub fn hint(mut self, hint: impl Into<String>) -> Self {
-        self.hint = hint.into();
-        self
-    }
-
-    pub fn when(mut self, key: &'static str, options: &'static [&'static str]) -> Self {
-        self.when = Some((key, options));
-        self
-    }
-
-    pub fn depends_on(&self) -> Option<(&'static str, &'static [&'static str])> {
-        self.when
-    }
-
-    pub fn without_condition(mut self) -> Self {
-        self.when = None;
-        self
-    }
-
-    /// The selected option of a choice field.
-    pub fn chosen(&self) -> &'static str {
-        match self.input {
-            Input::Choice(options) => options[self.choice],
-            _ => "",
-        }
-    }
-}
+pub use crate::forms::{Field, Form, Input, is_variable_name};
+use crate::forms::{PAIR_HELP, parse_pair};
 
 /// What a key did to the form.
 pub enum Reply {
@@ -115,94 +14,7 @@ pub enum Reply {
     Message(String),
 }
 
-pub struct Form {
-    title: String,
-    fields: Vec<Field>,
-    /// `fields.len()` is the Save row.
-    focus: usize,
-}
-
 impl Form {
-    pub fn new(title: impl Into<String>, fields: Vec<Field>) -> Self {
-        let mut form = Self {
-            title: title.into(),
-            fields,
-            focus: 0,
-        };
-        if !form.is_shown(0) {
-            form.move_focus(1);
-        }
-        form
-    }
-
-    pub fn title(&self) -> &str {
-        &self.title
-    }
-
-    /// The key of the focused field, or `None` on the Save row.
-    pub fn focused(&self) -> Option<&str> {
-        self.fields.get(self.focus).map(|f| f.key)
-    }
-
-    /// The fields on screen, with whether each has the focus.
-    pub fn shown(&self) -> impl Iterator<Item = (&Field, bool)> {
-        self.fields
-            .iter()
-            .enumerate()
-            .filter(|(i, _)| self.is_shown(*i))
-            .map(|(i, f)| (f, i == self.focus))
-    }
-
-    pub fn save_focused(&self) -> bool {
-        self.focus == self.fields.len()
-    }
-
-    pub fn field(&self, key: &str) -> &Field {
-        self.fields
-            .iter()
-            .find(|f| f.key == key)
-            .unwrap_or_else(|| panic!("the form has no field {key}"))
-    }
-
-    pub fn field_mut(&mut self, key: &str) -> &mut Field {
-        self.fields
-            .iter_mut()
-            .find(|f| f.key == key)
-            .unwrap_or_else(|| panic!("the form has no field {key}"))
-    }
-
-    /// Puts the focus on a field, if it is shown.
-    pub fn focus_on(&mut self, key: &str) {
-        if let Some(index) = self.fields.iter().position(|f| f.key == key)
-            && self.is_shown(index)
-        {
-            self.focus = index;
-        }
-    }
-
-    pub fn has(&self, key: &str) -> bool {
-        self.fields.iter().any(|f| f.key == key)
-    }
-
-    /// The trimmed text of a field, or "" if the form has no such field.
-    pub fn text(&self, key: &str) -> &str {
-        self.fields
-            .iter()
-            .find(|f| f.key == key)
-            .map_or("", |f| f.text.trim())
-    }
-
-    pub fn chosen(&self, key: &str) -> &'static str {
-        self.field(key).chosen()
-    }
-
-    pub fn is_shown_key(&self, key: &str) -> bool {
-        self.fields
-            .iter()
-            .position(|f| f.key == key)
-            .is_some_and(|i| self.is_shown(i))
-    }
-
     pub fn handle_key(&mut self, key: KeyEvent) -> Reply {
         match key.code {
             KeyCode::Esc => return Reply::Cancel,
@@ -288,50 +100,4 @@ impl Form {
         self.move_focus(1);
         Reply::Nothing
     }
-
-    fn is_shown(&self, index: usize) -> bool {
-        let Some(field) = self.fields.get(index) else {
-            return true;
-        };
-        let Some((key, options)) = field.when else {
-            return true;
-        };
-        self.fields
-            .iter()
-            .position(|f| f.key == key)
-            .is_some_and(|i| self.is_shown(i) && options.contains(&self.fields[i].chosen()))
-    }
-
-    /// Steps to the next or previous shown row, wrapping past Save.
-    fn move_focus(&mut self, step: isize) {
-        let rows = self.fields.len() + 1;
-        let mut next = self.focus;
-        for _ in 0..rows {
-            next = (next as isize + step).rem_euclid(rows as isize) as usize;
-            if self.is_shown(next) {
-                break;
-            }
-        }
-        self.focus = next;
-    }
-}
-
-const PAIR_HELP: &str =
-    "type a variable as NAME=value (letters, digits and _ in the name), then press Enter";
-
-/// `NAME=value` with a variable name and a value, or `None`.
-fn parse_pair(text: &str) -> Option<(String, SecretText)> {
-    let (name, value) = text.split_once('=')?;
-    let name = name.trim();
-    (is_variable_name(name) && !value.is_empty()).then(|| (name.to_owned(), SecretText::new(value)))
-}
-
-/// Letters, digits and `_`, not starting with a digit: what shells accept,
-/// and what the TUI is willing to draw before the value.
-pub fn is_variable_name(name: &str) -> bool {
-    let mut chars = name.chars();
-    chars
-        .next()
-        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
-        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
 }
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv --test forms --test tui --test tui_edit --test tui_requests --test tui_session --test tui_audit --test tui_device && cargo clippy -p kv --all-targets -- -D warnings`
Expected: PASS: 79 tests: 5 `forms`, 21 `tui`, 27 `tui_edit`, 10 `tui_requests`, 6 `tui_session`, 5 `tui_audit`, 5 `tui_device`. Clippy is clean.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Move the handle forms to kv::forms, so the window can share them"
```

### Task 2: The window's page protocol: `tray::window`

**Files:**
- Create: `crates/kv/tests/tray_window.rs`
- Modify: `crates/kv/src/audit.rs`
- Modify: `crates/kv/src/tray.rs`
- Create: `crates/kv/src/tray/window.rs`

**Interfaces:**
- Consumes: `forms::FormView` (Task 1), `kv_core::proto::{Overview, Verdict}`, `kv_core::secret::SecretText`, `audit::Entry`.
- Produces `kv::tray::window` (a `pub mod`, built everywhere):
  - `Tab { Approvals, Handles, Audit }` (Copy, serde snake_case).
  - `FormRequest`, serde tag `kind`: `New`, `Request { id: u64 }`, `Edit { name: String }`, `Policy { name: String }`.
  - `FromPage`, serde tag `type`, snake_case, `deny_unknown_fields`:
    - `Ready`, `Unlock { passphrase: SecretText }`, `DeviceUnlock`, `Decide { id: u64, verdict: Verdict }`;
    - `OpenForm { form: FormRequest }`, `SubmitForm { values: BTreeMap<String, SecretText> }`, `CloseForm`;
    - `Dismiss { id: u64 }`, `Remove { name: String }`, `Lock`, `Tab { tab: Tab }`.
  - `FromPage::parse(&str) -> Option<FromPage>`.
  - `ToPage`, Serialize, serde tag `type`:
    - `State { locked: bool, device: Option<String>, waiting_for_device: bool, overview: Option<Overview> }`;
    - `Show { tab }`, `Form { view: FormView }`, `FormError { message }`, `FormDone`;
    - `Audit { entries: Vec<Entry> }`, `Message { text: String, request: Option<u64> }`.
  - `ToPage::script(&self) -> String`, which returns `kv.receive(<json>)`.
  - `audit::Entry` gains `Serialize`.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv/tests/tray_window.rs b/crates/kv/tests/tray_window.rs
new file mode 100644
index 0000000000000000000000000000000000000000..a4245b20d22c798391caebc037597385b52e3b18
--- /dev/null
+++ b/crates/kv/tests/tray_window.rs
@@ -0,0 +1,170 @@
+//! What the `kv tray` window's page and the tray say to each other: the
+//! JSON the page sends is read into `FromPage` or dropped, and `ToPage`
+//! becomes the script the window runs.
+
+use std::collections::BTreeMap;
+
+use kv::audit::Entry;
+use kv::tray::window::{FormRequest, FromPage, Tab, ToPage};
+use kv_core::proto::Verdict;
+use kv_core::secret::SecretText;
+
+#[test]
+fn what_the_page_sends_is_read() {
+    let cases = [
+        (r#"{"type":"ready"}"#, FromPage::Ready),
+        (
+            r#"{"type":"unlock","passphrase":"correct horse"}"#,
+            FromPage::Unlock {
+                passphrase: SecretText::new("correct horse"),
+            },
+        ),
+        (r#"{"type":"device_unlock"}"#, FromPage::DeviceUnlock),
+        (
+            r#"{"type":"decide","id":7,"verdict":"allow_session"}"#,
+            FromPage::Decide {
+                id: 7,
+                verdict: Verdict::AllowSession,
+            },
+        ),
+        (
+            r#"{"type":"open_form","form":{"kind":"new"}}"#,
+            FromPage::OpenForm {
+                form: FormRequest::New,
+            },
+        ),
+        (
+            r#"{"type":"open_form","form":{"kind":"request","id":3}}"#,
+            FromPage::OpenForm {
+                form: FormRequest::Request { id: 3 },
+            },
+        ),
+        (
+            r#"{"type":"open_form","form":{"kind":"edit","name":"github"}}"#,
+            FromPage::OpenForm {
+                form: FormRequest::Edit {
+                    name: "github".into(),
+                },
+            },
+        ),
+        (
+            r#"{"type":"open_form","form":{"kind":"policy","name":"github"}}"#,
+            FromPage::OpenForm {
+                form: FormRequest::Policy {
+                    name: "github".into(),
+                },
+            },
+        ),
+        (
+            r#"{"type":"submit_form","values":{"name":"a","token":"t"}}"#,
+            FromPage::SubmitForm {
+                values: BTreeMap::from([
+                    ("name".to_owned(), SecretText::new("a")),
+                    ("token".to_owned(), SecretText::new("t")),
+                ]),
+            },
+        ),
+        (r#"{"type":"close_form"}"#, FromPage::CloseForm),
+        (r#"{"type":"dismiss","id":2}"#, FromPage::Dismiss { id: 2 }),
+        (
+            r#"{"type":"remove","name":"github"}"#,
+            FromPage::Remove {
+                name: "github".into(),
+            },
+        ),
+        (r#"{"type":"lock"}"#, FromPage::Lock),
+        (
+            r#"{"type":"tab","tab":"audit"}"#,
+            FromPage::Tab { tab: Tab::Audit },
+        ),
+    ];
+    for (json, expected) in cases {
+        assert_eq!(FromPage::parse(json), Some(expected), "{json}");
+    }
+}
+
+#[test]
+fn anything_else_is_dropped() {
+    for json in [
+        "",
+        "{",
+        "null",
+        r#"{"type":"nope"}"#,
+        r#"{"type":"decide","id":"7","verdict":"allow_once"}"#,
+        r#"{"type":"decide","id":7,"verdict":"allow_forever"}"#,
+        r#"{"type":"tab","tab":"settings"}"#,
+        r#"{"type":"dismiss","id":2,"extra":1}"#,
+        r#"{"type":"open_form","form":{"kind":"edit"}}"#,
+        r#"{"passphrase":"x"}"#,
+    ] {
+        assert_eq!(FromPage::parse(json), None, "{json}");
+    }
+}
+
+#[test]
+fn a_passphrase_never_shows_in_debug_output() {
+    let unlock = FromPage::parse(r#"{"type":"unlock","passphrase":"hunter2-secret"}"#).unwrap();
+    assert!(!format!("{unlock:?}").contains("hunter2"), "{unlock:?}");
+    let form = FromPage::parse(r#"{"type":"submit_form","values":{"token":"sk-12345"}}"#).unwrap();
+    assert!(!format!("{form:?}").contains("sk-12345"), "{form:?}");
+}
+
+#[test]
+fn what_the_tray_sends_is_a_call_to_kv_receive() {
+    let show = ToPage::Show { tab: Tab::Handles };
+    assert_eq!(
+        show.script(),
+        r#"kv.receive({"type":"show","tab":"handles"})"#
+    );
+    let message = ToPage::Message {
+        text: "that request is no longer waiting for approval".into(),
+        request: Some(4),
+    };
+    assert_eq!(
+        message.script(),
+        r#"kv.receive({"type":"message","text":"that request is no longer waiting for approval","request":4})"#
+    );
+    let audit = ToPage::Audit {
+        entries: vec![Entry {
+            ts: "2026-10-12T10:00:00Z".into(),
+            socket: "agent".into(),
+            action: "http_request".into(),
+            handle: Some("github".into()),
+            decision: Some("approved".into()),
+            summary: Some("GET https://api.github.com/user".into()),
+            outcome: "ok".into(),
+            duration_ms: Some(12),
+        }],
+    };
+    let script = audit.script();
+    assert!(
+        script.starts_with(r#"kv.receive({"type":"audit","entries":[{"ts":"#),
+        "{script}"
+    );
+    let locked = ToPage::State {
+        locked: true,
+        device: Some("Touch ID".into()),
+        waiting_for_device: false,
+        overview: None,
+    };
+    assert_eq!(
+        locked.script(),
+        r#"kv.receive({"type":"state","locked":true,"device":"Touch ID","waiting_for_device":false,"overview":null})"#
+    );
+}
+
+/// Agent text is only ever data inside the JSON, however it is written.
+#[test]
+fn agent_text_cannot_end_the_call() {
+    let message = ToPage::Message {
+        text: "\"});alert(1);({\"a\":\"\u{2028}</script>".into(),
+        request: None,
+    };
+    let script = message.script();
+    let json = script
+        .strip_prefix("kv.receive(")
+        .and_then(|s| s.strip_suffix(')'))
+        .unwrap();
+    let back: serde_json::Value = serde_json::from_str(json).unwrap();
+    assert_eq!(back["text"], "\"});alert(1);({\"a\":\"\u{2028}</script>");
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv --test tray_window`
Expected: `error[E0432]: unresolved import kv::tray::window`.

- [ ] **Step 3: Implement**

Apply with `git apply`:

```diff
diff --git a/crates/kv/src/audit.rs b/crates/kv/src/audit.rs
index 3b89aa7ca72f472a7ca1c857c6db3d09b3f7002a..dadaf87bf2d59856a82a6c5ef98408ddbaa35c5a 100644
--- a/crates/kv/src/audit.rs
+++ b/crates/kv/src/audit.rs
@@ -132,7 +132,7 @@ impl Audit {
 }
 
 /// One line of the audit log, as `kv tui` shows it.
-#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
 pub struct Entry {
     pub ts: String,
     pub socket: String,
diff --git a/crates/kv/src/tray.rs b/crates/kv/src/tray.rs
index 20c8a51bc3bccd18285f2b565733bf8e5658ff98..a147c2dd96c4bdb41e279413e0f88b08e25a7d03 100644
--- a/crates/kv/src/tray.rs
+++ b/crates/kv/src/tray.rs
@@ -7,6 +7,7 @@ pub mod login;
 pub mod model;
 #[cfg(any(target_os = "macos", windows))]
 mod ui;
+pub mod window;
 pub mod worker;
 
 use std::fs::{File, TryLockError};
diff --git a/crates/kv/src/tray/window.rs b/crates/kv/src/tray/window.rs
new file mode 100644
index 0000000000000000000000000000000000000000..5dbcd2cd7e4a1e153256c96e542634d511747013
--- /dev/null
+++ b/crates/kv/src/tray/window.rs
@@ -0,0 +1,124 @@
+//! What kv's window and the tray say to each other. The page sends JSON
+//! that is read into `FromPage` or dropped; the tray answers with `ToPage`,
+//! run in the page as a call to `kv.receive`. Nothing here touches the UI.
+
+use std::collections::BTreeMap;
+
+use kv_core::proto::{Overview, Verdict};
+use kv_core::secret::SecretText;
+use serde::{Deserialize, Serialize};
+
+use crate::audit::Entry;
+use crate::forms::FormView;
+
+/// The window's tabs.
+#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
+#[serde(rename_all = "snake_case")]
+pub enum Tab {
+    Approvals,
+    Handles,
+    Audit,
+}
+
+/// The form the page asks to open.
+#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
+#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
+pub enum FormRequest {
+    New,
+    /// Fill in an agent's handle request.
+    Request {
+        id: u64,
+    },
+    Edit {
+        name: String,
+    },
+    Policy {
+        name: String,
+    },
+}
+
+/// A message from the page. Passphrases and secret values are `SecretText`
+/// from the moment they are read.
+#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
+#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
+pub enum FromPage {
+    /// The page has loaded and wants the current state.
+    Ready,
+    Unlock {
+        passphrase: SecretText,
+    },
+    DeviceUnlock,
+    Decide {
+        id: u64,
+        verdict: Verdict,
+    },
+    OpenForm {
+        form: FormRequest,
+    },
+    SubmitForm {
+        values: BTreeMap<String, SecretText>,
+    },
+    CloseForm,
+    Dismiss {
+        id: u64,
+    },
+    Remove {
+        name: String,
+    },
+    Lock,
+    Tab {
+        tab: Tab,
+    },
+}
+
+impl FromPage {
+    /// The message in `json`, or `None` for anything that is not one.
+    pub fn parse(json: &str) -> Option<FromPage> {
+        serde_json::from_str(json).ok()
+    }
+}
+
+/// A message to the page.
+#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
+#[serde(tag = "type", rename_all = "snake_case")]
+pub enum ToPage {
+    /// Sent every tick while the window is open.
+    State {
+        locked: bool,
+        /// The device the vault has a slot for on this platform, such as
+        /// "Touch ID".
+        device: Option<String>,
+        waiting_for_device: bool,
+        /// `Some` while the tray holds a session.
+        overview: Option<Overview>,
+    },
+    Show {
+        tab: Tab,
+    },
+    /// A form to draw, with no secret text in it.
+    Form {
+        view: FormView,
+    },
+    FormError {
+        message: String,
+    },
+    FormDone,
+    Audit {
+        entries: Vec<Entry>,
+    },
+    /// What an action from the window came to; `request` names the card it
+    /// belongs on.
+    Message {
+        text: String,
+        request: Option<u64>,
+    },
+}
+
+impl ToPage {
+    /// The script that hands this message to the page. The message is only
+    /// ever JSON data inside the call.
+    pub fn script(&self) -> String {
+        let json = serde_json::to_string(self).expect("a ToPage always serializes");
+        format!("kv.receive({json})")
+    }
+}
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv --test tray_window && cargo clippy -p kv --all-targets -- -D warnings`
Expected: PASS: 5 `tray_window` tests, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add the protocol between kv's window and the tray"
```

### Task 3: The menu opens kv's window

**Files:**
- Modify: `crates/kv/tests/tray_model.rs`
- Modify: `crates/kv/tests/tray_worker.rs`
- Modify: `crates/kv/src/tray/model.rs`
- Modify: `crates/kv/src/tray/worker.rs`

**Interfaces:**
- Consumes: `tray::window::Tab` (Task 2).
- Produces:
  - `model::Action` loses `OpenTui` and `HandleRequests` and gains `Open(Tab)`, with ids `open:approvals`, `open:handles` and `open:audit`.
  - Labels:
    - Locked with a device slot: "Unlock with Touch ID" and "Open kv…" (`Open(Tab::Approvals)`).
    - Locked with no slot: "Unlock…" (`Open(Tab::Approvals)`).
    - No vault: the text line, then "Open kv…".
    - Unlocked: "N handle requests: open kv…" (`Open(Tab::Handles)`) and "Open kv…".
  - The worker still sends `Open(_)` to `Desktop::open_tui` until Task 4.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv/tests/tray_model.rs b/crates/kv/tests/tray_model.rs
index b2a08ca710fd4bbde3eee4046cc301782c42f6f7..986104cbf2af8105e25d05ad971e5be8357c06d0 100644
--- a/crates/kv/tests/tray_model.rs
+++ b/crates/kv/tests/tray_model.rs
@@ -2,6 +2,7 @@
 //! in, the icon, its tooltip and the menu come out.
 
 use kv::tray::model::{Action, Edit, IconState, Item, Model, View, edits, one_line, same_shape};
+use kv::tray::window::Tab;
 use kv_core::proto::{Approval, Overview, RequestedHandle, Status, Verdict};
 use kv_core::vault::DeviceKind;
 
@@ -106,7 +107,7 @@ fn without_a_session_the_menu_offers_to_unlock() {
         labels(&model.menu),
         [
             "Unlock with Touch ID",
-            "Open kv tui",
+            "Open kv…",
             "--",
             "Start at login",
             "Quit kv tray"
@@ -118,19 +119,19 @@ fn without_a_session_the_menu_offers_to_unlock() {
     });
     assert_eq!(labels(&hello.menu)[0], "Unlock with Windows Hello");
 
-    // No device slot: the passphrase is only typed into a terminal.
+    // No device slot: kv's window asks for the passphrase.
     let model = Model::new(View {
         device: None,
         ..view(Some(&locked), None)
     });
     assert_eq!(
         labels(&model.menu),
-        ["Unlock in kv tui", "--", "Start at login", "Quit kv tray"]
+        ["Unlock…", "--", "Start at login", "Quit kv tray"]
     );
     assert!(matches!(
         &model.menu[0],
         Item::Action {
-            action: Action::OpenTui,
+            action: Action::Open(Tab::Approvals),
             ..
         }
     ));
@@ -142,7 +143,10 @@ fn without_a_session_the_menu_offers_to_unlock() {
     let mut fresh = status(true, 0);
     fresh.vault_exists = false;
     let model = Model::new(view(Some(&fresh), None));
-    assert_eq!(labels(&model.menu)[0], "(No vault yet: run `kv init`)");
+    assert_eq!(
+        labels(&model.menu)[..2],
+        ["(No vault yet: run `kv init`)", "Open kv…"]
+    );
 }
 
 #[test]
@@ -159,7 +163,7 @@ fn each_waiting_request_has_its_answers() {
             "> agent · http_request · openrouter",
             "--",
             "Lock vault",
-            "Open kv tui",
+            "Open kv…",
             "--",
             "Start at login",
             "Quit kv tray"
@@ -236,15 +240,25 @@ fn with_a_session_and_nothing_waiting_the_menu_says_so() {
     let model = Model::new(view(Some(&overview.status), Some(&overview)));
     assert_eq!(
         labels(&model.menu)[..2],
-        ["(No requests waiting)", "2 handle requests: open kv tui"]
+        ["(No requests waiting)", "2 handle requests: open kv…"]
     );
     assert!(matches!(
         &model.menu[1],
         Item::Action {
-            action: Action::HandleRequests,
+            action: Action::Open(Tab::Handles),
             ..
         }
     ));
+    assert!(matches!(
+        model
+            .menu
+            .iter()
+            .find(|item| matches!(item, Item::Action { label, .. } if label == "Open kv…")),
+        Some(Item::Action {
+            action: Action::Open(Tab::Approvals),
+            ..
+        })
+    ));
 }
 
 #[test]
@@ -285,6 +299,12 @@ fn ids_are_unique_and_lead_back_to_the_same_action() {
     );
     assert_eq!(Action::from_id("decide:9:sideways"), None);
     assert_eq!(Action::from_id("request:7"), None);
+    assert_eq!(Action::Open(Tab::Handles).id(), "open:handles");
+    assert_eq!(
+        Action::from_id("open:audit"),
+        Some(Action::Open(Tab::Audit))
+    );
+    assert_eq!(Action::from_id("open:settings"), None);
 
     // The checkbox turns the login item off when it is on.
     let check = model
diff --git a/crates/kv/tests/tray_worker.rs b/crates/kv/tests/tray_worker.rs
index ea438ca71952ecf34784573325587a88c41ad83e..1a686962ae4dd6a497255f345f514a47d91f0c58 100644
--- a/crates/kv/tests/tray_worker.rs
+++ b/crates/kv/tests/tray_worker.rs
@@ -12,6 +12,7 @@ use fake::Fake;
 use kv::device::{self, Device};
 use kv::paths::Paths;
 use kv::tray::model::{Action, IconState, Item, Model};
+use kv::tray::window::Tab;
 use kv::tray::worker::{Desktop, Worker};
 use kv_core::proto::{AgentErrorCode, AgentResponse, ControlCommand, Verdict};
 use live::{Daemon, PASS};
@@ -243,8 +244,8 @@ async fn a_stopped_daemon_ends_the_session() {
 #[tokio::test(flavor = "multi_thread")]
 async fn the_tui_and_the_login_item_go_to_the_desktop() {
     let (_daemon, _fake, desk, mut worker) = locked().await;
-    assert!(!worker.act(Action::OpenTui).await);
-    assert!(!worker.act(Action::HandleRequests).await);
+    assert!(!worker.act(Action::Open(Tab::Approvals)).await);
+    assert!(!worker.act(Action::Open(Tab::Handles)).await);
     assert_eq!(*desk.tuis.lock().unwrap(), 2);
 
     assert!(!worker.act(Action::Login(true)).await);
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv --test tray_model --test tray_worker`
Expected: both fail to compile with `error[E0599]: no variant, associated function, or constant named Open found for enum kv::tray::model::Action`.

- [ ] **Step 3: Implement**

Apply with `git apply`:

```diff
diff --git a/crates/kv/src/tray/model.rs b/crates/kv/src/tray/model.rs
index e3e463183aad7552e0fbc6eeb17cbc4717c779d9..1bff08a0c62baacfe9ca38c51f6add11b3112d74 100644
--- a/crates/kv/src/tray/model.rs
+++ b/crates/kv/src/tray/model.rs
@@ -5,6 +5,8 @@
 use kv_core::proto::{Approval, Overview, Status, Verdict};
 use kv_core::vault::DeviceKind;
 
+use super::window::Tab;
+
 /// How long a request's label may be.
 const LABEL_LEN: usize = 60;
 /// How long a line of a request's detail may be.
@@ -25,10 +27,8 @@ pub enum IconState {
 pub enum Action {
     /// Touch ID or Windows Hello, then a session.
     Unlock,
-    /// A terminal running `kv tui`.
-    OpenTui,
-    /// `kv tui`, where agents' handle requests are answered.
-    HandleRequests,
+    /// kv's window, on this tab once unlocked, or on its unlock screen.
+    Open(Tab),
     Lock,
     /// Turns the login item on or off.
     Login(bool),
@@ -45,8 +45,9 @@ impl Action {
     pub fn id(&self) -> String {
         match self {
             Action::Unlock => "unlock".into(),
-            Action::OpenTui => "tui".into(),
-            Action::HandleRequests => "handle-requests".into(),
+            Action::Open(Tab::Approvals) => "open:approvals".into(),
+            Action::Open(Tab::Handles) => "open:handles".into(),
+            Action::Open(Tab::Audit) => "open:audit".into(),
             Action::Lock => "lock".into(),
             Action::Login(true) => "login:on".into(),
             Action::Login(false) => "login:off".into(),
@@ -58,8 +59,9 @@ impl Action {
     pub fn from_id(id: &str) -> Option<Action> {
         Some(match id {
             "unlock" => Action::Unlock,
-            "tui" => Action::OpenTui,
-            "handle-requests" => Action::HandleRequests,
+            "open:approvals" => Action::Open(Tab::Approvals),
+            "open:handles" => Action::Open(Tab::Handles),
+            "open:audit" => Action::Open(Tab::Audit),
             "lock" => Action::Lock,
             "login:on" => Action::Login(true),
             "login:off" => Action::Login(false),
@@ -182,16 +184,16 @@ fn locked_menu(view: &View) -> Vec<Item> {
     if view.status.is_some_and(|s| !s.vault_exists) {
         return vec![
             Item::Text("No vault yet: run `kv init`".into()),
-            action("Open kv tui", Action::OpenTui),
+            action("Open kv…", Action::Open(Tab::Approvals)),
         ];
     }
     match view.device {
         Some(device) => vec![
             action(&format!("Unlock with {}", device.label()), Action::Unlock),
-            action("Open kv tui", Action::OpenTui),
+            action("Open kv…", Action::Open(Tab::Approvals)),
         ],
-        // The passphrase is only ever typed into a terminal.
-        None => vec![action("Unlock in kv tui", Action::OpenTui)],
+        // kv's window asks for the passphrase.
+        None => vec![action("Unlock…", Action::Open(Tab::Approvals))],
     }
 }
 
@@ -203,17 +205,17 @@ fn unlocked_menu(overview: &Overview) -> Vec<Item> {
     match overview.handle_requests.len() {
         0 => {}
         1 => menu.push(action(
-            "1 handle request: open kv tui",
-            Action::HandleRequests,
+            "1 handle request: open kv…",
+            Action::Open(Tab::Handles),
         )),
         n => menu.push(action(
-            &format!("{n} handle requests: open kv tui"),
-            Action::HandleRequests,
+            &format!("{n} handle requests: open kv…"),
+            Action::Open(Tab::Handles),
         )),
     }
     menu.push(Item::Separator);
     menu.push(action("Lock vault", Action::Lock));
-    menu.push(action("Open kv tui", Action::OpenTui));
+    menu.push(action("Open kv…", Action::Open(Tab::Approvals)));
     menu
 }
 
diff --git a/crates/kv/src/tray/worker.rs b/crates/kv/src/tray/worker.rs
index 0629d3065fc6acd9fbec9fe633cc9d0faa91e7ee..6935386d10243f893a4f108e25a796d4c7ac4163 100644
--- a/crates/kv/src/tray/worker.rs
+++ b/crates/kv/src/tray/worker.rs
@@ -81,7 +81,7 @@ impl<D: Desktop> Worker<D> {
                 let outcome = self.driver.run(Effect::Lock).await;
                 self.report(outcome);
             }
-            Action::OpenTui | Action::HandleRequests => {
+            Action::Open(_) => {
                 if let Err(e) = self.desktop.open_tui() {
                     self.desktop.notify(&format!("Could not open kv tui: {e}"));
                 }
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv --test tray_model --test tray_worker && cargo clippy -p kv --all-targets -- -D warnings`
Expected: PASS: 10 `tray_model` tests and 10 `tray_worker` tests, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Point the tray's menu at kv's window instead of kv tui"
```

### Task 4: The worker drives kv's window

**Files:**
- Modify: `crates/kv/tests/tray_worker.rs`
- Modify: `crates/kv/src/tray.rs`
- Modify: `crates/kv/src/tray/model.rs`
- Modify: `crates/kv/src/tray/ui.rs`
- Modify: `crates/kv/src/tray/worker.rs`
- Modify: `crates/kv/src/tui.rs`
- Modify: `crates/kv/tests/tray.rs`

**Interfaces:**
- Consumes:
  - From Task 1: `forms::{describe, fill, submit, new_handle, requested_handle, edit_handle, edit_policy, Purpose, Form}`.
  - From Task 2: `window::{FromPage, ToPage, Tab, FormRequest}`.
  - From Task 3: `Action::Open(Tab)`.
  - `tui::Driver::{run, ask_device, finish_device, refresh, audit, device}`.
- Produces:
  - `Desktop` loses `open_tui` and gains `show_window(&self, Tab)` and `page(&self, ToPage)`.
  - `Action` gains `Window(FromPage)` and `WindowClosed`. Neither ever sits on a menu: `id()` gives `window` and `window-closed`, which `from_id` never reads.
  - `tui::Driver::has_session(&self) -> bool`.
  - `Worker::model()` now also sends the window a `State` each tick while it is open, and an `Audit` on the Audit tab. It drops the open form when the session is gone.
  - `Worker::act` and `Worker::run` handle every `FromPage`. Failures from the window go back as `ToPage::Message`, or `FormError` beside a form; failures from the menu stay notifications.
  - `tray::tui_command` and its tests are removed. `ui::System` gets do-nothing `show_window` and `page` until Task 5.

- [ ] **Step 1: Write the failing tests**

The fake desktop now records the windows it was asked to show and every page message. The old "opens kv tui" test becomes `the_window_and_the_login_item_go_to_the_desktop`.

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv/tests/tray_worker.rs b/crates/kv/tests/tray_worker.rs
index 1a686962ae4dd6a497255f345f514a47d91f0c58..d678e067def3b4c9b5ac57d450dbc43402dbdb07 100644
--- a/crates/kv/tests/tray_worker.rs
+++ b/crates/kv/tests/tray_worker.rs
@@ -1,20 +1,27 @@
 //! The worker behind `kv tray`, against a daemon running in this process,
-//! a fake Touch ID and a desktop that records what it was asked to do.
+//! a fake Touch ID and a desktop that records what it was asked to do,
+//! including every message to the window's page.
 
 mod fake;
 mod live;
 
+use std::collections::BTreeMap;
 use std::io;
 use std::sync::{Arc, Mutex};
 use std::time::{Duration, Instant};
 
 use fake::Fake;
+use kv::client;
 use kv::device::{self, Device};
 use kv::paths::Paths;
 use kv::tray::model::{Action, IconState, Item, Model};
-use kv::tray::window::Tab;
+use kv::tray::window::{FormRequest, FromPage, Tab, ToPage};
 use kv::tray::worker::{Desktop, Worker};
-use kv_core::proto::{AgentErrorCode, AgentResponse, ControlCommand, Verdict};
+use kv_core::proto::{
+    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, HandleRequest, Overview,
+    SessionInfo, Verdict,
+};
+use kv_core::secret::{SecretKind, SecretText};
 use live::{Daemon, PASS};
 use tempfile::TempDir;
 
@@ -23,7 +30,8 @@ const REASON: &str = "open kv tray, where you approve agent requests";
 #[derive(Clone, Default)]
 struct Desk {
     notes: Arc<Mutex<Vec<String>>>,
-    tuis: Arc<Mutex<usize>>,
+    windows: Arc<Mutex<Vec<Tab>>>,
+    pages: Arc<Mutex<Vec<ToPage>>>,
     login: Arc<Mutex<bool>>,
 }
 
@@ -32,9 +40,12 @@ impl Desktop for Desk {
         self.notes.lock().unwrap().push(text.to_owned());
     }
 
-    fn open_tui(&self) -> io::Result<()> {
-        *self.tuis.lock().unwrap() += 1;
-        Ok(())
+    fn show_window(&self, tab: Tab) {
+        self.windows.lock().unwrap().push(tab);
+    }
+
+    fn page(&self, message: ToPage) {
+        self.pages.lock().unwrap().push(message);
     }
 
     fn login_is_on(&self) -> bool {
@@ -51,6 +62,85 @@ impl Desk {
     fn notes(&self) -> Vec<String> {
         self.notes.lock().unwrap().clone()
     }
+
+    /// The page messages since the last call.
+    fn take(&self) -> Vec<ToPage> {
+        std::mem::take(&mut *self.pages.lock().unwrap())
+    }
+}
+
+/// The last `State` in `pages`: whether locked, whether waiting for the
+/// device, and the overview.
+fn state(pages: &[ToPage]) -> (bool, bool, Option<Overview>) {
+    pages
+        .iter()
+        .rev()
+        .find_map(|page| match page {
+            ToPage::State {
+                locked,
+                waiting_for_device,
+                overview,
+                ..
+            } => Some((*locked, *waiting_for_device, overview.clone())),
+            _ => None,
+        })
+        .unwrap_or_else(|| panic!("no state in {pages:?}"))
+}
+
+fn messages(pages: &[ToPage]) -> Vec<(String, Option<u64>)> {
+    pages
+        .iter()
+        .filter_map(|page| match page {
+            ToPage::Message { text, request } => Some((text.clone(), *request)),
+            _ => None,
+        })
+        .collect()
+}
+
+fn page(message: FromPage) -> Action {
+    Action::Window(message)
+}
+
+fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, SecretText> {
+    pairs
+        .iter()
+        .map(|(key, value)| ((*key).to_owned(), SecretText::new(*value)))
+        .collect()
+}
+
+/// The handle names the last state's overview lists.
+async fn handles(worker: &mut Worker<Desk>, desk: &Desk) -> Vec<String> {
+    worker.model().await;
+    let (_, _, overview) = state(&desk.take());
+    overview
+        .expect("a session")
+        .handles
+        .into_iter()
+        .map(|handle| handle.name)
+        .collect()
+}
+
+/// What an agent's `request_handle` sends.
+async fn request_handle(daemon: &Daemon, name: &str) {
+    let session = SessionInfo {
+        id: "session-1".into(),
+        client: "tray test".into(),
+    };
+    let request = AgentRequest::RequestHandle(HandleRequest {
+        name: name.into(),
+        kind: SecretKind::Http,
+        description: "Staging API".into(),
+        reason: "to check the staging deploy".into(),
+        auth: None,
+        base_url: false,
+        allowed_hosts: vec!["staging.example.com".into()],
+        env_vars: Vec::new(),
+        allowed_cmds: Vec::new(),
+    });
+    let response = client::agent(&daemon.paths, Some(&session), &request)
+        .await
+        .unwrap();
+    assert_eq!(response, AgentResponse::Requested { name: name.into() });
 }
 
 /// A daemon with Touch ID set up and the vault locked, and a worker for it.
@@ -242,11 +332,19 @@ async fn a_stopped_daemon_ends_the_session() {
 }
 
 #[tokio::test(flavor = "multi_thread")]
-async fn the_tui_and_the_login_item_go_to_the_desktop() {
-    let (_daemon, _fake, desk, mut worker) = locked().await;
+async fn the_window_and_the_login_item_go_to_the_desktop() {
+    let (_daemon, _fake, desk, mut worker) = unlocked().await;
     assert!(!worker.act(Action::Open(Tab::Approvals)).await);
     assert!(!worker.act(Action::Open(Tab::Handles)).await);
-    assert_eq!(*desk.tuis.lock().unwrap(), 2);
+    assert_eq!(
+        *desk.windows.lock().unwrap(),
+        [Tab::Approvals, Tab::Handles]
+    );
+    let pages = desk.take();
+    assert!(
+        pages.contains(&ToPage::Show { tab: Tab::Handles }),
+        "{pages:?}"
+    );
 
     assert!(!worker.act(Action::Login(true)).await);
     assert!(*desk.login.lock().unwrap());
@@ -313,3 +411,390 @@ async fn the_loop_keeps_showing_while_the_prompt_is_open() {
         .expect("the loop stops on Quit")
         .unwrap();
 }
+
+/// Opening the window while locked asks for Touch ID once; a cancelled
+/// prompt says why in the window, not in a notification, and the window can
+/// ask again.
+#[tokio::test(flavor = "multi_thread")]
+async fn the_window_asks_for_touch_id_when_it_opens() {
+    let (_daemon, fake, desk, mut worker) = locked().await;
+    let key = fake.keys.lock().unwrap().clone();
+    fake.keys.lock().unwrap().clear();
+    assert!(!worker.act(Action::Open(Tab::Approvals)).await);
+    assert_eq!(fake.reasons.lock().unwrap().len(), 1);
+    let pages = desk.take();
+    let said = messages(&pages);
+    assert_eq!(said.len(), 1, "{pages:?}");
+    assert!(said[0].0.starts_with("Touch ID: "), "{said:?}");
+    assert_eq!(desk.notes(), Vec::<String>::new());
+
+    // Already open: no second prompt.
+    assert!(!worker.act(Action::Open(Tab::Approvals)).await);
+    assert_eq!(fake.reasons.lock().unwrap().len(), 1);
+
+    *fake.keys.lock().unwrap() = key;
+    assert!(!worker.act(page(FromPage::DeviceUnlock)).await);
+    assert_eq!(fake.reasons.lock().unwrap().len(), 2);
+    worker.model().await;
+    let (locked, waiting, overview) = state(&desk.take());
+    assert!(!locked && !waiting && overview.is_some());
+}
+
+#[tokio::test(flavor = "multi_thread")]
+async fn the_passphrase_typed_in_the_window_unlocks() {
+    let (daemon, _fake, _desk, _worker) = locked().await;
+    let desk = Desk::default();
+    let mut worker = Worker::new(daemon.paths.clone(), None, desk.clone());
+    // No device: the window opens on the passphrase field, asking nothing.
+    assert!(!worker.act(Action::Open(Tab::Approvals)).await);
+    worker.model().await;
+    let pages = desk.take();
+    assert!(state(&pages).0, "{pages:?}");
+    assert!(messages(&pages).is_empty(), "{pages:?}");
+
+    let wrong = FromPage::Unlock {
+        passphrase: SecretText::new("not it"),
+    };
+    assert!(!worker.act(page(wrong)).await);
+    let pages = desk.take();
+    assert_eq!(
+        messages(&pages),
+        [("Wrong passphrase".to_owned(), None)],
+        "{pages:?}"
+    );
+
+    let right = FromPage::Unlock {
+        passphrase: SecretText::new(PASS),
+    };
+    assert!(!worker.act(page(right)).await);
+    assert_eq!(worker.model().await.icon, IconState::Unlocked);
+    assert!(!state(&desk.take()).0);
+    assert_eq!(desk.notes(), Vec::<String>::new());
+}
+
+#[tokio::test(flavor = "multi_thread")]
+async fn a_card_in_the_window_answers_its_request() {
+    let (daemon, _fake, desk, mut worker) = unlocked().await;
+    assert!(!worker.act(Action::Open(Tab::Approvals)).await);
+    let call = daemon.agent_call();
+    let Action::Decide { id, .. } = waiting(&mut worker, "Allow once").await else {
+        unreachable!()
+    };
+    let allow = FromPage::Decide {
+        id,
+        verdict: Verdict::AllowOnce,
+    };
+    assert!(!worker.act(page(allow)).await);
+    match call.await.unwrap() {
+        AgentResponse::Http(reply) => assert_eq!(reply.status, 200),
+        other => panic!("{other:?}"),
+    }
+
+    desk.take();
+    let gone = FromPage::Decide {
+        id: 999,
+        verdict: Verdict::Deny,
+    };
+    assert!(!worker.act(page(gone)).await);
+    let said = messages(&desk.take());
+    assert_eq!(said.len(), 1, "{said:?}");
+    assert!(
+        said[0].0.starts_with("That request is no longer waiting"),
+        "{said:?}"
+    );
+    assert_eq!(said[0].1, Some(999));
+    assert_eq!(desk.notes(), Vec::<String>::new());
+}
+
+#[tokio::test(flavor = "multi_thread")]
+async fn handles_are_added_edited_policed_and_removed_from_the_window() {
+    let (_daemon, _fake, desk, mut worker) = unlocked().await;
+    assert!(!worker.act(Action::Open(Tab::Handles)).await);
+    worker.model().await;
+    desk.take();
+
+    let open = |form| page(FromPage::OpenForm { form });
+    let submit = |pairs: &[(&str, &str)]| {
+        page(FromPage::SubmitForm {
+            values: values(pairs),
+        })
+    };
+    assert!(!worker.act(open(FormRequest::New)).await);
+    let pages = desk.take();
+    let Some(ToPage::Form { view }) = pages.last() else {
+        panic!("{pages:?}");
+    };
+    assert_eq!(view.title, "New handle");
+
+    // Rust checks the form: no token yet.
+    assert!(
+        !worker
+            .act(submit(&[("name", "github"), ("hosts", "api.github.com")]))
+            .await
+    );
+    let pages = desk.take();
+    assert!(
+        matches!(pages.as_slice(), [ToPage::FormError { .. }]),
+        "{pages:?}"
+    );
+    assert!(
+        !worker
+            .act(submit(&[
+                ("name", "github"),
+                ("hosts", "api.github.com"),
+                ("token", "ghp_secret"),
+            ]))
+            .await
+    );
+    assert!(desk.take().contains(&ToPage::FormDone));
+    assert!(handles(&mut worker, &desk).await.contains(&"github".into()));
+
+    assert!(
+        !worker
+            .act(open(FormRequest::Edit {
+                name: "github".into()
+            }))
+            .await
+    );
+    let pages = desk.take();
+    let Some(ToPage::Form { view }) = pages.last() else {
+        panic!("{pages:?}");
+    };
+    assert_eq!(view.title, "Edit github");
+    assert!(
+        !serde_json::to_string(view).unwrap().contains("ghp_secret"),
+        "{view:?}"
+    );
+    assert!(!worker.act(submit(&[("description", "GitHub API")])).await);
+    assert!(desk.take().contains(&ToPage::FormDone));
+
+    assert!(
+        !worker
+            .act(open(FormRequest::Policy {
+                name: "github".into()
+            }))
+            .await
+    );
+    assert!(!worker.act(submit(&[("mode", "deny")])).await);
+    assert!(desk.take().contains(&ToPage::FormDone));
+    worker.model().await;
+    let (_, _, overview) = state(&desk.take());
+    let github = overview
+        .unwrap()
+        .handles
+        .into_iter()
+        .find(|handle| handle.name == "github")
+        .unwrap();
+    assert_eq!(github.description, "GitHub API");
+    assert_eq!(github.mode, kv_core::policy::Mode::Deny);
+
+    assert!(
+        !worker
+            .act(page(FromPage::Remove {
+                name: "github".into()
+            }))
+            .await
+    );
+    assert!(!handles(&mut worker, &desk).await.contains(&"github".into()));
+    assert_eq!(desk.notes(), Vec::<String>::new());
+}
+
+#[tokio::test(flavor = "multi_thread")]
+async fn an_agents_handle_request_is_filled_in_or_dismissed_from_the_window() {
+    let (daemon, _fake, desk, mut worker) = unlocked().await;
+    assert!(!worker.act(Action::Open(Tab::Handles)).await);
+    request_handle(&daemon, "staging").await;
+    request_handle(&daemon, "other").await;
+    worker.model().await;
+    let (_, _, overview) = state(&desk.take());
+    let ids: Vec<(u64, String)> = overview
+        .unwrap()
+        .handle_requests
+        .into_iter()
+        .map(|r| (r.id, r.request.name))
+        .collect();
+    let id_of = |name: &str| ids.iter().find(|(_, n)| n == name).unwrap().0;
+
+    let fill = FromPage::OpenForm {
+        form: FormRequest::Request {
+            id: id_of("staging"),
+        },
+    };
+    assert!(!worker.act(page(fill)).await);
+    let pages = desk.take();
+    let Some(ToPage::Form { view }) = pages.last() else {
+        panic!("{pages:?}");
+    };
+    assert_eq!(view.focus.as_deref(), Some("token"));
+    let name = view.fields.iter().find(|f| f.key == "name").unwrap();
+    assert_eq!(name.value, "staging");
+    let submit = FromPage::SubmitForm {
+        values: values(&[("token", "t0ken")]),
+    };
+    assert!(!worker.act(page(submit)).await);
+    assert!(desk.take().contains(&ToPage::FormDone));
+
+    let dismiss = FromPage::Dismiss { id: id_of("other") };
+    assert!(!worker.act(page(dismiss)).await);
+    worker.model().await;
+    let (_, _, overview) = state(&desk.take());
+    let overview = overview.unwrap();
+    assert!(overview.handle_requests.is_empty(), "{overview:?}");
+    assert!(overview.handles.iter().any(|h| h.name == "staging"));
+}
+
+#[tokio::test(flavor = "multi_thread")]
+async fn the_audit_log_goes_to_the_window_only_on_its_tab() {
+    let (_daemon, _fake, desk, mut worker) = unlocked().await;
+    let audits = |pages: &[ToPage]| {
+        pages
+            .iter()
+            .filter(|page| matches!(page, ToPage::Audit { .. }))
+            .count()
+    };
+    assert!(!worker.act(Action::Open(Tab::Approvals)).await);
+    worker.model().await;
+    assert_eq!(audits(&desk.take()), 0);
+    assert!(!worker.act(page(FromPage::Tab { tab: Tab::Audit })).await);
+    assert_eq!(audits(&desk.take()), 1);
+    worker.model().await;
+    assert_eq!(audits(&desk.take()), 1);
+}
+
+/// A lock from anywhere sends the locked state and drops the open form with
+/// what was typed into it.
+#[tokio::test(flavor = "multi_thread")]
+async fn a_lock_elsewhere_drops_the_open_form() {
+    let (daemon, _fake, desk, mut worker) = unlocked().await;
+    assert!(!worker.act(Action::Open(Tab::Handles)).await);
+    let new = FromPage::OpenForm {
+        form: FormRequest::New,
+    };
+    assert!(!worker.act(page(new)).await);
+    let pages = desk.take();
+    assert!(
+        pages.iter().any(|page| matches!(page, ToPage::Form { .. })),
+        "{pages:?}"
+    );
+    daemon.control(None, ControlCommand::Lock).await;
+    worker.model().await;
+    let pages = desk.take();
+    assert!(state(&pages).0, "{pages:?}");
+
+    // Unlocked again, the old form is gone: Ready brings no form back.
+    assert!(!worker.act(Action::Unlock).await);
+    assert!(!worker.act(page(FromPage::Ready)).await);
+    let pages = desk.take();
+    assert!(
+        !pages.iter().any(|page| matches!(page, ToPage::Form { .. })),
+        "{pages:?}"
+    );
+    let submit = FromPage::SubmitForm {
+        values: values(&[("name", "x"), ("token", "t")]),
+    };
+    assert!(!worker.act(page(submit)).await);
+    assert!(!desk.take().contains(&ToPage::FormDone));
+}
+
+/// A page that has just loaded gets the tab, the state and the open form.
+#[tokio::test(flavor = "multi_thread")]
+async fn a_page_that_loads_gets_everything() {
+    let (_daemon, _fake, desk, mut worker) = unlocked().await;
+    assert!(!worker.act(Action::Open(Tab::Handles)).await);
+    let new = FromPage::OpenForm {
+        form: FormRequest::New,
+    };
+    assert!(!worker.act(page(new)).await);
+    desk.take();
+    assert!(!worker.act(page(FromPage::Ready)).await);
+    let pages = desk.take();
+    assert!(
+        pages.contains(&ToPage::Show { tab: Tab::Handles }),
+        "{pages:?}"
+    );
+    assert!(!state(&pages).0);
+    assert!(
+        pages.iter().any(|page| matches!(page, ToPage::Form { .. })),
+        "{pages:?}"
+    );
+}
+
+/// Once closed, the window hears nothing and its form is gone; the session
+/// stays.
+#[tokio::test(flavor = "multi_thread")]
+async fn a_closed_window_hears_nothing() {
+    let (_daemon, _fake, desk, mut worker) = unlocked().await;
+    assert!(!worker.act(Action::Open(Tab::Handles)).await);
+    let new = FromPage::OpenForm {
+        form: FormRequest::New,
+    };
+    assert!(!worker.act(page(new)).await);
+    let pages = desk.take();
+    assert!(
+        pages.iter().any(|page| matches!(page, ToPage::Form { .. })),
+        "{pages:?}"
+    );
+    assert!(!worker.act(Action::WindowClosed).await);
+    desk.take();
+    assert_eq!(worker.model().await.icon, IconState::Unlocked);
+    assert!(desk.take().is_empty());
+
+    assert!(!worker.act(Action::Open(Tab::Handles)).await);
+    assert!(!worker.act(page(FromPage::Ready)).await);
+    let pages = desk.take();
+    assert!(
+        !pages.iter().any(|page| matches!(page, ToPage::Form { .. })),
+        "{pages:?}"
+    );
+}
+
+/// In the loop, the window's Touch ID prompt runs beside it, and the page
+/// is told it is waiting.
+#[tokio::test(flavor = "multi_thread")]
+async fn the_window_shows_it_is_waiting_for_touch_id() {
+    let (_daemon, fake, desk, worker) = locked().await;
+    let (release, gate) = std::sync::mpsc::channel();
+    *fake.gate.lock().unwrap() = Some(gate);
+    let (actions, inbox) = tokio::sync::mpsc::unbounded_channel();
+    let running = tokio::spawn(worker.run(inbox, |_| {}));
+    actions.send(Action::Open(Tab::Approvals)).unwrap();
+
+    let saw = |test: fn(&ToPage) -> bool| {
+        let pages = desk.pages.clone();
+        async move {
+            let deadline = Instant::now() + Duration::from_secs(5);
+            while !pages.lock().unwrap().iter().any(test) {
+                assert!(Instant::now() < deadline, "never sent it");
+                tokio::time::sleep(Duration::from_millis(20)).await;
+            }
+        }
+    };
+    saw(|page| {
+        matches!(
+            page,
+            ToPage::State {
+                locked: true,
+                waiting_for_device: true,
+                ..
+            }
+        )
+    })
+    .await;
+    release.send(()).unwrap();
+    saw(|page| {
+        matches!(
+            page,
+            ToPage::State {
+                locked: false,
+                waiting_for_device: false,
+                ..
+            }
+        )
+    })
+    .await;
+    actions.send(Action::Quit).unwrap();
+    tokio::time::timeout(Duration::from_secs(5), running)
+        .await
+        .expect("the loop stops on Quit")
+        .unwrap();
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv --test tray_worker`
Expected: fails to compile, with:
- `error[E0407]: method show_window is not a member of trait Desktop`
- `error[E0407]: method page is not a member of trait Desktop`
- `error[E0046]: not all trait items implemented, missing: open_tui`
- `error[E0599]` for `Action::Window` and `Action::WindowClosed`

- [ ] **Step 3: Implement**

The worker's new loop:

- `begin(action)` does an action and returns `Next::Done`, `Next::Prompt(Asker)` or `Next::Quit`.
- `act` (which tests call) awaits a prompt inline.
- `run` holds the prompt beside its loop and records who asked in `prompting`, which is also what `State.waiting_for_device` reports.

Apply with `git apply`:

```diff
diff --git a/crates/kv/src/tray.rs b/crates/kv/src/tray.rs
index a147c2dd96c4bdb41e279413e0f88b08e25a7d03..2108f1a888cf36ef4fb4797b9c3da086fc244854 100644
--- a/crates/kv/src/tray.rs
+++ b/crates/kv/src/tray.rs
@@ -1,6 +1,7 @@
 //! `kv tray`: a menu bar (macOS) or notification area (Windows) icon that
-//! shows waiting agent requests and answers them from its menu, after
-//! unlocking with Touch ID or Windows Hello.
+//! shows waiting agent requests and answers them from its menu, and kv's
+//! window, where the vault is unlocked and handles are managed without
+//! `kv tui`.
 
 pub mod icon;
 pub mod login;
@@ -12,10 +13,6 @@ pub mod worker;
 
 use std::fs::{File, TryLockError};
 use std::io;
-#[cfg(any(target_os = "macos", windows))]
-use std::path::Path;
-#[cfg(any(target_os = "macos", windows))]
-use std::process::Command;
 
 use crate::paths::Paths;
 
@@ -51,35 +48,3 @@ pub fn lock_single(paths: &Paths) -> io::Result<File> {
         Err(TryLockError::Error(e)) => Err(e),
     }
 }
-
-/// Opens a Terminal window running `<exe> tui`.
-#[cfg(target_os = "macos")]
-pub fn tui_command(exe: &Path) -> Command {
-    let shell = format!("'{}' tui", exe.to_string_lossy().replace('\'', r"'\''"));
-    let script = shell.replace('\\', r"\\").replace('"', r#"\""#);
-    let mut command = Command::new("osascript");
-    command.args([
-        "-e",
-        &format!(r#"tell application "Terminal" to do script "{script}""#),
-        "-e",
-        r#"tell application "Terminal" to activate"#,
-    ]);
-    command
-}
-
-/// Opens a console window running `<exe> tui`, in the user's default
-/// terminal.
-#[cfg(windows)]
-pub fn tui_command(exe: &Path) -> Command {
-    use std::os::windows::process::CommandExt;
-    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
-
-    let mut command = Command::new("cmd");
-    command
-        .args(["/c", "start", ""])
-        .arg(exe)
-        .arg("tui")
-        // `start` opens the window; cmd itself needs none.
-        .creation_flags(CREATE_NO_WINDOW);
-    command
-}
diff --git a/crates/kv/src/tray/model.rs b/crates/kv/src/tray/model.rs
index 1bff08a0c62baacfe9ca38c51f6add11b3112d74..1812b0cfc5b8f112a737d257a59b664efac70ee5 100644
--- a/crates/kv/src/tray/model.rs
+++ b/crates/kv/src/tray/model.rs
@@ -5,7 +5,7 @@
 use kv_core::proto::{Approval, Overview, Status, Verdict};
 use kv_core::vault::DeviceKind;
 
-use super::window::Tab;
+use super::window::{FromPage, Tab};
 
 /// How long a request's label may be.
 const LABEL_LEN: usize = 60;
@@ -29,6 +29,10 @@ pub enum Action {
     Unlock,
     /// kv's window, on this tab once unlocked, or on its unlock screen.
     Open(Tab),
+    /// A message from the window's page. Never on a menu.
+    Window(FromPage),
+    /// The user closed the window. Never on a menu.
+    WindowClosed,
     Lock,
     /// Turns the login item on or off.
     Login(bool),
@@ -48,6 +52,9 @@ impl Action {
             Action::Open(Tab::Approvals) => "open:approvals".into(),
             Action::Open(Tab::Handles) => "open:handles".into(),
             Action::Open(Tab::Audit) => "open:audit".into(),
+            // `from_id` reads neither, so no menu item can stand for them.
+            Action::Window(_) => "window".into(),
+            Action::WindowClosed => "window-closed".into(),
             Action::Lock => "lock".into(),
             Action::Login(true) => "login:on".into(),
             Action::Login(false) => "login:off".into(),
diff --git a/crates/kv/src/tray/ui.rs b/crates/kv/src/tray/ui.rs
index ea92d0f0a1f4d85c09cc1693676871ed62cde09f..028aae15f32df371d9ee2b1c61e57318b7f392d2 100644
--- a/crates/kv/src/tray/ui.rs
+++ b/crates/kv/src/tray/ui.rs
@@ -15,8 +15,9 @@ use tray_icon::menu::{
 use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
 
 use super::model::{Action, Edit, IconState, Item, Model, edits};
+use super::window::{Tab, ToPage};
 use super::worker::{Desktop, Worker};
-use super::{icon, login, tui_command};
+use super::{icon, login};
 use crate::device;
 use crate::notify;
 use crate::paths::Paths;
@@ -248,7 +249,7 @@ fn native(item: &Item) -> Native {
     }
 }
 
-/// The real desktop: notifications, a terminal, the login item.
+/// The real desktop: notifications, kv's window, the login item.
 struct System;
 
 impl Desktop for System {
@@ -256,11 +257,10 @@ impl Desktop for System {
         notify::tray(text.to_owned());
     }
 
-    fn open_tui(&self) -> io::Result<()> {
-        let mut child = tui_command(&std::env::current_exe()?).spawn()?;
-        std::thread::spawn(move || child.wait());
-        Ok(())
-    }
+    // Task 5 draws the window.
+    fn show_window(&self, _tab: Tab) {}
+
+    fn page(&self, _message: ToPage) {}
 
     fn login_is_on(&self) -> bool {
         login::is_on()
diff --git a/crates/kv/src/tray/worker.rs b/crates/kv/src/tray/worker.rs
index 6935386d10243f893a4f108e25a796d4c7ac4163..01856b745abe7576739fc18994238fb83a972ae3 100644
--- a/crates/kv/src/tray/worker.rs
+++ b/crates/kv/src/tray/worker.rs
@@ -1,18 +1,22 @@
 //! The tray's daemon side, on a tokio runtime of its own: reads the
-//! daemon's status every second, holds the session, and carries out what
-//! the menu asks for. Failures become notifications, since a menu cannot
-//! show a message.
+//! daemon's status every second, holds the session the menu and the window
+//! share, and carries out what they ask for. A failure is told where the
+//! user asked: in the window, or as a notification for the menu.
 
+use std::collections::BTreeMap;
 use std::io;
 use std::sync::Arc;
 use std::time::Duration;
 
-use kv_core::proto::{AgentRequest, AgentResponse};
+use kv_core::proto::{AgentRequest, AgentResponse, Overview};
+use kv_core::secret::SecretText;
 use tokio::sync::mpsc::UnboundedReceiver;
 
 use super::model::{Action, Model, View};
+use super::window::{FormRequest, FromPage, Tab, ToPage};
 use crate::client;
 use crate::device::Device;
+use crate::forms::{self, Form, Purpose};
 use crate::paths::Paths;
 use crate::tui::app::{Effect, Outcome};
 use crate::tui::{DeviceAnswer, Driver};
@@ -26,16 +30,45 @@ const REASON: &str = "open kv tray, where you approve agent requests";
 /// What the worker needs from the desktop around it.
 pub trait Desktop: Send {
     fn notify(&self, text: &str);
-    /// Opens a terminal running `kv tui`.
-    fn open_tui(&self) -> io::Result<()>;
+    /// Opens kv's window on `tab`, or brings it to the front on `tab`.
+    fn show_window(&self, tab: Tab);
+    /// Hands a message to the window's page.
+    fn page(&self, message: ToPage);
     fn login_is_on(&self) -> bool;
     fn set_login(&self, on: bool) -> io::Result<()>;
 }
 
+/// Who asked for something, and so hears how it went.
+#[derive(Clone, Copy, PartialEq, Eq)]
+enum Asker {
+    Menu,
+    Window,
+}
+
+/// What is left to do after an action.
+enum Next {
+    Done,
+    /// A device prompt, then a session.
+    Prompt(Asker),
+    Quit,
+}
+
+/// kv's window while it is open.
+struct Window {
+    tab: Tab,
+    /// The open form, and what saving it means.
+    form: Option<(Purpose, Form)>,
+}
+
 pub struct Worker<D> {
     paths: Paths,
     driver: Driver,
     desktop: D,
+    window: Option<Window>,
+    /// The overview of the last tick, which the forms open from.
+    overview: Option<Overview>,
+    /// Who is waiting on the device prompt `run` holds beside its loop.
+    prompting: Option<Asker>,
 }
 
 impl<D: Desktop> Worker<D> {
@@ -44,62 +77,60 @@ impl<D: Desktop> Worker<D> {
             driver: Driver::with_device(paths.clone(), device).with_reason(REASON),
             paths,
             desktop,
+            window: None,
+            overview: None,
+            prompting: None,
         }
     }
 
-    /// What the tray should show now. Reading the status never starts the
-    /// daemon; a session the daemon no longer knows is dropped.
+    /// What the tray should show now, and the window brought up to date.
+    /// Reading the status never starts the daemon; a session the daemon no
+    /// longer knows is dropped, with any open form.
     pub async fn model(&mut self) -> Model {
         let status = match client::agent_if_running(&self.paths, &AgentRequest::Status).await {
             Ok(Some(AgentResponse::Status { status })) => Some(status),
             _ => None,
         };
-        let overview = match self.driver.refresh().await {
+        self.overview = match self.driver.refresh().await {
             Some(Outcome::Overview(overview)) => Some(overview),
+            Some(Outcome::Ended(message)) => {
+                self.say(Asker::Window, &message, None);
+                None
+            }
             _ => None,
         };
+        if self.overview.is_none() {
+            self.set_form(None);
+        }
+        self.send_state();
+        if self.window.as_ref().is_some_and(|w| w.tab == Tab::Audit) {
+            self.send_audit().await;
+        }
         Model::new(View {
             status: status.as_ref(),
-            overview: overview.as_ref(),
+            overview: self.overview.as_ref(),
             device: self.driver.device(),
             login: self.desktop.login_is_on(),
         })
     }
 
-    /// Carries out one click. Returns true for Quit.
+    /// Carries out one action, a device prompt included. Returns true for
+    /// Quit.
     pub async fn act(&mut self, action: Action) -> bool {
-        match action {
-            Action::Unlock => {
+        match self.begin(action).await {
+            Next::Done => false,
+            Next::Prompt(asker) => {
                 let answer = self.driver.ask_device().await;
-                self.unlock(answer).await;
-            }
-            Action::Decide { id, verdict } => {
-                let outcome = self.driver.run(Effect::Decide { id, verdict }).await;
-                self.report(outcome);
-            }
-            Action::Lock => {
-                let outcome = self.driver.run(Effect::Lock).await;
-                self.report(outcome);
-            }
-            Action::Open(_) => {
-                if let Err(e) = self.desktop.open_tui() {
-                    self.desktop.notify(&format!("Could not open kv tui: {e}"));
-                }
-            }
-            Action::Login(on) => {
-                if let Err(e) = self.desktop.set_login(on) {
-                    self.desktop
-                        .notify(&format!("Could not change the login item: {e}"));
-                }
+                self.unlock(asker, answer).await;
+                false
             }
-            Action::Quit => return true,
+            Next::Quit => true,
         }
-        false
     }
 
-    /// Shows a model every tick and after every click until Quit, or until
-    /// the UI drops its sender. A Touch ID prompt runs beside the loop, so
-    /// the icon stays current while the user decides.
+    /// Shows a model every tick and after every action until Quit, or until
+    /// the UI drops its sender. A device prompt runs beside the loop, so the
+    /// icon and the window stay current while the user decides.
     pub async fn run(
         mut self,
         mut actions: UnboundedReceiver<Action>,
@@ -111,38 +142,252 @@ impl<D: Desktop> Worker<D> {
             tokio::select! {
                 answer = async { prompt.as_mut().expect("guarded").await }, if prompt.is_some() => {
                     prompt = None;
-                    self.unlock(answer).await;
+                    let asker = self.prompting.take().unwrap_or(Asker::Menu);
+                    self.unlock(asker, answer).await;
                 }
-                action = actions.recv() => match action {
-                    None | Some(Action::Quit) => return,
-                    Some(Action::Unlock) => {
-                        prompt.get_or_insert_with(|| self.driver.ask_device());
-                        continue;
+                action = actions.recv() => {
+                    let Some(action) = action else { return };
+                    match self.begin(action).await {
+                        Next::Done => {}
+                        Next::Prompt(asker) => {
+                            if prompt.is_none() {
+                                prompt = Some(self.driver.ask_device());
+                                self.prompting = Some(asker);
+                            }
+                        }
+                        Next::Quit => return,
                     }
-                    Some(action) => {
-                        self.act(action).await;
-                    }
-                },
+                }
                 _ = tick.tick() => {}
             }
             show(self.model().await);
         }
     }
 
-    async fn unlock(&mut self, answer: DeviceAnswer) {
+    /// Does what `action` asks for, short of a device prompt.
+    async fn begin(&mut self, action: Action) -> Next {
+        match action {
+            Action::Unlock => return Next::Prompt(Asker::Menu),
+            Action::Decide { id, verdict } => {
+                let outcome = self.driver.run(Effect::Decide { id, verdict }).await;
+                self.report(Asker::Menu, outcome, None);
+            }
+            Action::Lock => self.lock(Asker::Menu).await,
+            Action::Open(tab) => {
+                let opening = self.window.is_none();
+                match &mut self.window {
+                    Some(window) => window.tab = tab,
+                    None => self.window = Some(Window { tab, form: None }),
+                }
+                self.desktop.show_window(tab);
+                self.desktop.page(ToPage::Show { tab });
+                self.send_state();
+                // The window opens on its unlock screen, asking at once.
+                if opening && !self.driver.has_session() && self.driver.device().is_some() {
+                    return Next::Prompt(Asker::Window);
+                }
+            }
+            Action::Window(message) => return self.on_page(message).await,
+            Action::WindowClosed => self.window = None,
+            Action::Login(on) => {
+                if let Err(e) = self.desktop.set_login(on) {
+                    self.desktop
+                        .notify(&format!("Could not change the login item: {e}"));
+                }
+            }
+            Action::Quit => return Next::Quit,
+        }
+        Next::Done
+    }
+
+    /// Does what the page asks for. A page message while the window is
+    /// closed is a leftover and is dropped.
+    async fn on_page(&mut self, message: FromPage) -> Next {
+        let Some(window) = &self.window else {
+            return Next::Done;
+        };
+        let tab = window.tab;
+        match message {
+            FromPage::Ready => {
+                self.desktop.page(ToPage::Show { tab });
+                self.send_state();
+                if let Some((_, form)) = self.form() {
+                    let view = forms::describe(form);
+                    self.desktop.page(ToPage::Form { view });
+                }
+                if tab == Tab::Audit {
+                    self.send_audit().await;
+                }
+            }
+            FromPage::Unlock { passphrase } => {
+                let outcome = self.driver.run(Effect::OpenSession(passphrase)).await;
+                self.report(Asker::Window, outcome, None);
+            }
+            FromPage::DeviceUnlock => return Next::Prompt(Asker::Window),
+            FromPage::Decide { id, verdict } => {
+                let outcome = self.driver.run(Effect::Decide { id, verdict }).await;
+                self.report(Asker::Window, outcome, Some(id));
+            }
+            FromPage::OpenForm { form } => match self.open_form(form) {
+                Ok(opened) => {
+                    let view = forms::describe(&opened.1);
+                    self.set_form(Some(opened));
+                    self.desktop.page(ToPage::Form { view });
+                }
+                Err(message) => self.say(Asker::Window, &message, None),
+            },
+            FromPage::SubmitForm { values } => self.submit(values).await,
+            FromPage::CloseForm => self.set_form(None),
+            FromPage::Dismiss { id } => {
+                let outcome = self.driver.run(Effect::Dismiss(id)).await;
+                self.report(Asker::Window, outcome, None);
+            }
+            FromPage::Remove { name } => {
+                let outcome = self.driver.run(Effect::Remove(name)).await;
+                self.report(Asker::Window, outcome, None);
+            }
+            FromPage::Lock => self.lock(Asker::Window).await,
+            FromPage::Tab { tab } => {
+                if let Some(window) = &mut self.window {
+                    window.tab = tab;
+                }
+                if tab == Tab::Audit {
+                    self.send_audit().await;
+                }
+            }
+        }
+        Next::Done
+    }
+
+    /// Saves the open form with what the page sent. The form stays open,
+    /// with the error beside it, until the daemon has taken it.
+    async fn submit(&mut self, values: BTreeMap<String, SecretText>) {
+        let Some((purpose, mut form)) = self.window.as_mut().and_then(|w| w.form.take()) else {
+            return;
+        };
+        let effect = forms::fill(&mut form, &values).and_then(|()| forms::submit(&purpose, &form));
+        let failed = match effect {
+            Err(message) => message,
+            Ok(effect) => match self.driver.run(effect).await {
+                Outcome::Done(warnings) => {
+                    self.desktop.page(ToPage::FormDone);
+                    for warning in warnings {
+                        self.say(Asker::Window, &warning, None);
+                    }
+                    return;
+                }
+                Outcome::Failed(message) => message,
+                // The session ended: the form goes with it.
+                other => return self.report(Asker::Window, other, None),
+            },
+        };
+        self.set_form(Some((purpose, form)));
+        self.desktop.page(ToPage::FormError {
+            message: sentence(&failed),
+        });
+    }
+
+    fn form(&self) -> Option<&(Purpose, Form)> {
+        self.window.as_ref()?.form.as_ref()
+    }
+
+    fn set_form(&mut self, form: Option<(Purpose, Form)>) {
+        if let Some(window) = &mut self.window {
+            window.form = form;
+        }
+    }
+
+    /// The form the page asked for. A new handle needs only a session; the
+    /// others open from what the last overview showed.
+    fn open_form(&self, request: FormRequest) -> Result<(Purpose, Form), String> {
+        if !self.driver.has_session() {
+            return Err("unlock first".into());
+        }
+        let overview = || self.overview.as_ref().ok_or("unlock first");
+        let handle = |name: &str| {
+            overview()?
+                .handles
+                .iter()
+                .find(|handle| handle.name == name)
+                .cloned()
+                .ok_or(format!("there is no handle named {name}"))
+        };
+        Ok(match request {
+            FormRequest::New => (Purpose::Add, forms::new_handle()),
+            FormRequest::Request { id } => {
+                let requested = overview()?
+                    .handle_requests
+                    .iter()
+                    .find(|requested| requested.id == id)
+                    .ok_or("that handle request is no longer waiting")?;
+                (Purpose::Add, forms::requested_handle(requested))
+            }
+            FormRequest::Edit { name } => {
+                let handle = handle(&name)?;
+                let form = forms::edit_handle(&handle);
+                (Purpose::Edit(handle), form)
+            }
+            FormRequest::Policy { name } => {
+                let handle = handle(&name)?;
+                let form = forms::edit_policy(&handle);
+                (Purpose::Policy(handle), form)
+            }
+        })
+    }
+
+    async fn lock(&mut self, asker: Asker) {
+        let outcome = self.driver.run(Effect::Lock).await;
+        self.set_form(None);
+        self.report(asker, outcome, None);
+    }
+
+    async fn unlock(&mut self, asker: Asker, answer: DeviceAnswer) {
         let outcome = self.driver.finish_device(answer).await;
-        self.report(outcome);
+        self.report(asker, outcome, None);
     }
 
-    fn report(&self, outcome: Outcome) {
+    /// Tells `asker` how an action went, when it failed.
+    fn report(&self, asker: Asker, outcome: Outcome, request: Option<u64>) {
         if let Outcome::Failed(message) | Outcome::Ended(message) = outcome {
-            self.desktop.notify(&sentence(&message));
+            self.say(asker, &message, request);
+        }
+    }
+
+    /// Tells `asker`; with the window closed, the window's news becomes a
+    /// notification only if the menu asked.
+    fn say(&self, asker: Asker, message: &str, request: Option<u64>) {
+        match asker {
+            Asker::Menu => self.desktop.notify(&sentence(message)),
+            Asker::Window if self.window.is_some() => self.desktop.page(ToPage::Message {
+                text: sentence(message),
+                request,
+            }),
+            Asker::Window => {}
+        }
+    }
+
+    fn send_state(&self) {
+        if self.window.is_none() {
+            return;
+        }
+        self.desktop.page(ToPage::State {
+            locked: !self.driver.has_session(),
+            device: self.driver.device().map(|kind| kind.label().to_owned()),
+            waiting_for_device: self.prompting.is_some(),
+            overview: self.overview.clone(),
+        });
+    }
+
+    async fn send_audit(&self) {
+        match self.driver.audit().await {
+            Outcome::Audit(entries) => self.desktop.page(ToPage::Audit { entries }),
+            other => self.report(Asker::Window, other, None),
         }
     }
 }
 
 /// The daemon's messages start in lower case, to follow other text; a
-/// notification shows one on its own.
+/// notification or the window shows one on its own.
 fn sentence(message: &str) -> String {
     let mut chars = message.chars();
     match chars.next() {
diff --git a/crates/kv/src/tui.rs b/crates/kv/src/tui.rs
index 96f88bb75fb6dbe635fe622978f683573f5fc77a..ea42f96b5e4f28034a8a5c3112aa3c5d315fc0de 100644
--- a/crates/kv/src/tui.rs
+++ b/crates/kv/src/tui.rs
@@ -94,6 +94,12 @@ impl Driver {
         self
     }
 
+    /// Whether the driver holds a session. The daemon may have ended it
+    /// since; the next request finds out.
+    pub fn has_session(&self) -> bool {
+        self.token.is_some()
+    }
+
     /// The device to offer: this platform's, if the vault has a slot for it.
     pub fn device(&self) -> Option<DeviceKind> {
         let kind = self.device.as_ref()?.kind();
diff --git a/crates/kv/tests/tray.rs b/crates/kv/tests/tray.rs
index cd630f18dc7da15a72f7d90c2fdb8630b6a71b8a..9699f8dcde6d86b7292ec393043347aa51fdb450 100644
--- a/crates/kv/tests/tray.rs
+++ b/crates/kv/tests/tray.rs
@@ -1,5 +1,5 @@
-//! The parts of `kv tray` around its UI: the icon images, the
-//! one-tray-at-a-time lock, and the command that opens `kv tui`.
+//! The parts of `kv tray` around its UI: the icon images and the
+//! one-tray-at-a-time lock.
 
 use kv::paths::Paths;
 use kv::tray::icon::{SIZE, rgba};
@@ -65,38 +65,3 @@ fn only_one_tray_runs_at_a_time() {
     drop(first);
     lock_single(&paths).unwrap();
 }
-
-#[cfg(target_os = "macos")]
-#[test]
-fn terminal_runs_kv_tui_with_the_path_quoted() {
-    let command = kv::tray::tui_command(std::path::Path::new("/Users/me/it's here/kv"));
-    assert_eq!(command.get_program(), "osascript");
-    let args: Vec<_> = command
-        .get_args()
-        .map(|a| a.to_str().unwrap().to_owned())
-        .collect();
-    assert_eq!(
-        args,
-        [
-            "-e",
-            r#"tell application "Terminal" to do script "'/Users/me/it'\\''s here/kv' tui""#,
-            "-e",
-            r#"tell application "Terminal" to activate"#,
-        ]
-    );
-}
-
-#[cfg(windows)]
-#[test]
-fn a_new_console_runs_kv_tui() {
-    let command = kv::tray::tui_command(std::path::Path::new(r"C:\Program Files\kv\kv.exe"));
-    assert_eq!(command.get_program(), "cmd");
-    let args: Vec<_> = command
-        .get_args()
-        .map(|a| a.to_str().unwrap().to_owned())
-        .collect();
-    assert_eq!(
-        args,
-        ["/c", "start", "", r"C:\Program Files\kv\kv.exe", "tui"]
-    );
-}
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv --test tray_worker && cargo test -p kv && cargo clippy -p kv --all-targets -- -D warnings`
Expected: PASS: 20 `tray_worker` tests, then the whole `kv` suite (377 tests; `tray` has 3 now that the terminal tests are gone), clippy clean.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Give the tray worker kv's window: one session, the forms, and answers where the user asked"
```

### Task 5: Draw kv's window: the page and the webview

**Files:**
- Create: `crates/kv/tests/tray_page.rs`
- Modify: `Cargo.lock`
- Modify: `crates/kv/Cargo.toml`
- Create: `crates/kv/src/tray/page/app.css`
- Create: `crates/kv/src/tray/page/app.js`
- Create: `crates/kv/src/tray/page/index.html`
- Modify: `crates/kv/src/tray/ui.rs`
- Create: `crates/kv/src/tray/ui/webview.rs`
- Modify: `crates/kv/src/tray/window.rs`

**Interfaces:**
- Consumes:
  - From Task 2: `window::{FromPage, ToPage, Tab}`.
  - From Task 4: `Action::{Window, WindowClosed}` and `Desktop::{show_window, page}`.
- Produces, in `tray::window`:
  - `CSP: &str`.
  - `PAGE_URL: &str` (`kv://app/index.html`; on Windows `https://kv.app/index.html`).
  - `is_page_url(&str) -> bool`.
  - `Asset { mime, body }` and `asset(path: &str) -> Option<Asset>`, serving `/`, `/index.html`, `/app.js` and `/app.css`.
- Produces the page: `crates/kv/src/tray/page/{index.html, app.css, app.js}`.
  - `app.js` defines `window.kv.receive(message)`.
  - It sends with `window.ipc.postMessage(JSON.stringify(message))`, and sends `{"type":"ready"}` once loaded.
- Produces `tray::ui::webview::KvWindow`:
  - `open(&EventLoopWindowTarget<Message>, UnboundedSender<Action>) -> Result<KvWindow, String>`, plus `id()`, `raise()` and `send(&ToPage)`.
  - On macOS, `edit_menu() -> Option<Menu>`.
- `ui::Message` gains `Open` and `Page(ToPage)`. `System` sends them through an `EventLoopProxy`.
- New dependency: `wry = { version = "0.57", default-features = false }` for macOS and Windows.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv/tests/tray_page.rs b/crates/kv/tests/tray_page.rs
new file mode 100644
index 0000000000000000000000000000000000000000..098081e25bf26416d183771c161f184ca99982b0
--- /dev/null
+++ b/crates/kv/tests/tray_page.rs
@@ -0,0 +1,91 @@
+//! kv's window page, as the binary embeds and serves it: only its own
+//! files, each with the Content-Security-Policy, and nothing in them that
+//! could turn agent text into markup or code.
+
+use kv::tray::window::{CSP, PAGE_URL, asset, is_page_url};
+
+const FILES: [&str; 3] = ["/index.html", "/app.js", "/app.css"];
+
+#[test]
+fn the_page_and_only_the_page_is_served() {
+    let index = asset("/").unwrap();
+    assert_eq!(index.mime, "text/html");
+    assert_eq!(asset("/index.html").unwrap().body, index.body);
+    assert_eq!(asset("/app.js").unwrap().mime, "text/javascript");
+    assert_eq!(asset("/app.css").unwrap().mime, "text/css");
+    for path in [
+        "",
+        "/nope.js",
+        "/../Cargo.toml",
+        "/app.js/",
+        "/APP.JS",
+        "//app.js",
+    ] {
+        assert!(asset(path).is_none(), "{path:?}");
+    }
+}
+
+#[test]
+fn the_policy_allows_only_the_pages_own_files() {
+    assert_eq!(
+        CSP,
+        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'"
+    );
+    let index = asset("/index.html").unwrap().body;
+    assert!(
+        index.contains(&format!(
+            r#"<meta http-equiv="Content-Security-Policy" content="{CSP}">"#
+        )),
+        "the page carries the policy itself too"
+    );
+}
+
+#[test]
+fn the_page_never_writes_markup_or_runs_strings() {
+    for path in FILES {
+        let body = asset(path).unwrap().body;
+        for banned in [
+            "innerHTML",
+            "outerHTML",
+            "insertAdjacentHTML",
+            "document.write",
+            "eval(",
+            "new Function",
+            "javascript:",
+        ] {
+            assert!(!body.contains(banned), "{path} uses {banned}");
+        }
+    }
+    let index = asset("/index.html").unwrap().body;
+    // Every script is a file; no inline script or handler attribute.
+    for (at, _) in index.match_indices("<script") {
+        let tag = &index[at..];
+        let end = tag.find("</script>").unwrap();
+        assert!(tag[..end].contains(r#"src="app.js""#), "{}", &tag[..end]);
+        assert!(tag[..end].ends_with('>'), "inline script: {}", &tag[..end]);
+    }
+    let lower = index.to_lowercase();
+    for handler in [
+        " onclick=",
+        " onload=",
+        " onerror=",
+        " onsubmit=",
+        " oninput=",
+    ] {
+        assert!(!lower.contains(handler), "{handler}");
+    }
+}
+
+#[test]
+fn messages_count_only_from_the_page() {
+    assert!(is_page_url(PAGE_URL));
+    for url in [
+        "https://example.com/",
+        "kv://app.evil.example/index.html",
+        "https://kv.app.evil.example/index.html",
+        "kv://appx/index.html",
+        "",
+    ] {
+        assert!(!is_page_url(url), "{url}");
+    }
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv --test tray_page --test tray`
Expected: `error[E0432]: unresolved imports kv::tray::window::CSP, kv::tray::window::PAGE_URL, kv::tray::window::asset, kv::tray::window::is_page_url`.

- [ ] **Step 3: Implement**

The page draws lists only when they change, comparing each list's JSON with what it last drew, so a tick never moves a button or the focus. Only the "Expires in Ns" text is set every second. Forms live in a `<dialog>` that ticks never touch. To prove the page scan bites, add `x.innerHTML = y;` to `app.js` and watch `the_page_never_writes_markup_or_runs_strings` fail, then remove it.

Apply with `git apply`:

```diff
diff --git a/Cargo.lock b/Cargo.lock
index eb008dcc31272d61d1a58ac98e9efd5bb6bd3604..9ac321d86993b5e19147c4a246d18fdca455de6d 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -760,6 +760,16 @@ dependencies = [
  "unicode-segmentation",
 ]
 
+[[package]]
+name = "cookie"
+version = "0.18.2"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "1a373e3602691c3cdea496d2f0ee5935151e6168fe87739483c463db1b2f2f87"
+dependencies = [
+ "time",
+ "version_check",
+]
+
 [[package]]
 name = "core-foundation"
 version = "0.10.1"
@@ -906,6 +916,29 @@ dependencies = [
  "phf 0.11.3",
 ]
 
+[[package]]
+name = "cssparser"
+version = "0.37.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "8c9cdaae01d5ed7882b04d795e7f752f46ff52d2fa3b50a20d28c464510bba98"
+dependencies = [
+ "cssparser-macros",
+ "dtoa-short",
+ "itoa",
+ "phf 0.13.1",
+ "smallvec",
+]
+
+[[package]]
+name = "cssparser-macros"
+version = "0.7.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "d045de693cb712d0b22c6a64be5b953f67b3ce00ab5ad3dd5d8b441886ab8e1a"
+dependencies = [
+ "quote",
+ "syn 3.0.6",
+]
+
 [[package]]
 name = "ctutils"
 version = "0.4.3"
@@ -1153,12 +1186,42 @@ dependencies = [
  "litrs",
 ]
 
+[[package]]
+name = "dom_query"
+version = "0.28.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "fac5fca71e65e94cc718a6e2af65d6e0f9c6027751c2aa562fbb5087fda639bc"
+dependencies = [
+ "bit-set 0.8.0",
+ "cssparser",
+ "foldhash",
+ "html5ever",
+ "precomputed-hash",
+ "selectors",
+ "tendril",
+]
+
 [[package]]
 name = "dpi"
 version = "0.1.2"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "d8b14ccef22fc6f5a8f4d7d768562a182c04ce9a3b3157b91390b52ddfdf1a76"
 
+[[package]]
+name = "dtoa"
+version = "1.0.11"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "4c3cf4824e2d5f025c7b531afcb2325364084a16806f6d47fbc1f5fbd9960590"
+
+[[package]]
+name = "dtoa-short"
+version = "0.3.5"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "cd1511a7b6a56299bd043a9c167a6d2bfb37bf84a6dfceaba651168adfb43c87"
+dependencies = [
+ "dtoa",
+]
+
 [[package]]
 name = "dunce"
 version = "1.0.5"
@@ -1850,6 +1913,16 @@ dependencies = [
  "digest 0.11.3",
 ]
 
+[[package]]
+name = "html5ever"
+version = "0.39.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "46a1761807faccc9a19e86944bbf40610014066306f96edcdedc2fb714bcb7b8"
+dependencies = [
+ "log",
+ "markup5ever",
+]
+
 [[package]]
 name = "http"
 version = "1.5.0"
@@ -2345,6 +2418,7 @@ dependencies = [
  "windows-future",
  "windows-sys 0.61.2",
  "wiremock",
+ "wry",
  "zeroize",
 ]
 
@@ -2533,6 +2607,17 @@ version = "0.7.0"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "b0d28e293f2b8c9d2b2d1c0193bd3c1cbdc0d2cf396888dc01162f7cf9d6c3f3"
 
+[[package]]
+name = "markup5ever"
+version = "0.39.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "7122d987ec5f704ee56f6e5b41a7d93722e9aae27ae07cafa4036c4d3f9757de"
+dependencies = [
+ "log",
+ "tendril",
+ "web_atoms",
+]
+
 [[package]]
 name = "md-5"
 version = "0.11.0"
@@ -2652,6 +2737,12 @@ dependencies = [
  "jni-sys 0.3.1",
 ]
 
+[[package]]
+name = "new_debug_unreachable"
+version = "1.0.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "650eef8c711430f1a879fdd01d4745a7deea475becfb90269c06775983bbf086"
+
 [[package]]
 name = "nix"
 version = "0.29.0"
@@ -2806,6 +2897,7 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "08849bbd4767dfae9457696856ae1c84fe4e0281bbe4a7abff2d0e06fb7981f8"
 dependencies = [
  "objc2-encode",
+ "objc2-exception-helper",
 ]
 
 [[package]]
@@ -2903,6 +2995,15 @@ version = "4.1.0"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "ef25abbcd74fb2609453eb695bd2f860d389e457f67dc17cafc8b8cbc89d0c33"
 
+[[package]]
+name = "objc2-exception-helper"
+version = "0.1.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "c7a1c5fbb72d7735b076bb47b578523aedc40f3c439bea6dfd595c089d79d98a"
+dependencies = [
+ "cc",
+]
+
 [[package]]
 name = "objc2-foundation"
 version = "0.3.2"
@@ -3002,6 +3103,20 @@ dependencies = [
  "objc2-foundation",
 ]
 
+[[package]]
+name = "objc2-web-kit"
+version = "0.3.2"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "b2e5aaab980c433cf470df9d7af96a7b46a9d892d521a2cbbb2f8a4c16751e7f"
+dependencies = [
+ "bitflags 2.13.2",
+ "block2",
+ "objc2",
+ "objc2-app-kit",
+ "objc2-core-foundation",
+ "objc2-foundation",
+]
+
 [[package]]
 name = "oid-registry"
 version = "0.8.1"
@@ -3232,7 +3347,7 @@ version = "0.11.3"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "1fd6780a80ae0c52cc120a26a1a42c1ae51b247a253e4e06113d23d2c2edd078"
 dependencies = [
- "phf_macros",
+ "phf_macros 0.11.3",
  "phf_shared 0.11.3",
 ]
 
@@ -3242,6 +3357,7 @@ version = "0.13.1"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "c1562dc717473dbaa4c1f85a36410e03c047b2e7df7f45ee938fbef64ae7fadf"
 dependencies = [
+ "phf_macros 0.13.1",
  "phf_shared 0.13.1",
  "serde",
 ]
@@ -3252,10 +3368,20 @@ version = "0.11.3"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "aef8048c789fa5e851558d709946d6d79a8ff88c0440c587967f8e94bfb1216a"
 dependencies = [
- "phf_generator",
+ "phf_generator 0.11.3",
  "phf_shared 0.11.3",
 ]
 
+[[package]]
+name = "phf_codegen"
+version = "0.13.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "49aa7f9d80421bca176ca8dbfebe668cc7a2684708594ec9f3c0db0805d5d6e1"
+dependencies = [
+ "phf_generator 0.13.1",
+ "phf_shared 0.13.1",
+]
+
 [[package]]
 name = "phf_generator"
 version = "0.11.3"
@@ -3266,19 +3392,42 @@ dependencies = [
  "rand 0.8.8",
 ]
 
+[[package]]
+name = "phf_generator"
+version = "0.13.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "135ace3a761e564ec88c03a77317a7c6b80bb7f7135ef2544dbe054243b89737"
+dependencies = [
+ "fastrand",
+ "phf_shared 0.13.1",
+]
+
 [[package]]
 name = "phf_macros"
 version = "0.11.3"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "f84ac04429c13a7ff43785d75ad27569f2951ce0ffd30a3321230db2fc727216"
 dependencies = [
- "phf_generator",
+ "phf_generator 0.11.3",
  "phf_shared 0.11.3",
  "proc-macro2",
  "quote",
  "syn 2.0.119",
 ]
 
+[[package]]
+name = "phf_macros"
+version = "0.13.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "812f032b54b1e759ccd5f8b6677695d5268c588701effba24601f6932f8269ef"
+dependencies = [
+ "phf_generator 0.13.1",
+ "phf_shared 0.13.1",
+ "proc-macro2",
+ "quote",
+ "syn 2.0.119",
+]
+
 [[package]]
 name = "phf_shared"
 version = "0.11.3"
@@ -3416,6 +3565,12 @@ dependencies = [
  "zerocopy",
 ]
 
+[[package]]
+name = "precomputed-hash"
+version = "0.1.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "925383efa346730478fb4838dbe9137d2a47675ad789c546d150a6e1dd4ab31c"
+
 [[package]]
 name = "proc-macro-crate"
 version = "1.3.1"
@@ -4215,6 +4370,25 @@ dependencies = [
  "libc",
 ]
 
+[[package]]
+name = "selectors"
+version = "0.38.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "8adfa1c298912827b8a28b223b3b874357397ae706e6190acd9bf28cee99114d"
+dependencies = [
+ "bitflags 2.13.2",
+ "cssparser",
+ "derive_more",
+ "log",
+ "new_debug_unreachable",
+ "phf 0.13.1",
+ "phf_codegen 0.13.1",
+ "precomputed-hash",
+ "rustc-hash",
+ "servo_arc",
+ "smallvec",
+]
+
 [[package]]
 name = "semver"
 version = "1.0.28"
@@ -4295,6 +4469,15 @@ dependencies = [
  "serde",
 ]
 
+[[package]]
+name = "servo_arc"
+version = "0.4.3"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "170fb83ab34de17dc69aa7c67482b22218ddb85da56546f9bd6b929e32a05930"
+dependencies = [
+ "stable_deref_trait",
+]
+
 [[package]]
 name = "sha2"
 version = "0.10.9"
@@ -4426,6 +4609,30 @@ version = "1.1.0"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "a2eb9349b6444b326872e140eb1cf5e7c522154d69e7a0ffb0fb81c06b37543f"
 
+[[package]]
+name = "string_cache"
+version = "0.9.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "a18596f8c785a729f2819c0f6a7eae6ebeebdfffbfe4214ae6b087f690e31901"
+dependencies = [
+ "new_debug_unreachable",
+ "parking_lot",
+ "phf_shared 0.13.1",
+ "precomputed-hash",
+]
+
+[[package]]
+name = "string_cache_codegen"
+version = "0.6.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "585635e46db231059f76c5849798146164652513eb9e8ab2685939dd90f29b69"
+dependencies = [
+ "phf_generator 0.13.1",
+ "phf_shared 0.13.1",
+ "proc-macro2",
+ "quote",
+]
+
 [[package]]
 name = "stringprep"
 version = "0.1.5"
@@ -4628,6 +4835,15 @@ dependencies = [
  "windows-sys 0.61.2",
 ]
 
+[[package]]
+name = "tendril"
+version = "0.5.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "5fed54709c5b3a53d09bb1c113ea4f5ceafd1e772ddcb0030a82e1d56c087b08"
+dependencies = [
+ "new_debug_unreachable",
+]
+
 [[package]]
 name = "termina"
 version = "0.3.3"
@@ -4650,7 +4866,7 @@ dependencies = [
  "fnv",
  "nom",
  "phf 0.11.3",
- "phf_codegen",
+ "phf_codegen 0.11.3",
 ]
 
 [[package]]
@@ -5383,6 +5599,18 @@ dependencies = [
  "wasm-bindgen",
 ]
 
+[[package]]
+name = "web_atoms"
+version = "0.2.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "ba8b815c1b593dc0baf78dd0f4fc8fdb2de53198fb1163738093e9a311c33fb3"
+dependencies = [
+ "phf 0.13.1",
+ "phf_codegen 0.13.1",
+ "string_cache",
+ "string_cache_codegen",
+]
+
 [[package]]
 name = "webpki-root-certs"
 version = "1.0.9"
@@ -5392,6 +5620,40 @@ dependencies = [
  "rustls-pki-types",
 ]
 
+[[package]]
+name = "webview2-com"
+version = "0.39.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "3f89fca7a704cee10dcb3654c1dbb8941d1783132f1917358af75bec37a7d7e6"
+dependencies = [
+ "webview2-com-macros",
+ "webview2-com-sys",
+ "windows",
+ "windows-core",
+]
+
+[[package]]
+name = "webview2-com-macros"
+version = "0.8.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "67a921c1b6914c367b2b823cd4cde6f96beec77d30a939c8199bb377cf9b9b54"
+dependencies = [
+ "proc-macro2",
+ "quote",
+ "syn 2.0.119",
+]
+
+[[package]]
+name = "webview2-com-sys"
+version = "0.39.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "b3a07132775117d6065853d9d1178157b8c90e228de47129d6bce2c7edebedfb"
+dependencies = [
+ "thiserror 2.0.21",
+ "windows",
+ "windows-core",
+]
+
 [[package]]
 name = "wezterm-bidi"
 version = "0.2.3"
@@ -5828,6 +6090,43 @@ version = "0.6.4"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "3ad82d2a33cdc9674dc7465672f271e096168fcdbe0f799d9e6db8c5892679dc"
 
+[[package]]
+name = "wry"
+version = "0.57.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "a819957a01b3119af85e638a38d242af76dbc87d130dca67bfd0441072e21ff0"
+dependencies = [
+ "base64 0.22.1",
+ "block2",
+ "cookie",
+ "crossbeam-channel",
+ "dirs",
+ "dom_query",
+ "dpi",
+ "dunce",
+ "http",
+ "jni 0.21.1",
+ "libc",
+ "ndk",
+ "objc2",
+ "objc2-app-kit",
+ "objc2-core-foundation",
+ "objc2-foundation",
+ "objc2-ui-kit",
+ "objc2-web-kit",
+ "once_cell",
+ "percent-encoding",
+ "raw-window-handle",
+ "sha2 0.10.9",
+ "tao-macros",
+ "thiserror 2.0.21",
+ "url",
+ "webview2-com",
+ "windows",
+ "windows-core",
+ "windows-version",
+]
+
 [[package]]
 name = "x11"
 version = "2.21.0"
diff --git a/crates/kv/Cargo.toml b/crates/kv/Cargo.toml
index f803f43bfe579322a2e35a901ed8ca34a490bea7..fc0c9c40958268a3164cd1422f99f521882fefcb 100644
--- a/crates/kv/Cargo.toml
+++ b/crates/kv/Cargo.toml
@@ -47,6 +47,9 @@ security-framework = "3"
 [target.'cfg(any(target_os = "macos", windows))'.dependencies]
 tao = "0.37"
 tray-icon = "0.26"
+# kv's window. No default features: they are Linux's, and `devtools` stays
+# off.
+wry = { version = "0.57", default-features = false }
 
 [target.'cfg(unix)'.dependencies]
 rustix = { version = "1.1", features = ["process"] }
diff --git a/crates/kv/src/tray/page/app.css b/crates/kv/src/tray/page/app.css
new file mode 100644
index 0000000000000000000000000000000000000000..31796c54706b04684463fb822815d589eb69d921
--- /dev/null
+++ b/crates/kv/src/tray/page/app.css
@@ -0,0 +1,148 @@
+:root {
+  --bg: #ffffff;
+  --panel: #f5f5f7;
+  --line: #d9d9de;
+  --text: #1d1d1f;
+  --muted: #6e6e73;
+  --accent: #0a66d8;
+  --accent-text: #ffffff;
+  --danger: #c4281c;
+  --warn-bg: #fff4d6;
+  font: 13px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
+  color-scheme: light dark;
+}
+
+@media (prefers-color-scheme: dark) {
+  :root {
+    --bg: #1e1e20;
+    --panel: #2a2a2d;
+    --line: #3d3d42;
+    --text: #f2f2f4;
+    --muted: #9a9aa1;
+    --accent: #3d8bfd;
+    --danger: #ff6b5e;
+    --warn-bg: #3d3420;
+  }
+}
+
+* { box-sizing: border-box; }
+
+body {
+  margin: 0;
+  background: var(--bg);
+  color: var(--text);
+}
+
+[hidden] { display: none !important; }
+
+h1 { font-size: 18px; margin: 0 0 16px; }
+h2 { font-size: 14px; margin: 0; }
+
+button, input, select, textarea {
+  font: inherit;
+  color: inherit;
+}
+
+button {
+  border: 1px solid var(--line);
+  background: var(--panel);
+  border-radius: 6px;
+  padding: 4px 10px;
+  cursor: pointer;
+}
+
+button.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-text); }
+button.danger { color: var(--danger); }
+button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible {
+  outline: 2px solid var(--accent);
+  outline-offset: 1px;
+}
+
+input, select, textarea {
+  border: 1px solid var(--line);
+  background: var(--bg);
+  border-radius: 6px;
+  padding: 5px 8px;
+  width: 100%;
+}
+
+textarea { min-height: 64px; resize: vertical; font-family: ui-monospace, Menlo, Consolas, monospace; }
+
+.muted, .hint { color: var(--muted); }
+.hint { font-size: 12px; margin: 2px 0 0; }
+.empty { color: var(--muted); padding: 24px 0; text-align: center; }
+.message { color: var(--danger); margin: 8px 0 0; min-height: 1em; }
+.message:empty { display: none; }
+
+.unlock {
+  max-width: 360px;
+  margin: 72px auto;
+  padding: 0 16px;
+}
+
+.unlock label { display: block; margin-bottom: 4px; }
+.row { display: flex; gap: 8px; }
+.row input { flex: 1; }
+.waiting { color: var(--muted); }
+#use-device { margin-top: 12px; }
+
+header {
+  display: flex;
+  align-items: center;
+  gap: 12px;
+  padding: 8px 16px;
+  border-bottom: 1px solid var(--line);
+  position: sticky;
+  top: 0;
+  background: var(--bg);
+}
+
+nav { display: flex; gap: 4px; flex: 1; }
+nav button { border-color: transparent; background: transparent; }
+nav button[aria-selected="true"] { background: var(--panel); border-color: var(--line); font-weight: 600; }
+
+#app-message { margin: 8px 16px 0; }
+
+section { padding: 12px 16px 24px; }
+
+.card {
+  border: 1px solid var(--line);
+  border-radius: 8px;
+  padding: 10px 12px;
+  margin-bottom: 10px;
+  background: var(--panel);
+}
+
+.card .title { font-weight: 600; overflow-wrap: anywhere; }
+.card .detail {
+  white-space: pre-wrap;
+  overflow-wrap: anywhere;
+  font-family: ui-monospace, Menlo, Consolas, monospace;
+  font-size: 12px;
+  margin: 6px 0;
+}
+.card .buttons { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
+
+.toolbar { display: flex; align-items: center; justify-content: space-between; margin: 8px 0; }
+
+table { width: 100%; border-collapse: collapse; }
+th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
+th { color: var(--muted); font-weight: 500; }
+td.actions { white-space: nowrap; text-align: right; }
+td.actions button { margin-left: 4px; }
+.warning { background: var(--warn-bg); border-radius: 4px; padding: 2px 6px; font-size: 12px; margin-top: 4px; }
+
+dialog {
+  border: 1px solid var(--line);
+  border-radius: 10px;
+  background: var(--bg);
+  color: var(--text);
+  padding: 16px;
+  width: min(520px, 92vw);
+  max-height: 88vh;
+}
+
+dialog::backdrop { background: rgba(0, 0, 0, 0.35); }
+.field { margin: 10px 0; }
+.field label { display: block; margin-bottom: 3px; }
+.actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 14px; }
diff --git a/crates/kv/src/tray/page/app.js b/crates/kv/src/tray/page/app.js
new file mode 100644
index 0000000000000000000000000000000000000000..f5aa038ab500400a0108f5969632d43ce9067784
--- /dev/null
+++ b/crates/kv/src/tray/page/app.js
@@ -0,0 +1,433 @@
+// kv's window. The tray sends messages through kv.receive; the page sends
+// its own with window.ipc.postMessage. All text from the tray, much of it
+// written by agents, goes into the page as text nodes, never as markup.
+"use strict";
+
+(() => {
+  const $ = (id) => document.getElementById(id);
+
+  const page = {
+    locked: true,
+    device: null,
+    waiting: false,
+    overview: null,
+    tab: "approvals",
+    // What each list was last drawn from, to redraw only on a change.
+    drawn: { cards: "", requests: "", handles: "" },
+    form: null,
+    removing: null,
+  };
+
+  function send(message) {
+    window.ipc.postMessage(JSON.stringify(message));
+  }
+
+  // An element with text and children; strings become text nodes.
+  function el(tag, className, ...children) {
+    const node = document.createElement(tag);
+    if (className) node.className = className;
+    for (const child of children) {
+      if (child === null || child === undefined) continue;
+      node.append(typeof child === "string" ? document.createTextNode(child) : child);
+    }
+    return node;
+  }
+
+  function button(label, onClick, className) {
+    const node = el("button", className || null, label);
+    node.type = "button";
+    node.addEventListener("click", onClick);
+    return node;
+  }
+
+  function show(node, shown) {
+    node.hidden = !shown;
+  }
+
+  // "7h 52m", "3m", "40s".
+  function duration(secs) {
+    const h = Math.floor(secs / 3600);
+    const m = Math.floor((secs % 3600) / 60);
+    if (h > 0) return `${h}h ${m}m`;
+    if (m > 0) return `${m}m`;
+    return `${secs}s`;
+  }
+
+  // Messages from the tray.
+
+  function receive(message) {
+    switch (message.type) {
+      case "state":
+        page.locked = message.locked;
+        page.device = message.device;
+        page.waiting = message.waiting_for_device;
+        page.overview = message.overview;
+        if (page.locked) {
+          closeForm(false);
+          closeConfirm();
+        }
+        draw();
+        break;
+      case "show":
+        page.tab = message.tab;
+        draw();
+        break;
+      case "form":
+        openForm(message.view);
+        break;
+      case "form_error":
+        $("form-error").textContent = message.message;
+        break;
+      case "form_done":
+        closeForm(false);
+        break;
+      case "audit":
+        drawAudit(message.entries);
+        break;
+      case "message":
+        say(message.text, message.request);
+        break;
+    }
+  }
+
+  function say(text, request) {
+    if (request !== null && request !== undefined) {
+      const card = document.querySelector(`.card[data-id="${Number(request)}"] .message`);
+      if (card) {
+        card.textContent = text;
+        return;
+      }
+    }
+    if (page.locked) {
+      $("unlock-message").textContent = text;
+    } else {
+      const note = $("app-message");
+      note.textContent = text;
+      show(note, true);
+    }
+  }
+
+  // Drawing.
+
+  function draw() {
+    show($("unlock"), page.locked);
+    show($("app"), !page.locked);
+    if (page.locked) {
+      drawUnlock();
+    } else {
+      drawApp();
+    }
+  }
+
+  function drawUnlock() {
+    const waiting = page.waiting && page.device;
+    const waitingNote = $("unlock-waiting");
+    waitingNote.textContent = waiting ? `Waiting for ${page.device}…` : "";
+    show(waitingNote, waiting);
+    const form = $("unlock-form");
+    const wasHidden = form.hidden;
+    show(form, !waiting);
+    const useDevice = $("use-device");
+    useDevice.textContent = page.device ? `Use ${page.device}` : "";
+    show(useDevice, Boolean(page.device) && !waiting);
+    if (wasHidden && !waiting) $("passphrase").focus();
+    page.drawn = { cards: "", requests: "", handles: "" };
+  }
+
+  function drawApp() {
+    $("unlock-message").textContent = "";
+    const overview = page.overview;
+    const secs = overview && overview.status.locks_in_secs;
+    $("locks-in").textContent =
+      secs === null || secs === undefined ? "Unlocked" : `Unlocked · locks in ${duration(secs)}`;
+    const waiting = overview ? overview.approvals.length : 0;
+    for (const tab of document.querySelectorAll("nav button")) {
+      const name = tab.dataset.tab;
+      tab.setAttribute("aria-selected", String(name === page.tab));
+      if (name === "approvals") {
+        tab.textContent = waiting > 0 ? `Approvals (${waiting})` : "Approvals";
+      }
+    }
+    for (const name of ["approvals", "handles", "audit"]) {
+      show($(name), name === page.tab);
+    }
+    if (!overview) return;
+    drawCards(overview.approvals);
+    drawRequests(overview.handle_requests);
+    drawHandles(overview.handles, overview.role_warnings || {});
+  }
+
+  function drawCards(approvals) {
+    show($("no-approvals"), approvals.length === 0);
+    // The countdowns change every second; the cards only when requests come
+    // or go, so a button the user is about to press stays put.
+    const shape = JSON.stringify(approvals.map((a) => ({ ...a, expires_in_secs: 0 })));
+    if (shape !== page.drawn.cards) {
+      page.drawn.cards = shape;
+      const kept = new Map();
+      for (const card of $("cards").children) kept.set(card.dataset.id, card);
+      const cards = approvals.map((approval) => kept.get(String(approval.id)) || card(approval));
+      $("cards").replaceChildren(...cards);
+    }
+    for (const approval of approvals) {
+      const expires = document.querySelector(`.card[data-id="${Number(approval.id)}"] .expires`);
+      if (expires) expires.textContent = `Expires in ${approval.expires_in_secs}s`;
+    }
+  }
+
+  function card(approval) {
+    const handles = approval.handles.join(", ");
+    const decide = (verdict) => () => send({ type: "decide", id: approval.id, verdict });
+    const buttons = el(
+      "div",
+      "buttons",
+      button("Allow once", decide("allow_once"), "primary"),
+      approval.can_grant ? button("Allow for this session", decide("allow_session")) : null,
+      button("Deny", decide("deny")),
+      button(`Deny and block ${handles}`, decide("deny_always"), "danger"),
+    );
+    const node = el(
+      "div",
+      "card",
+      el("div", "title", `${approval.client || "agent"} · ${approval.tool} · ${handles}`),
+      el("div", "detail", approval.detail),
+      approval.cwd ? el("div", "muted", `in ${approval.cwd}`) : null,
+      el("div", "muted expires", `Expires in ${approval.expires_in_secs}s`),
+      buttons,
+      el("p", "message"),
+    );
+    node.dataset.id = String(approval.id);
+    return node;
+  }
+
+  function drawRequests(requests) {
+    const shape = JSON.stringify(requests);
+    if (shape === page.drawn.requests) return;
+    page.drawn.requests = shape;
+    const cards = requests.map((requested) => {
+      const r = requested.request;
+      const allows = r.kind === "env" ? r.env_vars : r.allowed_hosts;
+      return el(
+        "div",
+        "card",
+        el("div", "title", `${requested.client || "An agent"} asked for ${r.name} (${r.kind})`),
+        r.description ? el("div", null, r.description) : null,
+        el("div", "muted", `Why: ${r.reason}`),
+        allows.length > 0 ? el("div", "muted", allows.join(", ")) : null,
+        el(
+          "div",
+          "buttons",
+          button("Fill in", () => openRequest({ kind: "request", id: requested.id }), "primary"),
+          button("Dismiss", () => send({ type: "dismiss", id: requested.id })),
+        ),
+      );
+    });
+    $("requests").replaceChildren(...cards);
+  }
+
+  function drawHandles(handles, warnings) {
+    const shape = JSON.stringify([handles, warnings]);
+    if (shape === page.drawn.handles) return;
+    page.drawn.handles = shape;
+    show($("no-handles"), handles.length === 0);
+    show($("handle-table"), handles.length > 0);
+    const rows = handles.map((handle) => {
+      const allows = {
+        http: handle.allowed_hosts,
+        env: handle.allowed_cmds,
+      }[handle.kind];
+      const name = el("td", null, el("div", "title", handle.name));
+      if (handle.description) name.append(el("div", "muted", handle.description));
+      if (warnings[handle.name]) name.append(el("div", "warning", warnings[handle.name]));
+      return el(
+        "tr",
+        null,
+        name,
+        el("td", null, handle.kind),
+        el("td", null, handle.read_only ? `${handle.mode}, read only` : handle.mode),
+        el("td", null, allows ? allows.join(", ") : ""),
+        el(
+          "td",
+          "actions",
+          button("Edit", () => openRequest({ kind: "edit", name: handle.name })),
+          button("Policy", () => openRequest({ kind: "policy", name: handle.name })),
+          button("Remove", () => confirmRemove(handle.name), "danger"),
+        ),
+      );
+    });
+    $("handle-rows").replaceChildren(...rows);
+  }
+
+  function drawAudit(entries) {
+    show($("no-audit"), entries.length === 0);
+    show($("audit-table"), entries.length > 0);
+    const rows = entries.map((e) =>
+      el(
+        "tr",
+        null,
+        el("td", "muted", e.ts),
+        el("td", null, e.action),
+        el("td", null, e.handle || ""),
+        el("td", null, e.decision || ""),
+        el("td", null, e.outcome),
+        el("td", null, e.summary || ""),
+      ),
+    );
+    $("audit-rows").replaceChildren(...rows);
+  }
+
+  // Forms, drawn from the tray's description of them. The tray checks what
+  // is typed; the page only shows and hides fields as the TUI does.
+
+  function openRequest(form) {
+    send({ type: "open_form", form });
+  }
+
+  function openForm(view) {
+    page.form = view;
+    $("form-title").textContent = view.title;
+    $("form-error").textContent = "";
+    const fields = view.fields.map(field);
+    $("form-fields").replaceChildren(...fields);
+    applyConditions();
+    const dialog = $("form-dialog");
+    if (!dialog.open) dialog.showModal();
+    const focus = view.focus && $(`field-${view.focus}`);
+    if (focus) focus.focus();
+  }
+
+  function field(spec) {
+    const id = `field-${spec.key}`;
+    let input;
+    switch (spec.kind) {
+      case "choice":
+        input = el("select");
+        for (const option of spec.options) {
+          const node = el("option", null, option);
+          node.value = option;
+          input.append(node);
+        }
+        input.value = spec.value;
+        input.addEventListener("change", applyConditions);
+        break;
+      case "pairs":
+        input = el("textarea");
+        input.placeholder = "NAME=value, one per line";
+        input.spellcheck = false;
+        break;
+      case "secret":
+        input = el("input");
+        input.type = "password";
+        input.autocomplete = "off";
+        break;
+      default:
+        input = el("input");
+        input.type = "text";
+        input.value = spec.value;
+        input.spellcheck = false;
+    }
+    input.id = id;
+    input.dataset.key = spec.key;
+    const label = el("label", null, spec.label);
+    label.htmlFor = id;
+    const node = el("div", "field", label, input, spec.hint ? el("p", "hint", spec.hint) : null);
+    node.dataset.key = spec.key;
+    return node;
+  }
+
+  function applyConditions() {
+    if (!page.form) return;
+    for (const spec of page.form.fields) {
+      if (!spec.when) continue;
+      const other = $(`field-${spec.when.key}`);
+      const node = document.querySelector(`.field[data-key="${CSS.escape(spec.key)}"]`);
+      if (other && node) show(node, spec.when.options.includes(other.value));
+    }
+  }
+
+  function submitForm(event) {
+    event.preventDefault();
+    if (!page.form) return;
+    const values = {};
+    for (const node of $("form-fields").children) {
+      if (node.hidden) continue;
+      const input = node.querySelector("input, select, textarea");
+      values[input.dataset.key] = input.value;
+    }
+    $("form-error").textContent = "";
+    send({ type: "submit_form", values });
+  }
+
+  // Closes the form and wipes what was typed. `tell` says the tray does not
+  // know yet.
+  function closeForm(tell) {
+    const dialog = $("form-dialog");
+    if (!page.form && !dialog.open) return;
+    page.form = null;
+    $("form").reset();
+    $("form-fields").replaceChildren();
+    if (dialog.open) dialog.close();
+    if (tell) send({ type: "close_form" });
+  }
+
+  function confirmRemove(name) {
+    page.removing = name;
+    $("confirm-text").textContent = `Remove ${name}? Agents lose it at once, and its secret is gone.`;
+    $("confirm-dialog").showModal();
+  }
+
+  function closeConfirm() {
+    page.removing = null;
+    const dialog = $("confirm-dialog");
+    if (dialog.open) dialog.close();
+  }
+
+  // Wiring.
+
+  function start() {
+    $("unlock-form").addEventListener("submit", (event) => {
+      event.preventDefault();
+      const input = $("passphrase");
+      const passphrase = input.value;
+      input.value = "";
+      $("unlock-message").textContent = "";
+      if (passphrase) send({ type: "unlock", passphrase });
+    });
+    $("use-device").addEventListener("click", () => {
+      $("unlock-message").textContent = "";
+      send({ type: "device_unlock" });
+    });
+    $("lock").addEventListener("click", () => send({ type: "lock" }));
+    $("add").addEventListener("click", () => openRequest({ kind: "new" }));
+    for (const tab of document.querySelectorAll("nav button")) {
+      tab.addEventListener("click", () => {
+        page.tab = tab.dataset.tab;
+        $("app-message").hidden = true;
+        send({ type: "tab", tab: page.tab });
+        draw();
+      });
+    }
+    $("form").addEventListener("submit", submitForm);
+    $("form-cancel").addEventListener("click", () => closeForm(true));
+    // Esc on an open form.
+    $("form-dialog").addEventListener("cancel", (event) => {
+      event.preventDefault();
+      closeForm(true);
+    });
+    $("confirm").addEventListener("submit", (event) => {
+      event.preventDefault();
+      if (page.removing) send({ type: "remove", name: page.removing });
+      closeConfirm();
+    });
+    $("confirm-cancel").addEventListener("click", closeConfirm);
+    $("confirm-dialog").addEventListener("cancel", (event) => {
+      event.preventDefault();
+      closeConfirm();
+    });
+    draw();
+    send({ type: "ready" });
+  }
+
+  window.kv = Object.freeze({ receive });
+  start();
+})();
diff --git a/crates/kv/src/tray/page/index.html b/crates/kv/src/tray/page/index.html
new file mode 100644
index 0000000000000000000000000000000000000000..b162ff0200ce7abf4f8470cfa0323a57cb19831c
--- /dev/null
+++ b/crates/kv/src/tray/page/index.html
@@ -0,0 +1,87 @@
+<!doctype html>
+<html lang="en">
+<head>
+<meta charset="utf-8">
+<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'">
+<meta name="color-scheme" content="light dark">
+<title>kv</title>
+<link rel="stylesheet" href="app.css">
+<script src="app.js" defer></script>
+</head>
+<body>
+<main id="unlock" class="unlock" hidden>
+  <h1>kv is locked</h1>
+  <p id="unlock-waiting" class="waiting" hidden></p>
+  <form id="unlock-form" hidden>
+    <label for="passphrase">Passphrase</label>
+    <div class="row">
+      <input id="passphrase" type="password" autocomplete="off" spellcheck="false">
+      <button type="submit" class="primary">Unlock</button>
+    </div>
+  </form>
+  <button id="use-device" type="button" hidden></button>
+  <p id="unlock-message" class="message" role="alert"></p>
+</main>
+
+<div id="app" hidden>
+  <header>
+    <nav role="tablist">
+      <button type="button" role="tab" data-tab="approvals">Approvals</button>
+      <button type="button" role="tab" data-tab="handles">Handles</button>
+      <button type="button" role="tab" data-tab="audit">Audit</button>
+    </nav>
+    <span id="locks-in" class="muted"></span>
+    <button id="lock" type="button">Lock</button>
+  </header>
+  <p id="app-message" class="message" role="status" hidden></p>
+
+  <section id="approvals" role="tabpanel">
+    <p id="no-approvals" class="empty">No requests waiting</p>
+    <div id="cards"></div>
+  </section>
+
+  <section id="handles" role="tabpanel" hidden>
+    <div id="requests"></div>
+    <div class="toolbar">
+      <h2>Handles</h2>
+      <button id="add" type="button" class="primary">Add handle</button>
+    </div>
+    <p id="no-handles" class="empty">No handles yet</p>
+    <table id="handle-table">
+      <thead><tr><th>Name</th><th>Kind</th><th>Mode</th><th>Allows</th><th></th></tr></thead>
+      <tbody id="handle-rows"></tbody>
+    </table>
+  </section>
+
+  <section id="audit" role="tabpanel" hidden>
+    <p id="no-audit" class="empty">Nothing in the audit log yet</p>
+    <table id="audit-table">
+      <thead><tr><th>Time</th><th>Action</th><th>Handle</th><th>Decision</th><th>Outcome</th><th>Detail</th></tr></thead>
+      <tbody id="audit-rows"></tbody>
+    </table>
+  </section>
+</div>
+
+<dialog id="form-dialog">
+  <form id="form">
+    <h2 id="form-title"></h2>
+    <div id="form-fields"></div>
+    <p id="form-error" class="message" role="alert"></p>
+    <div class="actions">
+      <button type="button" id="form-cancel">Cancel</button>
+      <button type="submit" class="primary">Save</button>
+    </div>
+  </form>
+</dialog>
+
+<dialog id="confirm-dialog">
+  <form id="confirm">
+    <p id="confirm-text"></p>
+    <div class="actions">
+      <button type="button" id="confirm-cancel">Cancel</button>
+      <button type="submit" class="danger">Remove</button>
+    </div>
+  </form>
+</dialog>
+</body>
+</html>
diff --git a/crates/kv/src/tray/ui.rs b/crates/kv/src/tray/ui.rs
index 028aae15f32df371d9ee2b1c61e57318b7f392d2..bc2c4bb79d65f7e7e656ab9754b5a4fc7149d074 100644
--- a/crates/kv/src/tray/ui.rs
+++ b/crates/kv/src/tray/ui.rs
@@ -1,14 +1,17 @@
-//! The tray's main thread: the event loop, the icon and its menu. macOS
-//! wants the status item on the main thread, so the daemon side runs on a
-//! thread of its own (`worker`) and sends each new `Model` here through the
-//! event loop; menu clicks go back to it as `Action`s.
+//! The tray's main thread: the event loop, the icon, its menu and kv's
+//! window. macOS wants all of them on the main thread, so the daemon side
+//! runs on a thread of its own (`worker`) and sends each new `Model` and
+//! each message for the page here through the event loop; menu clicks and
+//! what the page sends go back to it as `Action`s.
+
+mod webview;
 
 use std::fs::File;
 use std::io;
 use std::sync::Arc;
 
-use tao::event::{Event, StartCause};
-use tao::event_loop::{ControlFlow, EventLoopBuilder};
+use tao::event::{Event, StartCause, WindowEvent};
+use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
 use tray_icon::menu::{
     CheckMenuItem, IsMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu,
 };
@@ -21,9 +24,14 @@ use super::{icon, login};
 use crate::device;
 use crate::notify;
 use crate::paths::Paths;
+use webview::KvWindow;
 
 enum Message {
     Show(Model),
+    /// Open kv's window, or bring it to the front. The worker sends the tab
+    /// to the page itself.
+    Open,
+    Page(ToPage),
     /// The worker has stopped.
     Quit,
 }
@@ -45,14 +53,18 @@ pub fn run(paths: Paths, lock: File) -> io::Result<()> {
     }
 
     let (actions, inbox) = tokio::sync::mpsc::unbounded_channel();
+    let clicks = actions.clone();
     MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
         if let Some(action) = Action::from_id(event.id.as_ref()) {
-            let _ = actions.send(action);
+            let _ = clicks.send(action);
         }
     }));
     let proxy = event_loop.create_proxy();
+    let system = System {
+        proxy: proxy.clone(),
+    };
     std::thread::spawn(move || {
-        let worker = Worker::new(paths, device::platform().map(Arc::from), System);
+        let worker = Worker::new(paths, device::platform().map(Arc::from), system);
         let show = proxy.clone();
         runtime.block_on(worker.run(inbox, move |model| {
             let _ = show.send_event(Message::Show(model));
@@ -61,7 +73,8 @@ pub fn run(paths: Paths, lock: File) -> io::Result<()> {
     });
 
     let mut tray: Option<Tray> = None;
-    event_loop.run(move |event, _, flow| {
+    let mut window: Option<KvWindow> = None;
+    event_loop.run(move |event, target, flow| {
         // Held for as long as the loop runs.
         let _ = &lock;
         *flow = ControlFlow::Wait;
@@ -78,7 +91,32 @@ pub fn run(paths: Paths, lock: File) -> io::Result<()> {
                     tray.show(model);
                 }
             }
+            Event::UserEvent(Message::Open) => match &window {
+                Some(open) => open.raise(),
+                None => match KvWindow::open(target, actions.clone()) {
+                    Ok(opened) => window = Some(opened),
+                    Err(e) => {
+                        eprintln!("kv: cannot open kv's window: {e}");
+                        notify::tray(no_window(&e));
+                        let _ = actions.send(Action::WindowClosed);
+                    }
+                },
+            },
+            Event::UserEvent(Message::Page(message)) => {
+                if let Some(open) = &window {
+                    open.send(&message);
+                }
+            }
+            Event::WindowEvent {
+                window_id,
+                event: WindowEvent::CloseRequested,
+                ..
+            } if window.as_ref().is_some_and(|open| open.id() == window_id) => {
+                window = None;
+                let _ = actions.send(Action::WindowClosed);
+            }
             Event::UserEvent(Message::Quit) => {
+                window = None;
                 tray = None;
                 *flow = ControlFlow::Exit;
             }
@@ -96,6 +134,9 @@ struct Tray {
     /// What `menu` holds, item for item.
     items: Vec<Native>,
     shown: Option<Model>,
+    /// The editing keys for kv's window.
+    #[cfg(target_os = "macos")]
+    _edit: Option<Menu>,
 }
 
 impl Tray {
@@ -114,6 +155,8 @@ impl Tray {
             menu,
             items: Vec::new(),
             shown: None,
+            #[cfg(target_os = "macos")]
+            _edit: webview::edit_menu(),
         })
     }
 
@@ -249,18 +292,34 @@ fn native(item: &Item) -> Native {
     }
 }
 
+/// What to tell the user when the window cannot open.
+fn no_window(error: &str) -> String {
+    if cfg!(windows) {
+        // Almost always a missing runtime; the error is on stderr.
+        let _ = error;
+        "kv's window needs the Microsoft Edge WebView2 Runtime".to_owned()
+    } else {
+        format!("kv's window could not open: {error}")
+    }
+}
+
 /// The real desktop: notifications, kv's window, the login item.
-struct System;
+struct System {
+    proxy: EventLoopProxy<Message>,
+}
 
 impl Desktop for System {
     fn notify(&self, text: &str) {
         notify::tray(text.to_owned());
     }
 
-    // Task 5 draws the window.
-    fn show_window(&self, _tab: Tab) {}
+    fn show_window(&self, _tab: Tab) {
+        let _ = self.proxy.send_event(Message::Open);
+    }
 
-    fn page(&self, _message: ToPage) {}
+    fn page(&self, message: ToPage) {
+        let _ = self.proxy.send_event(Message::Page(message));
+    }
 
     fn login_is_on(&self) -> bool {
         login::is_on()
diff --git a/crates/kv/src/tray/ui/webview.rs b/crates/kv/src/tray/ui/webview.rs
new file mode 100644
index 0000000000000000000000000000000000000000..c1ea04758659082c71c49233638d73c6172ad270
--- /dev/null
+++ b/crates/kv/src/tray/ui/webview.rs
@@ -0,0 +1,120 @@
+//! kv's window on screen: a tao window holding a wry webview that shows the
+//! page `tray::window` carries, and nothing else.
+
+use std::borrow::Cow;
+
+use tao::dpi::LogicalSize;
+use tao::event_loop::EventLoopWindowTarget;
+use tao::window::{Window, WindowBuilder, WindowId};
+use tokio::sync::mpsc::UnboundedSender;
+use wry::http::{Response, header};
+use wry::{NewWindowResponse, WebView, WebViewBuilder};
+use zeroize::Zeroizing;
+
+use super::Message;
+use crate::tray::model::Action;
+use crate::tray::window::{CSP, FromPage, PAGE_URL, ToPage, asset, is_page_url};
+
+pub struct KvWindow {
+    // Declared first so it is dropped before the window it draws in.
+    webview: WebView,
+    window: Window,
+}
+
+impl KvWindow {
+    /// Opens the window in front. What the page sends goes to `actions`.
+    pub fn open(
+        target: &EventLoopWindowTarget<Message>,
+        actions: UnboundedSender<Action>,
+    ) -> Result<Self, String> {
+        let window = WindowBuilder::new()
+            .with_title("kv")
+            .with_inner_size(LogicalSize::new(760.0, 520.0))
+            .with_min_inner_size(LogicalSize::new(520.0, 360.0))
+            .build(target)
+            .map_err(|e| e.to_string())?;
+        // WebView2 keeps its data in a folder; by default that is next to
+        // kv.exe, which may not be writable.
+        #[cfg(windows)]
+        let mut context = wry::WebContext::new(Some(std::env::temp_dir().join("kv-webview")));
+        #[cfg(windows)]
+        let builder = {
+            use wry::WebViewBuilderExtWindows;
+            WebViewBuilder::new_with_web_context(&mut context).with_https_scheme(true)
+        };
+        #[cfg(not(windows))]
+        let builder = WebViewBuilder::new();
+        let webview = builder
+            .with_custom_protocol("kv".into(), |_, request| serve(request.uri().path()))
+            .with_ipc_handler(move |request| {
+                let from_page = is_page_url(&request.uri().to_string());
+                let body = Zeroizing::new(request.into_body());
+                if from_page && let Some(message) = FromPage::parse(&body) {
+                    let _ = actions.send(Action::Window(message));
+                }
+            })
+            .with_navigation_handler(|url| is_page_url(&url))
+            .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
+            .with_incognito(true)
+            .with_devtools(false)
+            .with_url(PAGE_URL)
+            .build(&window)
+            .map_err(|e| e.to_string())?;
+        window.set_focus();
+        Ok(Self { webview, window })
+    }
+
+    pub fn id(&self) -> WindowId {
+        self.window.id()
+    }
+
+    /// Brings the window to the front.
+    pub fn raise(&self) {
+        self.window.set_minimized(false);
+        self.window.set_visible(true);
+        self.window.set_focus();
+    }
+
+    pub fn send(&self, message: &ToPage) {
+        let _ = self.webview.evaluate_script(&message.script());
+    }
+}
+
+/// The page's file at `path`, or a 404, always with the policy.
+fn serve(path: &str) -> Response<Cow<'static, [u8]>> {
+    let response = Response::builder().header("Content-Security-Policy", CSP);
+    let response = match asset(path) {
+        Some(asset) => response
+            .header(header::CONTENT_TYPE, asset.mime)
+            .body(Cow::Borrowed(asset.body.as_bytes())),
+        None => response.status(404).body(Cow::Borrowed(&[][..])),
+    };
+    response.unwrap_or_else(|_| Response::new(Cow::Borrowed(&[][..])))
+}
+
+/// The app menu macOS reads Cmd+C, Cmd+V and the other editing keys from.
+/// An accessory app shows no menu bar, but without these items the keys do
+/// nothing in the window's fields.
+#[cfg(target_os = "macos")]
+pub fn edit_menu() -> Option<tray_icon::menu::Menu> {
+    use tray_icon::menu::{Menu, PredefinedMenuItem, Submenu};
+
+    let app = Submenu::with_items("kv", true, &[&PredefinedMenuItem::close_window(None)]).ok()?;
+    let edit = Submenu::with_items(
+        "Edit",
+        true,
+        &[
+            &PredefinedMenuItem::undo(None),
+            &PredefinedMenuItem::redo(None),
+            &PredefinedMenuItem::separator(),
+            &PredefinedMenuItem::cut(None),
+            &PredefinedMenuItem::copy(None),
+            &PredefinedMenuItem::paste(None),
+            &PredefinedMenuItem::select_all(None),
+        ],
+    )
+    .ok()?;
+    let menu = Menu::with_items(&[&app, &edit]).ok()?;
+    menu.init_for_nsapp();
+    Some(menu)
+}
diff --git a/crates/kv/src/tray/window.rs b/crates/kv/src/tray/window.rs
index 5dbcd2cd7e4a1e153256c96e542634d511747013..7f75e328e918b8aac2ce84c6fc72b7de81fc4de1 100644
--- a/crates/kv/src/tray/window.rs
+++ b/crates/kv/src/tray/window.rs
@@ -1,6 +1,7 @@
-//! What kv's window and the tray say to each other. The page sends JSON
-//! that is read into `FromPage` or dropped; the tray answers with `ToPage`,
-//! run in the page as a call to `kv.receive`. Nothing here touches the UI.
+//! kv's window, free of the UI: the page the binary carries, and what the
+//! page and the tray say to each other. The page sends JSON that is read
+//! into `FromPage` or dropped; the tray answers with `ToPage`, run in the
+//! page as a call to `kv.receive`.
 
 use std::collections::BTreeMap;
 
@@ -11,6 +12,44 @@ use serde::{Deserialize, Serialize};
 use crate::audit::Entry;
 use crate::forms::FormView;
 
+/// What the page may load: its own files, nothing else.
+pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'";
+
+/// Where the page is served from: the `kv` protocol on macOS, and on
+/// Windows the https address WebView2 gives it.
+#[cfg(windows)]
+pub const PAGE_URL: &str = "https://kv.app/index.html";
+#[cfg(not(windows))]
+pub const PAGE_URL: &str = "kv://app/index.html";
+
+#[cfg(windows)]
+const ORIGIN: &str = "https://kv.app/";
+#[cfg(not(windows))]
+const ORIGIN: &str = "kv://app/";
+
+/// Whether `url` is kv's page, the only one whose messages count and the
+/// only one the window may show.
+pub fn is_page_url(url: &str) -> bool {
+    url.starts_with(ORIGIN)
+}
+
+/// One of the page's files.
+pub struct Asset {
+    pub mime: &'static str,
+    pub body: &'static str,
+}
+
+/// The file at `path` under the page's address, if the page has one.
+pub fn asset(path: &str) -> Option<Asset> {
+    let (mime, body) = match path {
+        "/" | "/index.html" => ("text/html", include_str!("page/index.html")),
+        "/app.js" => ("text/javascript", include_str!("page/app.js")),
+        "/app.css" => ("text/css", include_str!("page/app.css")),
+        _ => return None,
+    };
+    Some(Asset { mime, body })
+}
+
 /// The window's tabs.
 #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
 #[serde(rename_all = "snake_case")]
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv --test tray_page --test tray && cargo build -p kv && cargo clippy -p kv --all-targets -- -D warnings`
Expected: PASS: 4 `tray_page` tests and 3 `tray` tests. `kv` builds with wry, and clippy is clean. The first build downloads and compiles wry.

- [ ] **Step 5: Check the Windows code from macOS**

Windows-only lines in `webview.rs` (`WebContext`, `with_https_scheme`) are compiled by CI's windows-latest job. To check them from macOS first, build the file in a throwaway crate with the neighbours stubbed:

```bash
P=$(mktemp -d) && mkdir -p $P/src/tray/ui
cat > $P/Cargo.toml <<'EOF'
[package]
name = "kv-webview-probe"
version = "0.1.0"
edition = "2024"
[dependencies]
tao = "0.37"
wry = { version = "0.57", default-features = false }
tray-icon = "0.26"
tokio = { version = "1", features = ["sync"] }
zeroize = "1.9"
EOF
printf 'mod tray;\nfn main() {}\n' > $P/src/main.rs
printf 'pub mod model;\npub mod ui;\npub mod window;\n' > $P/src/tray.rs
cat > $P/src/tray/model.rs <<'EOF'
#[derive(Debug)]
pub enum Action {
    Window(super::window::FromPage),
    WindowClosed,
}
EOF
cat > $P/src/tray/window.rs <<'EOF'
pub const CSP: &str = "x";
pub const PAGE_URL: &str = "https://kv.app/index.html";
pub fn is_page_url(url: &str) -> bool { url.starts_with("https://kv.app/") }
pub struct Asset { pub mime: &'static str, pub body: &'static str }
pub fn asset(_path: &str) -> Option<Asset> { None }
#[derive(Debug)]
pub struct FromPage;
impl FromPage { pub fn parse(_json: &str) -> Option<FromPage> { None } }
pub struct ToPage;
impl ToPage { pub fn script(&self) -> String { String::new() } }
EOF
cat > $P/src/tray/ui.rs <<'EOF'
pub enum Message {}
pub mod webview;
#[allow(dead_code)]
fn uses(target: &tao::event_loop::EventLoopWindowTarget<Message>, tx: tokio::sync::mpsc::UnboundedSender<super::model::Action>) {
    let w = webview::KvWindow::open(target, tx).unwrap();
    w.raise();
    w.send(&super::window::ToPage);
    let _ = w.id();
    #[cfg(target_os = "macos")]
    let _ = webview::edit_menu();
}
EOF
cp crates/kv/src/tray/ui/webview.rs $P/src/tray/ui/webview.rs
(cd $P && cargo clippy --target x86_64-pc-windows-msvc && cargo clippy --target aarch64-apple-darwin)
rm -rf $P
```

Expected: both finish with only the stub's `variant WindowClosed is never constructed` warning. Needs `rustup target add x86_64-pc-windows-msvc` once.

- [ ] **Step 6: Smoke-run the window**

On macOS, against an empty home so nothing touches your vault, and with a clean environment:

```bash
H=$(mktemp -d)
env -i HOME=$HOME PATH=/usr/bin:/bin KV_HOME=$H target/debug/kv tray
```

Expected:
- A grey key appears in the menu bar. Its menu reads "Unlock…", then "Start at login" and "Quit kv tray".
- "Unlock…" opens a window titled "kv" showing "kv is locked" and a passphrase field.
- Typing any passphrase and pressing Enter clears the field. The daemon's answer appears under it ("No vault yet: run `kv init`" or similar, since this home has no vault).
- Closing the window and choosing "Unlock…" again opens it again. "Quit kv tray" ends the process.

Then `rm -rf $H`.

- [ ] **Step 7: Hand the Review Focus to a person**

These checks need a webview, a keyboard, a finger on the sensor and a Windows machine, so an executor does not block on them. It lists this plan's Review Focus in its final message, for the human partner to run before release. The person runs `target/debug/kv tray` with a vault that has Touch ID on (`kv biometric enable`) and one `--mode ask` handle, then goes through each line. Anything that fails becomes a test first, where one can reproduce it.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "Draw kv's window: a webview showing the page kv carries"
```

### Task 6: README and specs

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-10-12-kv-tray-design.md`
- Modify: `docs/superpowers/specs/2026-10-12-kv-tray-window-design.md`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - The README's tray section describes kv's window, the look-alike warning and the WebView2 runtime.
  - The tray spec's status points to the window spec.
  - The window spec says "implemented", and its architecture section uses this plan's names: `Ready`, `Show { tab }`, `Message { text, request }`, `Action::Open(Tab)`, `Desktop::{show_window, page}`.

- [ ] **Step 1: Edit the docs**

Apply with `git apply` from the repository root:

````diff
diff --git a/README.md b/README.md
index d7656a5199a7e20690117fb77cd61a79cb3ff0be..5726b777210dcfb14ea81043273b9907201c1113 100644
--- a/README.md
+++ b/README.md
@@ -18,8 +18,8 @@ Protocol over stdio.
 
 Status: agents can make HTTP requests, run programs, and query or connect to
 Postgres and Redis with your secrets over MCP, `kv tui` or a menu bar icon
-(`kv tray`) approves `--mode ask` requests as they arrive, and Touch ID or
-Windows Hello can stand in for the passphrase.
+(`kv tray`, with a window of its own) approves `--mode ask` requests as they
+arrive, and Touch ID or Windows Hello can stand in for the passphrase.
 
 ![kv tui: two agent requests waiting for approval](docs/images/tui-approvals.svg)
 
@@ -204,14 +204,22 @@ kv tray --login on            # --login off removes the login item
 ```
 
 Unlock the tray from its menu with Touch ID or Windows Hello (set up with
-`kv biometric enable`, below); it never asks for the passphrase, so without
-either its menu opens `kv tui` instead. Once unlocked, each waiting request is
-an entry with the agent, tool and handles, and a submenu showing what it
-asked for and the same four answers as the TUI: Allow once, Allow for this
-session, Deny, and Deny and block. "Lock vault" locks the vault for every
-client. Handle requests from agents are answered in `kv tui`, which the menu
-opens. Anything the tray cannot do, such as answering a request that has
-already timed out, shows up as a notification.
+`kv biometric enable`, below). Without either, or when the prompt is
+cancelled, "Unlock…" opens kv's window, which asks for the passphrase. Once
+unlocked, each waiting request is an entry with the agent, tool and handles,
+and a submenu showing what it asked for and the same four answers as the
+TUI: Allow once, Allow for this session, Deny, and Deny and block. "Lock
+vault" locks the vault for every client. Anything the menu cannot do, such as
+answering a request that has already timed out, shows up as a notification.
+
+"Open kv…" opens kv's window, which does everything `kv tui` does without a
+terminal: an Approvals tab with each waiting request in full, a Handles tab
+where you fill in agents' handle requests and add, edit, re-police or remove
+handles, and an Audit tab. The menu and the window share one session; closing
+the window keeps it, and Lock (in either) ends it. kv's window only opens
+when you pick one of these menu items. Treat a kv window that appears on its
+own, asking for your passphrase, as fake. On Windows the window needs the
+Microsoft Edge WebView2 Runtime, which Windows 10 and 11 normally have.
 
 The login item takes effect at your next login. On Windows a console window
 may flash as it starts.
@@ -306,9 +314,10 @@ program you let a handle run does receive the secret.
 
 An unlocked `kv tui` or `kv tray` answers requests for whoever drives it. A
 program running as you that can control other programs' windows can type
-into the TUI or click Allow in the tray's menu: on macOS only programs you
-have given the Accessibility permission, on Windows any program at the same
-integrity level. Lock the vault, or quit both, when agents run unattended.
+into the TUI or click Allow in the tray's menu or window: on macOS only
+programs you have given the Accessibility permission, on Windows any program
+at the same integrity level. Lock the vault, or quit both, when agents run
+unattended.
 
 Single-user, for macOS, Linux and Windows, written in Rust.
 
diff --git a/docs/superpowers/specs/2026-10-12-kv-tray-design.md b/docs/superpowers/specs/2026-10-12-kv-tray-design.md
index 2be27423640002b0a7002bb44b67470c23fd587a..efea544ca5d9c24aac147eef8d0543dd893772f1 100644
--- a/docs/superpowers/specs/2026-10-12-kv-tray-design.md
+++ b/docs/superpowers/specs/2026-10-12-kv-tray-design.md
@@ -1,7 +1,8 @@
 # kv tray: approve agent requests from the menu bar — design
 
 Date: 2026-10-12
-Status: implemented on feat/tray
+Status: implemented on feat/tray; the menu items that opened `kv tui` now
+open kv's window (`2026-10-12-kv-tray-window-design.md`)
 
 ## 1. Goal
 
diff --git a/docs/superpowers/specs/2026-10-12-kv-tray-window-design.md b/docs/superpowers/specs/2026-10-12-kv-tray-window-design.md
index 321239e07f3baf971f8ee3325f2473acf60059a5..d024168928afc52ee84b7d8495647a9dd5db7061 100644
--- a/docs/superpowers/specs/2026-10-12-kv-tray-window-design.md
+++ b/docs/superpowers/specs/2026-10-12-kv-tray-window-design.md
@@ -1,7 +1,7 @@
 # kv tray window: unlock and manage kv without the TUI — design
 
 Date: 2026-10-12
-Status: approved for planning
+Status: implemented on feat/tray-window
 
 ## 1. Goal
 
@@ -131,23 +131,28 @@ All in the `kv tray` process.
   `fill(&mut Form, values)` (sets each field the page sent, ignoring keys
   the form does not have). `tui::form` keeps the key handling and drawing.
 - **`tray::window`** (pure, all platforms): the page protocol.
-  - `FromPage` (serde, tagged): `Unlock { passphrase }`, `DeviceUnlock`,
-    `Decide { id, verdict }`, `OpenForm { form }` where `form` is
-    `New`, `Request { id }`, `Edit { name }` or `Policy { name }`,
-    `SubmitForm { values }`, `CloseForm`, `Dismiss { id }`, `Remove {
-    name }`, `Lock`, `Tab { tab }`.
+  - `FromPage` (serde, tagged): `Ready` (the page has loaded),
+    `Unlock { passphrase }`, `DeviceUnlock`, `Decide { id, verdict }`,
+    `OpenForm { form }` where `form` is `New`, `Request { id }`,
+    `Edit { name }` or `Policy { name }`, `SubmitForm { values }`,
+    `CloseForm`, `Dismiss { id }`, `Remove { name }`, `Lock`,
+    `Tab { tab }`.
   - `ToPage` (serde, tagged): `State { locked, device, waiting_for_device,
     overview }`, `Form { view }`, `FormError { message }`, `FormDone`,
-    `Audit { entries }`, `Message { text }`, `Show { screen }`.
+    `Audit { entries }`, `Message { text, request }` (`request` names the
+    card it belongs on), `Show { tab }`. The unlock screen is not a tab:
+    the page shows it whenever `State.locked` is true.
   - Passphrases and secret values arrive as plain strings and are turned
     into `SecretText` before anything else touches them.
 - **`tray::worker`** gains the window's state: whether it is open, its
-  active tab, the open form and its `Purpose`, and a pending device prompt
-  for the window. `Action` gains `Window(FromPage)`, `OpenWindow(Screen)`
-  and `WindowClosed`. Every tick it sends the menu's `Model` as today and,
+  active tab, the open form and its `Purpose`, and who is waiting on a
+  device prompt. The menu's `OpenTui` and `HandleRequests` become
+  `Action::Open(Tab)`, and `Action` gains `Window(FromPage)` and
+  `WindowClosed`. Its `Desktop` swaps `open_tui` for `show_window(Tab)` and
+  `page(ToPage)`. Every tick it sends the menu's `Model` as today and,
   while the window is open, a `State` (and `Audit` on the Audit tab).
-- **`tray::ui`** creates the wry `WebView` in a tao window on
-  `OpenWindow`, shows it if it exists, serves the page under the custom
+- **`tray::ui`** creates the wry `WebView` in a tao window when the worker
+  asks to show the window, raises it if it exists, serves the page under the custom
   protocol `kv`, forwards IPC strings to the worker as `FromPage` (dropping
   any that do not parse or that come from another URL), and runs
   `kv.receive(<json>)` for each `ToPage`. Closing the window sends
````

- [ ] **Step 2: Run everything**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: PASS: 510 tests without the database servers (their live tests skip), more with `KV_TEST_POSTGRES_URL` and `KV_TEST_REDIS_URL` set.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "Document kv's window"
```
