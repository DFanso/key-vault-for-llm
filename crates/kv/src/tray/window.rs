//! kv's window, free of the UI: the page the binary carries, and what the
//! page and the tray say to each other. The page sends JSON that is read
//! into `FromPage` or dropped; the tray answers with `ToPage`, run in the
//! page as a call to `kv.receive`.

use std::collections::BTreeMap;

use kv_core::proto::{Overview, RevealedField, Verdict};
use kv_core::secret::SecretText;
use serde::{Deserialize, Serialize};

use crate::audit::Entry;
use crate::forms::FormView;
use crate::tui::app::ShareDone;

/// What the page may load: its own files, nothing else.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'";

/// Where the page is served from: the `kv` protocol on macOS, and on
/// Windows the https address WebView2 gives it.
#[cfg(windows)]
pub const PAGE_URL: &str = "https://kv.app/index.html";
#[cfg(not(windows))]
pub const PAGE_URL: &str = "kv://app/index.html";

#[cfg(windows)]
const ORIGIN: &str = "https://kv.app/";
#[cfg(not(windows))]
const ORIGIN: &str = "kv://app/";

/// Whether `url` is kv's page, the only one whose messages count and the
/// only one the window may show.
pub fn is_page_url(url: &str) -> bool {
    url.starts_with(ORIGIN)
}

/// One of the page's files.
pub struct Asset {
    pub mime: &'static str,
    pub body: &'static str,
}

/// The file at `path` under the page's address, if the page has one.
pub fn asset(path: &str) -> Option<Asset> {
    let (mime, body) = match path {
        "/" | "/index.html" => ("text/html", include_str!("page/index.html")),
        "/app.js" => ("text/javascript", include_str!("page/app.js")),
        "/app.css" => ("text/css", include_str!("page/app.css")),
        _ => return None,
    };
    Some(Asset { mime, body })
}

/// The window's tabs. The page has a Settings screen of its own besides.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tab {
    /// What needs the user, the numbers and the latest activity.
    Home,
    Approvals,
    Handles,
    Shares,
    Audit,
}

/// How the window looks: as the system's light or dark mode, or always
/// one of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

impl Theme {
    /// The theme saved in `path`; the default if there is none or it does
    /// not read as one.
    pub fn load(path: &std::path::Path) -> Theme {
        match std::fs::read_to_string(path).as_deref().map(str::trim) {
            Ok("light") => Theme::Light,
            Ok("dark") => Theme::Dark,
            _ => Theme::System,
        }
    }

    pub fn save(self, path: &std::path::Path) -> std::io::Result<()> {
        let name = match self {
            Theme::System => "system",
            Theme::Light => "light",
            Theme::Dark => "dark",
        };
        std::fs::write(path, name)
    }
}

/// The form the page asks to open.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FormRequest {
    New,
    /// Fill in an agent's handle request.
    Request {
        id: u64,
    },
    Edit {
        name: String,
    },
    Policy {
        name: String,
    },
}

/// A message from the page. Passphrases and secret values are `SecretText`
/// from the moment they are read.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FromPage {
    /// The page has loaded and wants the current state.
    Ready,
    Unlock {
        passphrase: SecretText,
    },
    DeviceUnlock,
    Decide {
        id: u64,
        verdict: Verdict,
    },
    OpenForm {
        form: FormRequest,
    },
    SubmitForm {
        values: BTreeMap<String, SecretText>,
    },
    CloseForm,
    Dismiss {
        id: u64,
    },
    Remove {
        name: String,
    },
    /// Show the value of a handle that came from a share.
    Reveal {
        handle: String,
    },
    /// Cancel a share request, or drop a received or sent record.
    Forget {
        id: String,
    },
    /// A `.env` or JSON settings file the user picked to import. Its values
    /// stay with the worker; the page hears back only the variables' names.
    ImportFile {
        file_name: String,
        text: SecretText,
    },
    /// Save the import being shown as the handle `name`, with the variables
    /// in `keep`.
    ImportSave {
        name: String,
        keep: Vec<String>,
    },
    /// Drop the import being shown.
    ImportCancel,
    /// Any file the user picked to keep as a `file` handle, as base64. Its
    /// bytes stay with the worker; the page hears back only what it is.
    FileRead {
        file_name: String,
        data: SecretText,
    },
    /// Save the file being shown as the handle `name`, for the programs in
    /// `cmds` (comma-separated).
    FileSave {
        name: String,
        cmds: String,
    },
    /// Drop the file being shown.
    FileCancel,
    /// Save the file a received `file` handle holds to the Downloads folder.
    SaveFile {
        handle: String,
    },
    /// Show the file last saved in the file manager.
    ShowSaved,
    /// Make a request code for the user to send someone.
    RequestShare {
        note: String,
        from: String,
    },
    /// Seal a handle to a request code the user pasted. Blank `name` keeps
    /// the handle's own.
    SendShare {
        request: String,
        handle: String,
        name: String,
        from: String,
        note: String,
    },
    /// Save a share the user pasted as a handle. Blank `name` takes the
    /// sender's suggestion.
    ReceiveShare {
        share: String,
        name: String,
    },
    Lock,
    Tab {
        tab: Tab,
    },
    /// Hide the window (Esc, or its close button). The window side takes
    /// this one itself.
    Hide,
    /// Grow the small menu into the full window (its Open kv). The window
    /// side takes this one itself.
    Expand,
    Theme {
        theme: Theme,
    },
    /// Turn the login item on or off.
    Login {
        on: bool,
    },
    Quit,
}

impl FromPage {
    /// The message in `json`, or `None` for anything that is not one.
    pub fn parse(json: &str) -> Option<FromPage> {
        serde_json::from_str(json).ok()
    }
}

/// A variable of a file being imported: its name, never its value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportVar {
    pub name: String,
    /// Whether it changes how a program runs or where it connects.
    pub risky: bool,
    /// Whether it starts ticked.
    pub keep: bool,
}

/// A message to the page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToPage {
    /// What a file to import holds, for the user to tick.
    ImportPreview {
        file_name: String,
        /// The handle name to suggest.
        name: String,
        format: String,
        vars: Vec<ImportVar>,
        notes: Vec<String>,
    },
    /// The import was saved as `name`.
    Imported {
        name: String,
        warnings: Vec<String>,
    },
    /// What a file to keep holds, for the user to name and allow.
    FilePreview {
        file_name: String,
        /// The handle name to suggest.
        name: String,
        /// The size in bytes.
        size: usize,
        /// A short fingerprint of the bytes.
        fingerprint: String,
        /// Whether kv can scrub the file's contents from program output.
        scrubbed: bool,
        notes: Vec<String>,
    },
    /// The file was saved as the handle `name`.
    FileAdded {
        name: String,
        warnings: Vec<String>,
    },
    /// Why a file cannot be kept.
    FileError {
        message: String,
    },
    /// A share too long for a message, saved as a file to send as an
    /// attachment.
    ShareSaved {
        path: String,
        safety_code: String,
        to: String,
        asked_for: String,
    },
    /// A received file, saved where the user can find it.
    FileSaved {
        handle: String,
        path: String,
    },
    /// Why a file cannot be imported or saved.
    ImportError {
        message: String,
    },
    /// Sent every tick while the window is open.
    State {
        locked: bool,
        /// The device the vault has a slot for on this platform, such as
        /// "Touch ID".
        device: Option<String>,
        waiting_for_device: bool,
        /// `Some` while the tray holds a session.
        overview: Option<Overview>,
        /// Whether kv tray starts at login.
        login: bool,
        theme: Theme,
    },
    Show {
        tab: Tab,
    },
    /// The window went out of sight: the page puts away a value on show.
    Hidden,
    /// The window shows the small menu a click on the tray icon opens
    /// (`on`), or the full page.
    Menu {
        on: bool,
    },
    /// A form to draw, with no secret text in it.
    Form {
        view: FormView,
    },
    FormError {
        message: String,
    },
    FormDone,
    Audit {
        entries: Vec<Entry>,
    },
    /// A received handle's value, which the user asked to see.
    Revealed {
        handle: String,
        fields: Vec<RevealedField>,
    },
    /// A share step the user took in the share dialog.
    Shared {
        result: ShareDone,
    },
    /// Why a share step failed, for the share dialog.
    ShareError {
        message: String,
    },
    /// What an action from the window came to; `request` names the card it
    /// belongs on.
    Message {
        text: String,
        request: Option<u64>,
    },
}

impl ToPage {
    /// The script that hands this message to the page. The message is only
    /// ever JSON data inside the call.
    pub fn script(&self) -> String {
        let json = serde_json::to_string(self).expect("a ToPage always serializes");
        format!("kv.receive({json})")
    }
}
