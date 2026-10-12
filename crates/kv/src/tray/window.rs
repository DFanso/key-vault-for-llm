//! kv's window, free of the UI: the page the binary carries, and what the
//! page and the tray say to each other. The page sends JSON that is read
//! into `FromPage` or dropped; the tray answers with `ToPage`, run in the
//! page as a call to `kv.receive`.

use std::collections::BTreeMap;

use kv_core::proto::{Overview, Verdict};
use kv_core::secret::SecretText;
use serde::{Deserialize, Serialize};

use crate::audit::Entry;
use crate::forms::FormView;

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

/// The window's tabs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tab {
    Approvals,
    Handles,
    Audit,
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
    Lock,
    Tab {
        tab: Tab,
    },
}

impl FromPage {
    /// The message in `json`, or `None` for anything that is not one.
    pub fn parse(json: &str) -> Option<FromPage> {
        serde_json::from_str(json).ok()
    }
}

/// A message to the page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToPage {
    /// Sent every tick while the window is open.
    State {
        locked: bool,
        /// The device the vault has a slot for on this platform, such as
        /// "Touch ID".
        device: Option<String>,
        waiting_for_device: bool,
        /// `Some` while the tray holds a session.
        overview: Option<Overview>,
    },
    Show {
        tab: Tab,
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
