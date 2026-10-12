//! What kv's window and the tray say to each other. The page sends JSON
//! that is read into `FromPage` or dropped; the tray answers with `ToPage`,
//! run in the page as a call to `kv.receive`. Nothing here touches the UI.

use std::collections::BTreeMap;

use kv_core::proto::{Overview, Verdict};
use kv_core::secret::SecretText;
use serde::{Deserialize, Serialize};

use crate::audit::Entry;
use crate::forms::FormView;

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
