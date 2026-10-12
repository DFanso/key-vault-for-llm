//! What the tray shows, free of the UI and the daemon: the daemon's status
//! and overview come in, the icon, its tooltip and the menu come out. Every
//! menu item carries the `Action` a click on it means.

use kv_core::proto::{Approval, Overview, Status, Verdict};
use kv_core::vault::DeviceKind;

use super::window::Tab;

/// How long a request's label may be.
const LABEL_LEN: usize = 60;
/// How long a line of a request's detail may be.
const DETAIL_LEN: usize = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IconState {
    /// No daemon, or no vault yet.
    Off,
    Locked,
    Unlocked,
    /// This many agent requests are waiting.
    Waiting(usize),
}

/// What a click asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Touch ID or Windows Hello, then a session.
    Unlock,
    /// kv's window, on this tab once unlocked, or on its unlock screen.
    Open(Tab),
    Lock,
    /// Turns the login item on or off.
    Login(bool),
    Quit,
    Decide {
        id: u64,
        verdict: Verdict,
    },
}

impl Action {
    /// The menu item id. It names the request and the answer, so a click
    /// always means what the item said, however the menu moved.
    pub fn id(&self) -> String {
        match self {
            Action::Unlock => "unlock".into(),
            Action::Open(Tab::Approvals) => "open:approvals".into(),
            Action::Open(Tab::Handles) => "open:handles".into(),
            Action::Open(Tab::Audit) => "open:audit".into(),
            Action::Lock => "lock".into(),
            Action::Login(true) => "login:on".into(),
            Action::Login(false) => "login:off".into(),
            Action::Quit => "quit".into(),
            Action::Decide { id, verdict } => format!("decide:{id}:{}", verdict_name(*verdict)),
        }
    }

    pub fn from_id(id: &str) -> Option<Action> {
        Some(match id {
            "unlock" => Action::Unlock,
            "open:approvals" => Action::Open(Tab::Approvals),
            "open:handles" => Action::Open(Tab::Handles),
            "open:audit" => Action::Open(Tab::Audit),
            "lock" => Action::Lock,
            "login:on" => Action::Login(true),
            "login:off" => Action::Login(false),
            "quit" => Action::Quit,
            _ => {
                let rest = id.strip_prefix("decide:")?;
                let (request, verdict) = rest.split_once(':')?;
                let verdict = [
                    Verdict::AllowOnce,
                    Verdict::AllowSession,
                    Verdict::Deny,
                    Verdict::DenyAlways,
                ]
                .into_iter()
                .find(|v| verdict_name(*v) == verdict)?;
                Action::Decide {
                    id: request.parse().ok()?,
                    verdict,
                }
            }
        })
    }
}

fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::AllowOnce => "allow_once",
        Verdict::AllowSession => "allow_session",
        Verdict::Deny => "deny",
        Verdict::DenyAlways => "deny_always",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Action {
        label: String,
        action: Action,
    },
    Check {
        label: String,
        checked: bool,
        action: Action,
    },
    /// A line that cannot be clicked.
    Text(String),
    Separator,
    Submenu {
        id: String,
        label: String,
        items: Vec<Item>,
    },
}

/// What the tray knows.
pub struct View<'a> {
    /// `None` when no daemon is running.
    pub status: Option<&'a Status>,
    /// `Some` while the tray holds a session.
    pub overview: Option<&'a Overview>,
    /// The device the vault has a slot for on this platform.
    pub device: Option<DeviceKind>,
    /// Whether the login item is on.
    pub login: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    pub icon: IconState,
    pub tooltip: String,
    /// Text beside the icon, where the platform shows one (macOS).
    pub title: Option<String>,
    pub menu: Vec<Item>,
}

impl Model {
    pub fn new(view: View) -> Model {
        let icon = match view.status {
            None => IconState::Off,
            Some(status) if !status.vault_exists => IconState::Off,
            Some(status) if status.locked => IconState::Locked,
            Some(status) if status.pending_approvals > 0 => {
                IconState::Waiting(status.pending_approvals)
            }
            Some(_) => IconState::Unlocked,
        };
        let tooltip = match (icon, view.status) {
            (IconState::Off, None) => "kv: not running".to_owned(),
            (IconState::Off, Some(_)) => "kv: no vault yet".to_owned(),
            (IconState::Locked, _) => "kv: locked".to_owned(),
            (IconState::Unlocked, _) => "kv: unlocked".to_owned(),
            (IconState::Waiting(1), _) => "kv: 1 request waiting".to_owned(),
            (IconState::Waiting(n), _) => format!("kv: {n} requests waiting"),
        };
        let title = match icon {
            IconState::Waiting(n) => Some(n.to_string()),
            _ => None,
        };
        let mut menu = match view.overview {
            Some(overview) if !view.status.is_some_and(|s| s.locked) => unlocked_menu(overview),
            _ => locked_menu(&view),
        };
        menu.push(Item::Separator);
        menu.push(Item::Check {
            label: "Start at login".into(),
            checked: view.login,
            action: Action::Login(!view.login),
        });
        menu.push(action("Quit kv tray", Action::Quit));
        Model {
            icon,
            tooltip,
            title,
            menu,
        }
    }
}

fn locked_menu(view: &View) -> Vec<Item> {
    if view.status.is_some_and(|s| !s.vault_exists) {
        return vec![
            Item::Text("No vault yet: run `kv init`".into()),
            action("Open kv…", Action::Open(Tab::Approvals)),
        ];
    }
    match view.device {
        Some(device) => vec![
            action(&format!("Unlock with {}", device.label()), Action::Unlock),
            action("Open kv…", Action::Open(Tab::Approvals)),
        ],
        // kv's window asks for the passphrase.
        None => vec![action("Unlock…", Action::Open(Tab::Approvals))],
    }
}

fn unlocked_menu(overview: &Overview) -> Vec<Item> {
    let mut menu: Vec<Item> = overview.approvals.iter().map(request).collect();
    if menu.is_empty() {
        menu.push(Item::Text("No requests waiting".into()));
    }
    match overview.handle_requests.len() {
        0 => {}
        1 => menu.push(action(
            "1 handle request: open kv…",
            Action::Open(Tab::Handles),
        )),
        n => menu.push(action(
            &format!("{n} handle requests: open kv…"),
            Action::Open(Tab::Handles),
        )),
    }
    menu.push(Item::Separator);
    menu.push(action("Lock vault", Action::Lock));
    menu.push(action("Open kv…", Action::Open(Tab::Approvals)));
    menu
}

fn request(approval: &Approval) -> Item {
    let handles = approval.handles.join(", ");
    let client = approval.client.as_deref().unwrap_or("agent");
    let mut items = vec![Item::Text(one_line(&approval.detail, DETAIL_LEN))];
    if let Some(cwd) = &approval.cwd {
        items.push(Item::Text(one_line(&format!("in {cwd}"), DETAIL_LEN)));
    }
    items.push(Item::Text(format!(
        "Expires in {}s",
        approval.expires_in_secs
    )));
    items.push(Item::Separator);
    let decide = |verdict| Action::Decide {
        id: approval.id,
        verdict,
    };
    items.push(action("Allow once", decide(Verdict::AllowOnce)));
    if approval.can_grant {
        items.push(action(
            "Allow for this session",
            decide(Verdict::AllowSession),
        ));
    }
    items.push(action("Deny", decide(Verdict::Deny)));
    items.push(action(
        &one_line(&format!("Deny and block {handles}"), LABEL_LEN),
        decide(Verdict::DenyAlways),
    ));
    Item::Submenu {
        id: format!("request:{}", approval.id),
        label: one_line(
            &format!("{client} · {} · {handles}", approval.tool),
            LABEL_LEN,
        ),
        items,
    }
}

fn action(label: &str, action: Action) -> Item {
    Item::Action {
        label: label.to_owned(),
        action,
    }
}

/// `text` on one line of at most `max` characters: control characters and
/// line breaks become spaces, runs of whitespace collapse, and a longer
/// text ends in "…". Each `&` is then doubled, since menus read a single
/// one as a keyboard shortcut marker and do not show it.
pub fn one_line(text: &str, max: usize) -> String {
    let words: Vec<&str> = text
        .split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|word| !word.is_empty())
        .collect();
    let mut line = words.join(" ");
    if line.chars().count() > max {
        line = line.chars().take(max.saturating_sub(1)).collect();
        line.push('…');
    }
    line.replace('&', "&&")
}

/// Whether two menus differ only in the text of their `Text` lines, such as
/// a request's countdown. Then the tray changes those lines in place rather
/// than replacing a menu the user may have open.
pub fn same_shape(a: &[Item], b: &[Item]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|pair| match pair {
            (Item::Text(_), Item::Text(_)) => true,
            (
                Item::Submenu {
                    id: a_id,
                    label: a_label,
                    items: a_items,
                },
                Item::Submenu {
                    id: b_id,
                    label: b_label,
                    items: b_items,
                },
            ) => a_id == b_id && a_label == b_label && same_shape(a_items, b_items),
            (a, b) => a == b,
        })
}

/// One step of turning the menu on screen into a new one. Applied in
/// order; `at` is a position in the menu as the earlier steps left it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edit {
    /// The item at `at` stays; its text and check mark come from
    /// `new[index]`.
    Keep {
        at: usize,
        index: usize,
    },
    Insert {
        at: usize,
        index: usize,
    },
    Remove {
        at: usize,
    },
}

/// The edits that turn `shown` into `new` while keeping every item both
/// have, so a request the user has open is never taken out and put back
/// (on Windows a click on an item that was taken out is lost).
pub fn edits(shown: &[Item], new: &[Item]) -> Vec<Edit> {
    let mut out = Vec::new();
    // What is on screen past the edits so far, as indices into `shown`.
    let mut left: Vec<usize> = (0..shown.len()).collect();
    let mut at = 0;
    for (index, item) in new.iter().enumerate() {
        match left.iter().position(|&s| same_item(&shown[s], item)) {
            Some(skip) => {
                for _ in 0..skip {
                    out.push(Edit::Remove { at });
                }
                left.drain(..=skip);
                out.push(Edit::Keep { at, index });
            }
            None => out.push(Edit::Insert { at, index }),
        }
        at += 1;
    }
    out.extend(left.iter().map(|_| Edit::Remove { at }));
    out
}

/// Whether `new` can stand in for `shown` by changing text in place.
fn same_item(shown: &Item, new: &Item) -> bool {
    match (shown, new) {
        (Item::Text(a), Item::Text(b)) => a == b,
        (Item::Separator, Item::Separator) => true,
        (Item::Action { action: a, .. }, Item::Action { action: b, .. })
        | (Item::Check { action: a, .. }, Item::Check { action: b, .. }) => a == b,
        (
            Item::Submenu {
                id: a_id,
                label: a_label,
                items: a_items,
            },
            Item::Submenu {
                id: b_id,
                label: b_label,
                items: b_items,
            },
        ) => a_id == b_id && a_label == b_label && same_shape(a_items, b_items),
        _ => false,
    }
}
