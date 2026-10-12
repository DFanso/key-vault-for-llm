//! What `kv tray` shows, free of any UI: the daemon's status and overview go
//! in, the icon, its tooltip and the menu come out.

use kv::tray::model::{Action, IconState, Item, Model, View, one_line, same_shape};
use kv_core::proto::{Approval, Overview, RequestedHandle, Status, Verdict};
use kv_core::vault::DeviceKind;

fn status(locked: bool, waiting: usize) -> Status {
    Status {
        vault_exists: true,
        locked,
        handle_count: (!locked).then_some(1),
        locks_in_secs: None,
        pending_approvals: waiting,
        devices: Vec::new(),
    }
}

fn approval(id: u64, can_grant: bool) -> Approval {
    Approval {
        id,
        client: Some("claude-code".into()),
        tool: "http_request".into(),
        handles: vec!["openrouter".into()],
        detail: format!("GET https://openrouter.ai/api/v1/models?page={id}"),
        cwd: None,
        can_grant,
        expires_in_secs: 42,
    }
}

fn overview(approvals: Vec<Approval>) -> Overview {
    Overview {
        status: status(false, approvals.len()),
        handles: Vec::new(),
        approvals,
        handle_requests: Vec::new(),
        role_warnings: Default::default(),
    }
}

fn labels(items: &[Item]) -> Vec<String> {
    items
        .iter()
        .map(|item| match item {
            Item::Action { label, .. } | Item::Check { label, .. } => label.clone(),
            Item::Submenu { label, .. } => format!("> {label}"),
            Item::Text(text) => format!("({text})"),
            Item::Separator => "--".into(),
        })
        .collect()
}

fn view<'a>(status: Option<&'a Status>, overview: Option<&'a Overview>) -> View<'a> {
    View {
        status,
        overview,
        device: Some(DeviceKind::TouchId),
        login: false,
    }
}

#[test]
fn the_icon_follows_the_daemon_without_a_session() {
    let model = Model::new(view(None, None));
    assert_eq!(model.icon, IconState::Off);
    assert_eq!(model.tooltip, "kv: not running");

    let mut fresh = status(true, 0);
    fresh.vault_exists = false;
    assert_eq!(
        Model::new(view(Some(&fresh), None)).tooltip,
        "kv: no vault yet"
    );

    let locked = status(true, 0);
    let model = Model::new(view(Some(&locked), None));
    assert_eq!(
        (model.icon, model.tooltip.as_str()),
        (IconState::Locked, "kv: locked")
    );

    let idle = status(false, 0);
    let model = Model::new(view(Some(&idle), None));
    assert_eq!((model.icon, model.title), (IconState::Unlocked, None));
    assert_eq!(model.tooltip, "kv: unlocked");

    // The count needs no session: a tray that has not unlocked still shows it.
    let one = status(false, 1);
    let model = Model::new(view(Some(&one), None));
    assert_eq!(model.icon, IconState::Waiting(1));
    assert_eq!(model.tooltip, "kv: 1 request waiting");
    assert_eq!(model.title.as_deref(), Some("1"));
    let two = status(false, 2);
    assert_eq!(
        Model::new(view(Some(&two), None)).tooltip,
        "kv: 2 requests waiting"
    );
}

#[test]
fn without_a_session_the_menu_offers_to_unlock() {
    let locked = status(true, 0);
    let model = Model::new(view(Some(&locked), None));
    assert_eq!(
        labels(&model.menu),
        [
            "Unlock with Touch ID",
            "Open kv tui",
            "--",
            "Start at login",
            "Quit kv tray"
        ]
    );
    let hello = Model::new(View {
        device: Some(DeviceKind::WindowsHello),
        ..view(Some(&locked), None)
    });
    assert_eq!(labels(&hello.menu)[0], "Unlock with Windows Hello");

    // No device slot: the passphrase is only typed into a terminal.
    let model = Model::new(View {
        device: None,
        ..view(Some(&locked), None)
    });
    assert_eq!(
        labels(&model.menu),
        ["Unlock in kv tui", "--", "Start at login", "Quit kv tray"]
    );
    assert!(matches!(
        &model.menu[0],
        Item::Action {
            action: Action::OpenTui,
            ..
        }
    ));

    // Unlocking starts the daemon, as every client does.
    let model = Model::new(view(None, None));
    assert_eq!(labels(&model.menu)[0], "Unlock with Touch ID");

    let mut fresh = status(true, 0);
    fresh.vault_exists = false;
    let model = Model::new(view(Some(&fresh), None));
    assert_eq!(labels(&model.menu)[0], "(No vault yet: run `kv init`)");
}

#[test]
fn each_waiting_request_has_its_answers() {
    let mut waiting = vec![approval(7, true), approval(9, false)];
    waiting[1].client = None;
    waiting[1].cwd = Some("/Users/me/project".into());
    let overview = overview(waiting);
    let model = Model::new(view(Some(&overview.status), Some(&overview)));
    assert_eq!(
        labels(&model.menu),
        [
            "> claude-code · http_request · openrouter",
            "> agent · http_request · openrouter",
            "--",
            "Lock vault",
            "Open kv tui",
            "--",
            "Start at login",
            "Quit kv tray"
        ]
    );
    let Item::Submenu { id, items, .. } = &model.menu[0] else {
        panic!("{:?}", model.menu[0]);
    };
    assert_eq!(id, "request:7");
    assert_eq!(
        labels(items),
        [
            "(GET https://openrouter.ai/api/v1/models?page=7)",
            "(Expires in 42s)",
            "--",
            "Allow once",
            "Allow for this session",
            "Deny",
            "Deny and block openrouter"
        ]
    );
    let Item::Submenu { items, .. } = &model.menu[1] else {
        panic!("{:?}", model.menu[1]);
    };
    // No agent session to grant to, and the working directory shown.
    assert_eq!(
        labels(items),
        [
            "(GET https://openrouter.ai/api/v1/models?page=9)",
            "(in /Users/me/project)",
            "(Expires in 42s)",
            "--",
            "Allow once",
            "Deny",
            "Deny and block openrouter"
        ]
    );
    let answers: Vec<&Action> = items
        .iter()
        .filter_map(|item| match item {
            Item::Action { action, .. } => Some(action),
            _ => None,
        })
        .collect();
    assert_eq!(
        answers,
        [
            &Action::Decide {
                id: 9,
                verdict: Verdict::AllowOnce
            },
            &Action::Decide {
                id: 9,
                verdict: Verdict::Deny
            },
            &Action::Decide {
                id: 9,
                verdict: Verdict::DenyAlways
            },
        ]
    );
}

#[test]
fn with_a_session_and_nothing_waiting_the_menu_says_so() {
    let mut overview = overview(Vec::new());
    overview.handle_requests = [1, 2]
        .map(|id| RequestedHandle {
            id,
            client: None,
            request: serde_json::from_str(r#"{"name":"github","kind":"http"}"#).unwrap(),
        })
        .to_vec();
    let model = Model::new(view(Some(&overview.status), Some(&overview)));
    assert_eq!(
        labels(&model.menu)[..2],
        ["(No requests waiting)", "2 handle requests: open kv tui"]
    );
    assert!(matches!(
        &model.menu[1],
        Item::Action {
            action: Action::HandleRequests,
            ..
        }
    ));
}

#[test]
fn ids_are_unique_and_lead_back_to_the_same_action() {
    let overview = overview(vec![approval(7, true), approval(9, true)]);
    let model = Model::new(View {
        login: true,
        ..view(Some(&overview.status), Some(&overview))
    });
    let mut ids = Vec::new();
    fn walk(items: &[Item], ids: &mut Vec<String>) {
        for item in items {
            match item {
                Item::Action { action, .. } | Item::Check { action, .. } => {
                    assert_eq!(Action::from_id(&action.id()).as_ref(), Some(action));
                    ids.push(action.id());
                }
                Item::Submenu { id, items, .. } => {
                    ids.push(id.clone());
                    walk(items, ids);
                }
                _ => {}
            }
        }
    }
    walk(&model.menu, &mut ids);
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), ids.len(), "{ids:?}");
    assert_eq!(
        Action::Decide {
            id: 9,
            verdict: Verdict::AllowSession
        }
        .id(),
        "decide:9:allow_session"
    );
    assert_eq!(Action::from_id("decide:9:sideways"), None);
    assert_eq!(Action::from_id("request:7"), None);

    // The checkbox turns the login item off when it is on.
    let check = model
        .menu
        .iter()
        .find_map(|item| match item {
            Item::Check {
                checked, action, ..
            } => Some((*checked, action)),
            _ => None,
        })
        .unwrap();
    assert_eq!(check, (true, &Action::Login(false)));
}

#[test]
fn agent_text_is_cut_to_one_short_line() {
    assert_eq!(one_line("GET\n /a\t\x07b  ", 60), "GET /a b");
    assert_eq!(one_line("abcdefgh", 5), "abcd…");
    assert_eq!(one_line("abcde", 5), "abcde");
    let mut long = approval(1, true);
    long.detail = format!("POST {}\nsecond line", "x".repeat(200));
    long.client = Some(format!("bot\n{}", "y".repeat(80)));
    let overview = overview(vec![long]);
    let model = Model::new(view(Some(&overview.status), Some(&overview)));
    let Item::Submenu { label, items, .. } = &model.menu[0] else {
        panic!();
    };
    assert_eq!(label.chars().count(), 60);
    assert!(!label.contains('\n'));
    let Item::Text(detail) = &items[0] else {
        panic!()
    };
    assert_eq!(detail.chars().count(), 100);
    assert!(detail.ends_with('…'));
}

/// The countdown changes every second; the menu around it does not, so the
/// tray updates the text in place instead of replacing a menu the user may
/// have open.
#[test]
fn a_countdown_does_not_change_the_menus_shape() {
    let shown = overview(vec![approval(1, true)]);
    let mut later = shown.clone();
    later.approvals[0].expires_in_secs = 41;
    let a = Model::new(view(Some(&shown.status), Some(&shown)));
    let b = Model::new(view(Some(&later.status), Some(&later)));
    assert_ne!(a.menu, b.menu);
    assert!(same_shape(&a.menu, &b.menu));

    let mut narrower = shown.clone();
    narrower.approvals[0].can_grant = false;
    let c = Model::new(view(Some(&narrower.status), Some(&narrower)));
    assert!(!same_shape(&a.menu, &c.menu), "an answer went away");

    let mut other = shown.clone();
    other.approvals[0].id = 2;
    let d = Model::new(view(Some(&other.status), Some(&other)));
    assert!(!same_shape(&a.menu, &d.menu), "another request");

    let more = overview(vec![approval(1, true), approval(2, true)]);
    let e = Model::new(view(Some(&more.status), Some(&more)));
    assert!(!same_shape(&a.menu, &e.menu), "one more request");
}

/// Menus read a single `&` as a keyboard shortcut marker and drop it, so
/// agent text has each `&` doubled to show as typed.
#[test]
fn an_ampersand_in_agent_text_survives_the_menu() {
    assert_eq!(one_line("GET /a?x=1&y=2", 60), "GET /a?x=1&&y=2");
    assert_eq!(one_line("abcd&fgh", 5), "abcd…", "cut before doubling");
    let mut asking = approval(1, true);
    asking.client = Some("me & co".into());
    asking.detail = "make && deploy".into();
    let overview = overview(vec![asking]);
    let model = Model::new(view(Some(&overview.status), Some(&overview)));
    let Item::Submenu { label, items, .. } = &model.menu[0] else {
        panic!();
    };
    assert!(label.starts_with("me && co · "), "{label}");
    assert_eq!(items[0], Item::Text("make &&&& deploy".into()));
}
