//! What an `env` handle may hold: variable names that cannot load code into
//! or redirect the programs kv starts, when they come from someone else, and
//! values short enough for the output scrubber.

mod common;

use common::*;
use kv::daemon::Prepared;
use kv_core::policy::Mode;
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlRequest,
    ControlResponse, ReceiveShareCall, SendShareCall, ShareRequestCall,
};
use kv_core::secret::{SecretText, SecretValue};
use kv_core::share::{self, ShareRequest, SharedSecret};
use kv_core::vault::Vault;

const API_KEY: &str = "sk-test-0123456789abcdef";

fn vars(pairs: &[(&str, &str)]) -> SecretValue {
    SecretValue::Env {
        vars: pairs
            .iter()
            .map(|(k, v)| (k.to_string(), SecretText::new(*v)))
            .collect(),
    }
}

/// Bob's vault asks for a share; returns the request code.
fn request(bob: &mut Fixture) -> String {
    match bob.prepare(AgentRequest::RequestShare(ShareRequestCall {
        note: String::new(),
        from: "bob".into(),
    })) {
        Prepared::Reply(AgentResponse::ShareRequested { code, .. }) => code,
        _ => panic!("expected a request code"),
    }
}

/// A share sealed to `code` by someone whose kv does not check what it
/// sends, as a hostile sender's would not.
fn hostile_share(code: &str, value: SecretValue) -> String {
    let request = ShareRequest::decode(code).unwrap();
    share::seal(
        &request,
        &SharedSecret {
            name: "app-env".into(),
            description: String::new(),
            value,
            allowed_hosts: Vec::new(),
            allow_plain_http: false,
            allowed_methods: Vec::new(),
            read_only: false,
            from: "mallory".into(),
            note: String::new(),
        },
    )
    .unwrap()
}

fn receive(bob: &mut Fixture, share: &str) -> AgentResponse {
    match bob.prepare(AgentRequest::ReceiveShare(ReceiveShareCall {
        share: share.into(),
        name: None,
    })) {
        Prepared::Reply(response) => response,
        _ => panic!("expected a reply"),
    }
}

fn refused(response: AgentResponse) -> (AgentErrorCode, String) {
    match response {
        AgentResponse::Error { code, message } => (code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

fn add(f: &mut Fixture, name: &str, value: SecretValue) -> ControlResponse {
    f.daemon
        .handle_control(
            ControlRequest {
                passphrase: Some(SecretText::new(PASS)),
                device: None,
                token: None,
                command: ControlCommand::Add {
                    secret: secret(name, value, Default::default()),
                    replace: false,
                },
            },
            f.t0,
        )
        .0
}

#[test]
fn a_share_that_sets_loader_or_proxy_variables_is_refused_and_keeps_the_request() {
    for risky in [
        "NODE_OPTIONS",
        "LD_PRELOAD",
        "npm_config_registry",
        "HTTPS_PROXY",
    ] {
        let mut bob = Fixture::new();
        let code = request(&mut bob);
        let share = hostile_share(
            &code,
            vars(&[("API_KEY", API_KEY), (risky, "--require /tmp/x.js")]),
        );
        let (kind, message) = refused(receive(&mut bob, &share));
        assert_eq!(kind, AgentErrorCode::BadRequest);
        assert!(message.contains(risky), "{message}");
        assert!(!message.contains(API_KEY), "{message}");
        let token = bob.token();
        let overview = bob.overview(&token);
        assert!(overview.handles.is_empty(), "nothing was saved");
        assert_eq!(
            overview.shares.requests.len(),
            1,
            "the request is still open"
        );
        // Without the variable, the same request takes the share.
        let clean = hostile_share(&code, vars(&[("API_KEY", API_KEY)]));
        assert!(matches!(
            receive(&mut bob, &clean),
            AgentResponse::ShareReceived { .. }
        ));
    }
}

#[test]
fn a_share_with_a_value_too_long_to_scrub_or_a_bad_name_is_refused() {
    let mut bob = Fixture::new();
    let code = request(&mut bob);
    let long = "x".repeat(4097);
    for value in [
        vars(&[("BLOB", long.as_str())]),
        vars(&[("not-a-name", API_KEY)]),
        vars(&[("A B", API_KEY)]),
    ] {
        let share = hostile_share(&code, value);
        let (kind, message) = refused(receive(&mut bob, &share));
        assert_eq!(kind, AgentErrorCode::BadRequest, "{message}");
        assert!(message.starts_with("the share holds"), "{message}");
    }
    let many: Vec<(String, String)> = (0..257)
        .map(|i| (format!("V{i}"), API_KEY.into()))
        .collect();
    let many: Vec<(&str, &str)> = many.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (_, message) = refused(receive(&mut bob, &hostile_share(&code, vars(&many))));
    assert!(message.contains("256"), "{message}");
}

#[test]
fn your_own_handle_may_set_them_with_a_warning_but_cannot_be_shared() {
    let mut alice = Fixture::new();
    match add(
        &mut alice,
        "pip",
        vars(&[("PIP_INDEX_URL", "https://pypi.example.com/simple")]),
    ) {
        ControlResponse::Done { warnings } => {
            assert!(
                warnings.iter().any(|w| w.contains("PIP_INDEX_URL")),
                "{warnings:?}"
            );
        }
        other => panic!("expected the handle to be added, got {other:?}"),
    }
    let mut bob = Fixture::new();
    let code = request(&mut bob);
    let call = AgentRequest::SendShare(SendShareCall {
        request: code,
        handle: "pip".into(),
        name: None,
        from: "alice".into(),
        note: String::new(),
    });
    // Refused before anything waits for approval.
    let (kind, message) = refused(match alice.prepare(call) {
        Prepared::Reply(response) => response,
        _ => panic!("expected a refusal before any approval"),
    });
    assert_eq!(kind, AgentErrorCode::BadRequest);
    assert!(message.contains("PIP_INDEX_URL"), "{message}");
    assert_eq!(alice.status().pending_approvals, 0);
}

#[test]
fn values_too_long_to_scrub_and_bad_names_are_refused_on_add() {
    let mut f = Fixture::new();
    let long = "x".repeat(4097);
    for value in [
        vars(&[("BLOB", long.as_str())]),
        vars(&[("1ST", API_KEY)]),
        vars(&[("A=B", API_KEY)]),
    ] {
        match add(&mut f, "bad", value) {
            ControlResponse::Error { code, .. } => assert_eq!(code, ControlErrorCode::Invalid),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
    let mut token = openrouter(Mode::Ask);
    if let SecretValue::Http { token: t, .. } = &mut token.value {
        *t = SecretText::new(long.clone());
    }
    match add(&mut f, "long-token", token.value) {
        ControlResponse::Error { code, message } => {
            assert_eq!(code, ControlErrorCode::Invalid);
            assert!(message.contains("4096"), "{message}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // 4096 bytes still fit: a PEM key or a service-account JSON.
    let fits = "y".repeat(4096);
    assert!(matches!(
        add(&mut f, "pem", vars(&[("PRIVATE_KEY", fits.as_str())])),
        ControlResponse::Done { .. }
    ));
}

/// A handle received before kv refused such shares: Bob's vault is edited on
/// disk the way an older kv would have saved it. (How a vault with no marks
/// at all opens is tested in kv-core's vault module.)
fn received_before_the_fix(bob: &mut Fixture) {
    let code = request(bob);
    let share = hostile_share(&code, vars(&[("API_KEY", API_KEY)]));
    assert!(matches!(
        receive(bob, &share),
        AgentResponse::ShareReceived { .. }
    ));
    bob.send(None, None, ControlCommand::Lock);
    let path = bob.dir.path().join("vault.kv");
    let mut vault = Vault::unlock(&path, PASS).unwrap();
    let mut held = vault.get("app-env").cloned().unwrap();
    assert_eq!(held.from_share, Some(true));
    held.value = vars(&[
        ("API_KEY", API_KEY),
        ("NODE_OPTIONS", "--require /tmp/x.js"),
    ]);
    held.policy.mode = Mode::Auto;
    held.policy.allowed_cmds = vec!["node".into()];
    held.policy.run = Some(vec!["/usr/local/bin/node".into(), "server.js".into()]);
    let digest = share::value_digest(&held.value);
    vault.upsert(held).unwrap();
    vault.shares_mut().received[0].value_digest = digest;
    vault.save().unwrap();
    drop(vault);
    bob.control(ControlCommand::Unlock);
}

fn exec_refused(bob: &mut Fixture) -> String {
    let cwd = bob.dir.path().to_path_buf();
    let (kind, message) = bob
        .exec(run(&["app-env"], &["node", "app.js"], cwd))
        .unwrap_err();
    assert_eq!(kind, AgentErrorCode::PolicyDenied);
    assert!(message.contains("NODE_OPTIONS"), "{message}");
    message
}

fn forget_the_record(bob: &mut Fixture) {
    let token = bob.token();
    let id = bob.overview(&token).shares.received[0].id.clone();
    let response = bob.send(None, Some(&token), ControlCommand::ForgetShare { id });
    assert!(
        matches!(response, ControlResponse::Done { .. }),
        "{response:?}"
    );
    assert!(bob.overview(&token).shares.received.is_empty());
}

#[test]
fn a_handle_received_before_the_fix_starts_no_program_until_its_variables_go() {
    {
        let mut bob = Fixture::new();
        received_before_the_fix(&mut bob);
        let cwd = bob.dir.path().to_path_buf();

        assert!(exec_refused(&mut bob).contains("came from a share"));
        let (kind, message) = bob.run_job(launch("app-env")).unwrap_err();
        assert_eq!(kind, AgentErrorCode::PolicyDenied);
        assert!(message.contains("NODE_OPTIONS"), "{message}");

        // Forgetting the share's record does not lift it, nor does an edit
        // that keeps the variable.
        forget_the_record(&mut bob);
        exec_refused(&mut bob);
        bob.control(ControlCommand::Update {
            name: "app-env".into(),
            description: None,
            value: Some(vars(&[
                ("API_KEY", "sk-test-rotated-0123456789"),
                ("NODE_OPTIONS", "--require /tmp/x.js"),
            ])),
        });
        exec_refused(&mut bob);
        // Through a restart too.
        bob.send(None, None, ControlCommand::Lock);
        bob.control(ControlCommand::Unlock);
        exec_refused(&mut bob);

        // Taking the variable out does.
        bob.control(ControlCommand::Update {
            name: "app-env".into(),
            description: None,
            value: Some(vars(&[("API_KEY", API_KEY)])),
        });
        let job = bob
            .exec(run(&["app-env"], &["node", "app.js"], cwd))
            .unwrap();
        assert_eq!(job.env.len(), 1);
    }
}

#[test]
fn adding_the_handle_again_as_your_own_lifts_it() {
    let mut bob = Fixture::new();
    received_before_the_fix(&mut bob);
    let mut own = env_secret(
        "app-env",
        &[
            ("API_KEY", API_KEY),
            ("NODE_OPTIONS", "--max-old-space-size=4096"),
        ],
        &["node"],
        Mode::Auto,
    );
    own.from_share = Some(true); // what the client says does not count
    bob.control(ControlCommand::Add {
        secret: own,
        replace: true,
    });
    let cwd = bob.dir.path().to_path_buf();
    assert!(
        bob.exec(run(&["app-env"], &["node", "app.js"], cwd))
            .is_ok()
    );
}

#[test]
fn a_handle_holds_at_most_8_kib_of_values() {
    let mut f = Fixture::new();
    let full = "v".repeat(4096);
    assert!(matches!(
        add(
            &mut f,
            "two",
            vars(&[("A", full.as_str()), ("B", full.as_str())])
        ),
        ControlResponse::Done { .. }
    ));
    let third = "w".repeat(3000);
    match add(
        &mut f,
        "three",
        vars(&[
            ("A", third.as_str()),
            ("B", third.as_str()),
            ("C", third.as_str()),
        ]),
    ) {
        ControlResponse::Error { code, message } => {
            assert_eq!(code, ControlErrorCode::Invalid);
            assert!(message.contains("8 KiB"), "{message}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    let mut bob = Fixture::new();
    let code = request(&mut bob);
    let share = hostile_share(
        &code,
        vars(&[
            ("A", third.as_str()),
            ("B", third.as_str()),
            ("C", third.as_str()),
        ]),
    );
    let (_, message) = refused(receive(&mut bob, &share));
    assert!(message.contains("8 KiB"), "{message}");
}

#[test]
fn messages_show_names_someone_else_picked_safely() {
    let mut bob = Fixture::new();
    let code = request(&mut bob);
    let share = hostile_share(&code, vars(&[("BAD\u{1b}[2J", API_KEY)]));
    let (_, message) = refused(receive(&mut bob, &share));
    assert!(!message.contains('\u{1b}'), "{message:?}");
    assert!(message.contains("BAD??2J"), "{message}");
}

#[test]
fn the_users_own_handle_with_such_a_variable_still_runs() {
    let mut f = Fixture::new();
    f.add(env_secret(
        "pip",
        &[("PIP_INDEX_URL", "https://pypi.example.com/simple")],
        &["pip"],
        Mode::Auto,
    ));
    let cwd = f.dir.path().to_path_buf();
    assert!(f.exec(run(&["pip"], &["pip", "install", "x"], cwd)).is_ok());
}

fn edit_vars(
    f: &mut Fixture,
    name: &str,
    set: &[(&str, &str)],
    remove: &[&str],
) -> ControlResponse {
    f.send(
        Some(PASS),
        None,
        ControlCommand::EditVars {
            name: name.into(),
            description: None,
            set: set
                .iter()
                .map(|(k, v)| (k.to_string(), SecretText::new(*v)))
                .collect(),
            remove: remove.iter().map(|r| r.to_string()).collect(),
        },
    )
}

#[test]
fn a_blocked_handle_is_repaired_by_removing_the_variable_without_seeing_the_rest() {
    let mut bob = Fixture::new();
    received_before_the_fix(&mut bob);
    // After Forget kv will not show the values, and need not.
    forget_the_record(&mut bob);
    exec_refused(&mut bob);
    let response = edit_vars(&mut bob, "app-env", &[], &["NODE_OPTIONS"]);
    assert!(
        matches!(response, ControlResponse::Done { .. }),
        "{response:?}"
    );
    let cwd = bob.dir.path().to_path_buf();
    let job = bob
        .exec(run(&["app-env"], &["node", "app.js"], cwd))
        .unwrap();
    // The other variable kept its value.
    assert_eq!(job.env.len(), 1);
    assert_eq!(job.env[0].0, "API_KEY");
    assert_eq!(job.env[0].1.expose(), API_KEY);
}

#[test]
fn editing_variables_sets_some_keeps_the_rest_and_refuses_what_add_refuses() {
    let mut f = Fixture::new();
    f.add(env_secret(
        "app",
        &[("API_KEY", API_KEY), ("REGION", "eu-west-1-zone")],
        &["node"],
        Mode::Auto,
    ));
    let done = |r: ControlResponse| assert!(matches!(r, ControlResponse::Done { .. }), "{r:?}");
    done(edit_vars(
        &mut f,
        "app",
        &[("REGION", "us-east-1-zone")],
        &[],
    ));
    let cwd = f.dir.path().to_path_buf();
    let job = f.exec(run(&["app"], &["node"], cwd)).unwrap();
    let env: Vec<(String, String)> = job
        .env
        .iter()
        .map(|(k, v)| (k.clone(), v.expose().to_owned()))
        .collect();
    assert!(env.contains(&("API_KEY".into(), API_KEY.into())));
    assert!(env.contains(&("REGION".into(), "us-east-1-zone".into())));

    let invalid = |r: ControlResponse| -> String {
        match r {
            ControlResponse::Error { code, message } => {
                assert_eq!(code, ControlErrorCode::Invalid);
                message
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    };
    assert!(invalid(edit_vars(&mut f, "app", &[], &["NOPE"])).contains("no variable NOPE"));
    assert!(
        invalid(edit_vars(&mut f, "app", &[], &["API_KEY", "REGION"]))
            .contains("no variables left")
    );
    assert!(
        invalid(edit_vars(&mut f, "app", &[("BAD-NAME", API_KEY)], &[]))
            .contains("not a variable name")
    );
    let long = "x".repeat(4097);
    assert!(invalid(edit_vars(&mut f, "app", &[("BLOB", long.as_str())], &[])).contains("4096"));
    f.add(openrouter(Mode::Ask));
    assert!(invalid(edit_vars(&mut f, "openrouter", &[], &["X"])).contains("not an env handle"));
    // A risky variable on the user's own handle is allowed, with a warning.
    match edit_vars(
        &mut f,
        "app",
        &[("PIP_INDEX_URL", "https://pypi.example.com/simple")],
        &[],
    ) {
        ControlResponse::Done { warnings } => {
            assert!(
                warnings.iter().any(|w| w.contains("PIP_INDEX_URL")),
                "{warnings:?}"
            )
        }
        other => panic!("{other:?}"),
    }
}
