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
/// disk the way an older kv would have saved it.
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

#[test]
fn a_handle_received_before_the_fix_starts_no_program_until_the_user_changes_it() {
    let mut bob = Fixture::new();
    received_before_the_fix(&mut bob);
    let cwd = bob.dir.path().to_path_buf();

    let (kind, message) = bob
        .exec(run(&["app-env"], &["node", "app.js"], cwd.clone()))
        .unwrap_err();
    assert_eq!(kind, AgentErrorCode::PolicyDenied);
    assert!(message.contains("NODE_OPTIONS"), "{message}");
    assert!(message.contains("came from a share"), "{message}");
    let (kind, message) = bob.run_job(launch("app-env")).unwrap_err();
    assert_eq!(kind, AgentErrorCode::PolicyDenied);
    assert!(message.contains("NODE_OPTIONS"), "{message}");

    // The user takes the variable out; the handle is theirs now and works.
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
