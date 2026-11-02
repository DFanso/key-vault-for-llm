//! Sharing a handle between two vaults through the daemon: a request on one
//! side, an approved seal on the other, and the share saved back as a
//! handle that agents can use but never read.

mod common;

use common::*;
use kv::daemon::Prepared;
use kv_core::policy::Mode;
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlResponse,
    PolicyPatch, ReceiveShareCall, RevealedField, SendShareCall, ShareRequestCall, Verdict,
};
use kv_core::secret::{SecretKind, SecretText, SecretValue};

/// Bob's vault asks; returns the request code and its safety code.
fn request(bob: &mut Fixture, note: &str) -> (String, String) {
    match bob.prepare(AgentRequest::RequestShare(ShareRequestCall {
        note: note.into(),
        from: "bob".into(),
    })) {
        Prepared::Reply(AgentResponse::ShareRequested {
            code,
            safety_code,
            expires_in_secs,
        }) => {
            assert_eq!(expires_in_secs, 7 * 24 * 60 * 60);
            (code, safety_code)
        }
        _ => panic!("expected a request code"),
    }
}

fn send_call(code: &str, handle: &str) -> AgentRequest {
    AgentRequest::SendShare(SendShareCall {
        request: format!("Hi Alice, can you share it with me?\n\n{code}"),
        handle: handle.into(),
        name: None,
        from: "alice".into(),
        note: "for the eval script".into(),
    })
}

/// Alice's vault seals `handle` to `code`, and Alice allows it.
fn send(alice: &mut Fixture, code: &str, handle: &str) -> String {
    let token = alice.token();
    let agent = session("alice-agent");
    let mut waiting = alice.wait(Some(&agent), send_call(code, handle), alice.t0);
    assert!(waiting.verdict.try_recv().is_err(), "nothing decided yet");
    done(&alice.decide(&token, waiting.id, Verdict::AllowOnce));
    match waiting.then {
        Prepared::Reply(AgentResponse::ShareSealed { share, .. }) => share,
        _ => panic!("expected sealed text"),
    }
}

fn receive(bob: &mut Fixture, share: &str, name: Option<&str>) -> AgentResponse {
    match bob.prepare(AgentRequest::ReceiveShare(ReceiveShareCall {
        share: share.into(),
        name: name.map(str::to_owned),
    })) {
        Prepared::Reply(response) => response,
        _ => panic!("receiving answers at once"),
    }
}

fn error(response: AgentResponse) -> (AgentErrorCode, String) {
    match response {
        AgentResponse::Error { code, message } => (code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

fn done(response: &ControlResponse) {
    assert!(
        matches!(response, ControlResponse::Done { .. }),
        "{response:?}"
    );
}

fn reveal(f: &mut Fixture, token: &SecretText, handle: &str) -> ControlResponse {
    f.send(
        None,
        Some(token),
        ControlCommand::RevealShare {
            handle: handle.into(),
        },
    )
}

#[test]
fn a_handle_goes_from_one_vault_to_another_without_showing_its_value() {
    let mut alice = Fixture::new();
    alice.add(openrouter(Mode::Auto));
    let mut bob = Fixture::new();
    let bob_token = bob.token();

    let (code, safety_code) = request(&mut bob, "the OpenRouter key");
    let requests = bob.overview(&bob_token).shares.requests;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].code, code);
    assert_eq!(requests[0].safety_code, safety_code);
    assert_eq!(requests[0].note, "the OpenRouter key");
    assert!(!code.contains(TOKEN));

    // Sending waits for Alice even though the handle is in auto mode, and
    // her approval card says who asked, for what, and the safety code.
    let alice_token = alice.token();
    let agent = session("alice-agent");
    let mut waiting = alice.wait(Some(&agent), send_call(&code, "openrouter"), alice.t0);
    let approval = alice.overview(&alice_token).approvals.remove(0);
    assert_eq!(approval.tool, "send_share");
    assert_eq!(approval.handles, ["openrouter"]);
    assert!(!approval.can_grant, "each share waits for the user");
    assert!(
        approval.detail.contains(&safety_code),
        "{}",
        approval.detail
    );
    assert!(approval.detail.contains("bob"), "{}", approval.detail);
    assert!(approval.detail.contains("the OpenRouter key"));
    done(&alice.decide(&alice_token, waiting.id, Verdict::AllowOnce));
    assert_eq!(waiting.verdict.try_recv().ok(), Some(Verdict::AllowOnce));
    let share = match waiting.then {
        Prepared::Reply(AgentResponse::ShareSealed {
            share,
            safety_code: sealed_to,
        }) => {
            assert_eq!(sealed_to, safety_code);
            share
        }
        _ => panic!("expected sealed text"),
    };
    assert!(!share.contains(TOKEN));
    let sent = alice.overview(&alice_token).shares.sent;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].handle, "openrouter");
    assert_eq!(sent[0].to, "bob");
    assert_eq!(sent[0].safety_code, safety_code);
    assert!(sent[0].sent_at > 0);
    let audit = alice.audit_lines();
    assert!(
        audit
            .iter()
            .any(|e| e["action"] == "send_share" && e["outcome"] == "sealed"),
        "{audit:?}"
    );

    // Bob's vault opens it and keeps it as a handle in ask mode.
    let (handle, from, note) = match receive(&mut bob, &format!("here: `{share}`"), None) {
        AgentResponse::ShareReceived {
            handle,
            from,
            note,
            safety_code: answered,
        } => {
            assert_eq!(answered, safety_code);
            (handle, from, note)
        }
        other => panic!("expected a saved share, got {other:?}"),
    };
    // Bob hears about it, since his agent did it.
    assert_eq!(
        bob.daemon.take_share_notice().as_deref(),
        Some("A secret shared by alice was saved as openrouter.")
    );
    assert_eq!(handle.name, "openrouter");
    assert_eq!(handle.kind, SecretKind::Http);
    assert_eq!(handle.mode, Mode::Ask);
    assert_eq!(handle.allowed_hosts, ["openrouter.ai"]);
    assert_eq!(
        (from.as_str(), note.as_str()),
        ("alice", "for the eval script")
    );
    assert!(
        !serde_json::to_string(&handle).unwrap().contains(TOKEN),
        "the agent sees the handle, never the value"
    );

    let overview = bob.overview(&bob_token);
    assert!(overview.handles.iter().any(|h| h.name == "openrouter"));
    assert!(
        overview.shares.requests.is_empty(),
        "the request is used up"
    );
    assert_eq!(overview.shares.received.len(), 1);
    assert!(overview.shares.received[0].viewable);
    assert_eq!(overview.shares.received[0].from, "alice");
    assert!(!serde_json::to_string(&overview).unwrap().contains(TOKEN));

    // The user can read it in kv's window.
    match reveal(&mut bob, &bob_token, "openrouter") {
        ControlResponse::Revealed { handle, fields } => {
            assert_eq!(handle, "openrouter");
            assert_eq!(
                fields,
                [RevealedField {
                    label: "Token".into(),
                    value: SecretText::new(TOKEN),
                }]
            );
        }
        other => panic!("expected the value, got {other:?}"),
    }

    // A share answers its request once.
    let (code, message) = error(receive(&mut bob, &share, Some("again")));
    assert_eq!(code, AgentErrorCode::BadRequest);
    assert!(message.contains("open request"), "{message}");
}

#[test]
fn a_share_never_replaces_a_handle_and_a_refused_name_keeps_the_request() {
    let mut alice = Fixture::new();
    alice.add(openrouter(Mode::Ask));
    let mut bob = Fixture::new();
    bob.add(openrouter(Mode::Ask));
    let (code, _) = request(&mut bob, "");
    let share = send(&mut alice, &code, "openrouter");

    let (code, message) = error(receive(&mut bob, &share, None));
    assert_eq!(code, AgentErrorCode::BadRequest);
    assert!(message.contains("exists already"), "{message}");
    let (_, message) = error(receive(&mut bob, &share, Some("Not A Name")));
    assert!(message.contains("not a handle name"), "{message}");

    match receive(&mut bob, &share, Some("openrouter-alice")) {
        AgentResponse::ShareReceived { handle, .. } => {
            assert_eq!(handle.name, "openrouter-alice");
        }
        other => panic!("expected a saved share, got {other:?}"),
    }
}

#[test]
fn a_received_handle_never_takes_plain_http_from_the_sender() {
    // Anyone who sees a request code can seal to it, so the receiving user
    // turns plain http on themselves if they want it.
    let mut alice = Fixture::new();
    let mut plain = openrouter(Mode::Auto);
    plain.policy.allow_plain_http = true;
    alice.add(plain);
    let mut bob = Fixture::new();
    let (code, _) = request(&mut bob, "");
    let share = send(&mut alice, &code, "openrouter");
    match receive(&mut bob, &share, None) {
        AgentResponse::ShareReceived { handle, .. } => {
            assert_eq!(handle.allowed_hosts, ["openrouter.ai"]);
            assert!(!handle.allow_plain_http);
        }
        other => panic!("expected a saved share, got {other:?}"),
    }
}

#[test]
fn a_received_server_handle_keeps_no_program() {
    let mut alice = Fixture::new();
    let mut ssh = run_secret(
        "ssh-dev",
        &[("SSH_MCP_PASSWORD", "hunter2-hunter2-hunter2")],
        &["/usr/local/bin/bunx", "ssh-mcp@1.2.3", "--host=10.0.0.5"],
        Mode::Auto,
    );
    ssh.policy.allowed_cmds = vec!["ssh".into()];
    alice.add(ssh);
    let mut bob = Fixture::new();
    let (code, _) = request(&mut bob, "");
    let share = send(&mut alice, &code, "ssh-dev");
    match receive(&mut bob, &share, None) {
        AgentResponse::ShareReceived { handle, .. } => {
            assert_eq!(handle.kind, SecretKind::Env);
            assert_eq!(handle.env_vars, ["SSH_MCP_PASSWORD"]);
            assert_eq!(handle.runs, None, "no command comes with a share");
            assert!(handle.allowed_cmds.is_empty());
            assert_eq!(handle.mode, Mode::Ask);
        }
        other => panic!("expected a saved share, got {other:?}"),
    }
}

#[test]
fn a_denied_share_sends_nothing_and_allow_for_the_session_grants_nothing() {
    let mut alice = Fixture::new();
    alice.add(openrouter(Mode::Ask));
    let token = alice.token();
    let mut bob = Fixture::new();
    let (code, _) = request(&mut bob, "");
    let agent = session("alice-agent");

    let mut denied = alice.wait(Some(&agent), send_call(&code, "openrouter"), alice.t0);
    done(&alice.decide(&token, denied.id, Verdict::Deny));
    assert_eq!(denied.verdict.try_recv().ok(), Some(Verdict::Deny));
    assert!(alice.overview(&token).shares.sent.is_empty());

    let first = alice.wait(Some(&agent), send_call(&code, "openrouter"), alice.t0);
    done(&alice.decide(&token, first.id, Verdict::AllowSession));
    // The next share from the same agent session still waits.
    alice.wait(Some(&agent), send_call(&code, "openrouter"), alice.t0);
}

#[test]
fn a_handle_set_to_deny_or_a_bad_code_is_refused_before_asking() {
    let mut alice = Fixture::new();
    alice.add(openrouter(Mode::Deny));
    alice.add(env_secret(
        "aws",
        &[("AWS_KEY", AWS_KEY)],
        &["aws"],
        Mode::Ask,
    ));
    let mut bob = Fixture::new();
    let (code, _) = request(&mut bob, "");

    let refused = |f: &mut Fixture, call| match f.prepare(call) {
        Prepared::Reply(AgentResponse::Error { code, message }) => (code, message),
        _ => panic!("expected a refusal"),
    };
    let (kind, _) = refused(&mut alice, send_call(&code, "openrouter"));
    assert_eq!(kind, AgentErrorCode::PolicyDenied);
    let (kind, message) = refused(&mut alice, send_call("kv-request:v1:nope", "aws"));
    assert_eq!(kind, AgentErrorCode::BadRequest);
    assert!(message.contains("request code"), "{message}");
    let (kind, _) = refused(&mut alice, send_call(&code, "missing"));
    assert_eq!(kind, AgentErrorCode::UnknownHandle);
    assert_eq!(alice.status().pending_approvals, 0);
}

#[test]
fn kv_shows_only_values_it_received() {
    let mut alice = Fixture::new();
    alice.add(openrouter(Mode::Ask));
    alice.add(postgres(
        "prod-db",
        "postgres://app:s3cret-pass-word@db.example.com/app",
        true,
        Mode::Ask,
    ));
    let mut bob = Fixture::new();
    bob.add(env_secret(
        "aws",
        &[("AWS_KEY", AWS_KEY)],
        &["aws"],
        Mode::Ask,
    ));
    let token = bob.token();

    // A handle the user typed in is never shown.
    let ControlResponse::Error { code, .. } = reveal(&mut bob, &token, "aws") else {
        panic!("expected a refusal");
    };
    assert_eq!(code, ControlErrorCode::Invalid);

    let (code, _) = request(&mut bob, "");
    let share = send(&mut alice, &code, "prod-db");
    assert!(matches!(
        receive(&mut bob, &share, None),
        AgentResponse::ShareReceived { .. }
    ));
    match reveal(&mut bob, &token, "prod-db") {
        ControlResponse::Revealed { fields, .. } => {
            assert_eq!(fields[0].label, "URL");
            assert_eq!(
                fields[0].value.expose(),
                "postgres://app:s3cret-pass-word@db.example.com/app"
            );
        }
        other => panic!("expected the value, got {other:?}"),
    }

    // A policy change keeps it viewable; a new value does not.
    bob.control(ControlCommand::SetPolicy {
        name: "prod-db".into(),
        patch: PolicyPatch {
            mode: Some(Mode::Auto),
            ..PolicyPatch::default()
        },
    });
    assert!(bob.overview(&token).shares.received[0].viewable);
    bob.control(ControlCommand::Update {
        name: "prod-db".into(),
        description: None,
        value: Some(SecretValue::Postgres {
            url: SecretText::new("postgres://me:typed-by-the-user@db.example.com/app"),
        }),
    });
    assert!(!bob.overview(&token).shares.received[0].viewable);
    let ControlResponse::Error { code, .. } = reveal(&mut bob, &token, "prod-db") else {
        panic!("expected a refusal");
    };
    assert_eq!(code, ControlErrorCode::Invalid);

    // Revealing needs the user: a session or the passphrase.
    let ControlResponse::Error { code, .. } = bob.send(
        None,
        None,
        ControlCommand::RevealShare {
            handle: "prod-db".into(),
        },
    ) else {
        panic!("expected a refusal");
    };
    assert_eq!(code, ControlErrorCode::PassphraseRequired);
}

#[test]
fn forget_cancels_a_request_so_its_share_no_longer_opens() {
    let mut alice = Fixture::new();
    alice.add(openrouter(Mode::Ask));
    let mut bob = Fixture::new();
    let token = bob.token();
    let (code, _) = request(&mut bob, "");
    let share = send(&mut alice, &code, "openrouter");

    let id = bob.overview(&token).shares.requests[0].id.clone();
    done(&bob.send(
        None,
        Some(&token),
        ControlCommand::ForgetShare { id: id.clone() },
    ));
    assert!(bob.overview(&token).shares.requests.is_empty());
    let (_, message) = error(receive(&mut bob, &share, None));
    assert!(message.contains("open request"), "{message}");
    let ControlResponse::Error { code, .. } =
        bob.send(None, Some(&token), ControlCommand::ForgetShare { id })
    else {
        panic!("expected a refusal");
    };
    assert_eq!(code, ControlErrorCode::Invalid);
}

#[test]
fn sharing_needs_the_vault_unlocked() {
    let mut bob = Fixture::new();
    let (code, _) = request(&mut bob, "");
    bob.send(None, None, ControlCommand::Lock);
    let locked = |response: Prepared| match response {
        Prepared::Reply(AgentResponse::Error { code, .. }) => code,
        _ => panic!("expected an error"),
    };
    assert_eq!(
        locked(bob.prepare(AgentRequest::RequestShare(ShareRequestCall {
            note: String::new(),
            from: String::new(),
        }))),
        AgentErrorCode::VaultLocked
    );
    assert_eq!(
        locked(bob.prepare(send_call(&code, "openrouter"))),
        AgentErrorCode::VaultLocked
    );
    assert_eq!(
        locked(bob.prepare(AgentRequest::ReceiveShare(ReceiveShareCall {
            share: "kv-share:v1:x".into(),
            name: None,
        }))),
        AgentErrorCode::VaultLocked
    );
}

#[test]
fn shares_survive_a_restart_of_the_daemon() {
    let mut alice = Fixture::new();
    alice.add(openrouter(Mode::Ask));
    let mut bob = Fixture::new();
    let (code, _) = request(&mut bob, "");
    // Bob's daemon locks (as a restart would leave it) and unlocks again.
    bob.send(None, None, ControlCommand::Lock);
    bob.control(ControlCommand::Unlock);
    let share = send(&mut alice, &code, "openrouter");
    assert!(matches!(
        receive(&mut bob, &share, None),
        AgentResponse::ShareReceived { .. }
    ));
}

/// What kv's window sends for the user, with their session token.
fn by_hand(f: &mut Fixture, token: &SecretText, command: ControlCommand) -> ControlResponse {
    f.send(None, Some(token), command)
}

fn refused_by_hand(response: ControlResponse) -> (ControlErrorCode, String) {
    match response {
        ControlResponse::Error { code, message } => (code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[test]
fn two_people_share_a_handle_from_their_windows_without_an_agent() {
    let mut alice = Fixture::new();
    alice.add(openrouter(Mode::Ask));
    let alice_token = alice.token();
    let mut bob = Fixture::new();
    let bob_token = bob.token();

    // Bob makes a request in his window and sends the code himself.
    let (code, safety_code) = match by_hand(
        &mut bob,
        &bob_token,
        ControlCommand::RequestShare(ShareRequestCall {
            note: "the OpenRouter key".into(),
            from: "bob".into(),
        }),
    ) {
        ControlResponse::ShareRequested {
            code,
            safety_code,
            expires_in_secs,
        } => {
            assert_eq!(expires_in_secs, 7 * 24 * 60 * 60);
            (code, safety_code)
        }
        other => panic!("expected a request code, got {other:?}"),
    };
    let requests = bob.overview(&bob_token).shares.requests;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].code, code);

    // Alice pastes it into her window. She is the one asking, so the share
    // is sealed at once, without an approval, even in ask mode.
    let share = match by_hand(
        &mut alice,
        &alice_token,
        ControlCommand::SendShare(SendShareCall {
            request: format!("Hi Alice, can you share it?\n{code}"),
            handle: "openrouter".into(),
            name: None,
            from: "alice".into(),
            note: "for the eval script".into(),
        }),
    ) {
        ControlResponse::ShareSealed {
            share,
            safety_code: sealed_to,
            to,
            asked_for,
        } => {
            assert_eq!(sealed_to, safety_code);
            assert_eq!(to, "bob");
            assert_eq!(asked_for, "the OpenRouter key");
            share
        }
        other => panic!("expected sealed text, got {other:?}"),
    };
    assert!(share.starts_with("kv-share:v1:"));
    assert!(!share.contains(TOKEN));
    assert_eq!(alice.status().pending_approvals, 0);
    let sent = alice.overview(&alice_token).shares.sent;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].handle, "openrouter");
    assert_eq!(sent[0].to, "bob");
    assert_eq!(sent[0].safety_code, safety_code);

    // Bob pastes the share into his window and it is saved as a handle.
    match by_hand(
        &mut bob,
        &bob_token,
        ControlCommand::ReceiveShare(ReceiveShareCall {
            share: share.clone(),
            name: Some("openrouter-alice".into()),
        }),
    ) {
        ControlResponse::ShareReceived {
            handle,
            from,
            note,
            safety_code: opened_with,
        } => {
            assert_eq!(handle.name, "openrouter-alice");
            assert_eq!(handle.kind, SecretKind::Http);
            assert_eq!(handle.mode, Mode::Ask);
            assert_eq!(from, "alice");
            assert_eq!(note, "for the eval script");
            assert_eq!(opened_with, safety_code);
        }
        other => panic!("expected a saved handle, got {other:?}"),
    }
    // Bob did it himself: there is nothing to tell him.
    assert_eq!(bob.daemon.take_share_notice(), None);
    let overview = bob.overview(&bob_token);
    assert!(overview.shares.requests.is_empty());
    assert_eq!(overview.shares.received.len(), 1);
    assert!(overview.shares.received[0].viewable);
    match reveal(&mut bob, &bob_token, "openrouter-alice") {
        ControlResponse::Revealed { fields, .. } => assert_eq!(fields[0].value.expose(), TOKEN),
        other => panic!("expected the value, got {other:?}"),
    }

    // Each step is in the audit log, with no secret in it.
    let actions: Vec<(String, Option<String>, String)> = bob
        .audit_lines()
        .into_iter()
        .chain(alice.audit_lines())
        .map(|line| {
            (
                line["action"].as_str().unwrap().to_owned(),
                line["handle"].as_str().map(str::to_owned),
                line["outcome"].as_str().unwrap().to_owned(),
            )
        })
        .filter(|(action, ..)| action.ends_with("_share") && action != "reveal_share")
        .collect();
    assert_eq!(
        actions,
        [
            ("request_share".to_owned(), None, "done".to_owned()),
            (
                "receive_share".to_owned(),
                Some("openrouter-alice".to_owned()),
                "done".to_owned()
            ),
            (
                "send_share".to_owned(),
                Some("openrouter".to_owned()),
                "done".to_owned()
            ),
        ]
    );
    for lines in [bob.audit_lines(), alice.audit_lines()] {
        assert!(!serde_json::to_string(&lines).unwrap().contains(TOKEN));
    }
}

#[test]
fn the_window_refuses_what_an_agent_would_be_refused() {
    let mut alice = Fixture::new();
    alice.add(openrouter(Mode::Deny));
    alice.add(env_secret(
        "aws",
        &[("AWS_KEY", AWS_KEY)],
        &["aws"],
        Mode::Ask,
    ));
    let token = alice.token();
    let mut bob = Fixture::new();
    let (code, _) = request(&mut bob, "");
    let send = |handle: &str, request: &str| {
        ControlCommand::SendShare(SendShareCall {
            request: request.into(),
            handle: handle.into(),
            name: None,
            from: String::new(),
            note: String::new(),
        })
    };

    let (kind, message) = refused_by_hand(by_hand(&mut alice, &token, send("openrouter", &code)));
    assert_eq!(kind, ControlErrorCode::Invalid);
    assert!(message.contains("deny"), "{message}");
    let (kind, message) = refused_by_hand(by_hand(
        &mut alice,
        &token,
        send("aws", "kv-request:v1:nope"),
    ));
    assert_eq!(kind, ControlErrorCode::Invalid);
    assert!(message.contains("request code"), "{message}");
    let (kind, _) = refused_by_hand(by_hand(&mut alice, &token, send("missing", &code)));
    assert_eq!(kind, ControlErrorCode::UnknownHandle);
    let (kind, message) = refused_by_hand(by_hand(
        &mut alice,
        &token,
        ControlCommand::ReceiveShare(ReceiveShareCall {
            share: code.clone(),
            name: None,
        }),
    ));
    assert_eq!(kind, ControlErrorCode::Invalid);
    assert!(message.contains("not a kv share"), "{message}");
    assert!(alice.overview(&token).shares.sent.is_empty());

    // Without a session or the passphrase, nothing happens.
    let (kind, _) = refused_by_hand(alice.send(None, None, send("aws", &code)));
    assert_eq!(kind, ControlErrorCode::PassphraseRequired);
    let (kind, _) = refused_by_hand(alice.send(
        None,
        None,
        ControlCommand::RequestShare(ShareRequestCall {
            note: String::new(),
            from: String::new(),
        }),
    ));
    assert_eq!(kind, ControlErrorCode::PassphraseRequired);
}

#[test]
fn a_taken_name_in_the_window_keeps_the_request_for_another_try() {
    let mut alice = Fixture::new();
    alice.add(openrouter(Mode::Ask));
    let mut bob = Fixture::new();
    bob.add(openrouter(Mode::Auto));
    let bob_token = bob.token();
    let (code, _) = request(&mut bob, "");
    let share = send(&mut alice, &code, "openrouter");
    let receive = |name: Option<&str>| {
        ControlCommand::ReceiveShare(ReceiveShareCall {
            share: share.clone(),
            name: name.map(str::to_owned),
        })
    };

    let (kind, message) = refused_by_hand(by_hand(&mut bob, &bob_token, receive(None)));
    assert_eq!(kind, ControlErrorCode::Invalid);
    assert!(message.contains("exists already"), "{message}");
    assert!(!message.contains("pass name"), "{message}");
    assert_eq!(bob.overview(&bob_token).shares.requests.len(), 1);
    assert!(matches!(
        by_hand(&mut bob, &bob_token, receive(Some("openrouter-2"))),
        ControlResponse::ShareReceived { .. }
    ));
}
