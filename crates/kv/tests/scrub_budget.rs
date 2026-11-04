//! The output scrubber's budget across the whole vault: handles whose
//! values would take it past what the scrubber takes are refused on every
//! path that saves a value, and a change that lowers the total still goes
//! through.

mod common;

use common::*;
use kv::daemon::Prepared;
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlRequest,
    ControlResponse, ReceiveShareCall, ShareRequestCall,
};
use kv_core::secret::{SecretText, SecretValue};
use kv_core::share::{self, ShareRequest, SharedSecret};

/// Two values of 4096 bytes of punctuation: the most one env handle may
/// hold, and the most it can cost the scrubber.
fn costly(seed: usize) -> SecretValue {
    let set = b"!#$%&*+/=?@ ;:,<>[]{}^~";
    let value = |n: usize| -> String {
        (0..4096)
            .map(|i| set[(i * 7 + n * 13 + i / 23) % set.len()] as char)
            .collect()
    };
    SecretValue::Env {
        vars: [
            ("A".to_owned(), SecretText::new(value(seed * 2))),
            ("B".to_owned(), SecretText::new(value(seed * 2 + 1))),
        ]
        .into(),
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

/// Adds costly handles until the vault refuses one; returns how many fit.
fn fill(f: &mut Fixture) -> usize {
    for n in 0..64 {
        match add(f, &format!("blob{n}"), costly(n)) {
            ControlResponse::Done { .. } => {}
            ControlResponse::Error { code, message } => {
                assert_eq!(code, ControlErrorCode::Invalid);
                assert!(message.contains("output scrubber"), "{message}");
                return n;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    panic!("the budget never ran out");
}

#[test]
fn the_vault_refuses_values_past_the_scrubbers_budget() {
    let mut f = Fixture::new();
    let fitted = fill(&mut f);
    assert!((2..16).contains(&fitted), "{fitted} handles fit");
    // An ordinary token costs little, so it still fits in what is left.
    f.add(openrouter(kv_core::policy::Mode::Ask));
}

fn update(f: &mut Fixture, name: &str, value: SecretValue) -> ControlResponse {
    f.send(
        Some(PASS),
        None,
        ControlCommand::Update {
            name: name.into(),
            description: None,
            value: Some(value),
        },
    )
}

fn small() -> SecretValue {
    SecretValue::Env {
        vars: [("A".to_owned(), SecretText::new("sk-test-0123456789"))].into(),
    }
}

#[test]
fn a_change_that_raises_the_total_past_it_is_refused_and_one_that_lowers_it_goes_through() {
    let mut f = Fixture::new();
    let fitted = fill(&mut f);
    assert!(matches!(
        add(&mut f, "tiny", small()),
        ControlResponse::Done { .. }
    ));
    // Growing a small handle would take the vault past the budget.
    match update(&mut f, "tiny", costly(99)) {
        ControlResponse::Error { code, message } => {
            assert_eq!(code, ControlErrorCode::Invalid);
            assert!(message.contains("output scrubber"), "{message}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // Shrinking another one always goes through, and makes room.
    let last = format!("blob{}", fitted - 1);
    assert!(matches!(
        update(&mut f, &last, small()),
        ControlResponse::Done { .. }
    ));
    assert!(matches!(
        update(&mut f, "tiny", costly(99)),
        ControlResponse::Done { .. }
    ));
}

#[test]
fn a_share_past_the_budget_is_refused_and_keeps_the_request() {
    let mut bob = Fixture::new();
    fill(&mut bob);
    let code = match bob.prepare(AgentRequest::RequestShare(ShareRequestCall {
        note: String::new(),
        from: "bob".into(),
    })) {
        Prepared::Reply(AgentResponse::ShareRequested { code, .. }) => code,
        _ => panic!("expected a request code"),
    };
    let sealed = share::seal(
        &ShareRequest::decode(&code).unwrap(),
        &SharedSecret {
            name: "more".into(),
            description: String::new(),
            value: costly(42),
            allowed_hosts: Vec::new(),
            allow_plain_http: false,
            allowed_methods: Vec::new(),
            read_only: false,
            from: "mallory".into(),
            note: String::new(),
        },
    )
    .unwrap();
    match bob.prepare(AgentRequest::ReceiveShare(ReceiveShareCall {
        share: sealed,
        name: None,
    })) {
        Prepared::Reply(AgentResponse::Error { code, message }) => {
            assert_eq!(code, AgentErrorCode::BadRequest);
            assert!(message.contains("output scrubber"), "{message}");
        }
        _ => panic!("expected a refusal"),
    }
    let token = bob.token();
    assert_eq!(bob.overview(&token).shares.requests.len(), 1);
}
