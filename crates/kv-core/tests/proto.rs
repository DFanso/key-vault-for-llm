use std::collections::BTreeMap;
use std::time::Duration;

use kv_core::policy::{Mode, Policy};
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlRequest, ExecCall,
    ExecReply, HttpReply, MAX_FRAME_LEN, MAX_OUTPUT_LEN, PolicyPatch, Status,
};
use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};

fn secrets() -> Vec<Secret> {
    let mut vars = BTreeMap::new();
    vars.insert(
        "AWS_SECRET_ACCESS_KEY".to_string(),
        SecretText::new("wJalrXUtnFEMI-K7MDENG"),
    );
    let make = |name: &str, value| Secret {
        name: name.into(),
        description: format!("{name} handle"),
        value,
        policy: Policy::default(),
        created_at: 0,
        updated_at: 0,
    };
    vec![
        make(
            "openrouter",
            SecretValue::Http {
                token: SecretText::new("sk-or-v1-0123456789abcdef"),
                placement: AuthPlacement::Header {
                    name: "Authorization".into(),
                    template: "Bearer {}".into(),
                },
                base_url: None,
            },
        ),
        make(
            "prod-db",
            SecretValue::Postgres {
                url: SecretText::new("postgres://app:hunter2hunter2@db.internal:5432/app"),
            },
        ),
        make(
            "cache",
            SecretValue::Redis {
                url: SecretText::new("redis://:r3d1s-pass@cache.internal:6379"),
            },
        ),
        make("aws", SecretValue::Env { vars }),
    ]
}

#[test]
fn agent_responses_never_contain_secret_values() {
    let secrets = secrets();
    let responses = [
        AgentResponse::Handles {
            handles: secrets.iter().map(Secret::info).collect(),
        },
        AgentResponse::Status {
            status: Status {
                vault_exists: true,
                locked: false,
                handle_count: Some(secrets.len()),
                locks_in_secs: Some(60),
            },
        },
    ];
    for response in &responses {
        let json = serde_json::to_string(response).unwrap();
        for secret in &secrets {
            for value in secret.sensitive_values() {
                assert!(
                    !json.contains(value.as_str()),
                    "{json} leaks {}",
                    value.as_str()
                );
            }
        }
        assert!(!json.contains(".internal"), "{json} leaks a host");
    }
}

#[test]
fn agent_requests_use_a_type_tag() {
    let json = serde_json::to_string(&AgentRequest::ListHandles).unwrap();
    assert_eq!(json, r#"{"type":"list_handles"}"#);
    let back: AgentRequest = serde_json::from_str(r#"{"type":"status"}"#).unwrap();
    assert_eq!(back, AgentRequest::Status);
}

#[test]
fn a_control_request_is_not_a_valid_agent_request() {
    let control = ControlRequest {
        passphrase: Some(SecretText::new("correct horse battery")),
        command: ControlCommand::Unlock,
    };
    let json = serde_json::to_string(&control).unwrap();
    assert!(serde_json::from_str::<AgentRequest>(&json).is_err());
}

#[test]
fn control_request_debug_hides_the_passphrase() {
    let control = ControlRequest {
        passphrase: Some(SecretText::new("correct horse battery")),
        command: ControlCommand::ChangePassphrase {
            new_passphrase: SecretText::new("a brand new passphrase"),
        },
    };
    let printed = format!("{control:?}");
    assert!(!printed.contains("horse"), "{printed}");
    assert!(!printed.contains("brand new"), "{printed}");
}

#[test]
fn error_codes_serialize_in_snake_case() {
    let response = AgentResponse::Error {
        code: AgentErrorCode::VaultLocked,
        message: "locked".into(),
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains(r#""code":"vault_locked""#), "{json}");
}

#[test]
fn policy_patch_changes_only_the_given_fields() {
    let mut policy = Policy {
        allowed_hosts: vec!["a.example.com".into()],
        allowed_cmds: vec!["psql".into()],
        ..Policy::default()
    };
    let patch = PolicyPatch {
        mode: Some(Mode::Auto),
        allowed_hosts: Some(vec!["b.example.com".into()]),
        grant_ttl: Some(Duration::from_secs(60)),
        ..PolicyPatch::default()
    };
    patch.apply(&mut policy);
    assert_eq!(policy.mode, Mode::Auto);
    assert_eq!(policy.allowed_hosts, vec!["b.example.com"]);
    assert_eq!(policy.allowed_cmds, vec!["psql"]);
    assert_eq!(policy.grant_ttl, Duration::from_secs(60));
}

#[test]
fn policy_patch_json_accepts_missing_fields_and_humantime() {
    let patch: PolicyPatch =
        serde_json::from_str(r#"{"read_only":true,"grant_ttl":"2h"}"#).unwrap();
    assert_eq!(patch.read_only, Some(true));
    assert_eq!(patch.grant_ttl, Some(Duration::from_secs(7200)));
    assert_eq!(patch.mode, None);
}

#[test]
fn http_and_exec_requests_are_flat_tagged_objects() {
    let http: AgentRequest = serde_json::from_str(
        r#"{"type":"http_request","handle":"openrouter","method":"GET","url":"https://openrouter.ai/api/v1/models"}"#,
    )
    .unwrap();
    match http {
        AgentRequest::HttpRequest(call) => {
            assert_eq!(call.handle, "openrouter");
            assert!(call.headers.is_empty());
            assert_eq!(call.body, None);
        }
        other => panic!("{other:?}"),
    }
    let exec: AgentRequest = serde_json::from_str(
        r#"{"type":"exec","handles":["aws"],"argv":["terraform","plan"],"cwd":"/work"}"#,
    )
    .unwrap();
    assert_eq!(
        exec,
        AgentRequest::Exec(ExecCall {
            handles: vec!["aws".into()],
            argv: vec!["terraform".into(), "plan".into()],
            cwd: "/work".into(),
            timeout_secs: None,
        })
    );
}

#[test]
fn replies_round_trip() {
    for response in [
        AgentResponse::Http(HttpReply {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: "{}".into(),
            truncated: false,
        }),
        AgentResponse::Exec(ExecReply {
            exit_code: None,
            timed_out: true,
            stdout: "partial".into(),
            stderr: String::new(),
            truncated: false,
        }),
    ] {
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            serde_json::from_str::<AgentResponse>(&json).unwrap(),
            response
        );
    }
}

#[test]
fn error_code_names_match_the_wire_format() {
    for code in [
        AgentErrorCode::NoVault,
        AgentErrorCode::VaultLocked,
        AgentErrorCode::BadRequest,
        AgentErrorCode::UnknownHandle,
        AgentErrorCode::PolicyDenied,
        AgentErrorCode::ApprovalTimeout,
        AgentErrorCode::UpstreamError,
    ] {
        assert_eq!(
            serde_json::to_string(&code).unwrap(),
            format!("\"{}\"", code.as_str())
        );
    }
}

#[test]
fn worst_case_escaped_output_fits_in_a_frame() {
    let control_bytes = "\u{1}".repeat(MAX_OUTPUT_LEN);
    let reply = AgentResponse::Exec(ExecReply {
        exit_code: Some(0),
        timed_out: false,
        stdout: control_bytes.clone(),
        stderr: control_bytes,
        truncated: true,
    });
    assert!(serde_json::to_vec(&reply).unwrap().len() < MAX_FRAME_LEN);
}
