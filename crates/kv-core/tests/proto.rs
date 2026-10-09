use std::collections::BTreeMap;
use std::time::Duration;

use kv_core::policy::{Mode, Policy};
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ConnectCall, ControlCommand, ControlRequest,
    ControlResponse, DbCall, ExecCall, ExecReply, HttpReply, LeaseReply, MAX_FRAME_LEN,
    MAX_OUTPUT_LEN, Overview, PolicyPatch, RedisReply, ResultSet, RowsReply, SessionInfo, Status,
    Verdict,
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
                pending_approvals: 0,
                devices: Vec::new(),
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
        device: None,
        token: None,
        command: ControlCommand::Unlock,
    };
    let json = serde_json::to_string(&control).unwrap();
    assert!(serde_json::from_str::<AgentRequest>(&json).is_err());
}

#[test]
fn control_request_debug_hides_the_passphrase() {
    let control = ControlRequest {
        passphrase: Some(SecretText::new("correct horse battery")),
        device: None,
        token: None,
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
        AgentErrorCode::ApprovalDenied,
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

#[test]
fn a_control_request_without_a_token_still_parses() {
    let request: ControlRequest =
        serde_json::from_str(r#"{"passphrase":"pw","command":{"type":"unlock"}}"#).unwrap();
    assert!(request.token.is_none());
}

#[test]
fn session_tokens_never_show_in_debug_output() {
    let token = "ab".repeat(32);
    let request = ControlRequest {
        passphrase: None,
        device: None,
        token: Some(SecretText::new(token.clone())),
        command: ControlCommand::Overview,
    };
    let response = ControlResponse::Session {
        token: SecretText::new(token.clone()),
    };
    for printed in [format!("{request:?}"), format!("{response:?}")] {
        assert!(!printed.contains(&token), "{printed}");
    }
}

#[test]
fn hello_names_the_agent_session() {
    let hello = AgentRequest::Hello(SessionInfo {
        id: "abc".into(),
        client: "claude-code".into(),
    });
    let json = serde_json::to_string(&hello).unwrap();
    assert_eq!(
        json,
        r#"{"type":"hello","id":"abc","client":"claude-code"}"#
    );
}

#[test]
fn verdicts_use_snake_case_names() {
    let json = serde_json::to_string(&[
        Verdict::AllowOnce,
        Verdict::AllowSession,
        Verdict::Deny,
        Verdict::DenyAlways,
    ])
    .unwrap();
    assert_eq!(
        json,
        r#"["allow_once","allow_session","deny","deny_always"]"#
    );
}

#[test]
fn a_status_from_before_approvals_still_parses() {
    let status: Status = serde_json::from_str(
        r#"{"vault_exists":true,"locked":true,"handle_count":null,"locks_in_secs":null}"#,
    )
    .unwrap();
    assert_eq!(status.pending_approvals, 0);
}

#[test]
fn update_fields_are_optional() {
    let parsed: ControlCommand = serde_json::from_str(r#"{"type":"update","name":"api"}"#).unwrap();
    assert!(
        matches!(
            &parsed,
            ControlCommand::Update {
                name,
                description: None,
                value: None,
            } if name == "api"
        ),
        "{parsed:?}"
    );
}

#[test]
fn a_handle_request_has_defaults_and_no_place_for_a_value() {
    let parsed: AgentRequest =
        serde_json::from_str(r#"{"type":"request_handle","name":"dokploy","kind":"http"}"#)
            .unwrap();
    match parsed {
        AgentRequest::RequestHandle(request) => {
            assert_eq!(request.name, "dokploy");
            assert_eq!(request.kind, kv_core::secret::SecretKind::Http);
            assert!(request.auth.is_none() && !request.base_url);
            assert!(request.allowed_hosts.is_empty() && request.env_vars.is_empty());
        }
        other => panic!("{other:?}"),
    }
    for extra in [r#""token":"sk-123""#, r#""value":"x""#, r#""mode":"auto""#] {
        let json = format!(r#"{{"type":"request_handle","name":"a","kind":"http",{extra}}}"#);
        assert!(
            serde_json::from_str::<AgentRequest>(&json).is_err(),
            "{extra} must be refused, not ignored"
        );
    }
}

#[test]
fn a_db_query_is_a_flat_tagged_object_with_an_optional_timeout() {
    let request: AgentRequest =
        serde_json::from_str(r#"{"type":"db_query","handle":"prod-db","query":"select 1"}"#)
            .unwrap();
    assert_eq!(
        request,
        AgentRequest::DbQuery(DbCall {
            handle: "prod-db".into(),
            query: "select 1".into(),
            timeout_secs: None,
        })
    );
}

#[test]
fn a_db_connect_takes_a_handle_and_an_optional_ttl() {
    let request: AgentRequest =
        serde_json::from_str(r#"{"type":"db_connect","handle":"prod-db"}"#).unwrap();
    assert_eq!(
        request,
        AgentRequest::DbConnect(ConnectCall {
            handle: "prod-db".into(),
            ttl_secs: None,
        })
    );
}

#[test]
fn database_replies_round_trip() {
    for response in [
        AgentResponse::Rows(RowsReply {
            results: vec![ResultSet {
                columns: vec!["id".into(), "email".into()],
                rows: vec![vec![Some("1".into()), None]],
                rows_affected: Some(1),
            }],
            truncated: false,
            warnings: vec!["the role can write".into()],
        }),
        AgentResponse::Redis(RedisReply {
            value: serde_json::json!(["a", 1, null]),
            truncated: true,
        }),
        AgentResponse::Lease(LeaseReply {
            url: "postgres://kv:token@127.0.0.1:41823/app".into(),
            expires_in_secs: 900,
            warnings: Vec::new(),
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
fn an_overview_from_before_role_warnings_still_parses() {
    let overview: Overview = serde_json::from_str(
        r#"{"status":{"vault_exists":true,"locked":false,"handle_count":0,"locks_in_secs":null},"handles":[]}"#,
    )
    .unwrap();
    assert!(overview.role_warnings.is_empty());
}

#[test]
fn a_control_request_without_a_device_credential_still_parses() {
    let request: ControlRequest =
        serde_json::from_str(r#"{"passphrase":"pw","command":{"type":"unlock"}}"#).unwrap();
    assert!(request.device.is_none());
    let status: Status = serde_json::from_str(
        r#"{"vault_exists":true,"locked":true,"handle_count":null,"locks_in_secs":null}"#,
    )
    .unwrap();
    assert!(status.devices.is_empty());
}
