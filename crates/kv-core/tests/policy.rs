use std::collections::BTreeMap;

use kv_core::policy::{Decision, DenyReason, Mode, Operation, Policy, evaluate, http_target};
use kv_core::secret::{AuthPlacement, Secret, SecretKind, SecretText, SecretValue};

fn secret(value: SecretValue, policy: Policy) -> Secret {
    Secret {
        name: "h".into(),
        description: String::new(),
        value,
        policy,
        created_at: 0,
        updated_at: 0,
    }
}

fn http(policy: Policy) -> Secret {
    secret(
        SecretValue::Http {
            token: SecretText::new("token-token-token"),
            placement: AuthPlacement::Query {
                param: "key".into(),
            },
            base_url: None,
        },
        policy,
    )
}

fn env(policy: Policy) -> Secret {
    secret(
        SecretValue::Env {
            vars: BTreeMap::new(),
        },
        policy,
    )
}

fn pg() -> Secret {
    secret(
        SecretValue::Postgres {
            url: SecretText::new("postgres://u:p@h/db"),
        },
        Policy {
            mode: Mode::Auto,
            ..Policy::default()
        },
    )
}

fn hosts(mode: Mode) -> Policy {
    Policy {
        mode,
        allowed_hosts: vec!["api.openrouter.ai".into()],
        ..Policy::default()
    }
}

fn get(s: &Secret, url: &str) -> Decision {
    evaluate(s, &Operation::Http { method: "GET", url })
}

fn exec(s: &Secret, program: &str) -> Decision {
    evaluate(s, &Operation::Exec { program })
}

#[test]
fn mode_controls_the_decision_when_rules_pass() {
    let url = "https://api.openrouter.ai/v1/models";
    assert_eq!(get(&http(hosts(Mode::Auto)), url), Decision::Allow);
    assert_eq!(get(&http(hosts(Mode::Ask)), url), Decision::Ask);
    assert_eq!(
        get(&http(hosts(Mode::Deny)), url),
        Decision::Deny(DenyReason::ModeDeny)
    );
}

#[test]
fn operation_must_match_secret_kind() {
    let wrong = |s: &Secret, op: Operation| {
        matches!(
            evaluate(s, &op),
            Decision::Deny(DenyReason::WrongKind { .. })
        )
    };
    assert!(wrong(
        &pg(),
        Operation::Http {
            method: "GET",
            url: "https://x.com"
        }
    ));
    assert!(wrong(&pg(), Operation::Exec { program: "psql" }));
    assert!(wrong(&http(hosts(Mode::Auto)), Operation::DbQuery));
    assert!(wrong(&env(Policy::default()), Operation::DbConnect));
    assert_eq!(evaluate(&pg(), &Operation::DbQuery), Decision::Allow);
    let redis = secret(
        SecretValue::Redis {
            url: SecretText::new("redis://h"),
        },
        Policy {
            mode: Mode::Auto,
            ..Policy::default()
        },
    );
    assert_eq!(evaluate(&redis, &Operation::DbConnect), Decision::Allow);
}

#[test]
fn wrong_kind_reason_names_the_kind_and_tool() {
    assert_eq!(
        evaluate(&pg(), &Operation::Exec { program: "psql" }),
        Decision::Deny(DenyReason::WrongKind {
            kind: SecretKind::Postgres,
            op: "exec"
        })
    );
}

#[test]
fn empty_allowed_hosts_denies_everything() {
    let s = http(Policy {
        mode: Mode::Auto,
        ..Policy::default()
    });
    assert!(matches!(
        get(&s, "https://api.openrouter.ai/"),
        Decision::Deny(DenyReason::HostNotAllowed { .. })
    ));
}

#[test]
fn host_matching_resists_lookalikes_and_normalizes_case() {
    let s = http(hosts(Mode::Auto));
    assert_eq!(get(&s, "HTTPS://API.OPENROUTER.AI/v1"), Decision::Allow);
    assert_eq!(get(&s, "https://api.openrouter.ai./v1"), Decision::Allow);
    assert_eq!(get(&s, "https://api.openrouter.ai:443/v1"), Decision::Allow);
    for bad in [
        "https://api.openrouter.ai.evil.com/",
        "https://evil.com/api.openrouter.ai",
        "https://openrouter.ai/",
        "https://evil.com/?h=api.openrouter.ai",
    ] {
        assert!(
            matches!(
                get(&s, bad),
                Decision::Deny(DenyReason::HostNotAllowed { .. })
            ),
            "{bad}"
        );
    }
    assert!(matches!(
        get(&s, "https://api.openrouter.ai@evil.com/"),
        Decision::Deny(DenyReason::InvalidUrl(_))
    ));
}

#[test]
fn scheme_rules() {
    let s = http(hosts(Mode::Auto));
    assert_eq!(
        get(&s, "http://api.openrouter.ai/"),
        Decision::Deny(DenyReason::PlainHttp)
    );
    assert!(matches!(
        get(&s, "ftp://api.openrouter.ai/"),
        Decision::Deny(DenyReason::InvalidUrl(_))
    ));
    assert!(matches!(
        get(&s, "not a url"),
        Decision::Deny(DenyReason::InvalidUrl(_))
    ));
    let plain = http(Policy {
        allow_plain_http: true,
        ..hosts(Mode::Auto)
    });
    assert_eq!(get(&plain, "http://api.openrouter.ai/"), Decision::Allow);
}

#[test]
fn methods_are_checked_case_insensitively_when_listed() {
    let s = http(Policy {
        allowed_methods: vec!["GET".into(), "POST".into()],
        ..hosts(Mode::Auto)
    });
    let call = |method| {
        evaluate(
            &s,
            &Operation::Http {
                method,
                url: "https://api.openrouter.ai/",
            },
        )
    };
    assert_eq!(call("post"), Decision::Allow);
    assert!(matches!(
        call("DELETE"),
        Decision::Deny(DenyReason::MethodNotAllowed { .. })
    ));
    assert_eq!(
        evaluate(
            &http(hosts(Mode::Auto)),
            &Operation::Http {
                method: "DELETE",
                url: "https://api.openrouter.ai/"
            }
        ),
        Decision::Allow
    );
}

fn cmds(entries: &[&str]) -> Secret {
    env(Policy {
        mode: Mode::Auto,
        allowed_cmds: entries.iter().map(|e| e.to_string()).collect(),
        ..Policy::default()
    })
}

fn denied(s: &Secret, program: &str) -> bool {
    matches!(
        exec(s, program),
        Decision::Deny(DenyReason::CommandNotAllowed { .. })
    )
}

#[test]
fn bare_cmd_entries_match_only_bare_program_names() {
    let s = cmds(&["terraform"]);
    assert_eq!(exec(&s, "terraform"), Decision::Allow);
    for bad in [
        "./terraform",
        "/tmp/agent-written/terraform",
        "/usr/local/bin/terraform",
        r"C:\tools\terraform.exe",
        "terraform-evil",
        "terraformx",
        "sh",
        "",
    ] {
        assert!(denied(&s, bad), "{bad}");
    }
}

#[test]
fn path_cmd_entries_match_only_that_exact_path() {
    let path = if cfg!(windows) {
        r"C:\tools\psql.exe"
    } else {
        "/usr/local/bin/psql"
    };
    let s = cmds(&[path]);
    assert_eq!(exec(&s, path), Decision::Allow);
    for bad in ["psql", "./psql", "/tmp/x/psql", r"C:\other\psql.exe"] {
        assert!(denied(&s, bad), "{bad}");
    }
}

#[test]
fn cmd_case_and_exe_suffix_are_ignored_only_on_windows() {
    let s = cmds(&["terraform"]);
    for spelling in ["TERRAFORM", "terraform.exe", "Terraform.EXE"] {
        if cfg!(windows) {
            assert_eq!(exec(&s, spelling), Decision::Allow, "{spelling}");
        } else {
            assert!(denied(&s, spelling), "{spelling}");
        }
    }
}

#[test]
fn empty_cmd_entries_never_match() {
    let s = cmds(&["", "  "]);
    for program in ["", "  ", "/"] {
        assert!(denied(&s, program), "{program:?}");
    }
}

#[test]
fn ports_must_match_the_allowed_entry() {
    let s = http(Policy {
        allow_plain_http: true,
        allowed_hosts: vec![
            "api.openrouter.ai".into(),
            "localhost:4000".into(),
            "[::1]:8080".into(),
            "::1".into(),
        ],
        ..hosts(Mode::Auto)
    });
    for ok in [
        "https://api.openrouter.ai/v1",
        "https://api.openrouter.ai:443/v1",
        "http://localhost:4000/v1",
        "http://[::1]:8080/",
        "http://[::1]/",
    ] {
        assert_eq!(get(&s, ok), Decision::Allow, "{ok}");
    }
    for bad in [
        "https://api.openrouter.ai:8080/",
        "http://localhost:9999/steal",
        "http://localhost/",
        "http://[::1]:9999/",
    ] {
        assert!(
            matches!(
                get(&s, bad),
                Decision::Deny(DenyReason::HostNotAllowed { .. })
            ),
            "{bad}"
        );
    }
}

#[test]
fn malformed_host_entries_never_match() {
    let s = http(Policy {
        allowed_hosts: vec![
            "".into(),
            "evil.com/path".into(),
            "user@api.openrouter.ai".into(),
        ],
        ..hosts(Mode::Auto)
    });
    for url in ["https://evil.com/path", "https://api.openrouter.ai/"] {
        assert!(
            matches!(
                get(&s, url),
                Decision::Deny(DenyReason::HostNotAllowed { .. })
            ),
            "{url}"
        );
    }
}

#[test]
fn empty_allowed_cmds_denies_everything() {
    let s = env(Policy {
        mode: Mode::Auto,
        ..Policy::default()
    });
    assert!(matches!(
        exec(&s, "psql"),
        Decision::Deny(DenyReason::CommandNotAllowed { .. })
    ));
}

fn base_handle(base: &str, policy: Policy) -> Secret {
    secret(
        SecretValue::Http {
            token: SecretText::new("token-token-token"),
            placement: AuthPlacement::Header {
                name: "Authorization".into(),
                template: "Bearer {}".into(),
            },
            base_url: Some(base.into()),
        },
        policy,
    )
}

fn auto() -> Policy {
    Policy {
        mode: Mode::Auto,
        ..Policy::default()
    }
}

#[test]
fn a_base_url_handle_appends_the_path_and_keeps_the_query() {
    for base in [
        "https://dokploy.example.com/api",
        "https://dokploy.example.com/api/",
    ] {
        let s = base_handle(base, auto());
        let url = http_target(&s, "/project.all?limit=5").unwrap();
        assert_eq!(
            url.as_str(),
            "https://dokploy.example.com/api/project.all?limit=5"
        );
        assert_eq!(get(&s, url.as_str()), Decision::Allow);
    }
}

#[test]
fn a_base_url_handle_rejects_paths_that_leave_the_base() {
    let s = base_handle("https://dokploy.example.com/api", auto());
    for path in [
        "https://evil.example/x",
        "//evil.example/x",
        "project.all",
        "/../admin",
        "/a/%2e%2e/b",
        "/a/%2E/b",
        "/a%2fb",
        "/a%5Cb",
        "/a\\b",
        "/x#frag",
        "",
    ] {
        assert!(
            http_target(&s, path).is_err(),
            "{path:?} should be rejected"
        );
    }
}

#[test]
fn a_base_url_at_the_root_takes_any_path() {
    let s = base_handle("https://api.example.com", auto());
    assert_eq!(
        http_target(&s, "/v1/items").unwrap().as_str(),
        "https://api.example.com/v1/items"
    );
}

#[test]
fn a_base_url_handle_only_reaches_its_own_origin() {
    let s = base_handle("https://dokploy.example.com/api", auto());
    assert_eq!(
        get(&s, "https://dokploy.example.com/elsewhere"),
        Decision::Allow,
        "redirects may leave the prefix but not the origin"
    );
    assert_eq!(
        get(&s, "https://other.example.com/api/x"),
        Decision::Deny(DenyReason::OutsideBaseUrl)
    );
    assert_eq!(
        get(&s, "https://dokploy.example.com:8443/api/x"),
        Decision::Deny(DenyReason::OutsideBaseUrl)
    );
}

#[test]
fn the_outside_base_url_message_does_not_name_the_host() {
    let message = DenyReason::OutsideBaseUrl.to_string();
    assert!(!message.contains("dokploy"), "{message}");
}

#[test]
fn a_plain_http_base_url_needs_allow_plain_http() {
    let s = base_handle("http://10.0.0.5:3000/api", auto());
    let url = http_target(&s, "/x").unwrap();
    assert_eq!(get(&s, url.as_str()), Decision::Deny(DenyReason::PlainHttp));
    let mut allowed = auto();
    allowed.allow_plain_http = true;
    let s = base_handle("http://10.0.0.5:3000/api", allowed);
    assert_eq!(get(&s, url.as_str()), Decision::Allow);
}

#[test]
fn a_url_handle_takes_a_full_url_not_a_path() {
    let s = http(hosts(Mode::Auto));
    assert!(matches!(
        http_target(&s, "/v1/items"),
        Err(DenyReason::InvalidUrl(_))
    ));
    assert_eq!(
        http_target(&s, "https://api.openrouter.ai/v1")
            .unwrap()
            .as_str(),
        "https://api.openrouter.ai/v1"
    );
}
