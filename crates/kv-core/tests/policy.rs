use std::collections::BTreeMap;

use kv_core::policy::{Decision, DenyReason, Mode, Operation, Policy, evaluate};
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

#[test]
fn exec_matches_program_name_across_platform_spellings() {
    let s = env(Policy {
        mode: Mode::Auto,
        allowed_cmds: vec!["terraform".into()],
        ..Policy::default()
    });
    for ok in [
        "terraform",
        "./terraform",
        "/usr/local/bin/terraform",
        r"C:\tools\Terraform.EXE",
        "terraform.exe",
    ] {
        assert_eq!(exec(&s, ok), Decision::Allow, "{ok}");
    }
    for bad in [
        "terraform-evil",
        "terraformx",
        "sh",
        "/bin/terraform/../sh",
        "",
    ] {
        assert!(
            matches!(
                exec(&s, bad),
                Decision::Deny(DenyReason::CommandNotAllowed { .. })
            ),
            "{bad}"
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
