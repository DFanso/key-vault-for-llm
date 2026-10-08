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
