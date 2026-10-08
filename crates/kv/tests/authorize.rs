//! How the daemon decides whether an agent's `http_request` or `exec` may
//! run, before any network or process work happens.

mod common;

use common::*;
use kv_core::policy::Mode;
use kv_core::proto::{AgentErrorCode, ControlCommand};

#[test]
fn an_allowed_request_becomes_a_job_with_a_scrubber() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    let job = f
        .http(get("openrouter", "https://openrouter.ai/api/v1/models"))
        .unwrap();
    assert_eq!(job.url.as_str(), "https://openrouter.ai/api/v1/models");
    assert_eq!(job.secret.name, "openrouter");
    let scrubbed = job.scrubber.scrub(format!("echo {TOKEN}").as_bytes());
    assert_eq!(String::from_utf8(scrubbed).unwrap(), "echo [kv:openrouter]");
}

#[test]
fn a_locked_vault_refuses_and_is_audited() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    f.control(ControlCommand::Lock);
    let (code, _) = f
        .http(get("openrouter", "https://openrouter.ai/"))
        .unwrap_err();
    assert_eq!(code, AgentErrorCode::VaultLocked);
    let last = f.audit_lines().pop().unwrap();
    assert_eq!(last["action"], "http_request");
    assert_eq!(last["decision"], "locked");
    assert_eq!(last["outcome"], "vault_locked");
}

#[test]
fn an_unknown_handle_lists_the_available_ones() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    let (code, message) = f
        .http(get("github", "https://api.github.com/"))
        .unwrap_err();
    assert_eq!(code, AgentErrorCode::UnknownHandle);
    assert!(message.contains("available: openrouter"), "{message}");
}

#[test]
fn policy_failures_name_the_rule() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    let (code, message) = f
        .http(get("openrouter", "https://evil.example/steal"))
        .unwrap_err();
    assert_eq!(code, AgentErrorCode::PolicyDenied);
    assert!(message.contains("openrouter.ai"), "{message}");
}

#[test]
fn ask_mode_fails_until_approvals_exist() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Ask));
    let (code, message) = f
        .http(get("openrouter", "https://openrouter.ai/"))
        .unwrap_err();
    assert_eq!(code, AgentErrorCode::ApprovalTimeout);
    assert!(
        message.contains("kv policy openrouter --mode auto"),
        "{message}"
    );
}

#[test]
fn malformed_http_requests_are_bad_requests() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    f.add(dokploy());
    let mut bad_method = get("openrouter", "https://openrouter.ai/");
    bad_method.method = "G ET".into();
    let mut host_header = get("openrouter", "https://openrouter.ai/");
    host_header
        .headers
        .insert("Host".into(), "evil.example".into());
    let mut auth_header = get("openrouter", "https://openrouter.ai/");
    auth_header
        .headers
        .insert("authorization".into(), "Bearer mine".into());
    let mut split_header = get("openrouter", "https://openrouter.ai/");
    split_header
        .headers
        .insert("x-note".into(), "a\r\nx-other: b".into());
    for call in [
        bad_method,
        host_header,
        auth_header,
        split_header,
        get("openrouter", "/api/v1/models"),
        get("dokploy", "https://dokploy.internal.example/api/x"),
        get("dokploy", "/../admin"),
    ] {
        let (code, message) = f.http(call.clone()).unwrap_err();
        assert_eq!(code, AgentErrorCode::BadRequest, "{call:?}: {message}");
    }
}

#[test]
fn headers_that_would_hide_or_split_a_secret_are_refused() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    for (name, value) in [
        ("Accept-Encoding", "gzip"),
        ("range", "bytes=0-3"),
        ("If-Range", "\"etag\""),
    ] {
        let mut call = get("openrouter", "https://openrouter.ai/");
        call.headers.insert(name.into(), value.into());
        let (code, message) = f.http(call).unwrap_err();
        assert_eq!(code, AgentErrorCode::BadRequest, "{name}: {message}");
        assert!(message.contains("set by kv"), "{message}");
    }
}

#[test]
fn method_override_headers_are_refused_when_methods_are_restricted() {
    let mut f = Fixture::new();
    let mut restricted = openrouter(Mode::Auto);
    restricted.policy.allowed_methods = vec!["GET".into()];
    f.add(restricted);
    for name in [
        "X-HTTP-Method-Override",
        "x-http-method",
        "X-Method-Override",
    ] {
        let mut call = get("openrouter", "https://openrouter.ai/");
        call.headers.insert(name.into(), "DELETE".into());
        let (code, message) = f.http(call).unwrap_err();
        assert_eq!(code, AgentErrorCode::BadRequest, "{name}: {message}");
        assert!(message.contains("method"), "{message}");
    }

    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    let mut call = get("openrouter", "https://openrouter.ai/");
    call.headers
        .insert("X-HTTP-Method-Override".into(), "PATCH".into());
    assert!(f.http(call).is_ok(), "no method rule, nothing to bypass");
}

#[test]
fn authorizing_exec_never_touches_the_cwd_on_disk() {
    // A path on a hung network mount would block the daemon while it holds
    // its lock, so prepare only checks that cwd is absolute.
    let mut f = Fixture::new();
    f.add(env_secret(
        "aws",
        &[("AWS_SECRET_ACCESS_KEY", AWS_KEY)],
        &["terraform"],
        Mode::Auto,
    ));
    let missing = f.dir.path().join("missing");
    let job = f
        .exec(run(&["aws"], &["terraform"], missing.clone()))
        .unwrap();
    assert_eq!(job.cwd, missing);
}

#[test]
fn a_base_url_handle_joins_the_path_and_scrubs_its_address() {
    let mut f = Fixture::new();
    f.add(dokploy());
    let job = f.http(get("dokploy", "/project.all")).unwrap();
    assert_eq!(
        job.url.as_str(),
        "https://dokploy.internal.example/api/project.all"
    );
    let scrubbed = job
        .scrubber
        .scrub(b"see https://dokploy.internal.example/api/x");
    assert!(
        !String::from_utf8_lossy(&scrubbed).contains("dokploy.internal"),
        "{}",
        String::from_utf8_lossy(&scrubbed)
    );
}

#[test]
fn the_scrubber_follows_changes_to_the_vault() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    f.http(get("openrouter", "https://openrouter.ai/")).unwrap();
    f.add(env_secret(
        "aws",
        &[("AWS_ACCESS_KEY_ID", AWS_KEY)],
        &[],
        Mode::Auto,
    ));
    let job = f.http(get("openrouter", "https://openrouter.ai/")).unwrap();
    let scrubbed = job.scrubber.scrub(AWS_KEY.as_bytes());
    assert_eq!(String::from_utf8(scrubbed).unwrap(), "[kv:aws]");
}

#[test]
fn exec_merges_variables_from_every_handle() {
    let mut f = Fixture::new();
    f.add(env_secret(
        "aws",
        &[("AWS_ACCESS_KEY_ID", AWS_KEY)],
        &["terraform"],
        Mode::Auto,
    ));
    f.add(env_secret(
        "cloudflare",
        &[("CLOUDFLARE_API_TOKEN", "cf-token-0123456789")],
        &["terraform"],
        Mode::Auto,
    ));
    let cwd = f.dir.path().to_path_buf();
    let job = f
        .exec(run(&["aws", "cloudflare"], &["terraform", "plan"], cwd))
        .unwrap();
    let names: Vec<&str> = job.env.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, ["AWS_ACCESS_KEY_ID", "CLOUDFLARE_API_TOKEN"]);
    assert_eq!(job.timeout.as_secs(), 60);
}

#[test]
fn exec_refuses_what_policy_and_input_rules_forbid() {
    let mut f = Fixture::new();
    f.add(env_secret(
        "aws",
        &[("AWS_ACCESS_KEY_ID", AWS_KEY)],
        &["terraform"],
        Mode::Auto,
    ));
    f.add(env_secret(
        "aws-other",
        &[("AWS_ACCESS_KEY_ID", "AKIAOTHERKEY0123456")],
        &["terraform"],
        Mode::Auto,
    ));
    f.add(env_secret(
        "asks",
        &[("TOKEN", "ask-token-0123456789")],
        &["terraform"],
        Mode::Ask,
    ));
    f.add(openrouter(Mode::Auto));
    let cwd = f.dir.path().to_path_buf();
    let cases = [
        (
            run(&["aws"], &["bash", "-c", "env"], cwd.clone()),
            AgentErrorCode::PolicyDenied,
        ),
        (
            run(&["openrouter"], &["terraform"], cwd.clone()),
            AgentErrorCode::PolicyDenied,
        ),
        (
            run(&["aws", "aws-other"], &["terraform"], cwd.clone()),
            AgentErrorCode::BadRequest,
        ),
        (
            run(&["aws", "aws"], &["terraform"], cwd.clone()),
            AgentErrorCode::BadRequest,
        ),
        (
            run(&[], &["terraform"], cwd.clone()),
            AgentErrorCode::BadRequest,
        ),
        (run(&["aws"], &[], cwd.clone()), AgentErrorCode::BadRequest),
        (
            run(&["aws"], &["terraform"], "relative".into()),
            AgentErrorCode::BadRequest,
        ),
        (
            run(&["nope"], &["terraform"], cwd.clone()),
            AgentErrorCode::UnknownHandle,
        ),
        (
            run(&["asks"], &["terraform"], cwd.clone()),
            AgentErrorCode::ApprovalTimeout,
        ),
    ];
    for (call, expected) in cases {
        let (code, message) = f.exec(call.clone()).unwrap_err();
        assert_eq!(code, expected, "{call:?}: {message}");
    }
    for timeout in [0, 601] {
        let mut call = run(&["aws"], &["terraform"], cwd.clone());
        call.timeout_secs = Some(timeout);
        assert_eq!(f.exec(call).unwrap_err().0, AgentErrorCode::BadRequest);
    }
}

#[test]
fn policy_denials_for_exec_name_the_handle() {
    let mut f = Fixture::new();
    f.add(env_secret(
        "aws",
        &[("AWS_ACCESS_KEY_ID", AWS_KEY)],
        &["terraform"],
        Mode::Auto,
    ));
    let cwd = f.dir.path().to_path_buf();
    let (_, message) = f.exec(run(&["aws"], &["sh"], cwd)).unwrap_err();
    assert!(message.starts_with("aws: "), "{message}");
    assert!(message.contains("terraform"), "{message}");
}
