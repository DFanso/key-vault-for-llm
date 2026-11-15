//! An `http_request` reaches only the hosts its handle allows. These
//! requests aim at addresses an agent may try to reach through kv instead:
//! cloud metadata services, loopback and private ranges, the same addresses
//! written in other forms, other URL schemes, and paths that try to leave a
//! handle's base URL. Every one is refused.
//!
//! Not covered: a host the user allowed whose name later resolves to an
//! internal address (DNS rebinding). kv checks the host as written, not the
//! address it connects to.

use kv_core::policy::{Decision, DenyReason, Mode, Operation, Policy, evaluate, http_target};
use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};

fn handle(base_url: Option<&str>, policy: Policy) -> Secret {
    Secret {
        name: "api".into(),
        description: String::new(),
        value: SecretValue::Http {
            token: SecretText::new("token-token-token"),
            placement: AuthPlacement::Header {
                name: "Authorization".into(),
                template: "Bearer {}".into(),
            },
            base_url: base_url.map(Into::into),
        },
        policy,
        created_at: 0,
        updated_at: 0,
        from_share: None,
    }
}

/// Allows one public host, plain HTTP included, so that a refusal below is
/// about the host and not the scheme.
fn one_host() -> Secret {
    handle(
        None,
        Policy {
            mode: Mode::Auto,
            allowed_hosts: vec!["api.example.com".into()],
            allow_plain_http: true,
            ..Policy::default()
        },
    )
}

fn get(s: &Secret, url: &str) -> Decision {
    evaluate(s, &Operation::Http { method: "GET", url })
}

fn refused(s: &Secret, url: &str) {
    match get(s, url) {
        Decision::Deny(_) => {}
        other => panic!("{url} was not refused: {other:?}"),
    }
}

#[test]
fn the_allowed_host_itself_goes_through() {
    assert_eq!(
        get(&one_host(), "https://api.example.com/v1"),
        Decision::Allow
    );
}

#[test]
fn metadata_loopback_and_private_addresses_are_refused() {
    let s = one_host();
    for url in [
        "http://169.254.169.254/latest/meta-data/",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://127.0.0.1/",
        "http://127.1/",
        "http://localhost/",
        "http://0.0.0.0/",
        "http://[::]/",
        "http://[::1]/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://[fd12:3456::1]/",
        "http://[fe80::1]/",
        "http://169.254.1.1/",
    ] {
        match get(&s, url) {
            Decision::Deny(DenyReason::HostNotAllowed { .. }) => {}
            other => panic!("{url}: expected host_not_allowed, got {other:?}"),
        }
    }
}

#[test]
fn other_spellings_of_an_address_are_refused() {
    let s = one_host();
    for url in [
        // 169.254.169.254 as one decimal number, in hex, in octal, and
        // with its last two parts joined.
        "http://2852039166/",
        "http://0xA9FEA9FE/",
        "http://0251.0376.0251.0376/",
        "http://169.254.43518/",
        // IPv4-mapped IPv6.
        "http://[::ffff:169.254.169.254]/",
        "http://[::ffff:127.0.0.1]/",
        // Percent-encoded and upper-case host names.
        "http://%6c%6f%63%61%6c%68%6f%73%74/",
        "http://LOCALHOST/",
        // A trailing dot.
        "http://localhost./",
    ] {
        refused(&s, url);
    }
}

#[test]
fn the_allowed_host_cannot_be_used_as_a_disguise() {
    let s = one_host();
    for url in [
        // User info: the real host is the one after the @.
        "https://api.example.com@169.254.169.254/",
        "https://api.example.com:pw@169.254.169.254/",
        // A fragment or query that names the allowed host.
        "https://169.254.169.254/#@api.example.com",
        "https://169.254.169.254/?host=api.example.com",
        // A longer name that only starts or ends like it.
        "https://api.example.com.evil.test/",
        "https://evilapi.example.com/",
        // The allowed host on another port.
        "https://api.example.com:8443/",
    ] {
        refused(&s, url);
    }
}

#[test]
fn other_schemes_are_refused() {
    let s = one_host();
    for url in [
        "file:///etc/passwd",
        "file://api.example.com/etc/passwd",
        "ftp://api.example.com/",
        "gopher://api.example.com/",
        "ws://api.example.com/",
        "wss://api.example.com/",
        "data:text/plain,hi",
        "javascript:alert(1)",
        "dict://api.example.com:11211/",
    ] {
        match get(&s, url) {
            Decision::Deny(DenyReason::InvalidUrl(_)) => {}
            other => panic!("{url}: expected invalid_url, got {other:?}"),
        }
    }
}

#[test]
fn a_path_cannot_leave_the_base_url() {
    let s = handle(
        Some("https://dokploy.example.com/api"),
        Policy {
            mode: Mode::Auto,
            ..Policy::default()
        },
    );
    for path in [
        "//169.254.169.254/latest",
        "/..//169.254.169.254/latest",
        "/../../other",
        "/%2e%2e/other",
        "/api/../../other",
        "@169.254.169.254/x",
        "http://169.254.169.254/",
    ] {
        assert!(
            http_target(&s, path).is_err(),
            "{path} was accepted: {:?}",
            http_target(&s, path)
        );
    }
}
