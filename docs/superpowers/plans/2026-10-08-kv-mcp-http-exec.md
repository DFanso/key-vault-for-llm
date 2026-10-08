# kv MCP server, HTTP requests and exec Implementation Plan (Plan 3 of 6)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let agents use secrets: `http_request` (with optional `base_url` handles that hide a service's address) and `exec` on the agent socket, and `kv mcp`, the stdio MCP server that agents such as Claude Code connect to.

**Architecture:** The daemon authorizes each request under its lock (`Daemon::prepare`) and hands back a job (`HttpJob` or `ExecJob`) that carries everything needed to run it, including a shared `Arc<Scrubber>` and an audit handle. The server runs the job outside the lock, so a slow upstream or a long-running program never blocks other requests. `broker::http` sends requests with `reqwest` and follows redirects itself; `broker::exec` runs programs from an argv in their own process group (Unix) or job object (Windows) and streams their output through the scrubber. `kv mcp` is a thin `rmcp` server: each tool call is one agent-socket request, so it never holds a secret.

**Tech Stack:** Rust 2024 (MSRV 1.89), reqwest 0.13 (rustls, platform verifier), rmcp 3.5, url 2.5, tokio 1.53 (`process`), windows-sys 0.61 (job objects); tests use wiremock 0.6, rcgen 0.14 and tokio-rustls 0.26.

**Spec:** `docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md`. This plan implements section 4 (`list_handles`, `http_request`, `exec`, `status` and the request pipeline, without approvals) and the parts of section 5 those tools need (scrubbing of responses and program output, audit records for each use, agent-facing errors). Approvals arrive with the TUI in Plan 4; until then `mode: ask` handles fail with `approval_timeout`. The database tools are Plan 5.

## Global Constraints

- `rust-version = "1.89"`, edition 2024.
- New dependencies are limited to: `url = "2.5"`, `reqwest = { version = "0.13", default-features = false, features = ["rustls"] }`, `rmcp = "3.5"` (`macros`, `server`, `transport-io`), tokio's `process` feature and windows-sys's `Win32_System_JobObjects`; dev-dependencies `rcgen = "0.14"`, `tokio-rustls = "0.26"`, `wiremock = "0.6"` and `rmcp` (`client`, `transport-child-process`).
- No agent-socket message may carry a secret value. `HttpJob` and `ExecJob` hold secrets and never cross the socket; their `Debug` output is redacted.
- Every byte returned to an agent (status line aside) passes through the scrubber: response headers and body, stdout, stderr and error messages. Output cut by the 256 KiB cap or by a kill drops the scrubber's held-back tail instead of flushing it.
- The daemon's mutex is never held across network I/O or a running program.
- `exec` never runs a shell string: argv only, and a bare program name is resolved through the PATH the daemon started with, skipping relative entries.
- All failures are closed: no partial results, no fallback to unauthenticated or unscrubbed paths.
- Commits: author `DFanso <leogavin123@outlook.com>`, no AI attribution lines or `Co-Authored-By` trailers.
- **On this Mac**, prefix cargo commands with `DEVELOPER_DIR=/Library/Developer/CommandLineTools` (the Xcode license is not accepted). The commands below include it; drop it elsewhere and in CI.
- From Task 3 on, `cargo clippy --target x86_64-pc-windows-msvc` no longer builds on this Mac: reqwest's rustls backend pulls in `aws-lc-sys`, which needs a C cross toolchain. Cross-check `kv-core` with `cargo clippy -p kv-core --target <triple>`; CI checks the Windows-only code in `broker/process.rs` on `windows-latest`.

## Review Focus

1. **APIs that echo the key** in an error body or header, split across chunks, in another encoding, or right at the 256 KiB cut, must come back as `[kv:<handle>]`, never the value or a fragment of it. Pinned by `the_credential_reaches_upstream_and_echoes_are_scrubbed` and `a_cut_body_never_ends_in_part_of_a_secret` (Task 3) and `injected_values_never_come_back_in_any_encoding` (Task 4).
2. **A compressed or byte-range response** would carry a secret past the scrubber, so the agent may not ask for one and an encoded response is refused. Pinned by `headers_that_would_hide_or_split_a_secret_are_refused` (Task 2) and `an_encoded_body_is_refused_because_it_cannot_be_scrubbed` (Task 3).
3. **Redirects to another host** (a CDN download, a login page) must not carry the credential, and a redirect the policy does not allow must come back to the agent rather than be followed. Pinned by `redirects_keep_the_credential_only_on_the_original_origin`, `a_redirect_to_a_host_that_is_not_allowed_is_returned_not_followed` and `see_other_turns_a_post_into_a_get_without_its_body` (Task 3).
4. **Paths that try to leave a `base_url`**: `..`, percent-encoded dots and slashes, backslashes, `//host` and absolute URLs must be refused without revealing the address. Pinned by `a_base_url_handle_rejects_paths_that_leave_the_base` and `the_outside_base_url_message_does_not_name_the_host` (Task 1).
5. **A program that hangs or leaves children running** (provider plugins, dev servers) must be killed with everything it started, and a partial secret written just before the kill must not escape. Pinned by `a_timeout_kills_the_program_without_flushing_part_of_a_secret` and `a_timeout_also_kills_what_the_program_started` (Task 4).

## File Structure

```
crates/kv-core/src/secret.rs        SecretValue::Http gains base_url; HandleInfo gains takes_path
crates/kv-core/src/policy.rs        http_target: the URL to send, joined onto base_url and checked
crates/kv-core/src/proto.rs         http_request and exec messages and replies, new error codes, 4 MiB frames
crates/kv/Cargo.toml                url, reqwest, rmcp, tokio process, job objects
crates/kv/src/audit.rs              record_use: decision, summary and duration per use; Audit is Clone
crates/kv/src/broker.rs             HttpJob, ExecJob, capped_text
crates/kv/src/broker/http.rs        reqwest client, credential placement, manual redirects, scrubbed replies
crates/kv/src/broker/exec.rs        argv runner, PATH resolution, streamed scrubbing, timeouts
crates/kv/src/broker/process.rs     process group (Unix) or job object (Windows) per program
crates/kv/src/daemon/state.rs       prepare: authorize http_request and exec, cached scrubber
crates/kv/src/daemon/server.rs      runs jobs outside the daemon lock
crates/kv/src/mcp.rs                kv mcp: rmcp tools over stdin and stdout
crates/kv/src/cli.rs                kv add --base-url, kv mcp
crates/kv/tests/common/mod.rs       shared Fixture for daemon-level tests
crates/kv/tests/authorize.rs, http.rs, exec.rs, resolve.rs, mcp.rs
README.md                           setup with Claude Code, base_url, PATH note
```

---

### Task 1: `base_url` on http secrets

**Files:**
- Modify: `crates/kv/Cargo.toml`, `crates/kv-core/src/policy.rs`, `crates/kv-core/src/secret.rs`, `crates/kv/src/cli.rs`, `crates/kv/src/daemon/state.rs`
- Test: `crates/kv-core/tests/policy.rs`, `crates/kv-core/tests/proto.rs`, `crates/kv-core/tests/secret.rs`, `crates/kv/tests/cli.rs`, `crates/kv/tests/state.rs`

**Interfaces:**
- Consumes: Plan 1's `Secret`, `SecretValue::Http { token, placement }`, `policy::evaluate`, `HandleInfo`; Plan 2's `kv add` prompts and `Daemon` secret validation in `daemon/state.rs`.
- Produces: `SecretValue::Http` gains `base_url: Option<String>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`, so existing vaults load unchanged); `HandleInfo.takes_path: bool`; `kv_core::policy::http_target(secret: &Secret, requested: &str) -> Result<url::Url, DenyReason>`, which returns the exact URL to send (the path joined onto the base URL for `base_url` handles, the parsed URL otherwise); `DenyReason::OutsideBaseUrl` and `DenyReason::InvalidPath(&'static str)`; `kv add --base-url` (a flag; the URL is prompted for like a secret value). Every place that builds `SecretValue::Http` now sets `base_url`.

- [ ] **Step 1: Add the dependencies**

Save as `task1-deps.patch`, run `git apply task1-deps.patch`, then delete the patch file:
```diff
diff --git a/crates/kv/Cargo.toml b/crates/kv/Cargo.toml
index 84d81ab..9740aa7 100644
--- a/crates/kv/Cargo.toml
+++ b/crates/kv/Cargo.toml
@@ -14,6 +14,7 @@ rpassword = "7.5"
 serde = { version = "1", features = ["derive"] }
 serde_json = "1"
 tokio = { version = "1.53", features = ["io-util", "macros", "net", "rt-multi-thread", "sync", "time"] }
+url = "2.5"
 zeroize = "1.9"
 
 [target.'cfg(unix)'.dependencies]
```

- [ ] **Step 2: Write the failing tests**

Save as `task1-tests.patch`, run `git apply task1-tests.patch`, then delete the patch file:
```diff
diff --git a/crates/kv-core/tests/policy.rs b/crates/kv-core/tests/policy.rs
index f112c35..b0f4b07 100644
--- a/crates/kv-core/tests/policy.rs
+++ b/crates/kv-core/tests/policy.rs
@@ -1,6 +1,6 @@
 use std::collections::BTreeMap;
 
-use kv_core::policy::{Decision, DenyReason, Mode, Operation, Policy, evaluate};
+use kv_core::policy::{Decision, DenyReason, Mode, Operation, Policy, evaluate, http_target};
 use kv_core::secret::{AuthPlacement, Secret, SecretKind, SecretText, SecretValue};
 
 fn secret(value: SecretValue, policy: Policy) -> Secret {
@@ -21,6 +21,7 @@ fn http(policy: Policy) -> Secret {
             placement: AuthPlacement::Query {
                 param: "key".into(),
             },
+            base_url: None,
         },
         policy,
     )
@@ -344,3 +345,122 @@ fn empty_allowed_cmds_denies_everything() {
         Decision::Deny(DenyReason::CommandNotAllowed { .. })
     ));
 }
+
+fn base_handle(base: &str, policy: Policy) -> Secret {
+    secret(
+        SecretValue::Http {
+            token: SecretText::new("token-token-token"),
+            placement: AuthPlacement::Header {
+                name: "Authorization".into(),
+                template: "Bearer {}".into(),
+            },
+            base_url: Some(base.into()),
+        },
+        policy,
+    )
+}
+
+fn auto() -> Policy {
+    Policy {
+        mode: Mode::Auto,
+        ..Policy::default()
+    }
+}
+
+#[test]
+fn a_base_url_handle_appends_the_path_and_keeps_the_query() {
+    for base in [
+        "https://dokploy.example.com/api",
+        "https://dokploy.example.com/api/",
+    ] {
+        let s = base_handle(base, auto());
+        let url = http_target(&s, "/project.all?limit=5").unwrap();
+        assert_eq!(
+            url.as_str(),
+            "https://dokploy.example.com/api/project.all?limit=5"
+        );
+        assert_eq!(get(&s, url.as_str()), Decision::Allow);
+    }
+}
+
+#[test]
+fn a_base_url_handle_rejects_paths_that_leave_the_base() {
+    let s = base_handle("https://dokploy.example.com/api", auto());
+    for path in [
+        "https://evil.example/x",
+        "//evil.example/x",
+        "project.all",
+        "/../admin",
+        "/a/%2e%2e/b",
+        "/a/%2E/b",
+        "/a%2fb",
+        "/a%5Cb",
+        "/a\\b",
+        "/x#frag",
+        "",
+    ] {
+        assert!(
+            http_target(&s, path).is_err(),
+            "{path:?} should be rejected"
+        );
+    }
+}
+
+#[test]
+fn a_base_url_at_the_root_takes_any_path() {
+    let s = base_handle("https://api.example.com", auto());
+    assert_eq!(
+        http_target(&s, "/v1/items").unwrap().as_str(),
+        "https://api.example.com/v1/items"
+    );
+}
+
+#[test]
+fn a_base_url_handle_only_reaches_its_own_origin() {
+    let s = base_handle("https://dokploy.example.com/api", auto());
+    assert_eq!(
+        get(&s, "https://dokploy.example.com/elsewhere"),
+        Decision::Allow,
+        "redirects may leave the prefix but not the origin"
+    );
+    assert_eq!(
+        get(&s, "https://other.example.com/api/x"),
+        Decision::Deny(DenyReason::OutsideBaseUrl)
+    );
+    assert_eq!(
+        get(&s, "https://dokploy.example.com:8443/api/x"),
+        Decision::Deny(DenyReason::OutsideBaseUrl)
+    );
+}
+
+#[test]
+fn the_outside_base_url_message_does_not_name_the_host() {
+    let message = DenyReason::OutsideBaseUrl.to_string();
+    assert!(!message.contains("dokploy"), "{message}");
+}
+
+#[test]
+fn a_plain_http_base_url_needs_allow_plain_http() {
+    let s = base_handle("http://10.0.0.5:3000/api", auto());
+    let url = http_target(&s, "/x").unwrap();
+    assert_eq!(get(&s, url.as_str()), Decision::Deny(DenyReason::PlainHttp));
+    let mut allowed = auto();
+    allowed.allow_plain_http = true;
+    let s = base_handle("http://10.0.0.5:3000/api", allowed);
+    assert_eq!(get(&s, url.as_str()), Decision::Allow);
+}
+
+#[test]
+fn a_url_handle_takes_a_full_url_not_a_path() {
+    let s = http(hosts(Mode::Auto));
+    assert!(matches!(
+        http_target(&s, "/v1/items"),
+        Err(DenyReason::InvalidUrl(_))
+    ));
+    assert_eq!(
+        http_target(&s, "https://api.openrouter.ai/v1")
+            .unwrap()
+            .as_str(),
+        "https://api.openrouter.ai/v1"
+    );
+}
diff --git a/crates/kv-core/tests/proto.rs b/crates/kv-core/tests/proto.rs
index d30bd1e..ec5d08d 100644
--- a/crates/kv-core/tests/proto.rs
+++ b/crates/kv-core/tests/proto.rs
@@ -31,6 +31,7 @@ fn secrets() -> Vec<Secret> {
                     name: "Authorization".into(),
                     template: "Bearer {}".into(),
                 },
+                base_url: None,
             },
         ),
         make(
diff --git a/crates/kv-core/tests/secret.rs b/crates/kv-core/tests/secret.rs
index 5544044..fab9d52 100644
--- a/crates/kv-core/tests/secret.rs
+++ b/crates/kv-core/tests/secret.rs
@@ -16,6 +16,7 @@ fn http_secret() -> Secret {
                 name: "Authorization".into(),
                 template: "Bearer {}".into(),
             },
+            base_url: None,
         },
         policy: Policy {
             allowed_hosts: vec!["openrouter.ai".into()],
@@ -160,3 +161,28 @@ fn handle_names_are_validated() {
         );
     }
 }
+
+#[test]
+fn a_base_url_is_scrubbed_and_never_shown_to_agents() {
+    let mut secret = http_secret();
+    secret.value = SecretValue::Http {
+        token: SecretText::new("sk-or-v1-0123456789abcdef"),
+        placement: AuthPlacement::Header {
+            name: "Authorization".into(),
+            template: "Bearer {}".into(),
+        },
+        base_url: Some("https://dokploy.internal.example/api/".into()),
+    };
+    let values: Vec<String> = secret
+        .sensitive_values()
+        .iter()
+        .map(|v| v.to_string())
+        .collect();
+    assert!(values.contains(&"https://dokploy.internal.example/api".to_owned()));
+    assert!(values.contains(&"dokploy.internal.example".to_owned()));
+    let info = secret.info();
+    assert!(info.takes_path);
+    let json = serde_json::to_string(&info).unwrap();
+    assert!(!json.contains("dokploy"), "{json}");
+    assert!(!http_secret().info().takes_path);
+}
diff --git a/crates/kv/tests/cli.rs b/crates/kv/tests/cli.rs
index 9c6d84f..3450a79 100644
--- a/crates/kv/tests/cli.rs
+++ b/crates/kv/tests/cli.rs
@@ -510,3 +510,31 @@ fn output_pipes_close_when_a_command_that_started_the_daemon_exits() {
     assert!(text.contains("no vault yet"), "{text}");
     child.wait().unwrap();
 }
+
+#[test]
+fn a_base_url_handle_lists_as_paths_only_without_its_address() {
+    let kv = Kv::initialized();
+    kv.ok(
+        &[
+            "add",
+            "dokploy",
+            "--kind",
+            "http",
+            "--base-url",
+            "--header",
+            "x-api-key",
+            "--template",
+            "{}",
+        ],
+        &format!("{PASS}\ndokploy-token-0123456789\n  https://dokploy.internal.example/api  \n"),
+    );
+    let list = kv.ok(&["list"], "");
+    assert!(list.contains("paths-only"), "{list}");
+    assert!(!list.contains("dokploy.internal"), "{list}");
+    let json = kv.ok(&["list", "--json"], "");
+    assert!(
+        json.contains(r#""takes_path": true"#) || json.contains(r#""takes_path":true"#),
+        "{json}"
+    );
+    assert!(!json.contains("dokploy.internal"), "{json}");
+}
diff --git a/crates/kv/tests/state.rs b/crates/kv/tests/state.rs
index d637c78..ea8ea19 100644
--- a/crates/kv/tests/state.rs
+++ b/crates/kv/tests/state.rs
@@ -102,6 +102,7 @@ fn http_secret(name: &str) -> Secret {
                 name: "Authorization".into(),
                 template: "Bearer {}".into(),
             },
+            base_url: None,
         },
         policy: Policy {
             allowed_hosts: vec!["openrouter.ai".into()],
@@ -258,6 +259,7 @@ fn add_rejects_unusable_values() {
             name: "Authorization".into(),
             template: "Bearer".into(),
         },
+        base_url: None,
     };
     let mut no_vars = http_secret("no-vars");
     no_vars.value = SecretValue::Env {
@@ -287,6 +289,7 @@ fn add_warns_about_short_values_and_empty_allow_lists() {
         placement: AuthPlacement::Query {
             param: "key".into(),
         },
+        base_url: None,
     };
     secret.policy = Policy::default();
     let response = f.control(
@@ -473,3 +476,64 @@ fn a_wall_clock_set_backwards_does_not_keep_the_vault_open() {
     f.daemon.tick(f.t0 + Duration::from_secs(11), wall);
     assert!(!f.daemon.is_unlocked());
 }
+
+fn base_url_secret(name: &str, base: &str) -> Secret {
+    let mut secret = http_secret(name);
+    secret.value = SecretValue::Http {
+        token: SecretText::new(TOKEN),
+        placement: AuthPlacement::Header {
+            name: "Authorization".into(),
+            template: "Bearer {}".into(),
+        },
+        base_url: Some(base.into()),
+    };
+    secret.policy = Policy::default();
+    secret
+}
+
+fn add_secret(f: &mut Fixture, secret: Secret) -> ControlResponse {
+    f.control(
+        Some(PASS),
+        ControlCommand::Add {
+            secret,
+            replace: false,
+        },
+    )
+}
+
+#[test]
+fn add_rejects_unusable_base_urls() {
+    let mut f = Fixture::initialized();
+    for base in [
+        "not a url",
+        "ftp://files.example.com",
+        "https://user:pw@dokploy.example.com",
+        "https://dokploy.example.com/api?x=1",
+        "https://dokploy.example.com/api#top",
+    ] {
+        let response = add_secret(&mut f, base_url_secret("dokploy", base));
+        assert_eq!(error_code(&response), ControlErrorCode::Invalid, "{base}");
+        if let ControlResponse::Error { message, .. } = &response {
+            assert!(!message.contains("dokploy.example.com"), "{message}");
+        }
+    }
+}
+
+#[test]
+fn a_base_url_handle_needs_no_allowed_hosts() {
+    let mut f = Fixture::initialized();
+    match add_secret(
+        &mut f,
+        base_url_secret("dokploy", "https://dokploy.example.com/api"),
+    ) {
+        ControlResponse::Done { warnings } => assert!(warnings.is_empty(), "{warnings:?}"),
+        other => panic!("{other:?}"),
+    }
+    match add_secret(&mut f, base_url_secret("lan", "http://10.0.0.5:3000/api")) {
+        ControlResponse::Done { warnings } => {
+            assert_eq!(warnings.len(), 1, "{warnings:?}");
+            assert!(warnings[0].contains("--allow-plain-http true"));
+        }
+        other => panic!("{other:?}"),
+    }
+}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv-core --test policy --test secret`
Expected: compile errors including `unresolved import kv_core::policy::http_target`, `variant SecretValue::Http has no field named base_url`, `no variant ... named OutsideBaseUrl` and `no field takes_path on type HandleInfo`.

- [ ] **Step 4: Implement**

Save as `task1-src.patch`, run `git apply task1-src.patch`, then delete the patch file:
```diff
diff --git a/crates/kv-core/src/policy.rs b/crates/kv-core/src/policy.rs
index 60c0bd5..92dd998 100644
--- a/crates/kv-core/src/policy.rs
+++ b/crates/kv-core/src/policy.rs
@@ -4,7 +4,7 @@ use std::time::Duration;
 
 use serde::{Deserialize, Serialize};
 
-use crate::secret::{Secret, SecretKind};
+use crate::secret::{Secret, SecretKind, SecretValue};
 
 #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
 #[serde(rename_all = "lowercase")]
@@ -102,6 +102,11 @@ pub enum DenyReason {
     PlainHttp,
     #[error("host {host:?} is not in allowed_hosts {allowed:?}")]
     HostNotAllowed { host: String, allowed: Vec<String> },
+    /// Deliberately vague: the base URL is hidden from the agent.
+    #[error("this handle only reaches its own service; send a path such as /v1/items")]
+    OutsideBaseUrl,
+    #[error("invalid path: {0}")]
+    InvalidPath(&'static str),
     #[error("method {method} is not in allowed_methods {allowed:?}")]
     MethodNotAllowed {
         method: String,
@@ -136,7 +141,9 @@ pub fn evaluate(secret: &Secret, op: &Operation<'_>) -> Decision {
         });
     }
     let check = match op {
-        Operation::Http { method, url } => check_http(policy, method, url),
+        Operation::Http { method, url } => {
+            base_url(secret).and_then(|base| check_http(policy, base.as_ref(), method, url))
+        }
         Operation::Exec { program } => check_exec(policy, program),
         Operation::DbQuery | Operation::DbConnect => Ok(()),
     };
@@ -147,7 +154,81 @@ pub fn evaluate(secret: &Secret, op: &Operation<'_>) -> Decision {
     }
 }
 
-fn check_http(policy: &Policy, method: &str, raw_url: &str) -> Result<(), DenyReason> {
+/// The URL an `http_request` goes to. A handle with a `base_url` takes a
+/// path, which is appended to the base URL's path and may not climb out of
+/// it; any other http handle takes an absolute URL.
+pub fn http_target(secret: &Secret, requested: &str) -> Result<url::Url, DenyReason> {
+    let Some(base) = base_url(secret)? else {
+        if requested.starts_with('/') {
+            return Err(DenyReason::InvalidUrl(
+                "this handle takes a full URL such as https://host/path".into(),
+            ));
+        }
+        return url::Url::parse(requested).map_err(|e| DenyReason::InvalidUrl(e.to_string()));
+    };
+    check_path(requested)?;
+    let prefix = base.path().trim_end_matches('/');
+    let joined = format!("{}{prefix}{requested}", base.origin().ascii_serialization());
+    let url = url::Url::parse(&joined).map_err(|_| DenyReason::InvalidPath("not a valid path"))?;
+    let path = url.path();
+    let inside = path == prefix || path.starts_with(&format!("{prefix}/"));
+    if url.origin() != base.origin() || !inside {
+        return Err(DenyReason::OutsideBaseUrl);
+    }
+    Ok(url)
+}
+
+/// Rejects paths that could leave the base URL's path once a server decodes
+/// them: dot segments (also percent-encoded), encoded slashes and
+/// backslashes.
+fn check_path(path: &str) -> Result<(), DenyReason> {
+    if !path.starts_with('/') {
+        return Err(DenyReason::InvalidPath(
+            "send a path starting with /, such as /v1/items; this handle's address is fixed",
+        ));
+    }
+    if path.starts_with("//") {
+        return Err(DenyReason::InvalidPath("a path cannot start with //"));
+    }
+    if path.contains(['\\', '#']) {
+        return Err(DenyReason::InvalidPath(
+            "backslashes and fragments are not allowed",
+        ));
+    }
+    let path_only = path.split('?').next().unwrap_or_default();
+    let lower = path_only.to_ascii_lowercase();
+    if lower.contains("%2f") || lower.contains("%5c") {
+        return Err(DenyReason::InvalidPath("encoded slashes are not allowed"));
+    }
+    let dot_segment = path_only.split('/').any(|segment| {
+        let decoded = percent_encoding::percent_decode_str(segment).decode_utf8_lossy();
+        decoded == "." || decoded == ".."
+    });
+    if dot_segment {
+        return Err(DenyReason::InvalidPath(". and .. segments are not allowed"));
+    }
+    Ok(())
+}
+
+/// The parsed `base_url` of an http secret, if it has one.
+fn base_url(secret: &Secret) -> Result<Option<url::Url>, DenyReason> {
+    match &secret.value {
+        SecretValue::Http {
+            base_url: Some(base),
+            ..
+        } => url::Url::parse(base)
+            .map(Some)
+            .map_err(|_| DenyReason::InvalidUrl("this handle's base URL is invalid".into())),
+        _ => Ok(None),
+    }
+}
+
+fn check_http(
+    policy: &Policy,
+    base: Option<&url::Url>,
+    method: &str,
+    raw_url: &str,
+) -> Result<(), DenyReason> {
     let url = url::Url::parse(raw_url).map_err(|e| DenyReason::InvalidUrl(e.to_string()))?;
     match url.scheme() {
         "https" => {}
@@ -171,15 +252,20 @@ fn check_http(policy: &Policy, method: &str, raw_url: &str) -> Result<(), DenyRe
         .port_or_known_default()
         .ok_or_else(|| DenyReason::InvalidUrl("URL has no port".into()))?;
     let target = (normalize_host(host), port);
-    if !policy
-        .allowed_hosts
-        .iter()
-        .any(|entry| host_entry(url.scheme(), entry).as_ref() == Some(&target))
-    {
-        return Err(DenyReason::HostNotAllowed {
-            host: format!("{}:{}", target.0, target.1),
-            allowed: policy.allowed_hosts.clone(),
-        });
+    match base {
+        Some(base) if url.origin() != base.origin() => return Err(DenyReason::OutsideBaseUrl),
+        Some(_) => {}
+        None if !policy
+            .allowed_hosts
+            .iter()
+            .any(|entry| host_entry(url.scheme(), entry).as_ref() == Some(&target)) =>
+        {
+            return Err(DenyReason::HostNotAllowed {
+                host: format!("{}:{}", target.0, target.1),
+                allowed: policy.allowed_hosts.clone(),
+            });
+        }
+        None => {}
     }
     if !policy.allowed_methods.is_empty()
         && !policy
diff --git a/crates/kv-core/src/secret.rs b/crates/kv-core/src/secret.rs
index 6e6ed13..056654b 100644
--- a/crates/kv-core/src/secret.rs
+++ b/crates/kv-core/src/secret.rs
@@ -62,6 +62,10 @@ pub enum SecretValue {
     Http {
         token: SecretText,
         placement: AuthPlacement,
+        /// Keeps the service's address hidden too: agents send a path, which
+        /// is appended to this URL, e.g. `https://dokploy.example.com/api`.
+        #[serde(default, skip_serializing_if = "Option::is_none")]
+        base_url: Option<String>,
     },
     Postgres {
         url: SecretText,
@@ -113,6 +117,9 @@ pub struct HandleInfo {
     pub grant_ttl: Duration,
     /// Names of the variables an `env` secret injects.
     pub env_vars: Vec<String>,
+    /// `http_request` with this handle takes a path such as `/v1/items`
+    /// instead of a URL; the service's address stays hidden.
+    pub takes_path: bool,
 }
 
 impl Secret {
@@ -137,15 +144,36 @@ impl Secret {
             allowed_cmds: self.policy.allowed_cmds.clone(),
             grant_ttl: self.policy.grant_ttl,
             env_vars,
+            takes_path: matches!(
+                self.value,
+                SecretValue::Http {
+                    base_url: Some(_),
+                    ..
+                }
+            ),
         }
     }
 
-    /// Every string that must never appear in output: the token or URL, and
-    /// for connection URLs the password both as written and percent-decoded.
+    /// Every string that must never appear in output: the token or URL, for
+    /// connection URLs the password both as written and percent-decoded, and
+    /// for an http `base_url` the URL and its host.
     pub fn sensitive_values(&self) -> Vec<Zeroizing<String>> {
         let mut out = Vec::new();
         match &self.value {
-            SecretValue::Http { token, .. } => out.push(Zeroizing::new(token.expose().to_owned())),
+            SecretValue::Http {
+                token, base_url, ..
+            } => {
+                out.push(Zeroizing::new(token.expose().to_owned()));
+                if let Some(base) = base_url {
+                    out.push(Zeroizing::new(base.trim_end_matches('/').to_owned()));
+                    if let Some(host) = url::Url::parse(base)
+                        .ok()
+                        .and_then(|u| u.host_str().map(str::to_owned))
+                    {
+                        out.push(Zeroizing::new(host));
+                    }
+                }
+            }
             SecretValue::Postgres { url } | SecretValue::Redis { url } => {
                 out.push(Zeroizing::new(url.expose().to_owned()));
                 if let Ok(parsed) = url::Url::parse(url.expose())
diff --git a/crates/kv/src/cli.rs b/crates/kv/src/cli.rs
index f748433..9671571 100644
--- a/crates/kv/src/cli.rs
+++ b/crates/kv/src/cli.rs
@@ -94,6 +94,10 @@ struct AddArgs {
     /// http: send the token as this query parameter instead of a header
     #[arg(long, conflicts_with_all = ["header", "template"])]
     query_param: Option<String>,
+    /// http: keep the service's address hidden too. Prompts for a base URL
+    /// such as https://dokploy.example.com/api; agents then send only paths
+    #[arg(long)]
+    base_url: bool,
     /// env: variable to inject (repeat for several); each value is prompted for
     #[arg(long = "var", value_name = "NAME")]
     vars: Vec<String>,
@@ -404,9 +408,17 @@ fn read_value(args: &AddArgs, input: &mut Input) -> Result<SecretValue> {
                     template: args.template.clone(),
                 },
             };
+            let token = trimmed(input.secret(&format!("Token for {name}: "))?);
+            let base_url = if args.base_url {
+                let base = trimmed(input.secret(&format!("Base URL for {name}: "))?);
+                Some(base.expose().to_owned())
+            } else {
+                None
+            };
             SecretValue::Http {
-                token: trimmed(input.secret(&format!("Token for {name}: "))?),
+                token,
                 placement,
+                base_url,
             }
         }
         Kind::Postgres => SecretValue::Postgres {
@@ -546,6 +558,9 @@ fn constraints(handle: &HandleInfo) -> String {
     if !handle.allowed_hosts.is_empty() {
         parts.push(format!("hosts={}", handle.allowed_hosts.join(",")));
     }
+    if handle.takes_path {
+        parts.push("paths-only".into());
+    }
     if handle.allow_plain_http {
         parts.push("plain-http".into());
     }
diff --git a/crates/kv/src/daemon/state.rs b/crates/kv/src/daemon/state.rs
index 1bd9381..b057038 100644
--- a/crates/kv/src/daemon/state.rs
+++ b/crates/kv/src/daemon/state.rs
@@ -396,10 +396,31 @@ fn unknown(name: &str) -> Failure {
 fn validate_value(value: &SecretValue) -> Result<(), Failure> {
     let invalid = |message: &str| Err(fail(ControlErrorCode::Invalid, message));
     match value {
-        SecretValue::Http { token, placement } => {
+        SecretValue::Http {
+            token,
+            placement,
+            base_url,
+        } => {
             if token.expose().is_empty() {
                 return invalid("the token is empty");
             }
+            if let Some(base) = base_url {
+                let Ok(parsed) = url::Url::parse(base) else {
+                    return invalid("the base URL is not a valid URL");
+                };
+                if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
+                    return invalid("the base URL must start with https:// or http://");
+                }
+                if !parsed.username().is_empty()
+                    || parsed.password().is_some()
+                    || parsed.query().is_some()
+                    || parsed.fragment().is_some()
+                {
+                    return invalid(
+                        "the base URL cannot contain credentials, a query or a fragment",
+                    );
+                }
+            }
             match placement {
                 AuthPlacement::Header { name, template } => {
                     if name.is_empty() {
@@ -456,7 +477,15 @@ fn warnings_for(secret: &Secret) -> Vec<String> {
         ));
     }
     match &secret.value {
-        SecretValue::Http { .. } if secret.policy.allowed_hosts.is_empty() => {
+        SecretValue::Http {
+            base_url: Some(base),
+            ..
+        } if base.starts_with("http:") && !secret.policy.allow_plain_http => {
+            warnings.push(format!(
+                "{name} has a plain http:// base URL, so every request with it is denied until you run `kv policy {name} --allow-plain-http true`"
+            ));
+        }
+        SecretValue::Http { base_url: None, .. } if secret.policy.allowed_hosts.is_empty() => {
             warnings.push(format!(
                 "{name} has no allowed hosts, so every request with it is denied; add one with `kv policy {name} --host <host>`"
             ));
```

Notes on the change:
- `http_target` is the single place a request URL is decided, so the policy check and the request that is sent can never disagree (a Plan 2 carry-over).
- A `base_url` path may not contain dot segments (also percent-encoded), `%2f`, `%5c`, backslashes or `#`, and may not start with `//`. Only the origin is compared after joining; the prefix is guaranteed by construction.
- `DenyReason::OutsideBaseUrl` deliberately does not name the host. The base URL and its host are added to the handle's sensitive values, so the scrubber hides them everywhere.
- `kv add` prompts for the base URL because the address itself may be the thing to hide, and warns when it is plain `http`.

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv-core`
Expected: 79 tests pass (lib 6, policy 21, proto 7, scrub 14, secret 9, vault 22).

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv`
Expected: 63 tests pass (lib 16, cli 23, ipc 3, state 21).

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo fmt --all --check && DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/kv-core/src/policy.rs crates/kv-core/src/secret.rs crates/kv-core/tests/policy.rs crates/kv-core/tests/proto.rs crates/kv-core/tests/secret.rs crates/kv/Cargo.toml crates/kv/src/cli.rs crates/kv/src/daemon/state.rs crates/kv/tests/cli.rs crates/kv/tests/state.rs
git commit -m "Add base_url to http secrets so agents send only paths"
```

---

### Task 2: Agent-socket messages and authorization

**Files:**
- Create: `crates/kv/src/broker.rs`
- Modify: `crates/kv-core/src/proto.rs`, `crates/kv/src/audit.rs`, `crates/kv/src/daemon.rs`, `crates/kv/src/daemon/server.rs`, `crates/kv/src/daemon/state.rs`, `crates/kv/src/lib.rs`
- Test: `crates/kv-core/tests/proto.rs`, `crates/kv/tests/authorize.rs`, `crates/kv/tests/common/mod.rs`, `crates/kv/tests/state.rs`

**Interfaces:**
- Consumes: Task 1's `http_target`, `HandleInfo.takes_path`; Plan 1's `Scrubber`, `policy::evaluate`; Plan 2's `Daemon`, `Audit`, `AgentRequest`/`AgentResponse`.
- Produces:
  - `kv_core::proto`: `AgentRequest::HttpRequest(HttpCall { handle, method, url, headers: BTreeMap<String, String>, body: Option<String> })`, `AgentRequest::Exec(ExecCall { handles: Vec<String>, argv: Vec<String>, cwd: PathBuf, timeout_secs: Option<u64> })`, `AgentResponse::Http(HttpReply { status: u16, headers: Vec<(String, String)>, body: String, truncated: bool })`, `AgentResponse::Exec(ExecReply { exit_code: Option<i32>, timed_out: bool, stdout: String, stderr: String, truncated: bool })`, `AgentErrorCode::{UnknownHandle, PolicyDenied, ApprovalTimeout, UpstreamError}` and `AgentErrorCode::as_str(self) -> &'static str`, `MAX_FRAME_LEN = 4 MiB`, `MAX_OUTPUT_LEN = 256 KiB`.
  - `kv::audit`: `Audit` is `Clone` (clones share one write lock); `Use<'a> { action, handle, decision, summary, outcome, duration }`; `Audit::record_use(&self, entry: &Use<'_>)`.
  - `kv::broker::{HttpJob { secret, url, call, scrubber: Arc<Scrubber>, audit, started }, ExecJob { handles, argv, cwd, timeout, env: Vec<(String, SecretText)>, scrubber, audit, started }}` with redacted `Debug`.
  - `kv::daemon::{Prepared::{Reply(AgentResponse), Http(Box<HttpJob>), Exec(Box<ExecJob>)}, Daemon::prepare(&mut self, request: AgentRequest, now: Instant) -> Prepared}`.
  - `tests/common/mod.rs`: `Fixture` (`new`, `control`, `add`, `prepare`, `http`, `exec`, `audit_lines`) and secret builders shared by the later test files.

- [ ] **Step 1: Write the failing tests**

Save as `task2-tests.patch`, run `git apply task2-tests.patch`, then delete the patch file:
```diff
diff --git a/crates/kv-core/tests/proto.rs b/crates/kv-core/tests/proto.rs
index ec5d08d..6024eaa 100644
--- a/crates/kv-core/tests/proto.rs
+++ b/crates/kv-core/tests/proto.rs
@@ -3,8 +3,8 @@ use std::time::Duration;
 
 use kv_core::policy::{Mode, Policy};
 use kv_core::proto::{
-    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlRequest, PolicyPatch,
-    Status,
+    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlRequest, ExecCall,
+    ExecReply, HttpReply, MAX_FRAME_LEN, MAX_OUTPUT_LEN, PolicyPatch, Status,
 };
 use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
 
@@ -150,3 +150,88 @@ fn policy_patch_json_accepts_missing_fields_and_humantime() {
     assert_eq!(patch.grant_ttl, Some(Duration::from_secs(7200)));
     assert_eq!(patch.mode, None);
 }
+
+#[test]
+fn http_and_exec_requests_are_flat_tagged_objects() {
+    let http: AgentRequest = serde_json::from_str(
+        r#"{"type":"http_request","handle":"openrouter","method":"GET","url":"https://openrouter.ai/api/v1/models"}"#,
+    )
+    .unwrap();
+    match http {
+        AgentRequest::HttpRequest(call) => {
+            assert_eq!(call.handle, "openrouter");
+            assert!(call.headers.is_empty());
+            assert_eq!(call.body, None);
+        }
+        other => panic!("{other:?}"),
+    }
+    let exec: AgentRequest = serde_json::from_str(
+        r#"{"type":"exec","handles":["aws"],"argv":["terraform","plan"],"cwd":"/work"}"#,
+    )
+    .unwrap();
+    assert_eq!(
+        exec,
+        AgentRequest::Exec(ExecCall {
+            handles: vec!["aws".into()],
+            argv: vec!["terraform".into(), "plan".into()],
+            cwd: "/work".into(),
+            timeout_secs: None,
+        })
+    );
+}
+
+#[test]
+fn replies_round_trip() {
+    for response in [
+        AgentResponse::Http(HttpReply {
+            status: 200,
+            headers: vec![("content-type".into(), "application/json".into())],
+            body: "{}".into(),
+            truncated: false,
+        }),
+        AgentResponse::Exec(ExecReply {
+            exit_code: None,
+            timed_out: true,
+            stdout: "partial".into(),
+            stderr: String::new(),
+            truncated: false,
+        }),
+    ] {
+        let json = serde_json::to_string(&response).unwrap();
+        assert_eq!(
+            serde_json::from_str::<AgentResponse>(&json).unwrap(),
+            response
+        );
+    }
+}
+
+#[test]
+fn error_code_names_match_the_wire_format() {
+    for code in [
+        AgentErrorCode::NoVault,
+        AgentErrorCode::VaultLocked,
+        AgentErrorCode::BadRequest,
+        AgentErrorCode::UnknownHandle,
+        AgentErrorCode::PolicyDenied,
+        AgentErrorCode::ApprovalTimeout,
+        AgentErrorCode::UpstreamError,
+    ] {
+        assert_eq!(
+            serde_json::to_string(&code).unwrap(),
+            format!("\"{}\"", code.as_str())
+        );
+    }
+}
+
+#[test]
+fn worst_case_escaped_output_fits_in_a_frame() {
+    let control_bytes = "\u{1}".repeat(MAX_OUTPUT_LEN);
+    let reply = AgentResponse::Exec(ExecReply {
+        exit_code: Some(0),
+        timed_out: false,
+        stdout: control_bytes.clone(),
+        stderr: control_bytes,
+        truncated: true,
+    });
+    assert!(serde_json::to_vec(&reply).unwrap().len() < MAX_FRAME_LEN);
+}
diff --git a/crates/kv/tests/state.rs b/crates/kv/tests/state.rs
index ea8ea19..4b14611 100644
--- a/crates/kv/tests/state.rs
+++ b/crates/kv/tests/state.rs
@@ -5,7 +5,7 @@ use std::path::PathBuf;
 use std::time::{Duration, Instant, SystemTime};
 
 use kv::audit::Audit;
-use kv::daemon::{After, Daemon, Settings};
+use kv::daemon::{After, Daemon, Prepared, Settings};
 use kv_core::policy::{Mode, Policy};
 use kv_core::proto::{
     AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlRequest,
@@ -76,7 +76,14 @@ impl Fixture {
     }
 
     fn agent(&mut self, request: AgentRequest) -> AgentResponse {
-        self.daemon.handle_agent(request, self.t0)
+        self.agent_at(self.t0, request)
+    }
+
+    fn agent_at(&mut self, now: Instant, request: AgentRequest) -> AgentResponse {
+        match self.daemon.prepare(request, now) {
+            Prepared::Reply(response) => response,
+            Prepared::Http(_) | Prepared::Exec(_) => panic!("expected a reply, got a job"),
+        }
     }
 
     fn handles(&mut self) -> Vec<String> {
@@ -389,7 +396,7 @@ fn idle_vault_locks_and_status_polls_do_not_keep_it_open() {
     });
     f.init();
     let status_at = f.t0 + Duration::from_secs(9);
-    match f.daemon.handle_agent(AgentRequest::Status, status_at) {
+    match f.agent_at(status_at, AgentRequest::Status) {
         AgentResponse::Status { status } => {
             assert!(!status.locked);
             assert_eq!(status.locks_in_secs, Some(1));
@@ -415,8 +422,7 @@ fn locked_daemon_exits_after_a_quiet_period() {
             .tick(f.t0 + Duration::from_secs(59), SystemTime::now()),
         After::Continue
     );
-    f.daemon
-        .handle_agent(AgentRequest::Status, f.t0 + Duration::from_secs(59));
+    f.agent_at(f.t0 + Duration::from_secs(59), AgentRequest::Status);
     assert_eq!(
         f.daemon
             .tick(f.t0 + Duration::from_secs(100), SystemTime::now()),
```

Create `crates/kv/tests/authorize.rs`:
```rust
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
            run(&["aws"], &["terraform"], cwd.join("missing")),
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
```

Create `crates/kv/tests/common/mod.rs`:
```rust
//! Shared test fixture: a daemon with an unlocked vault, driven directly
//! through `Daemon::prepare` and `Daemon::handle_control`.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use kv::audit::Audit;
use kv::broker::{ExecJob, HttpJob};
use kv::daemon::{Daemon, Prepared, Settings};
use kv_core::policy::{Mode, Policy};
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlRequest, ControlResponse,
    ExecCall, HttpCall,
};
use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
use tempfile::TempDir;

pub const PASS: &str = "correct horse battery";
pub const TOKEN: &str = "sk-or-v1-0123456789abcdef";
pub const AWS_KEY: &str = "AKIAEXAMPLEKEY0123456";

pub struct Fixture {
    pub dir: TempDir,
    pub daemon: Daemon,
    pub t0: Instant,
}

impl Fixture {
    pub fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let t0 = Instant::now();
        let daemon = Daemon::new(
            dir.path().join("vault.kv"),
            Audit::new(dir.path().join("audit.jsonl")),
            Settings::default(),
            t0,
        );
        let mut f = Self { dir, daemon, t0 };
        f.control(ControlCommand::Init {
            insecure_fast_kdf: true,
        });
        f
    }

    pub fn control(&mut self, command: ControlCommand) {
        let (response, _) = self.daemon.handle_control(
            ControlRequest {
                passphrase: Some(SecretText::new(PASS)),
                command,
            },
            self.t0,
        );
        assert!(
            matches!(response, ControlResponse::Done { .. }),
            "{response:?}"
        );
    }

    pub fn add(&mut self, secret: Secret) {
        self.control(ControlCommand::Add {
            secret,
            replace: false,
        });
    }

    pub fn prepare(&mut self, request: AgentRequest) -> Prepared {
        self.daemon.prepare(request, self.t0)
    }

    pub fn http(&mut self, call: HttpCall) -> Result<HttpJob, (AgentErrorCode, String)> {
        match self.prepare(AgentRequest::HttpRequest(call)) {
            Prepared::Http(job) => Ok(*job),
            Prepared::Reply(AgentResponse::Error { code, message }) => Err((code, message)),
            Prepared::Reply(other) => panic!("unexpected reply {other:?}"),
            Prepared::Exec(_) => panic!("unexpected exec job"),
        }
    }

    pub fn exec(&mut self, call: ExecCall) -> Result<ExecJob, (AgentErrorCode, String)> {
        match self.prepare(AgentRequest::Exec(call)) {
            Prepared::Exec(job) => Ok(*job),
            Prepared::Reply(AgentResponse::Error { code, message }) => Err((code, message)),
            Prepared::Reply(other) => panic!("unexpected reply {other:?}"),
            Prepared::Http(_) => panic!("unexpected http job"),
        }
    }

    pub fn audit_lines(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

pub fn secret(name: &str, value: SecretValue, policy: Policy) -> Secret {
    Secret {
        name: name.into(),
        description: String::new(),
        value,
        policy,
        created_at: 0,
        updated_at: 0,
    }
}

pub fn openrouter(mode: Mode) -> Secret {
    secret(
        "openrouter",
        SecretValue::Http {
            token: SecretText::new(TOKEN),
            placement: AuthPlacement::Header {
                name: "Authorization".into(),
                template: "Bearer {}".into(),
            },
            base_url: None,
        },
        Policy {
            mode,
            allowed_hosts: vec!["openrouter.ai".into()],
            ..Policy::default()
        },
    )
}

pub fn dokploy() -> Secret {
    secret(
        "dokploy",
        SecretValue::Http {
            token: SecretText::new("dokploy-token-0123456789"),
            placement: AuthPlacement::Header {
                name: "x-api-key".into(),
                template: "{}".into(),
            },
            base_url: Some("https://dokploy.internal.example/api".into()),
        },
        Policy {
            mode: Mode::Auto,
            ..Policy::default()
        },
    )
}

pub fn env_secret(name: &str, vars: &[(&str, &str)], cmds: &[&str], mode: Mode) -> Secret {
    secret(
        name,
        SecretValue::Env {
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), SecretText::new(*v)))
                .collect(),
        },
        Policy {
            mode,
            allowed_cmds: cmds.iter().map(|c| c.to_string()).collect(),
            ..Policy::default()
        },
    )
}

pub fn get(handle: &str, url: &str) -> HttpCall {
    HttpCall {
        handle: handle.into(),
        method: "GET".into(),
        url: url.into(),
        headers: BTreeMap::new(),
        body: None,
    }
}

pub fn run(handles: &[&str], argv: &[&str], cwd: PathBuf) -> ExecCall {
    ExecCall {
        handles: handles.iter().map(|h| h.to_string()).collect(),
        argv: argv.iter().map(|a| a.to_string()).collect(),
        cwd,
        timeout_secs: None,
    }
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test authorize`
Expected: compile errors including `unresolved import kv::broker`, `unresolved import kv::daemon::Prepared`, `unresolved imports kv_core::proto::ExecCall, kv_core::proto::HttpCall` and `no method named prepare found for struct Daemon`.

- [ ] **Step 3: Implement**

Save as `task2-src.patch`, run `git apply task2-src.patch`, then delete the patch file:
```diff
diff --git a/crates/kv-core/src/proto.rs b/crates/kv-core/src/proto.rs
index 40cd8ca..91d19f5 100644
--- a/crates/kv-core/src/proto.rs
+++ b/crates/kv-core/src/proto.rs
@@ -1,10 +1,12 @@
 //! Messages exchanged with the daemon over its two local sockets.
 //!
-//! Agent-socket responses are built only from `HandleInfo` and status data,
-//! so no agent message can carry a secret value. Control requests carry the
-//! vault passphrase, because every control command except `lock` and `stop`
-//! must prove the user is present.
+//! Agent-socket responses are built from `HandleInfo`, status data and
+//! scrubbed output, and no agent message type has a field that holds a
+//! secret value. Control requests carry the vault passphrase, because every
+//! control command except `lock` and `stop` must prove the user is present.
 
+use std::collections::BTreeMap;
+use std::path::PathBuf;
 use std::time::Duration;
 
 use serde::{Deserialize, Serialize};
@@ -12,14 +14,48 @@ use serde::{Deserialize, Serialize};
 use crate::policy::{Mode, Policy};
 use crate::secret::{HandleInfo, Secret, SecretText};
 
-/// Largest frame either side accepts, in bytes.
-pub const MAX_FRAME_LEN: usize = 1024 * 1024;
+/// Largest frame either side accepts, in bytes. Room for the output caps
+/// below even when every byte is JSON-escaped as `\u00XX`.
+pub const MAX_FRAME_LEN: usize = 4 * 1024 * 1024;
+
+/// Largest HTTP response body, and largest stdout or stderr from `exec`,
+/// returned to an agent, in bytes. Longer output is cut and marked
+/// `truncated`.
+pub const MAX_OUTPUT_LEN: usize = 256 * 1024;
 
 #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
 #[serde(tag = "type", rename_all = "snake_case")]
 pub enum AgentRequest {
     ListHandles,
     Status,
+    HttpRequest(HttpCall),
+    Exec(ExecCall),
+}
+
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
+pub struct HttpCall {
+    pub handle: String,
+    pub method: String,
+    /// A full URL, or a path such as `/v1/items` for handles whose
+    /// `takes_path` is true.
+    pub url: String,
+    #[serde(default)]
+    pub headers: BTreeMap<String, String>,
+    #[serde(default)]
+    pub body: Option<String>,
+}
+
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
+pub struct ExecCall {
+    /// `env` handles whose variables are injected.
+    pub handles: Vec<String>,
+    /// Program and arguments. Never run through a shell.
+    pub argv: Vec<String>,
+    /// Absolute working directory.
+    pub cwd: PathBuf,
+    /// Defaults to 60 seconds; at most 600.
+    #[serde(default)]
+    pub timeout_secs: Option<u64>,
 }
 
 #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
@@ -31,12 +67,35 @@ pub enum AgentResponse {
     Status {
         status: Status,
     },
+    Http(HttpReply),
+    Exec(ExecReply),
     Error {
         code: AgentErrorCode,
         message: String,
     },
 }
 
+/// A scrubbed HTTP response.
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
+pub struct HttpReply {
+    pub status: u16,
+    pub headers: Vec<(String, String)>,
+    /// Decoded as UTF-8, with invalid bytes replaced.
+    pub body: String,
+    pub truncated: bool,
+}
+
+/// Scrubbed output of a finished or killed program.
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
+pub struct ExecReply {
+    /// `None` if the program was killed or ended by a signal.
+    pub exit_code: Option<i32>,
+    pub timed_out: bool,
+    pub stdout: String,
+    pub stderr: String,
+    pub truncated: bool,
+}
+
 #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
 pub struct Status {
     pub vault_exists: bool,
@@ -53,6 +112,27 @@ pub enum AgentErrorCode {
     NoVault,
     VaultLocked,
     BadRequest,
+    UnknownHandle,
+    PolicyDenied,
+    /// The handle needs approval. Until `kv tui` exists, these requests
+    /// fail at once.
+    ApprovalTimeout,
+    UpstreamError,
+}
+
+impl AgentErrorCode {
+    /// The code as it appears on the wire, e.g. `vault_locked`.
+    pub fn as_str(self) -> &'static str {
+        match self {
+            Self::NoVault => "no_vault",
+            Self::VaultLocked => "vault_locked",
+            Self::BadRequest => "bad_request",
+            Self::UnknownHandle => "unknown_handle",
+            Self::PolicyDenied => "policy_denied",
+            Self::ApprovalTimeout => "approval_timeout",
+            Self::UpstreamError => "upstream_error",
+        }
+    }
 }
 
 #[derive(Debug, Serialize, Deserialize)]
diff --git a/crates/kv/src/audit.rs b/crates/kv/src/audit.rs
index d3a8ccd..eaba9ac 100644
--- a/crates/kv/src/audit.rs
+++ b/crates/kv/src/audit.rs
@@ -4,7 +4,8 @@
 use std::fs::{self, OpenOptions};
 use std::io::{self, Write};
 use std::path::{Path, PathBuf};
-use std::time::SystemTime;
+use std::sync::{Arc, Mutex, PoisonError};
+use std::time::{Duration, SystemTime};
 
 use serde::Serialize;
 
@@ -18,12 +19,37 @@ struct Record<'a> {
     action: &'a str,
     #[serde(skip_serializing_if = "Option::is_none")]
     handle: Option<&'a str>,
+    #[serde(skip_serializing_if = "Option::is_none")]
+    decision: Option<&'a str>,
+    #[serde(skip_serializing_if = "Option::is_none")]
+    summary: Option<&'a str>,
     outcome: &'a str,
+    #[serde(skip_serializing_if = "Option::is_none")]
+    duration_ms: Option<u128>,
 }
 
+/// One use of a handle by an agent.
+pub struct Use<'a> {
+    /// `http_request` or `exec`.
+    pub action: &'a str,
+    /// Handle name, or several joined with commas.
+    pub handle: &'a str,
+    /// `auto`, `policy`, `locked` or `approval`.
+    pub decision: &'a str,
+    /// What was asked for, already scrubbed: method and URL, or the program.
+    pub summary: &'a str,
+    /// HTTP status, exit code or error code.
+    pub outcome: &'a str,
+    pub duration: Duration,
+}
+
+/// Cheap to clone; clones share one lock so their appends and rotations do
+/// not interleave.
+#[derive(Clone)]
 pub struct Audit {
     path: PathBuf,
     max_bytes: u64,
+    lock: Arc<Mutex<()>>,
 }
 
 impl Audit {
@@ -34,20 +60,44 @@ impl Audit {
     /// Rotates once the log reaches `max_bytes`, keeping 5 old files
     /// (`audit.jsonl.1` is the newest).
     pub fn with_max_bytes(path: PathBuf, max_bytes: u64) -> Self {
-        Self { path, max_bytes }
+        Self {
+            path,
+            max_bytes,
+            lock: Arc::default(),
+        }
     }
 
     /// Appends one record. A failure is reported on stderr and otherwise
     /// ignored, so a full disk never blocks the daemon.
     pub fn record(&self, socket: &str, action: &str, handle: Option<&str>, outcome: &str) {
-        let record = Record {
-            ts: humantime::format_rfc3339_millis(SystemTime::now()).to_string(),
+        self.write(&Record {
+            ts: now(),
             socket,
             action,
             handle,
+            decision: None,
+            summary: None,
             outcome,
-        };
-        if let Err(e) = self.append(&record) {
+            duration_ms: None,
+        });
+    }
+
+    pub fn record_use(&self, entry: &Use<'_>) {
+        self.write(&Record {
+            ts: now(),
+            socket: "agent",
+            action: entry.action,
+            handle: Some(entry.handle),
+            decision: Some(entry.decision),
+            summary: Some(entry.summary),
+            outcome: entry.outcome,
+            duration_ms: Some(entry.duration.as_millis()),
+        });
+    }
+
+    fn write(&self, record: &Record<'_>) {
+        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
+        if let Err(e) = self.append(record) {
             eprintln!("kv: cannot write audit log {}: {e}", self.path.display());
         }
     }
@@ -81,6 +131,10 @@ impl Audit {
     }
 }
 
+fn now() -> String {
+    humantime::format_rfc3339_millis(SystemTime::now()).to_string()
+}
+
 fn rotated(path: &Path, index: usize) -> PathBuf {
     let mut name = path.as_os_str().to_owned();
     name.push(format!(".{index}"));
@@ -125,6 +179,57 @@ mod tests {
         assert!(path.exists());
     }
 
+    #[test]
+    fn uses_record_decision_summary_and_duration() {
+        let dir = tempfile::TempDir::new().unwrap();
+        let path = dir.path().join("audit.jsonl");
+        Audit::new(path.clone()).record_use(&Use {
+            action: "http_request",
+            handle: "openrouter",
+            decision: "auto",
+            summary: "GET https://openrouter.ai/api/v1/models",
+            outcome: "200",
+            duration: Duration::from_millis(42),
+        });
+        let line: serde_json::Value =
+            serde_json::from_str(fs::read_to_string(&path).unwrap().trim()).unwrap();
+        assert_eq!(line["socket"], "agent");
+        assert_eq!(line["decision"], "auto");
+        assert_eq!(line["summary"], "GET https://openrouter.ai/api/v1/models");
+        assert_eq!(line["outcome"], "200");
+        assert_eq!(line["duration_ms"], 42);
+    }
+
+    #[test]
+    fn clones_never_interleave_lines() {
+        let dir = tempfile::TempDir::new().unwrap();
+        let path = dir.path().join("audit.jsonl");
+        let audit = Audit::with_max_bytes(path.clone(), 4096);
+        std::thread::scope(|scope| {
+            for _ in 0..8 {
+                let audit = audit.clone();
+                scope.spawn(move || {
+                    for _ in 0..50 {
+                        audit.record(
+                            "agent",
+                            "list_handles",
+                            Some("a-fairly-long-handle-name"),
+                            "done",
+                        );
+                    }
+                });
+            }
+        });
+        for file in std::iter::once(path.clone()).chain((1..=5).map(|i| rotated(&path, i))) {
+            let Ok(text) = fs::read_to_string(&file) else {
+                continue;
+            };
+            for line in text.lines() {
+                serde_json::from_str::<serde_json::Value>(line).unwrap();
+            }
+        }
+    }
+
     #[cfg(unix)]
     #[test]
     fn log_is_private_to_the_user() {
diff --git a/crates/kv/src/daemon.rs b/crates/kv/src/daemon.rs
index 7ce9f40..541dd9c 100644
--- a/crates/kv/src/daemon.rs
+++ b/crates/kv/src/daemon.rs
@@ -6,4 +6,4 @@ mod server;
 mod state;
 
 pub use server::{Outcome, run};
-pub use state::{After, Daemon, Settings};
+pub use state::{After, Daemon, Prepared, Settings};
diff --git a/crates/kv/src/daemon/server.rs b/crates/kv/src/daemon/server.rs
index 3d5cc7c..cded1d9 100644
--- a/crates/kv/src/daemon/server.rs
+++ b/crates/kv/src/daemon/server.rs
@@ -12,7 +12,7 @@ use kv_core::proto::{
 use tokio::sync::watch;
 
 use super::harden;
-use super::state::{After, Daemon, Settings};
+use super::state::{After, Daemon, Prepared, Settings};
 use crate::audit::Audit;
 use crate::frame::{read_frame, write_frame};
 use crate::ipc::{self, ServerStream};
@@ -106,7 +106,13 @@ async fn serve_agent(mut stream: ServerStream, daemon: Shared) {
         };
         let daemon = daemon.clone();
         let handled = tokio::task::spawn_blocking(move || {
-            lock(&daemon).handle_agent(request, Instant::now())
+            match lock(&daemon).prepare(request, Instant::now()) {
+                Prepared::Reply(response) => response,
+                Prepared::Http(_) | Prepared::Exec(_) => AgentResponse::Error {
+                    code: AgentErrorCode::BadRequest,
+                    message: "not supported yet".into(),
+                },
+            }
         })
         .await;
         let Ok(response) = handled else { return };
diff --git a/crates/kv/src/daemon/state.rs b/crates/kv/src/daemon/state.rs
index b057038..e2676ee 100644
--- a/crates/kv/src/daemon/state.rs
+++ b/crates/kv/src/daemon/state.rs
@@ -1,22 +1,49 @@
 //! Daemon state and request handling, kept free of sockets and clocks so it
 //! can be tested directly.
 
+use std::collections::BTreeMap;
 use std::path::PathBuf;
+use std::sync::Arc;
 use std::time::{Duration, Instant, SystemTime};
 
 use kv_core::VaultError;
 use kv_core::crypto::KdfParams;
+use kv_core::policy::{Decision, DenyReason, Operation, evaluate, http_target};
 use kv_core::proto::{
     AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlRequest,
-    ControlResponse, PolicyPatch, Status,
+    ControlResponse, ExecCall, HttpCall, PolicyPatch, Status,
 };
-use kv_core::scrub::MIN_SECRET_LEN;
+use kv_core::scrub::{MIN_SECRET_LEN, Scrubber};
 use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
 use kv_core::vault::Vault;
+use zeroize::Zeroizing;
 
-use crate::audit::Audit;
+use crate::audit::{Audit, Use};
+use crate::broker::{ExecJob, HttpJob};
 use crate::throttle::Throttle;
 
+const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(60);
+const MAX_EXEC_TIMEOUT: Duration = Duration::from_secs(600);
+
+/// Headers kv sets itself, that would change how the request is framed, or
+/// that would let a response carry a secret past the scrubber: compressed,
+/// or cut into pieces too short to match.
+const RESERVED_HEADERS: [&str; 13] = [
+    "host",
+    "content-length",
+    "transfer-encoding",
+    "connection",
+    "upgrade",
+    "te",
+    "trailer",
+    "keep-alive",
+    "proxy-authorization",
+    "proxy-connection",
+    "accept-encoding",
+    "range",
+    "if-range",
+];
+
 /// Argon2 settings for `kv init --insecure-fast-kdf`. Tests only.
 const TEST_KDF: KdfParams = KdfParams {
     m_kib: 8,
@@ -60,6 +87,17 @@ pub struct Daemon {
     last_used_wall: SystemTime,
     /// Last request of any kind. Drives the exit while locked.
     last_request: Instant,
+    /// Built from the unlocked secrets on first use; cleared whenever they
+    /// may have changed.
+    scrubber: Option<Arc<Scrubber>>,
+}
+
+/// The outcome of an agent request: either an answer now, or authorized
+/// work for the broker to run without holding the daemon lock.
+pub enum Prepared {
+    Reply(AgentResponse),
+    Http(Box<HttpJob>),
+    Exec(Box<ExecJob>),
 }
 
 struct Failure {
@@ -89,6 +127,7 @@ impl Daemon {
             last_used: now,
             last_used_wall: SystemTime::now(),
             last_request: now,
+            scrubber: None,
         }
     }
 
@@ -96,12 +135,12 @@ impl Daemon {
         self.vault.is_some()
     }
 
-    pub fn handle_agent(&mut self, request: AgentRequest, now: Instant) -> AgentResponse {
+    pub fn prepare(&mut self, request: AgentRequest, now: Instant) -> Prepared {
         self.last_request = now;
         match request {
-            AgentRequest::Status => AgentResponse::Status {
+            AgentRequest::Status => Prepared::Reply(AgentResponse::Status {
                 status: self.status(now),
-            },
+            }),
             AgentRequest::ListHandles => {
                 let response = match &self.vault {
                     Some(vault) => {
@@ -115,9 +154,214 @@ impl Daemon {
                 };
                 self.audit
                     .record("agent", "list_handles", None, agent_outcome(&response));
-                response
+                Prepared::Reply(response)
+            }
+            AgentRequest::HttpRequest(call) => self.prepare_http(call, now),
+            AgentRequest::Exec(call) => self.prepare_exec(call, now),
+        }
+    }
+
+    fn prepare_http(&mut self, call: HttpCall, now: Instant) -> Prepared {
+        let summary = format!("{} {}", call.method, call.url);
+        let refuse = |daemon: &Self, decision, response| {
+            daemon.refuse("http_request", &call.handle, &summary, decision, response)
+        };
+        let Some(vault) = &self.vault else {
+            return refuse(self, "locked", self.locked_error());
+        };
+        let Some(secret) = vault.get(&call.handle).cloned() else {
+            return refuse(self, "invalid", unknown_handle(vault, &call.handle));
+        };
+        let url = match http_target(&secret, &call.url) {
+            Ok(url) => url,
+            Err(reason @ (DenyReason::InvalidUrl(_) | DenyReason::InvalidPath(_))) => {
+                return refuse(
+                    self,
+                    "invalid",
+                    agent_error(AgentErrorCode::BadRequest, reason),
+                );
+            }
+            Err(reason) => {
+                return refuse(
+                    self,
+                    "policy",
+                    agent_error(AgentErrorCode::PolicyDenied, reason),
+                );
+            }
+        };
+        if let Err(message) =
+            check_method(&call.method).and_then(|()| check_headers(&secret, &call.headers))
+        {
+            return refuse(
+                self,
+                "invalid",
+                agent_error(AgentErrorCode::BadRequest, message),
+            );
+        }
+        let operation = Operation::Http {
+            method: &call.method,
+            url: url.as_str(),
+        };
+        match evaluate(&secret, &operation) {
+            Decision::Allow => {}
+            Decision::Deny(reason) => {
+                return refuse(
+                    self,
+                    "policy",
+                    agent_error(AgentErrorCode::PolicyDenied, reason),
+                );
             }
+            Decision::Ask => return refuse(self, "denied", approval_needed(&call.handle)),
+        }
+        self.touch(now);
+        Prepared::Http(Box::new(HttpJob {
+            secret,
+            url,
+            call,
+            scrubber: self.scrubber(),
+            audit: self.audit.clone(),
+            started: now,
+        }))
+    }
+
+    fn prepare_exec(&mut self, call: ExecCall, now: Instant) -> Prepared {
+        let handles = call.handles.join(",");
+        let summary = call.argv.first().cloned().unwrap_or_default();
+        let refuse = |daemon: &Self, decision, response| {
+            daemon.refuse("exec", &handles, &summary, decision, response)
+        };
+        let bad = |message: &str| agent_error(AgentErrorCode::BadRequest, message);
+        let Some(vault) = &self.vault else {
+            return refuse(self, "locked", self.locked_error());
+        };
+        let Some(program) = call.argv.first().filter(|p| !p.is_empty()) else {
+            return refuse(
+                self,
+                "invalid",
+                bad("argv must start with the program to run"),
+            );
+        };
+        if call.handles.is_empty() {
+            return refuse(self, "invalid", bad("exec needs at least one env handle"));
+        }
+        if !call.cwd.is_absolute() || !call.cwd.is_dir() {
+            return refuse(
+                self,
+                "invalid",
+                bad("cwd must be an existing absolute directory"),
+            );
+        }
+        let timeout = call
+            .timeout_secs
+            .map_or(DEFAULT_EXEC_TIMEOUT, Duration::from_secs);
+        if timeout.is_zero() || timeout > MAX_EXEC_TIMEOUT {
+            return refuse(
+                self,
+                "invalid",
+                bad("timeout_secs must be between 1 and 600"),
+            );
+        }
+        let mut env = Vec::new();
+        let mut set_by: BTreeMap<String, &str> = BTreeMap::new();
+        let mut needs_approval = None;
+        for name in &call.handles {
+            let Some(secret) = vault.get(name) else {
+                return refuse(self, "invalid", unknown_handle(vault, name));
+            };
+            match evaluate(secret, &Operation::Exec { program }) {
+                Decision::Allow => {}
+                Decision::Ask => needs_approval = needs_approval.or(Some(name)),
+                Decision::Deny(reason) => {
+                    let message = format!("{name}: {reason}");
+                    return refuse(
+                        self,
+                        "policy",
+                        agent_error(AgentErrorCode::PolicyDenied, message),
+                    );
+                }
+            }
+            if let SecretValue::Env { vars } = &secret.value {
+                for (var, value) in vars {
+                    let key = if cfg!(windows) {
+                        var.to_ascii_uppercase()
+                    } else {
+                        var.clone()
+                    };
+                    if let Some(other) = set_by.insert(key, name) {
+                        let message = if other == name.as_str() {
+                            format!("{name} is listed twice")
+                        } else {
+                            format!("{other} and {name} both set {var}")
+                        };
+                        return refuse(self, "invalid", bad(&message));
+                    }
+                    env.push((var.clone(), value.clone()));
+                }
+            }
+        }
+        if let Some(name) = needs_approval {
+            return refuse(self, "denied", approval_needed(name));
+        }
+        self.touch(now);
+        Prepared::Exec(Box::new(ExecJob {
+            handles: call.handles,
+            argv: call.argv,
+            cwd: call.cwd,
+            timeout,
+            env,
+            scrubber: self.scrubber(),
+            audit: self.audit.clone(),
+            started: now,
+        }))
+    }
+
+    /// Records a request that never reached the broker and returns its reply.
+    fn refuse(
+        &self,
+        action: &str,
+        handle: &str,
+        summary: &str,
+        decision: &str,
+        response: AgentResponse,
+    ) -> Prepared {
+        let outcome = match &response {
+            AgentResponse::Error { code, .. } => code.as_str(),
+            _ => "error",
+        };
+        self.audit.record_use(&Use {
+            action,
+            handle,
+            decision,
+            summary,
+            outcome,
+            duration: Duration::ZERO,
+        });
+        Prepared::Reply(response)
+    }
+
+    /// The scrubber for every unlocked secret. Only call while unlocked.
+    fn scrubber(&mut self) -> Arc<Scrubber> {
+        if let Some(scrubber) = &self.scrubber {
+            return scrubber.clone();
         }
+        let values: Vec<(String, Zeroizing<String>)> = self
+            .vault
+            .iter()
+            .flat_map(|vault| vault.secrets())
+            .flat_map(|secret| {
+                secret
+                    .sensitive_values()
+                    .into_iter()
+                    .map(|value| (secret.name.clone(), value))
+            })
+            .collect();
+        let scrubber = Arc::new(Scrubber::new(
+            values
+                .iter()
+                .map(|(name, value)| (name.as_str(), value.as_str())),
+        ));
+        self.scrubber = Some(scrubber.clone());
+        scrubber
     }
 
     pub fn handle_control(
@@ -126,6 +370,7 @@ impl Daemon {
         now: Instant,
     ) -> (ControlResponse, After) {
         self.last_request = now;
+        self.scrubber = None;
         let ControlRequest {
             passphrase,
             command,
@@ -170,6 +415,7 @@ impl Daemon {
     pub fn tick(&mut self, now: Instant, wall: SystemTime) -> After {
         if self.vault.is_some() && self.idle_for(now, wall) >= self.settings.idle_lock {
             self.vault = None;
+            self.scrubber = None;
             self.audit.record("daemon", "idle_lock", None, "locked");
         }
         if self.vault.is_none()
@@ -513,6 +759,72 @@ fn describe(command: &ControlCommand) -> (&'static str, Option<String>) {
     }
 }
 
+fn agent_error(code: AgentErrorCode, message: impl ToString) -> AgentResponse {
+    AgentResponse::Error {
+        code,
+        message: message.to_string(),
+    }
+}
+
+fn unknown_handle(vault: &Vault, name: &str) -> AgentResponse {
+    let names: Vec<&str> = vault.secrets().iter().map(|s| s.name.as_str()).collect();
+    let available = if names.is_empty() {
+        "there are none yet".to_owned()
+    } else {
+        format!("available: {}", names.join(", "))
+    };
+    agent_error(
+        AgentErrorCode::UnknownHandle,
+        format!("there is no handle named {name}; {available}"),
+    )
+}
+
+fn approval_needed(name: &str) -> AgentResponse {
+    agent_error(
+        AgentErrorCode::ApprovalTimeout,
+        format!(
+            "{name} needs approval for each use, and kv cannot ask for approval yet (that arrives with `kv tui`). Ask the user whether to allow it with `kv policy {name} --mode auto`"
+        ),
+    )
+}
+
+fn check_method(method: &str) -> Result<(), String> {
+    if !method.is_empty() && method.len() <= 16 && method.bytes().all(|b| b.is_ascii_alphabetic()) {
+        Ok(())
+    } else {
+        Err("method must be a word such as GET or POST".into())
+    }
+}
+
+fn check_headers(secret: &Secret, headers: &BTreeMap<String, String>) -> Result<(), String> {
+    let auth_header = match &secret.value {
+        SecretValue::Http {
+            placement: AuthPlacement::Header { name, .. },
+            ..
+        } => Some(name.as_str()),
+        _ => None,
+    };
+    for (name, value) in headers {
+        let token_char = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
+        if name.is_empty() || !name.bytes().all(token_char) {
+            return Err(format!("{name:?} is not a valid header name"));
+        }
+        let lower = name.to_ascii_lowercase();
+        if RESERVED_HEADERS.contains(&lower.as_str()) {
+            return Err(format!("the {name} header is set by kv"));
+        }
+        if auth_header.is_some_and(|auth| auth.eq_ignore_ascii_case(name)) {
+            return Err(format!(
+                "the {name} header carries this handle's credential and is set by kv"
+            ));
+        }
+        if value.contains(['\r', '\n', '\0']) {
+            return Err(format!("the value of {name} contains a line break or NUL"));
+        }
+    }
+    Ok(())
+}
+
 fn agent_outcome(response: &AgentResponse) -> &'static str {
     match response {
         AgentResponse::Error { .. } => "error",
diff --git a/crates/kv/src/lib.rs b/crates/kv/src/lib.rs
index 495d77f..70e6575 100644
--- a/crates/kv/src/lib.rs
+++ b/crates/kv/src/lib.rs
@@ -1,6 +1,7 @@
 //! The kv daemon, its CLI, and the socket plumbing they share.
 
 pub mod audit;
+pub mod broker;
 pub mod cli;
 pub mod client;
 pub mod daemon;
```

Create `crates/kv/src/broker.rs`:
```rust
//! Work an agent asked for, authorized by the daemon and run outside the
//! daemon lock: HTTP requests and programs.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kv_core::proto::HttpCall;
use kv_core::scrub::Scrubber;
use kv_core::secret::{Secret, SecretText};

use crate::audit::Audit;

/// An `http_request` that passed every check.
pub struct HttpJob {
    pub secret: Secret,
    /// Where the first request goes, already checked against the policy.
    pub url: url::Url,
    pub call: HttpCall,
    pub scrubber: Arc<Scrubber>,
    pub audit: Audit,
    pub started: Instant,
}

/// An `exec` that passed every check.
pub struct ExecJob {
    pub handles: Vec<String>,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub timeout: Duration,
    /// Variables from every handle, already checked for clashes.
    pub env: Vec<(String, SecretText)>,
    pub scrubber: Arc<Scrubber>,
    pub audit: Audit,
    pub started: Instant,
}

/// Names only: the URL may hold a hidden base URL, and the job holds values.
impl std::fmt::Debug for HttpJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpJob")
            .field("handle", &self.secret.name)
            .field("method", &self.call.method)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ExecJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecJob")
            .field("handles", &self.handles)
            .field("program", &self.argv.first())
            .finish_non_exhaustive()
    }
}
```

Notes on the change:
- `prepare` only authorizes. It runs under the daemon mutex and returns a job; the server runs the job after releasing the lock (Tasks 3 and 4).
- The scrubber is built once and cached as an `Arc<Scrubber>`; any control command and any lock clears the cache, so a job always scrubs with the secrets that existed when it was authorized.
- `mode: ask` fails at once with `approval_timeout` and a message pointing at `kv policy <handle> --mode auto`: there is no one to ask until the TUI exists.
- Every refusal is audited with a decision: `locked`, `invalid` (malformed request, unknown handle), `policy` or `denied`.
- `Host`, framing headers, the handle's own auth header, and `Accept-Encoding`, `Range` and `If-Range` are refused: a compressed body or a byte range could carry a secret past the scrubber.
- Frames grow to 4 MiB so 256 KiB of stdout plus 256 KiB of stderr fit even if every byte is JSON-escaped (`worst_case_escaped_output_fits_in_a_frame`).

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv-core --test proto`
Expected: 11 tests pass (proto 11).

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv`
Expected: 77 tests pass (lib 18, authorize 12, cli 23, ipc 3, state 21).

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo fmt --all --check && DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output, exit 0.

- [ ] **Step 5: Commit**

```bash
git add crates/kv-core/src/proto.rs crates/kv-core/tests/proto.rs crates/kv/src/audit.rs crates/kv/src/broker.rs crates/kv/src/daemon.rs crates/kv/src/daemon/server.rs crates/kv/src/daemon/state.rs crates/kv/src/lib.rs crates/kv/tests/authorize.rs crates/kv/tests/common/mod.rs crates/kv/tests/state.rs
git commit -m "Authorize http_request and exec on the agent socket"
```

---

### Task 3: HTTP broker

**Files:**
- Create: `crates/kv/src/broker/http.rs`
- Modify: `crates/kv/Cargo.toml`, `crates/kv/src/broker.rs`, `crates/kv/src/daemon/server.rs`
- Test: `crates/kv/tests/http.rs`

**Interfaces:**
- Consumes: Task 2's `HttpJob`, `Prepared::Http`, `Use`, `MAX_OUTPUT_LEN`; Task 1's `http_target` (to re-check redirect targets).
- Produces: `kv::broker::http::{client() -> reqwest::Result<reqwest::Client>, send(client: &Client, job: HttpJob) -> AgentResponse}`; the server builds one client at start and runs `Prepared::Http` jobs through `send` outside the daemon lock.

- [ ] **Step 1: Add the dependencies**

Save as `task3-deps.patch`, run `git apply task3-deps.patch`, then delete the patch file:
```diff
diff --git a/crates/kv/Cargo.toml b/crates/kv/Cargo.toml
index 9740aa7..7324537 100644
--- a/crates/kv/Cargo.toml
+++ b/crates/kv/Cargo.toml
@@ -10,6 +10,7 @@ clap = { version = "4.6", features = ["derive", "env"] }
 dirs = "7.0"
 humantime = "2"
 kv-core = { path = "../kv-core" }
+reqwest = { version = "0.13", default-features = false, features = ["rustls"] }
 rpassword = "7.5"
 serde = { version = "1", features = ["derive"] }
 serde_json = "1"
@@ -30,4 +31,7 @@ windows-sys = { version = "0.61", features = [
 ] }
 
 [dev-dependencies]
+rcgen = "0.14"
 tempfile = "3.27"
+tokio-rustls = "0.26"
+wiremock = "0.6"
```

- [ ] **Step 2: Write the failing tests**


Create `crates/kv/tests/http.rs`:
```rust
//! `http_request` end to end against local servers: the credential reaches
//! the right place and nowhere else, and nothing secret comes back.

mod common;

use common::*;
use kv::broker::http::{client, send};
use kv_core::policy::{Mode, Policy};
use kv_core::proto::{AgentErrorCode, AgentResponse, HttpCall, HttpReply, MAX_OUTPUT_LEN};
use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn host_of(server: &MockServer) -> String {
    server.uri().trim_start_matches("http://").to_owned()
}

fn handle(placement: AuthPlacement, hosts: Vec<String>, base_url: Option<String>) -> Secret {
    Secret {
        name: "api".into(),
        description: String::new(),
        value: SecretValue::Http {
            token: SecretText::new(TOKEN),
            placement,
            base_url,
        },
        policy: Policy {
            mode: Mode::Auto,
            allowed_hosts: hosts,
            allow_plain_http: true,
            ..Policy::default()
        },
        created_at: 0,
        updated_at: 0,
    }
}

fn bearer() -> AuthPlacement {
    AuthPlacement::Header {
        name: "Authorization".into(),
        template: "Bearer {}".into(),
    }
}

fn call(method: &str, url: &str) -> HttpCall {
    HttpCall {
        handle: "api".into(),
        method: method.into(),
        url: url.into(),
        headers: Default::default(),
        body: None,
    }
}

async fn run(f: &mut Fixture, call: HttpCall) -> AgentResponse {
    let job = f.http(call).expect("authorized");
    send(&client().unwrap(), job).await
}

fn ok(response: AgentResponse) -> HttpReply {
    match response {
        AgentResponse::Http(reply) => reply,
        other => panic!("expected a reply, got {other:?}"),
    }
}

fn upstream_message(response: AgentResponse) -> String {
    match response {
        AgentResponse::Error {
            code: AgentErrorCode::UpstreamError,
            message,
        } => message,
        other => panic!("expected upstream_error, got {other:?}"),
    }
}

#[tokio::test]
async fn the_credential_reaches_upstream_and_echoes_are_scrubbed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-echo", TOKEN)
                .set_body_string(format!("{{\"you_sent\":\"{TOKEN}\"}}")),
        )
        .mount(&server)
        .await;
    let mut f = Fixture::new();
    f.add(handle(bearer(), vec![host_of(&server)], None));
    let reply = ok(run(&mut f, call("get", &format!("{}/models", server.uri()))).await);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, "{\"you_sent\":\"[kv:api]\"}");
    let echo = reply.headers.iter().find(|(k, _)| k == "x-echo").unwrap();
    assert_eq!(echo.1, "[kv:api]");
    let audit = f.audit_lines().pop().unwrap();
    assert_eq!(audit["decision"], "auto");
    assert_eq!(audit["outcome"], "200");
}

#[tokio::test]
async fn a_query_credential_replaces_one_the_agent_sent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let mut f = Fixture::new();
    let placement = AuthPlacement::Query {
        param: "key".into(),
    };
    f.add(handle(placement, vec![host_of(&server)], None));
    let url = format!("{}/v1?key=agent-guess&q=1", server.uri());
    assert_eq!(ok(run(&mut f, call("GET", &url)).await).status, 204);
    let received = server.received_requests().await.unwrap();
    let pairs: Vec<(String, String)> = received[0]
        .url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        pairs,
        [("q".into(), "1".into()), ("key".into(), TOKEN.to_owned())]
    );
}

#[tokio::test]
async fn a_cut_body_never_ends_in_part_of_a_secret() {
    let server = MockServer::start().await;
    let mut body = "a".repeat(MAX_OUTPUT_LEN - 5);
    body.push_str(TOKEN);
    body.push_str("tail");
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;
    let mut f = Fixture::new();
    f.add(handle(bearer(), vec![host_of(&server)], None));
    let reply = ok(run(&mut f, call("GET", &server.uri())).await);
    assert!(reply.truncated);
    assert!(reply.body.len() <= MAX_OUTPUT_LEN);
    assert!(
        !reply.body.contains("sk-or"),
        "{}",
        &reply.body[reply.body.len() - 40..]
    );
}

#[tokio::test]
async fn redirects_keep_the_credential_only_on_the_original_origin() {
    let first = MockServer::start().await;
    let second = MockServer::start().await;
    Mock::given(path("/start"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/next"))
        .mount(&first)
        .await;
    Mock::given(path("/next"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(
            ResponseTemplate::new(307).insert_header("location", format!("{}/final", second.uri())),
        )
        .mount(&first)
        .await;
    Mock::given(path("/final"))
        .respond_with(ResponseTemplate::new(200).set_body_string("done"))
        .mount(&second)
        .await;
    let mut f = Fixture::new();
    f.add(handle(
        bearer(),
        vec![host_of(&first), host_of(&second)],
        None,
    ));
    let reply = ok(run(&mut f, call("GET", &format!("{}/start", first.uri()))).await);
    assert_eq!((reply.status, reply.body.as_str()), (200, "done"));
    let at_second = second.received_requests().await.unwrap();
    assert!(at_second[0].headers.get("authorization").is_none());
}

#[tokio::test]
async fn a_redirect_to_a_host_that_is_not_allowed_is_returned_not_followed() {
    let server = MockServer::start().await;
    Mock::given(path("/away"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "http://127.0.0.1:9/steal"),
        )
        .mount(&server)
        .await;
    let mut f = Fixture::new();
    f.add(handle(bearer(), vec![host_of(&server)], None));
    let reply = ok(run(&mut f, call("GET", &format!("{}/away", server.uri()))).await);
    assert_eq!(reply.status, 302);
}

#[tokio::test]
async fn see_other_turns_a_post_into_a_get_without_its_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(303).insert_header("location", "/result"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/result"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let mut f = Fixture::new();
    f.add(handle(bearer(), vec![host_of(&server)], None));
    let mut post = call("POST", &format!("{}/submit", server.uri()));
    post.body = Some("payload".into());
    let reply = ok(run(&mut f, post).await);
    assert_eq!(reply.body, "ok");
    let received = server.received_requests().await.unwrap();
    assert!(received[1].body.is_empty());
}

#[tokio::test]
async fn an_encoded_body_is_refused_because_it_cannot_be_scrubbed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .set_body_bytes(TOKEN.as_bytes()),
        )
        .mount(&server)
        .await;
    let mut f = Fixture::new();
    f.add(handle(bearer(), vec![host_of(&server)], None));
    let message = upstream_message(run(&mut f, call("GET", &server.uri())).await);
    assert!(message.contains("gzip"), "{message}");
    assert!(!message.contains(TOKEN), "{message}");
}

#[tokio::test]
async fn a_base_url_handle_sends_paths_and_hides_its_address() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/project.all"))
        .and(header("x-api-key", TOKEN))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(format!("next: {}/api/project.all?page=2", server.uri())),
        )
        .mount(&server)
        .await;
    let mut f = Fixture::new();
    let placement = AuthPlacement::Header {
        name: "x-api-key".into(),
        template: "{}".into(),
    };
    f.add(handle(
        placement,
        Vec::new(),
        Some(format!("{}/api", server.uri())),
    ));
    let reply = ok(run(&mut f, call("GET", "/project.all")).await);
    assert_eq!(reply.status, 200);
    assert!(!reply.body.contains("127.0.0.1"), "{}", reply.body);
}

#[tokio::test]
async fn connection_errors_never_reveal_a_query_credential() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let mut f = Fixture::new();
    let placement = AuthPlacement::Query {
        param: "key".into(),
    };
    f.add(handle(placement, vec![format!("127.0.0.1:{port}")], None));
    let message =
        upstream_message(run(&mut f, call("GET", &format!("http://127.0.0.1:{port}/x"))).await);
    assert!(!message.contains(TOKEN), "{message}");
    assert!(!message.contains("key="), "{message}");
}

#[tokio::test]
async fn an_untrusted_certificate_fails_closed() {
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    let generated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![generated.cert.der().clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let _ = acceptor.accept(stream).await;
        }
    });
    let mut f = Fixture::new();
    let mut secret = handle(bearer(), vec![format!("127.0.0.1:{port}")], None);
    secret.policy.allow_plain_http = false;
    f.add(secret);
    let message =
        upstream_message(run(&mut f, call("GET", &format!("https://127.0.0.1:{port}/"))).await);
    assert!(!message.contains(TOKEN), "{message}");
}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test http`
Expected: `unresolved import kv::broker::http`.

- [ ] **Step 4: Implement**

Save as `task3-src.patch`, run `git apply task3-src.patch`, then delete the patch file:
```diff
diff --git a/crates/kv/src/broker.rs b/crates/kv/src/broker.rs
index 6868bae..8c97b3e 100644
--- a/crates/kv/src/broker.rs
+++ b/crates/kv/src/broker.rs
@@ -11,6 +11,8 @@ use kv_core::secret::{Secret, SecretText};
 
 use crate::audit::Audit;
 
+pub mod http;
+
 /// An `http_request` that passed every check.
 pub struct HttpJob {
     pub secret: Secret,
diff --git a/crates/kv/src/daemon/server.rs b/crates/kv/src/daemon/server.rs
index cded1d9..a1cccd7 100644
--- a/crates/kv/src/daemon/server.rs
+++ b/crates/kv/src/daemon/server.rs
@@ -14,6 +14,7 @@ use tokio::sync::watch;
 use super::harden;
 use super::state::{After, Daemon, Prepared, Settings};
 use crate::audit::Audit;
+use crate::broker;
 use crate::frame::{read_frame, write_frame};
 use crate::ipc::{self, ServerStream};
 use crate::paths::Paths;
@@ -55,6 +56,7 @@ pub async fn run(paths: Paths, settings: Settings) -> io::Result<Outcome> {
         settings,
         Instant::now(),
     )));
+    let http = broker::http::client().map_err(io::Error::other)?;
     let (stop_tx, mut stop_rx) = watch::channel(false);
     let check_every = (settings.idle_lock.min(settings.locked_exit) / 4)
         .clamp(Duration::from_millis(100), Duration::from_secs(30));
@@ -64,7 +66,7 @@ pub async fn run(paths: Paths, settings: Settings) -> io::Result<Outcome> {
         tokio::select! {
             accepted = agent.accept() => match accepted {
                 Ok(stream) => {
-                    tokio::spawn(serve_agent(stream, daemon.clone()));
+                    tokio::spawn(serve_agent(stream, daemon.clone(), http.clone()));
                 }
                 Err(e) => accept_failed("agent", e).await,
             },
@@ -89,7 +91,7 @@ pub async fn run(paths: Paths, settings: Settings) -> io::Result<Outcome> {
     Ok(Outcome::Stopped)
 }
 
-async fn serve_agent(mut stream: ServerStream, daemon: Shared) {
+async fn serve_agent(mut stream: ServerStream, daemon: Shared, http: reqwest::Client) {
     loop {
         let request: AgentRequest = match read_frame(&mut stream).await {
             Ok(Some(request)) => request,
@@ -105,17 +107,18 @@ async fn serve_agent(mut stream: ServerStream, daemon: Shared) {
             Err(_) => return,
         };
         let daemon = daemon.clone();
-        let handled = tokio::task::spawn_blocking(move || {
-            match lock(&daemon).prepare(request, Instant::now()) {
-                Prepared::Reply(response) => response,
-                Prepared::Http(_) | Prepared::Exec(_) => AgentResponse::Error {
-                    code: AgentErrorCode::BadRequest,
-                    message: "not supported yet".into(),
-                },
-            }
-        })
-        .await;
-        let Ok(response) = handled else { return };
+        let prepared =
+            tokio::task::spawn_blocking(move || lock(&daemon).prepare(request, Instant::now()))
+                .await;
+        let Ok(prepared) = prepared else { return };
+        let response = match prepared {
+            Prepared::Reply(response) => response,
+            Prepared::Http(job) => broker::http::send(&http, *job).await,
+            Prepared::Exec(_) => AgentResponse::Error {
+                code: AgentErrorCode::BadRequest,
+                message: "exec is not supported yet".into(),
+            },
+        };
         if write_frame(&mut stream, &response).await.is_err() {
             return;
         }
```

Create `crates/kv/src/broker/http.rs`:
```rust
//! Sends an authorized `http_request` with the handle's credential attached,
//! follows redirects only where the policy allows, and scrubs the answer.

use std::error::Error as _;
use std::time::Duration;

use kv_core::policy::{Decision, Operation, evaluate};
use kv_core::proto::{AgentErrorCode, AgentResponse, HttpReply, MAX_OUTPUT_LEN};
use kv_core::scrub::Scrubber;
use kv_core::secret::{AuthPlacement, SecretValue};
use reqwest::header::{CONTENT_ENCODING, HeaderValue};
use reqwest::{Client, Method, Request, Response, StatusCode, redirect};

use super::HttpJob;
use crate::audit::Use;

const MAX_REDIRECTS: usize = 5;
const TIMEOUT: Duration = Duration::from_secs(60);

/// One client for the daemon's lifetime. It ignores proxy settings, which
/// an agent could set in the daemon's environment, and never follows
/// redirects on its own.
pub fn client() -> reqwest::Result<Client> {
    Client::builder()
        .redirect(redirect::Policy::none())
        .no_proxy()
        .timeout(TIMEOUT)
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("kv/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// Runs the request and records it in the audit log.
pub async fn send(client: &Client, job: HttpJob) -> AgentResponse {
    let response = match exchange(client, &job).await {
        Ok(response) => response,
        Err(response) => response,
    };
    let outcome = match &response {
        AgentResponse::Http(reply) => reply.status.to_string(),
        AgentResponse::Error { code, .. } => code.as_str().to_owned(),
        _ => "error".to_owned(),
    };
    job.audit.record_use(&Use {
        action: "http_request",
        handle: &job.secret.name,
        decision: "auto",
        summary: &format!("{} {}", job.call.method, job.call.url),
        outcome: &outcome,
        duration: job.started.elapsed(),
    });
    response
}

async fn exchange(client: &Client, job: &HttpJob) -> Result<AgentResponse, AgentResponse> {
    let SecretValue::Http {
        token, placement, ..
    } = &job.secret.value
    else {
        return Err(error(AgentErrorCode::BadRequest, "not an http handle"));
    };
    let mut method = Method::from_bytes(job.call.method.to_ascii_uppercase().as_bytes())
        .map_err(|_| error(AgentErrorCode::BadRequest, "invalid method"))?;
    let mut body = job.call.body.clone();
    let origin = job.url.origin();
    let mut url = job.url.clone();
    let mut with_auth = true;
    for _ in 0..=MAX_REDIRECTS {
        let request = build(client, job, &method, &url, body.as_deref(), with_auth)?;
        let response = client
            .execute(request)
            .await
            .map_err(|e| upstream(&job.scrubber, e))?;
        let Some(mut next) = redirect_target(&response, &url) else {
            return reply(&job.scrubber, response).await;
        };
        if let AuthPlacement::Query { param } = placement {
            remove_param(&mut next, param);
        }
        let allowed = !matches!(
            evaluate(
                &job.secret,
                &Operation::Http {
                    method: method.as_str(),
                    url: next.as_str(),
                }
            ),
            Decision::Deny(_)
        );
        if !allowed || next.as_str().contains(token.expose()) {
            return reply(&job.scrubber, response).await;
        }
        if next.origin() != origin {
            with_auth = false;
        }
        let status = response.status();
        if status == StatusCode::SEE_OTHER
            || (matches!(status, StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND)
                && method == Method::POST)
        {
            method = Method::GET;
            body = None;
        }
        url = next;
    }
    Err(error(
        AgentErrorCode::UpstreamError,
        format!("more than {MAX_REDIRECTS} redirects"),
    ))
}

/// The request for one hop. The credential goes only on hops to the
/// origin the agent asked for.
fn build(
    client: &Client,
    job: &HttpJob,
    method: &Method,
    url: &url::Url,
    body: Option<&str>,
    with_auth: bool,
) -> Result<Request, AgentResponse> {
    let SecretValue::Http {
        token, placement, ..
    } = &job.secret.value
    else {
        return Err(error(AgentErrorCode::BadRequest, "not an http handle"));
    };
    let mut url = url.clone();
    if let (true, AuthPlacement::Query { param }) = (with_auth, placement) {
        remove_param(&mut url, param);
        url.query_pairs_mut().append_pair(param, token.expose());
    }
    let mut builder = client.request(method.clone(), url);
    for (name, value) in &job.call.headers {
        builder = builder.header(name, value);
    }
    if let (true, AuthPlacement::Header { name, template }) = (with_auth, placement) {
        let mut value =
            HeaderValue::from_str(&template.replace("{}", token.expose())).map_err(|_| {
                error(
                    AgentErrorCode::BadRequest,
                    "the credential is not a valid header value",
                )
            })?;
        value.set_sensitive(true);
        builder = builder.header(name, value);
    }
    if let Some(body) = body {
        builder = builder.body(body.to_owned());
    }
    builder.build().map_err(|e| {
        error(
            AgentErrorCode::BadRequest,
            scrub_text(&job.scrubber, e.without_url().to_string().as_bytes()),
        )
    })
}

fn redirect_target(response: &Response, current: &url::Url) -> Option<url::Url> {
    let redirects = matches!(
        response.status(),
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    );
    if !redirects {
        return None;
    }
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)?
        .to_str()
        .ok()?;
    current.join(location).ok()
}

fn remove_param(url: &mut url::Url, param: &str) {
    if url.query().is_none() {
        return;
    }
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(name, _)| name != param)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    if kept.is_empty() {
        url.set_query(None);
    } else {
        url.query_pairs_mut().clear().extend_pairs(kept);
    }
}

async fn reply(
    scrubber: &Scrubber,
    mut response: Response,
) -> Result<AgentResponse, AgentResponse> {
    // kv never asks for compression, but a server may send it anyway, and
    // the scrubber cannot see a secret inside an encoded body.
    if let Some(encoding) = response.headers().get(CONTENT_ENCODING)
        && !encoding.as_bytes().eq_ignore_ascii_case(b"identity")
    {
        return Err(error(
            AgentErrorCode::UpstreamError,
            format!(
                "the response is encoded ({}), which kv cannot scrub",
                scrub_text(scrubber, encoding.as_bytes())
            ),
        ));
    }
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                scrub_text(scrubber, value.as_bytes()),
            )
        })
        .collect();
    let mut stream = scrubber.stream();
    let mut out = Vec::new();
    let mut read = 0;
    let mut truncated = false;
    while let Some(chunk) = response.chunk().await.map_err(|e| upstream(scrubber, e))? {
        let room = MAX_OUTPUT_LEN - read;
        if chunk.len() > room {
            out.extend(stream.push(&chunk[..room]));
            truncated = true;
            break;
        }
        read += chunk.len();
        out.extend(stream.push(&chunk));
    }
    // A cut body may end inside a secret, so the held-back tail is dropped
    // rather than flushed.
    if !truncated {
        out.extend(stream.finish());
    }
    let (body, cut) = capped_text(&out);
    Ok(AgentResponse::Http(HttpReply {
        status,
        headers,
        body,
        truncated: truncated || cut,
    }))
}

/// Decodes scrubbed bytes, cutting them to `MAX_OUTPUT_LEN` (replacement
/// markers can make scrubbed output longer than its input).
pub(crate) fn capped_text(bytes: &[u8]) -> (String, bool) {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    if text.len() <= MAX_OUTPUT_LEN {
        return (text, false);
    }
    let mut end = MAX_OUTPUT_LEN;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    (text, true)
}

fn scrub_text(scrubber: &Scrubber, bytes: &[u8]) -> String {
    String::from_utf8_lossy(&scrubber.scrub(bytes)).into_owned()
}

/// An `upstream_error` that names the cause but never the URL, which can
/// hold the credential or the hidden base URL.
fn upstream(scrubber: &Scrubber, error: reqwest::Error) -> AgentResponse {
    if error.is_timeout() {
        return self::error(
            AgentErrorCode::UpstreamError,
            format!("the request timed out after {}s", TIMEOUT.as_secs()),
        );
    }
    let error = error.without_url();
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    self::error(
        AgentErrorCode::UpstreamError,
        scrub_text(scrubber, message.as_bytes()),
    )
}

fn error(code: AgentErrorCode, message: impl Into<String>) -> AgentResponse {
    AgentResponse::Error {
        code,
        message: message.into(),
    }
}
```

Notes on the change:
- The client ignores system proxies, verifies certificates with the platform verifier, times out after 60 s and never follows redirects itself.
- kv follows at most 5 redirects. The credential is attached only on the original origin; a query credential is removed from the next URL, and a `Location` that contains the token is not followed. 303, and 301/302 after a POST, become a GET without a body. A target the policy does not allow is returned to the agent as the 3xx.
- Transport errors use `without_url()` plus the error's source chain, then the scrubber, so a query token never appears in an error.
- A response with a `Content-Encoding` other than `identity` is an `upstream_error`: kv never asks for compression, and the scrubber cannot see inside an encoded body.

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test http`
Expected: 10 tests pass (http 10).

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo fmt --all --check && DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/kv/Cargo.toml crates/kv/src/broker.rs crates/kv/src/broker/http.rs crates/kv/src/daemon/server.rs crates/kv/tests/http.rs
git commit -m "Send authorized HTTP requests with the handle's credential"
```

---

### Task 4: exec broker

**Files:**
- Create: `crates/kv/src/broker/exec.rs`, `crates/kv/src/broker/process.rs`
- Modify: `crates/kv/Cargo.toml`, `crates/kv/src/broker.rs`, `crates/kv/src/broker/http.rs`, `crates/kv/src/daemon/server.rs`
- Test: `crates/kv/tests/exec.rs`, `crates/kv/tests/resolve.rs`

**Interfaces:**
- Consumes: Task 2's `ExecJob`, `Prepared::Exec`, `Use`, `MAX_OUTPUT_LEN`; Task 3's `capped_text`, which moves from `broker/http.rs` into `broker.rs` so both brokers share it.
- Produces: `kv::broker::exec::{run(job: ExecJob) -> AgentResponse, resolve(program: &str, path: Option<&OsStr>) -> Option<PathBuf>}`; `kv::broker::process::{isolate(&mut tokio::process::Command), ProcessTree::{adopt(&Child) -> io::Result<ProcessTree>, kill(&self)}}` (dropping a `ProcessTree` kills it). The server runs `Prepared::Exec` jobs through `run` outside the daemon lock.

- [ ] **Step 1: Add the dependencies**

Save as `task4-deps.patch`, run `git apply task4-deps.patch`, then delete the patch file:
```diff
diff --git a/crates/kv/Cargo.toml b/crates/kv/Cargo.toml
index 7324537..0a92b3a 100644
--- a/crates/kv/Cargo.toml
+++ b/crates/kv/Cargo.toml
@@ -14,7 +14,7 @@ reqwest = { version = "0.13", default-features = false, features = ["rustls"] }
 rpassword = "7.5"
 serde = { version = "1", features = ["derive"] }
 serde_json = "1"
-tokio = { version = "1.53", features = ["io-util", "macros", "net", "rt-multi-thread", "sync", "time"] }
+tokio = { version = "1.53", features = ["io-util", "macros", "net", "process", "rt-multi-thread", "sync", "time"] }
 url = "2.5"
 zeroize = "1.9"
 
@@ -27,6 +27,7 @@ windows-sys = { version = "0.61", features = [
     "Win32_Security",
     "Win32_Security_Authorization",
     "Win32_System_Console",
+    "Win32_System_JobObjects",
     "Win32_System_Threading",
 ] }
 
```

- [ ] **Step 2: Write the failing tests**


Create `crates/kv/tests/exec.rs`:
```rust
//! `exec` end to end. The program kv runs is this test binary itself: the
//! `helper` test below acts as a small tool when `KV_EXEC_HELPER` is set,
//! which kv injects through the env handle like any other variable.

mod common;

use std::io::Write;
use std::time::{Duration, Instant};

use common::*;
use kv::broker::exec::run;
use kv_core::policy::Mode;
use kv_core::proto::{AgentResponse, ExecCall, ExecReply, MAX_OUTPUT_LEN};

const SECRET: &str = "s3cr3t-value-0123456789";
const MODE_VAR: &str = "KV_EXEC_HELPER";

/// Not a real test. Run by kv with `KV_EXEC_HELPER` set, it behaves as the
/// program under test and exits without letting the harness print more.
#[test]
fn helper() {
    let Ok(mode) = std::env::var(MODE_VAR) else {
        return;
    };
    let value = std::env::var("SECRET_VALUE").unwrap_or_default();
    let mut out = std::io::stdout();
    match mode.as_str() {
        "print" => {
            let hex: String = value.bytes().map(|b| format!("{b:02x}")).collect();
            writeln!(out, "raw={value}").unwrap();
            writeln!(out, "hex={hex}").unwrap();
            writeln!(out, "b64={}", base64(value.as_bytes())).unwrap();
            eprintln!("err={value}");
        }
        "exit" => std::process::exit(3),
        "big" => {
            let line = "x".repeat(1023);
            for _ in 0..(MAX_OUTPUT_LEN / 1024 + 64) {
                writeln!(out, "{line}").unwrap();
            }
        }
        "slow-secret" => {
            write!(out, "{}", &value[..4]).unwrap();
            out.flush().unwrap();
            std::thread::sleep(Duration::from_secs(30));
        }
        "spawn" => {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(helper_args())
                .env(MODE_VAR, "sleep")
                .spawn()
                .unwrap();
            std::fs::write(std::env::var("PID_FILE").unwrap(), child.id().to_string()).unwrap();
            let _ = child.wait();
        }
        "sleep" => std::thread::sleep(Duration::from_secs(30)),
        other => panic!("unknown helper mode {other}"),
    }
    out.flush().unwrap();
    std::process::exit(0);
}

fn helper_args() -> Vec<String> {
    ["helper", "--exact", "--nocapture", "--test-threads=1"]
        .map(String::from)
        .to_vec()
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A fixture whose `tool` handle runs this test binary in `mode`.
fn fixture(mode: &str, extra: &[(&str, &str)]) -> (Fixture, ExecCall) {
    let mut f = Fixture::new();
    let exe = std::env::current_exe().unwrap();
    let mut vars = vec![("SECRET_VALUE", SECRET), (MODE_VAR, mode)];
    vars.extend_from_slice(extra);
    f.add(env_secret(
        "tool",
        &vars,
        &[exe.to_str().unwrap()],
        Mode::Auto,
    ));
    let mut argv = vec![exe.to_str().unwrap().to_owned()];
    argv.extend(helper_args());
    let call = ExecCall {
        handles: vec!["tool".into()],
        argv,
        cwd: f.dir.path().to_path_buf(),
        timeout_secs: None,
    };
    (f, call)
}

async fn exec(f: &mut Fixture, call: ExecCall) -> ExecReply {
    let job = f.exec(call).expect("authorized");
    match run(job).await {
        AgentResponse::Exec(reply) => reply,
        other => panic!("expected output, got {other:?}"),
    }
}

#[tokio::test]
async fn injected_values_never_come_back_in_any_encoding() {
    let (mut f, call) = fixture("print", &[]);
    let reply = exec(&mut f, call).await;
    assert_eq!(reply.exit_code, Some(0), "{reply:?}");
    let hex: String = SECRET.bytes().map(|b| format!("{b:02x}")).collect();
    for output in [&reply.stdout, &reply.stderr] {
        assert!(!output.contains(SECRET), "{output}");
        assert!(!output.contains(&hex), "{output}");
        assert!(!output.contains(&base64(SECRET.as_bytes())), "{output}");
    }
    assert!(reply.stdout.contains("raw=[kv:tool]"), "{}", reply.stdout);
    assert!(reply.stderr.contains("err=[kv:tool]"), "{}", reply.stderr);
    let audit = f.audit_lines().pop().unwrap();
    assert_eq!(audit["action"], "exec");
    assert_eq!(audit["outcome"], "exit 0");
}

#[tokio::test]
async fn the_exit_code_is_reported() {
    let (mut f, call) = fixture("exit", &[]);
    let reply = exec(&mut f, call).await;
    assert_eq!((reply.exit_code, reply.timed_out), (Some(3), false));
}

#[tokio::test]
async fn long_output_is_cut_at_the_cap() {
    let (mut f, call) = fixture("big", &[]);
    let reply = exec(&mut f, call).await;
    assert!(reply.truncated);
    assert!(reply.stdout.len() <= MAX_OUTPUT_LEN);
    assert_eq!(reply.exit_code, Some(0));
}

#[tokio::test]
async fn a_timeout_kills_the_program_without_flushing_part_of_a_secret() {
    let (mut f, mut call) = fixture("slow-secret", &[]);
    call.timeout_secs = Some(1);
    let started = Instant::now();
    let reply = exec(&mut f, call).await;
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(reply.timed_out);
    assert_eq!(reply.exit_code, None);
    assert!(!reply.stdout.contains(&SECRET[..4]), "{}", reply.stdout);
}

#[cfg(unix)]
#[tokio::test]
async fn a_timeout_also_kills_what_the_program_started() {
    let pid_dir = tempfile::TempDir::new().unwrap();
    let pid_file = pid_dir.path().join("pid");
    let (mut f, mut call) = fixture("spawn", &[("PID_FILE", pid_file.to_str().unwrap())]);
    call.timeout_secs = Some(2);
    let reply = exec(&mut f, call).await;
    assert!(reply.timed_out);
    let pid: i32 = std::fs::read_to_string(&pid_file).unwrap().parse().unwrap();
    let pid = rustix::process::Pid::from_raw(pid).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while rustix::process::test_kill_process(pid).is_ok() {
        assert!(Instant::now() < deadline, "the grandchild is still running");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[tokio::test]
async fn a_missing_program_is_a_bad_request() {
    let mut f = Fixture::new();
    f.add(env_secret(
        "tool",
        &[("SECRET_VALUE", SECRET)],
        &["kv-no-such-program"],
        Mode::Auto,
    ));
    let call = ExecCall {
        handles: vec!["tool".into()],
        argv: vec!["kv-no-such-program".into()],
        cwd: f.dir.path().to_path_buf(),
        timeout_secs: None,
    };
    let job = f.exec(call).unwrap();
    match run(job).await {
        AgentResponse::Error { message, .. } => {
            assert!(message.contains("not found"), "{message}")
        }
        other => panic!("{other:?}"),
    }
}
```

Create `crates/kv/tests/resolve.rs`:
```rust
//! How `exec` finds the program to run. Its own test binary, because one
//! test changes the working directory.

use std::path::{Path, PathBuf};

use kv::broker::exec::resolve;

fn tool(dir: &Path, name: &str) -> PathBuf {
    let file = dir.join(if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    });
    std::fs::write(&file, b"").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    file
}

#[test]
fn bare_names_are_found_on_absolute_path_entries_only() {
    let base = tempfile::TempDir::new().unwrap();
    let bin = base.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let expected = tool(&bin, "terraform");
    let path = std::env::join_paths([PathBuf::from("relative"), bin.clone()]).unwrap();
    assert_eq!(resolve("terraform", Some(&path)), Some(expected));

    let relative_only = std::env::join_paths([PathBuf::from("bin")]).unwrap();
    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(base.path()).unwrap();
    let found = resolve("terraform", Some(&relative_only));
    std::env::set_current_dir(cwd).unwrap();
    assert_eq!(found, None);
}

#[test]
fn relative_paths_with_a_directory_are_never_run() {
    assert_eq!(resolve("./terraform", None), None);
    assert_eq!(resolve("bin/terraform", None), None);
}

#[test]
fn absolute_paths_are_used_as_given() {
    let base = tempfile::TempDir::new().unwrap();
    let file = tool(base.path(), "deploy");
    assert_eq!(resolve(file.to_str().unwrap(), None), Some(file.clone()));
    assert_eq!(
        resolve(base.path().join("missing").to_str().unwrap(), None),
        None
    );
}

#[cfg(unix)]
#[test]
fn files_without_execute_permission_are_skipped() {
    use std::os::unix::fs::PermissionsExt;
    let base = tempfile::TempDir::new().unwrap();
    let first = base.path().join("a");
    let second = base.path().join("b");
    std::fs::create_dir_all(&first).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    let plain = first.join("tool");
    std::fs::write(&plain, b"").unwrap();
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
    let runnable = tool(&second, "tool");
    let path = std::env::join_paths([first, second]).unwrap();
    assert_eq!(resolve("tool", Some(&path)), Some(runnable));
}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test exec --test resolve`
Expected: compile errors starting with `unresolved import kv::broker::exec` (the others in `tests/exec.rs` follow from it).

- [ ] **Step 4: Implement**

Save as `task4-src.patch`, run `git apply task4-src.patch`, then delete the patch file:
```diff
diff --git a/crates/kv/src/broker.rs b/crates/kv/src/broker.rs
index 8c97b3e..b2c3e7f 100644
--- a/crates/kv/src/broker.rs
+++ b/crates/kv/src/broker.rs
@@ -9,9 +9,13 @@ use kv_core::proto::HttpCall;
 use kv_core::scrub::Scrubber;
 use kv_core::secret::{Secret, SecretText};
 
+use kv_core::proto::MAX_OUTPUT_LEN;
+
 use crate::audit::Audit;
 
+pub mod exec;
 pub mod http;
+mod process;
 
 /// An `http_request` that passed every check.
 pub struct HttpJob {
@@ -37,6 +41,21 @@ pub struct ExecJob {
     pub started: Instant,
 }
 
+/// Decodes scrubbed bytes, cutting them to `MAX_OUTPUT_LEN` (replacement
+/// markers can make scrubbed output longer than its input).
+pub(crate) fn capped_text(bytes: &[u8]) -> (String, bool) {
+    let mut text = String::from_utf8_lossy(bytes).into_owned();
+    if text.len() <= MAX_OUTPUT_LEN {
+        return (text, false);
+    }
+    let mut end = MAX_OUTPUT_LEN;
+    while !text.is_char_boundary(end) {
+        end -= 1;
+    }
+    text.truncate(end);
+    (text, true)
+}
+
 /// Names only: the URL may hold a hidden base URL, and the job holds values.
 impl std::fmt::Debug for HttpJob {
     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
diff --git a/crates/kv/src/broker/http.rs b/crates/kv/src/broker/http.rs
index 18ca692..fdae7ba 100644
--- a/crates/kv/src/broker/http.rs
+++ b/crates/kv/src/broker/http.rs
@@ -11,7 +11,7 @@ use kv_core::secret::{AuthPlacement, SecretValue};
 use reqwest::header::{CONTENT_ENCODING, HeaderValue};
 use reqwest::{Client, Method, Request, Response, StatusCode, redirect};
 
-use super::HttpJob;
+use super::{HttpJob, capped_text};
 use crate::audit::Use;
 
 const MAX_REDIRECTS: usize = 5;
@@ -248,21 +248,6 @@ async fn reply(
     }))
 }
 
-/// Decodes scrubbed bytes, cutting them to `MAX_OUTPUT_LEN` (replacement
-/// markers can make scrubbed output longer than its input).
-pub(crate) fn capped_text(bytes: &[u8]) -> (String, bool) {
-    let mut text = String::from_utf8_lossy(bytes).into_owned();
-    if text.len() <= MAX_OUTPUT_LEN {
-        return (text, false);
-    }
-    let mut end = MAX_OUTPUT_LEN;
-    while !text.is_char_boundary(end) {
-        end -= 1;
-    }
-    text.truncate(end);
-    (text, true)
-}
-
 fn scrub_text(scrubber: &Scrubber, bytes: &[u8]) -> String {
     String::from_utf8_lossy(&scrubber.scrub(bytes)).into_owned()
 }
diff --git a/crates/kv/src/daemon/server.rs b/crates/kv/src/daemon/server.rs
index a1cccd7..0420c6d 100644
--- a/crates/kv/src/daemon/server.rs
+++ b/crates/kv/src/daemon/server.rs
@@ -114,10 +114,7 @@ async fn serve_agent(mut stream: ServerStream, daemon: Shared, http: reqwest::Cl
         let response = match prepared {
             Prepared::Reply(response) => response,
             Prepared::Http(job) => broker::http::send(&http, *job).await,
-            Prepared::Exec(_) => AgentResponse::Error {
-                code: AgentErrorCode::BadRequest,
-                message: "exec is not supported yet".into(),
-            },
+            Prepared::Exec(job) => broker::exec::run(*job).await,
         };
         if write_frame(&mut stream, &response).await.is_err() {
             return;
```

Create `crates/kv/src/broker/exec.rs`:
```rust
//! Runs an authorized program with the handles' variables injected and
//! returns its scrubbed output. Never uses a shell.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kv_core::proto::{AgentErrorCode, AgentResponse, ExecReply, MAX_OUTPUT_LEN};
use kv_core::scrub::Scrubber;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use super::process::{ProcessTree, isolate};
use super::{ExecJob, capped_text};
use crate::audit::Use;

/// How long to wait for the output pipes once the program has ended and
/// anything it left running has been killed.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Runs the program and records it in the audit log.
pub async fn run(job: ExecJob) -> AgentResponse {
    let response = match execute(&job).await {
        Ok(response) => response,
        Err(response) => response,
    };
    let outcome = match &response {
        AgentResponse::Exec(reply) if reply.timed_out => "timed_out".to_owned(),
        AgentResponse::Exec(reply) => match reply.exit_code {
            Some(code) => format!("exit {code}"),
            None => "killed".to_owned(),
        },
        AgentResponse::Error { code, .. } => code.as_str().to_owned(),
        _ => "error".to_owned(),
    };
    job.audit.record_use(&Use {
        action: "exec",
        handle: &job.handles.join(","),
        decision: "auto",
        summary: &job.argv[0],
        outcome: &outcome,
        duration: job.started.elapsed(),
    });
    response
}

async fn execute(job: &ExecJob) -> Result<AgentResponse, AgentResponse> {
    let name = &job.argv[0];
    let program = resolve(name, std::env::var_os("PATH").as_deref()).ok_or_else(|| {
        error(
            AgentErrorCode::BadRequest,
            format!("{name} was not found on the daemon's PATH"),
        )
    })?;
    let mut command = Command::new(&program);
    command
        .args(&job.argv[1..])
        .current_dir(&job.cwd)
        .envs(job.env.iter().map(|(name, value)| (name, value.expose())))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    isolate(&mut command);
    let mut child = command.spawn().map_err(|e| {
        error(
            AgentErrorCode::UpstreamError,
            format!("could not start {name}: {e}"),
        )
    })?;
    let tree = ProcessTree::adopt(&child).map_err(|e| {
        error(
            AgentErrorCode::UpstreamError,
            format!("could not track {name}: {e}"),
        )
    })?;
    let cut = Arc::new(AtomicBool::new(false));
    let stdout = tokio::spawn(capture(
        child.stdout.take(),
        job.scrubber.clone(),
        cut.clone(),
    ));
    let stderr = tokio::spawn(capture(
        child.stderr.take(),
        job.scrubber.clone(),
        cut.clone(),
    ));
    let (status, timed_out) = match tokio::time::timeout(job.timeout, child.wait()).await {
        Ok(status) => (status.ok(), false),
        Err(_) => {
            cut.store(true, Ordering::SeqCst);
            tree.kill();
            (child.wait().await.ok(), true)
        }
    };
    // Anything the program left running would keep the pipes open and could
    // still hold the secrets.
    tree.kill();
    let (stdout, stdout_cut) = drain(stdout).await;
    let (stderr, stderr_cut) = drain(stderr).await;
    Ok(AgentResponse::Exec(ExecReply {
        exit_code: if timed_out {
            None
        } else {
            status.and_then(|s| s.code())
        },
        timed_out,
        stdout,
        stderr,
        truncated: stdout_cut || stderr_cut,
    }))
}

/// Reads one output stream through the scrubber. Keeps reading past the
/// cap, discarding, so the program never blocks on a full pipe.
async fn capture(
    reader: Option<impl AsyncRead + Unpin>,
    scrubber: Arc<Scrubber>,
    cut: Arc<AtomicBool>,
) -> (Vec<u8>, bool) {
    let Some(mut reader) = reader else {
        return (Vec::new(), false);
    };
    let mut stream = scrubber.stream();
    let mut out = Vec::new();
    let mut kept = 0;
    let mut truncated = false;
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let n = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if truncated {
            continue;
        }
        let room = MAX_OUTPUT_LEN - kept;
        if n > room {
            out.extend(stream.push(&buffer[..room]));
            truncated = true;
        } else {
            kept += n;
            out.extend(stream.push(&buffer[..n]));
        }
    }
    // Output cut short, by the cap or by a kill, may end inside a secret, so
    // the held-back tail is dropped rather than flushed.
    if !truncated && !cut.load(Ordering::SeqCst) {
        out.extend(stream.finish());
    }
    (out, truncated)
}

async fn drain(task: tokio::task::JoinHandle<(Vec<u8>, bool)>) -> (String, bool) {
    match tokio::time::timeout(DRAIN_GRACE, task).await {
        Ok(Ok((bytes, truncated))) => {
            let (text, cut) = capped_text(&bytes);
            (text, truncated || cut)
        }
        _ => (String::new(), true),
    }
}

/// Finds the program to run. An absolute path is used as is. A bare name is
/// looked up in `path`, skipping empty and relative entries so the working
/// directory can never supply the program. On Windows a name without an
/// extension gets `.exe`.
pub fn resolve(program: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    let given = Path::new(program);
    if given.is_absolute() {
        return is_executable(given).then(|| given.to_path_buf());
    }
    if program.contains('/') || (cfg!(windows) && program.contains('\\')) {
        return None;
    }
    let name: OsString = if cfg!(windows) && given.extension().is_none() {
        format!("{program}.exe").into()
    } else {
        program.into()
    };
    std::env::split_paths(path?)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(&name))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

fn error(code: AgentErrorCode, message: impl Into<String>) -> AgentResponse {
    AgentResponse::Error {
        code,
        message: message.into(),
    }
}
```

Create `crates/kv/src/broker/process.rs`:
```rust
//! Keeps everything a program starts together, so kv can kill all of it: a
//! process group on Unix, a job object on Windows.

use std::io;

use tokio::process::{Child, Command};

/// Call before spawning: starts the program in its own process group, and
/// on Windows without a console window.
pub fn isolate(command: &mut Command) {
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
}

/// A started program and everything it starts. Dropping it kills them all.
pub struct ProcessTree {
    #[cfg(unix)]
    group: rustix::process::Pid,
    #[cfg(windows)]
    job: windows_sys::Win32::Foundation::HANDLE,
}

// SAFETY: the job handle is only used through thread-safe Win32 calls.
#[cfg(windows)]
unsafe impl Send for ProcessTree {}
#[cfg(windows)]
unsafe impl Sync for ProcessTree {}

impl ProcessTree {
    /// Takes charge of a child started after `isolate`. On Windows,
    /// processes the child starts before this call are not covered.
    pub fn adopt(child: &Child) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let pid = child
                .id()
                .and_then(|id| rustix::process::Pid::from_raw(id as i32))
                .ok_or_else(|| io::Error::other("the program has already exited"))?;
            Ok(Self { group: pid })
        }
        #[cfg(windows)]
        {
            windows::adopt(child)
        }
    }

    /// Kills every process in the tree. Safe to call more than once.
    pub fn kill(&self) {
        #[cfg(unix)]
        {
            let _ = rustix::process::kill_process_group(self.group, rustix::process::Signal::KILL);
        }
        #[cfg(windows)]
        windows::terminate(self.job);
    }
}

impl Drop for ProcessTree {
    fn drop(&mut self) {
        self.kill();
        #[cfg(windows)]
        windows::close(self.job);
    }
}

#[cfg(windows)]
mod windows {
    use std::io;

    use tokio::process::Child;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    };

    use super::ProcessTree;

    pub fn adopt(child: &Child) -> io::Result<ProcessTree> {
        let process = child
            .raw_handle()
            .ok_or_else(|| io::Error::other("the program has already exited"))?;
        // SAFETY: plain Win32 calls on handles we own or that the child
        // keeps open; the job handle is closed on every failure path.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if configured == 0 || AssignProcessToJobObject(job, process as HANDLE) == 0 {
                let error = io::Error::last_os_error();
                CloseHandle(job);
                return Err(error);
            }
            Ok(ProcessTree { job })
        }
    }

    pub fn terminate(job: HANDLE) {
        // SAFETY: `job` stays open until `close`.
        unsafe { TerminateJobObject(job, 1) };
    }

    pub fn close(job: HANDLE) {
        // SAFETY: called once, from Drop.
        unsafe { CloseHandle(job) };
    }
}
```

Notes on the change:
- `resolve` looks bare names up on the daemon's own PATH, skips relative entries, requires an execute bit on Unix and adds `.exe` on Windows. The test that changes the working directory lives in its own binary (`tests/resolve.rs`) because the working directory is process-wide.
- stdin is null. The program runs in its own process group (Unix) or a job object with `CREATE_NO_WINDOW` (Windows); whatever it leaves running is killed when it exits, as well as on timeout.
- stdout and stderr each stream through the scrubber and stop at 256 KiB. After the program exits kv waits at most 2 s for the pipes to drain. Output cut by the cap or a kill drops the held-back tail.
- The exec tests run this test binary itself as the program: the `helper` test acts as a small tool when `KV_EXEC_HELPER` is set, which kv injects through the env handle.

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test exec --test resolve`
Expected: 11 tests pass (exec 7, resolve 4).

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo fmt --all --check && DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/kv/Cargo.toml crates/kv/src/broker.rs crates/kv/src/broker/exec.rs crates/kv/src/broker/http.rs crates/kv/src/broker/process.rs crates/kv/src/daemon/server.rs crates/kv/tests/exec.rs crates/kv/tests/resolve.rs
git commit -m "Run programs for exec with injected variables and scrubbed output"
```

---

### Task 5: `kv mcp` and README

**Files:**
- Create: `crates/kv/src/mcp.rs`
- Modify: `crates/kv/Cargo.toml`, `crates/kv/src/cli.rs`, `crates/kv/src/lib.rs`, `README.md`
- Test: `crates/kv/tests/mcp.rs`

**Interfaces:**
- Consumes: Plan 2's `client::agent(&Paths, &AgentRequest)` (starts the daemon on demand) and `Paths`; Task 2's `AgentErrorCode::as_str`, `HttpCall`, `ExecCall`.
- Produces: `kv mcp`; `kv::mcp::serve(paths: Paths) -> io::Result<()>`, serving the tools `list_handles`, `status`, `http_request` and `exec`.

- [ ] **Step 1: Add the dependencies**

Save as `task5-deps.patch`, run `git apply task5-deps.patch`, then delete the patch file:
```diff
diff --git a/crates/kv/Cargo.toml b/crates/kv/Cargo.toml
index 0a92b3a..4d1b8a3 100644
--- a/crates/kv/Cargo.toml
+++ b/crates/kv/Cargo.toml
@@ -11,6 +11,7 @@ dirs = "7.0"
 humantime = "2"
 kv-core = { path = "../kv-core" }
 reqwest = { version = "0.13", default-features = false, features = ["rustls"] }
+rmcp = { version = "3.5", default-features = false, features = ["macros", "server", "transport-io"] }
 rpassword = "7.5"
 serde = { version = "1", features = ["derive"] }
 serde_json = "1"
@@ -33,6 +34,7 @@ windows-sys = { version = "0.61", features = [
 
 [dev-dependencies]
 rcgen = "0.14"
+rmcp = { version = "3.5", default-features = false, features = ["client", "transport-child-process"] }
 tempfile = "3.27"
 tokio-rustls = "0.26"
 wiremock = "0.6"
```

- [ ] **Step 2: Write the failing tests**


Create `crates/kv/tests/mcp.rs`:
```rust
//! `kv mcp` end to end: a real MCP client drives the `kv` binary, which
//! talks to a real daemon in a temporary `KV_HOME`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock};
use rmcp::service::{RoleClient, RunningService};
use rmcp::transport::TokioChildProcess;
use tempfile::TempDir;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const PASS: &str = "correct horse battery";
const TOKEN: &str = "sk-or-v1-0123456789abcdef";
const SECRET: &str = "s3cr3t-value-0123456789";
const MODE_VAR: &str = "KV_MCP_HELPER";

/// Not a real test. Run through `exec` with `KV_MCP_HELPER` set, it prints
/// the injected secret and its working directory.
#[test]
fn helper() {
    if std::env::var(MODE_VAR).is_err() {
        return;
    }
    let mut out = std::io::stdout();
    writeln!(out, "secret={}", std::env::var("SECRET_VALUE").unwrap()).unwrap();
    writeln!(out, "cwd={}", std::env::current_dir().unwrap().display()).unwrap();
    out.flush().unwrap();
    std::process::exit(0);
}

struct Home {
    dir: TempDir,
}

impl Home {
    fn new() -> Self {
        Self {
            dir: TempDir::new().unwrap(),
        }
    }

    fn kv(&self, args: &[&str], stdin: &str) -> String {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kv"))
            .args(args)
            .env("KV_HOME", self.dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "kv {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    async fn mcp(&self, cwd: &Path) -> RunningService<RoleClient, ()> {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_kv"));
        command
            .arg("mcp")
            .env("KV_HOME", self.dir.path())
            .current_dir(cwd);
        ().serve(TokioChildProcess::new(command).unwrap())
            .await
            .unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = Command::new(env!("CARGO_BIN_EXE_kv"))
            .arg("stop")
            .env("KV_HOME", self.dir.path())
            .stdin(Stdio::null())
            .output();
    }
}

async fn call(
    client: &RunningService<RoleClient, ()>,
    tool: &'static str,
    args: serde_json::Value,
) -> (bool, String) {
    let mut params = CallToolRequestParams::new(tool);
    if let serde_json::Value::Object(map) = args {
        params = params.with_arguments(map);
    }
    let result: CallToolResult = client.call_tool(params).await.unwrap();
    let text = result
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Text(text) => Some(text.text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    (result.is_error == Some(true), text)
}

fn helper_argv() -> Vec<String> {
    let exe = std::env::current_exe().unwrap();
    [
        exe.to_str().unwrap(),
        "helper",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]
    .map(String::from)
    .to_vec()
}

#[tokio::test]
async fn an_agent_uses_handles_through_mcp_without_seeing_secrets() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("echo {TOKEN}")))
        .mount(&server)
        .await;
    let host = server.uri().trim_start_matches("http://").to_owned();
    let exe = std::env::current_exe().unwrap();

    let home = Home::new();
    home.kv(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
    home.kv(
        &[
            "add",
            "api",
            "--kind",
            "http",
            "--host",
            &host,
            "--allow-plain-http",
            "true",
            "--mode",
            "auto",
        ],
        &format!("{PASS}\n{TOKEN}\n"),
    );
    home.kv(
        &[
            "add",
            "tool",
            "--kind",
            "env",
            "--var",
            "SECRET_VALUE",
            "--var",
            MODE_VAR,
            "--cmd",
            exe.to_str().unwrap(),
            "--mode",
            "auto",
        ],
        &format!("{PASS}\n{SECRET}\nprint\n"),
    );

    let project = TempDir::new().unwrap();
    let client = home.mcp(project.path()).await;
    let tools: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    for name in ["list_handles", "status", "http_request", "exec"] {
        assert!(tools.contains(&name.to_owned()), "{tools:?}");
    }

    let (failed, handles) = call(&client, "list_handles", serde_json::json!({})).await;
    assert!(!failed, "{handles}");
    assert!(
        handles.contains("\"api\"") && handles.contains("\"tool\""),
        "{handles}"
    );
    assert!(
        !handles.contains(TOKEN) && !handles.contains(SECRET),
        "{handles}"
    );

    let (failed, reply) = call(
        &client,
        "http_request",
        serde_json::json!({"handle": "api", "method": "GET", "url": format!("{}/models", server.uri())}),
    )
    .await;
    assert!(!failed, "{reply}");
    assert!(reply.contains("echo [kv:api]"), "{reply}");
    assert!(!reply.contains(TOKEN), "{reply}");

    let (failed, output) = call(
        &client,
        "exec",
        serde_json::json!({"handles": ["tool"], "argv": helper_argv()}),
    )
    .await;
    assert!(!failed, "{output}");
    assert!(output.contains("secret=[kv:tool]"), "{output}");
    assert!(!output.contains(SECRET), "{output}");
    let cwd = canonical(project.path());
    assert!(
        output.contains(&format!("cwd={}", cwd.display()).replace('\\', "\\\\")),
        "kv mcp's directory is the default cwd: {output}"
    );

    home.kv(&["lock"], "");
    let (failed, error) = call(
        &client,
        "http_request",
        serde_json::json!({"handle": "api", "method": "GET", "url": server.uri()}),
    )
    .await;
    assert!(failed);
    assert!(error.starts_with("vault_locked: "), "{error}");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn bad_arguments_are_tool_errors_not_crashes() {
    let home = Home::new();
    let project = TempDir::new().unwrap();
    let client = home.mcp(project.path()).await;
    let (failed, error) = call(&client, "http_request", serde_json::json!({"handle": "x"})).await;
    assert!(failed, "{error}");
    let (failed, status) = call(&client, "status", serde_json::json!({})).await;
    assert!(!failed, "{status}");
    assert!(status.contains("\"vault_exists\": false"), "{status}");
    client.cancel().await.unwrap();
}

fn canonical(path: &Path) -> PathBuf {
    let path = path.canonicalize().unwrap();
    // Windows canonical paths carry a \\?\ prefix that current_dir omits.
    PathBuf::from(path.to_string_lossy().trim_start_matches(r"\\?\"))
}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test mcp`
Expected: `helper` passes and the two real tests fail, because `kv mcp` exits with `error: unrecognized subcommand 'mcp'`.

- [ ] **Step 4: Implement**

Save as `task5-src.patch`, run `git apply task5-src.patch`, then delete the patch file:
```diff
diff --git a/crates/kv/src/cli.rs b/crates/kv/src/cli.rs
index 9671571..7ead17f 100644
--- a/crates/kv/src/cli.rs
+++ b/crates/kv/src/cli.rs
@@ -62,6 +62,8 @@ enum Command {
     },
     /// Change the vault passphrase
     Passwd,
+    /// Serve MCP on stdin and stdout, for agents such as Claude Code
+    Mcp,
     /// Run the daemon in the foreground (other commands start it on demand)
     Daemon {
         /// Lock the vault after it has gone unused for this long. Daemons
@@ -347,6 +349,10 @@ async fn run(cli: Cli) -> Result<()> {
             println!("updated {name}");
             Ok(())
         }
+        Command::Mcp => {
+            crate::mcp::serve(paths).await?;
+            Ok(())
+        }
         Command::Passwd => {
             let passphrase = input.secret("Current passphrase: ")?;
             let new_passphrase = input.new_passphrase("New passphrase: ")?;
diff --git a/crates/kv/src/lib.rs b/crates/kv/src/lib.rs
index 70e6575..dc42f51 100644
--- a/crates/kv/src/lib.rs
+++ b/crates/kv/src/lib.rs
@@ -7,5 +7,6 @@ pub mod client;
 pub mod daemon;
 pub mod frame;
 pub mod ipc;
+pub mod mcp;
 pub mod paths;
 pub mod throttle;
```

Create `crates/kv/src/mcp.rs`:
```rust
//! `kv mcp`: an MCP server on stdin and stdout for agents such as Claude
//! Code. Each tool call becomes one agent-socket request, so this process
//! never holds a secret: the daemon does the work and returns scrubbed
//! results.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use kv_core::proto::{AgentRequest, AgentResponse, ExecCall, HttpCall};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{ErrorData, ServerHandler, ServiceExt, schemars, tool, tool_handler, tool_router};
use serde::Deserialize;

use crate::client;
use crate::paths::Paths;

#[derive(Deserialize, schemars::JsonSchema)]
pub struct HttpRequestArgs {
    /// Handle name from list_handles.
    handle: String,
    /// HTTP method, such as GET or POST.
    method: String,
    /// The full URL. For handles whose takes_path is true, a path such as
    /// /v1/items instead.
    url: String,
    /// Extra request headers. kv adds the credential itself.
    #[serde(default)]
    headers: BTreeMap<String, String>,
    /// Request body.
    #[serde(default)]
    body: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ExecArgs {
    /// env handles whose variables the program receives.
    handles: Vec<String>,
    /// The program and its arguments, such as ["terraform", "plan"]. Never
    /// run through a shell.
    argv: Vec<String>,
    /// Absolute working directory. Defaults to the directory kv mcp runs in.
    #[serde(default)]
    cwd: Option<PathBuf>,
    /// Seconds before the program is killed: 60 by default, at most 600.
    #[serde(default)]
    timeout_secs: Option<u64>,
}

#[derive(Clone)]
pub struct KvServer {
    paths: Paths,
    /// Where `kv mcp` was started, normally the agent's project directory.
    cwd: PathBuf,
}

#[tool_router]
impl KvServer {
    #[tool(
        description = "List the secret handles you can use, with their kind, description and policy. Never returns secret values."
    )]
    async fn list_handles(&self) -> Result<CallToolResult, ErrorData> {
        Ok(self.ask(AgentRequest::ListHandles).await)
    }

    #[tool(description = "Whether the vault exists and is unlocked.")]
    async fn status(&self) -> Result<CallToolResult, ErrorData> {
        Ok(self.ask(AgentRequest::Status).await)
    }

    #[tool(
        description = "Send an HTTP request with a handle's credential attached. Returns the status, headers and body (at most 256 KiB), with secrets replaced by [kv:<handle>]."
    )]
    async fn http_request(
        &self,
        Parameters(args): Parameters<HttpRequestArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self
            .ask(AgentRequest::HttpRequest(HttpCall {
                handle: args.handle,
                method: args.method,
                url: args.url,
                headers: args.headers,
                body: args.body,
            }))
            .await)
    }

    #[tool(
        description = "Run a program with the variables of one or more env handles set. Returns the exit code, stdout and stderr (each at most 256 KiB), with secrets replaced by [kv:<handle>]."
    )]
    async fn exec(
        &self,
        Parameters(args): Parameters<ExecArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self
            .ask(AgentRequest::Exec(ExecCall {
                handles: args.handles,
                argv: args.argv,
                cwd: args.cwd.unwrap_or_else(|| self.cwd.clone()),
                timeout_secs: args.timeout_secs,
            }))
            .await)
    }
}

#[tool_handler(
    name = "kv",
    instructions = "kv lets you use the user's API keys, tokens and other secrets \
without seeing them. Call list_handles to see what is available and how each handle may be \
used, then call http_request or exec with a handle name. Secret values never appear in \
results; where one would, you see [kv:<handle>]. If a call fails with vault_locked, ask the \
user to run `kv unlock`."
)]
impl ServerHandler for KvServer {}

impl KvServer {
    /// Sends one request, starting the daemon if needed. Daemon errors come
    /// back as tool errors that start with their code.
    async fn ask(&self, request: AgentRequest) -> CallToolResult {
        match client::agent(&self.paths, &request).await {
            Ok(AgentResponse::Error { code, message }) => {
                CallToolResult::error(vec![ContentBlock::text(format!(
                    "{}: {message}",
                    code.as_str()
                ))])
            }
            Ok(response) => {
                let json = serde_json::to_string_pretty(&response).unwrap_or_default();
                CallToolResult::success(vec![ContentBlock::text(json)])
            }
            Err(e) => CallToolResult::error(vec![ContentBlock::text(format!(
                "daemon_unavailable: the kv daemon could not be started or reached: {e}"
            ))]),
        }
    }
}

/// Serves MCP on stdin and stdout until the client disconnects.
pub async fn serve(paths: Paths) -> io::Result<()> {
    let server = KvServer {
        paths,
        cwd: std::env::current_dir()?,
    };
    let running = server
        .serve(rmcp::transport::stdio())
        .await
        .map_err(io::Error::other)?;
    running.waiting().await.map_err(io::Error::other)?;
    Ok(())
}
```

Replace `README.md` with:
````markdown
# key-vault-for-llm

A local secrets broker for AI coding agents. Agents get named handles to
secrets (`prod-db`, `openrouter`, `github`) and the broker does the
authenticated work, so API keys, database URLs and other credentials never
show up in a chat transcript or in the model's context.

Status: agents can make HTTP requests and run programs with your secrets over
MCP. Approval prompts (`--mode ask`) arrive with `kv tui`; until then only
handles set to `--mode auto` can be used. Database access comes after that.

## Setup

```sh
cargo install --path crates/kv

kv init                       # create the vault and choose a passphrase
kv add openrouter --kind http --host openrouter.ai --mode auto
kv add aws --kind env --var AWS_ACCESS_KEY_ID --var AWS_SECRET_ACCESS_KEY \
  --cmd terraform --mode auto

claude mcp add kv -- kv mcp   # or add `kv mcp` as a stdio server in any MCP client
```

The agent then sees four tools:

- `list_handles`: names, kinds and policies, never values.
- `http_request`: sends a request with the handle's credential attached.
- `exec`: runs a program (never a shell) with an `env` handle's variables set.
- `status`: whether the vault is unlocked.

Wherever a secret would appear in a response or in program output, the agent
sees `[kv:<handle>]` instead, including base64, hex, URL-encoded and
JSON-escaped forms.

### Keeping a service's address hidden

For self-hosted services such as Dokploy, the address can be as sensitive as
the key. Add the handle with `--base-url` and kv prompts for it; the agent
then sends only paths such as `/project.all`, and the address is scrubbed
from everything it gets back:

```sh
kv add dokploy --kind http --base-url --header x-api-key --template '{}' --mode auto
```

## Day to day

```sh
kv list                       # names and policies, never values
kv policy openrouter --method GET --method POST
kv lock                       # agents get "vault locked" until you unlock
kv unlock
kv passwd                     # also rotates the vault key
kv stop                       # lock and stop the daemon
```

Secret values and passphrases are read from a hidden prompt, or one per line
from stdin when stdin is not a terminal. They are never taken as command-line
arguments, where they would end up in shell history.

Every command that changes the vault asks for the passphrase, so an agent
running commands as you cannot add, remove or loosen secrets. The vault locks
itself after 8 hours without use. To change that, set `KV_IDLE_LOCK=2h` (any
duration) in your shell profile and run `kv stop` so the next command picks it
up.

`exec` looks bare program names up on the PATH the daemon started with,
skipping relative entries. Anything that can write to a directory on that
PATH can stand in for the program, so for the strongest guarantee list
programs by absolute path (`--cmd /usr/local/bin/terraform`).

Set `KV_HOME` to keep the vault, audit log and sockets in one directory
instead of the platform defaults. Every use of a handle is recorded in the
audit log (`audit.jsonl`), without values.

## Planned for v1

- `kv tui`: approval prompts for `--mode ask` handles, editing and the audit
  log in a terminal UI
- Local database proxy (Postgres, Redis) that connects upstream with the real
  credentials, with optional read-only enforcement
- Touch ID and Windows Hello unlock, and prebuilt binaries

## What kv protects against

kv keeps secrets out of the model's context and transcripts, and limits what
an agent can do with a handle through per-secret policy and approvals. It is
not a sandbox: a malicious process running as your own user can still attack
it (for example by reading process memory on platforms that allow it). A
program you let a handle run does receive the secret.

Single-user, for macOS, Linux and Windows, written in Rust.
````

Notes on the change:
- Each tool call is one agent-socket request; `kv mcp` never holds a secret.
- Daemon errors become MCP tool errors whose text starts with the code (`vault_locked: ...`). If the daemon cannot be started or reached the text starts with `daemon_unavailable:`. Bad arguments are tool errors, never a crash.
- `exec` fills in `kv mcp`'s own working directory when the agent omits `cwd`; that is the agent's project directory.
- The README is replaced: setup with `claude mcp add kv -- kv mcp`, the four tools, `--base-url` for Dokploy-style services, and the PATH note.

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test mcp`
Expected: 3 tests pass (mcp 3).

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test --workspace`
Expected: 184 tests pass (kv: lib 18, authorize 12, cli 23, exec 7, http 10, ipc 3, mcp 3, resolve 4, state 21; kv-core: lib 6, policy 21, proto 11, scrub 14, secret 9, vault 22).

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo fmt --all --check && DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output, exit 0.

Run: `for t in x86_64-pc-windows-msvc x86_64-unknown-linux-gnu; do DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy -p kv-core --target $t --all-targets -- -D warnings; done`
Expected: both finish with no warnings or errors. The `kv` crate's Windows and Linux paths are checked by CI.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock README.md crates/kv/Cargo.toml crates/kv/src/cli.rs crates/kv/src/lib.rs crates/kv/src/mcp.rs crates/kv/tests/mcp.rs
git commit -m "Add kv mcp, the stdio MCP server agents connect to"
```

---

## After Plan 3

Plan 4 adds `kv tui`: approvals for `mode: ask` handles (replacing the immediate `approval_timeout`), the control session token, editing and the audit log view. It inherits these notes:
- `exec` gives programs a null stdin, so interactive programs see end-of-file; approvals should show the argv and working directory.
- Plan 2 deferred minors still open: backoff reset on `kv stop`, a cap on concurrent connections, shutdown races, one lock per runtime directory, and `CREATE_BREAKAWAY_FROM_JOB` for the autostarted daemon.
- Still open from Plan 1: caps on KDF parameters and wrapped-key count read from the header, unknown wrap method versus `Corrupted` (Plan 6), CI SHA pins and an MSRV job.
