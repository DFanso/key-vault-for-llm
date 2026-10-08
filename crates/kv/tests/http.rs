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
