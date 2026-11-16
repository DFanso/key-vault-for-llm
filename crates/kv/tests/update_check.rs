//! Checking GitHub for a newer release, against a local stand-in for the
//! API. Asset links in the test releases name the real GitHub host because
//! they are only validated here, never downloaded.

use kv::update::check::{client, latest, offer_from, redirect_allowed};
use kv::update::{UpdateError, archive_name, current_version};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TARGET: &str = "x86_64-unknown-linux-gnu";

fn asset(tag: &str, name: &str) -> Value {
    json!({
        "name": name,
        "browser_download_url":
            format!("https://github.com/DFanso/key-vault-for-llm/releases/download/{tag}/{name}"),
        "size": 1234,
    })
}

fn release(tag: &str) -> Value {
    let archive = archive_name(TARGET);
    json!({
        "tag_name": tag,
        "html_url": format!("https://github.com/DFanso/key-vault-for-llm/releases/tag/{tag}"),
        "draft": false,
        "prerelease": false,
        "assets": [asset(tag, &archive), asset(tag, &format!("{archive}.sha256"))],
    })
}

async fn serve(status: u16, body: Vec<u8>, extra: Option<(&str, &str)>) -> MockServer {
    let server = MockServer::start().await;
    let mut reply = ResponseTemplate::new(status).set_body_bytes(body);
    if let Some((k, v)) = extra {
        reply = reply.insert_header(k, v);
    }
    Mock::given(method("GET"))
        .and(path("/latest"))
        .and(header("accept", "application/vnd.github+json"))
        .respond_with(reply)
        .mount(&server)
        .await;
    server
}

async fn check(server: &MockServer) -> Result<Option<kv::update::Offer>, UpdateError> {
    let url = format!("{}/latest", server.uri());
    latest(&client().unwrap(), &url, &current_version(), TARGET).await
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

#[tokio::test]
async fn offers_a_newer_release() {
    let server = serve(200, bytes(&release("v99.0.0")), None).await;
    let offer = check(&server).await.unwrap().expect("an offer");
    assert_eq!(offer.version.to_string(), "99.0.0");
    assert_eq!(offer.archive.name, archive_name(TARGET));
    assert_eq!(
        offer.checksum.name,
        format!("{}.sha256", archive_name(TARGET))
    );
    assert!(offer.notes_url.ends_with("/v99.0.0"));
}

#[tokio::test]
async fn same_or_older_is_no_update() {
    for tag in [format!("v{}", current_version()), "v0.1.0".to_owned()] {
        let server = serve(200, bytes(&release(&tag)), None).await;
        assert_eq!(check(&server).await, Ok(None), "{tag}");
    }
}

#[tokio::test]
async fn prerelease_version_is_not_offered() {
    // Published without the pre-release box ticked, but the tag says rc.
    let server = serve(200, bytes(&release("v99.0.0-rc.1")), None).await;
    assert_eq!(check(&server).await, Ok(None));
}

#[test]
fn drafts_prereleases_and_odd_tags_are_not_offered() {
    let current = current_version();
    let mut draft = release("v99.0.0");
    draft["draft"] = json!(true);
    let mut pre = release("v99.0.0");
    pre["prerelease"] = json!(true);
    for json in [draft, pre, release("99.0.0"), release("nightly")] {
        assert_eq!(offer_from(&bytes(&json), &current, TARGET), Ok(None));
    }
}

#[tokio::test]
async fn missing_sha256_is_no_update() {
    let mut json = release("v99.0.0");
    json["assets"].as_array_mut().unwrap().pop();
    let server = serve(200, bytes(&json), None).await;
    assert_eq!(check(&server).await, Ok(None));
}

#[tokio::test]
async fn foreign_asset_host_is_refused() {
    let mut json = release("v99.0.0");
    json["assets"][0]["browser_download_url"] = json!("https://evil.example/kv.tar.xz");
    let server = serve(200, bytes(&json), None).await;
    assert!(matches!(
        check(&server).await,
        Err(UpdateError::Malformed(_))
    ));

    let mut json = release("v99.0.0");
    json["assets"][1]["browser_download_url"] =
        json!("http://github.com/DFanso/key-vault-for-llm/x.sha256");
    assert!(matches!(
        offer_from(&bytes(&json), &current_version(), TARGET),
        Err(UpdateError::Malformed(_))
    ));
}

#[tokio::test]
async fn rate_limit_and_junk() {
    let limited = serve(403, b"{}".to_vec(), Some(("x-ratelimit-remaining", "0"))).await;
    let err = check(&limited).await.unwrap_err();
    assert_eq!(err, UpdateError::RateLimited);

    let junk = serve(200, b"<html>Oops</html>".to_vec(), None).await;
    let err2 = check(&junk).await.unwrap_err();
    assert!(matches!(err2, UpdateError::Malformed(_)));

    for e in [err, err2] {
        let text = e.to_string();
        assert!(!text.contains('\n'), "{text}");
        assert!(!text.contains('{') && !text.contains("serde"), "{text}");
    }
}

#[tokio::test]
async fn other_failures_are_network_errors() {
    let server = serve(500, b"boom".to_vec(), None).await;
    assert!(matches!(check(&server).await, Err(UpdateError::Network(_))));
}

#[tokio::test]
async fn oversized_reply_is_refused() {
    let server = serve(200, vec![b' '; 2 * 1024 * 1024], None).await;
    assert!(matches!(
        check(&server).await,
        Err(UpdateError::TooLarge(_))
    ));
}

async fn redirecting_to(location: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", location))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn redirects_off_github_or_to_plain_http_are_refused() {
    for target in [
        "https://evil.example/x",
        "http://github.com/DFanso/key-vault-for-llm/x",
        "https://github.com.evil.example/x",
    ] {
        let server = redirecting_to(target).await;
        let result = client()
            .unwrap()
            .get(format!("{}/start", server.uri()))
            .send()
            .await;
        assert!(result.is_err(), "{target} was followed");
    }
}

#[test]
fn redirect_rules_allow_five_hops_and_refuse_the_sixth() {
    let ok = |s: &str, n| redirect_allowed(&s.parse().unwrap(), n);
    for hops in 0..5 {
        assert!(ok("https://github.com/a", hops), "hop {}", hops + 1);
    }
    assert!(!ok("https://github.com/a", 5), "sixth hop");
    assert!(ok("https://api.github.com/a", 0));
    assert!(ok("https://objects.githubusercontent.com/a", 0));
    assert!(!ok("http://github.com/a", 0));
    assert!(!ok("https://evil.example/a", 0));
    assert!(!ok("https://githubusercontent.com.evil.example/a", 0));
}
