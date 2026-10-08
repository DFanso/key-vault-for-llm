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

use super::{HttpJob, capped_text};
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
