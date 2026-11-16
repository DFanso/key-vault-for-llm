//! Asking GitHub whether a newer release exists.

use std::time::Duration;

use reqwest::{Client, ClientBuilder, StatusCode, header, redirect};
use semver::Version;
use serde::Deserialize;
use url::Url;

use super::{Asset, Offer, UpdateError, archive_name, parse_tag};

/// The most of GitHub's reply kv will read.
const MAX_REPLY: usize = 1024 * 1024;
/// How many redirects a download may follow.
const MAX_REDIRECTS: usize = 5;

/// Whether kv may fetch from `url`: https, on GitHub or one of its
/// content hosts. Used for asset links and for every redirect.
pub fn allowed_url(url: &Url) -> bool {
    if url.scheme() != "https" {
        return false;
    }
    match url.host_str() {
        Some(host) => {
            host == "github.com"
                || host == "api.github.com"
                || host.ends_with(".githubusercontent.com")
        }
        None => false,
    }
}

/// Whether a download may follow a redirect to `next`, having already
/// followed `followed` redirects: at most five in all, each to https on
/// GitHub's own hosts.
pub fn redirect_allowed(next: &Url, followed: usize) -> bool {
    followed < MAX_REDIRECTS && allowed_url(next)
}

/// What every updater client shares: it ignores proxy settings, follows
/// at most five redirects and only to https on GitHub's own hosts, and
/// names itself `kv/<version>` and nothing more.
fn builder() -> ClientBuilder {
    Client::builder()
        .redirect(redirect::Policy::custom(|attempt| {
            // `previous` holds the original URL too, so it is one longer
            // than the number of redirects already followed.
            let followed = attempt.previous().len().saturating_sub(1);
            if redirect_allowed(attempt.url(), followed) {
                attempt.follow()
            } else {
                attempt.error("redirect refused")
            }
        }))
        .no_proxy()
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("kv/", env!("CARGO_PKG_VERSION")))
}

/// The client for asking GitHub about releases. It ignores proxy
/// settings, follows at most five redirects and only to https on GitHub's
/// own hosts, names itself `kv/<version>` and nothing more, and gives up
/// on a request after two minutes.
pub fn client() -> reqwest::Result<Client> {
    builder().timeout(Duration::from_secs(120)).build()
}

/// The client for downloading a release: the same rules as [`client`],
/// but a request may take fifteen minutes, so a 64 MiB archive arrives
/// over a slow connection too.
pub fn download_client() -> reqwest::Result<Client> {
    builder().timeout(Duration::from_secs(15 * 60)).build()
}

#[derive(Deserialize)]
struct ReleaseJson {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    assets: Vec<AssetJson>,
}

#[derive(Deserialize)]
struct AssetJson {
    name: String,
    browser_download_url: String,
    size: u64,
}

fn malformed(what: &str) -> UpdateError {
    UpdateError::Malformed(what.to_owned())
}

fn to_asset(found: &AssetJson) -> Result<Asset, UpdateError> {
    let url = Url::parse(&found.browser_download_url)
        .map_err(|_| malformed("a download link is not a valid address"))?;
    if !allowed_url(&url) {
        return Err(malformed("a download link points outside GitHub"));
    }
    Ok(Asset {
        name: found.name.clone(),
        url,
        size: found.size,
    })
}

/// What GitHub's "latest release" answer offers a build of version
/// `current` on `target`. `None` means nothing to update to: the release is
/// a draft or pre-release, is not newer, or has no archive and checksum
/// for this platform. Anything that does not look like a release, or whose
/// download links leave GitHub, is `Malformed`.
pub fn offer_from(
    json: &[u8],
    current: &Version,
    target: &str,
) -> Result<Option<Offer>, UpdateError> {
    let release: ReleaseJson =
        serde_json::from_slice(json).map_err(|_| malformed("it could not be read"))?;
    if release.draft || release.prerelease {
        return Ok(None);
    }
    let Some(version) = parse_tag(&release.tag_name) else {
        return Ok(None);
    };
    if version <= *current {
        return Ok(None);
    }
    let archive_name = archive_name(target);
    let checksum_name = format!("{archive_name}.sha256");
    let find = |name: &str| release.assets.iter().find(|a| a.name == name);
    let (Some(archive), Some(checksum)) = (find(&archive_name), find(&checksum_name)) else {
        return Ok(None);
    };
    Ok(Some(Offer {
        version,
        notes_url: release.html_url,
        archive: to_asset(archive)?,
        checksum: to_asset(checksum)?,
    }))
}

/// Asks GitHub at `url` for the latest release and returns what
/// [`offer_from`] makes of it. The reply is read in pieces and refused
/// once it passes 1 MiB.
pub async fn latest(
    client: &Client,
    url: &str,
    current: &Version,
    target: &str,
) -> Result<Option<Offer>, UpdateError> {
    let mut response = client
        .get(url)
        .header(header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| UpdateError::Network(e.without_url().to_string()))?;
    let status = response.status();
    if !status.is_success() {
        let exhausted = response
            .headers()
            .get("x-ratelimit-remaining")
            .is_some_and(|v| v.as_bytes() == b"0");
        return Err(
            if exhausted
                && matches!(
                    status,
                    StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
                )
            {
                UpdateError::RateLimited
            } else {
                UpdateError::Network(format!("GitHub answered {status}"))
            },
        );
    }
    let too_large = || UpdateError::TooLarge("release information");
    if response
        .content_length()
        .is_some_and(|len| len > MAX_REPLY as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| UpdateError::Network(e.without_url().to_string()))?
    {
        if body.len() + chunk.len() > MAX_REPLY {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    offer_from(&body, current, target)
}
