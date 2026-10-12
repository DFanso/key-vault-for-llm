//! kv's window page, as the binary embeds and serves it: only its own
//! files, each with the Content-Security-Policy, and nothing in them that
//! could turn agent text into markup or code.

use kv::tray::window::{CSP, PAGE_URL, asset, is_page_url};

const FILES: [&str; 3] = ["/index.html", "/app.js", "/app.css"];

#[test]
fn the_page_and_only_the_page_is_served() {
    let index = asset("/").unwrap();
    assert_eq!(index.mime, "text/html");
    assert_eq!(asset("/index.html").unwrap().body, index.body);
    assert_eq!(asset("/app.js").unwrap().mime, "text/javascript");
    assert_eq!(asset("/app.css").unwrap().mime, "text/css");
    for path in [
        "",
        "/nope.js",
        "/../Cargo.toml",
        "/app.js/",
        "/APP.JS",
        "//app.js",
    ] {
        assert!(asset(path).is_none(), "{path:?}");
    }
}

#[test]
fn the_policy_allows_only_the_pages_own_files() {
    assert_eq!(
        CSP,
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'"
    );
    let index = asset("/index.html").unwrap().body;
    assert!(
        index.contains(&format!(
            r#"<meta http-equiv="Content-Security-Policy" content="{CSP}">"#
        )),
        "the page carries the policy itself too"
    );
}

#[test]
fn the_page_never_writes_markup_or_runs_strings() {
    for path in FILES {
        let body = asset(path).unwrap().body;
        for banned in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
            "javascript:",
        ] {
            assert!(!body.contains(banned), "{path} uses {banned}");
        }
    }
    let index = asset("/index.html").unwrap().body;
    // Every script is a file; no inline script or handler attribute.
    for (at, _) in index.match_indices("<script") {
        let tag = &index[at..];
        let end = tag.find("</script>").unwrap();
        assert!(tag[..end].contains(r#"src="app.js""#), "{}", &tag[..end]);
        assert!(tag[..end].ends_with('>'), "inline script: {}", &tag[..end]);
    }
    let lower = index.to_lowercase();
    for handler in [
        " onclick=",
        " onload=",
        " onerror=",
        " onsubmit=",
        " oninput=",
    ] {
        assert!(!lower.contains(handler), "{handler}");
    }
}

#[test]
fn messages_count_only_from_the_page() {
    assert!(is_page_url(PAGE_URL));
    for url in [
        "https://example.com/",
        "kv://app.evil.example/index.html",
        "https://kv.app.evil.example/index.html",
        "kv://appx/index.html",
        "",
    ] {
        assert!(!is_page_url(url), "{url}");
    }
}
