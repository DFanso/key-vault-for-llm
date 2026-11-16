use kv::paths::Paths;
use kv::update::{
    archive_name, checks_enabled, current_version, is_release_build, parse_tag, target,
};
use semver::Version;

#[test]
fn tags_need_a_v_and_no_pre_release() {
    assert_eq!(parse_tag("v1.9.0"), Some(Version::new(1, 9, 0)));
    assert_eq!(parse_tag("1.9.0"), None);
    assert_eq!(parse_tag("v1.9.0-rc.1"), None);
    assert_eq!(parse_tag("vX"), None);
}

#[test]
fn archive_names_follow_the_platform() {
    assert_eq!(
        archive_name("x86_64-pc-windows-msvc"),
        "kv-x86_64-pc-windows-msvc.zip"
    );
    assert_eq!(
        archive_name("aarch64-apple-darwin"),
        "kv-aarch64-apple-darwin.tar.xz"
    );
}

#[test]
fn target_is_known_on_ci_platforms() {
    if cfg!(any(target_os = "macos", target_os = "linux", windows)) {
        assert!(target().is_some());
    }
}

#[test]
fn off_words_turn_checks_off() {
    assert!(checks_enabled(None));
    assert!(!checks_enabled(Some("off".as_ref())));
    assert!(!checks_enabled(Some("0".as_ref())));
    assert!(!checks_enabled(Some("False".as_ref())));
    assert!(checks_enabled(Some("on".as_ref())));
    assert!(checks_enabled(Some("garbage".as_ref())));
}

#[test]
fn version_and_build_kind() {
    assert_eq!(
        current_version(),
        Version::parse(env!("CARGO_PKG_VERSION")).unwrap()
    );
    assert_eq!(is_release_build(), cfg!(feature = "release-build"));
}

#[test]
fn update_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::under(tmp.path());
    assert!(paths.update_state_file().ends_with("update.json"));
    assert!(
        paths
            .update_lock_file()
            .ends_with(std::path::Path::new("run").join("update.lock"))
    );
}

/// A newer kv found by an earlier check is told on every run, without
/// asking GitHub again before the day is out; only a release build tells.
#[tokio::test]
async fn a_known_update_is_told_on_every_run() {
    use kv::update::state::{UpdateState, save};
    use kv::update::update_notice;

    if !checks_enabled(std::env::var_os("KV_UPDATE_CHECK").as_deref()) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::under(tmp.path());
    let file = paths.update_state_file();
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    let now = 1_000_000;
    let remembered = UpdateState {
        last_check: Some(now - 60),
        latest: Some("999.0.0".into()),
        announced: None,
    };
    save(&file, &remembered).unwrap();
    let expected = cfg!(feature = "release-build").then(|| "kv 999.0.0 is out: run `kv update`.");
    for _ in 0..2 {
        assert_eq!(update_notice(&paths, now).await.as_deref(), expected);
    }
    // Not asked again: the last check stays as it was.
    assert_eq!(kv::update::state::load(&file), remembered);
}
