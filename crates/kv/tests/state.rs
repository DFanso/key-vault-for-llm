use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use kv::audit::Audit;
use kv::daemon::{After, Daemon, Prepared, Settings};
use kv_core::policy::{Mode, Policy};
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlRequest,
    ControlResponse, PolicyPatch,
};
use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
use tempfile::TempDir;

const PASS: &str = "correct horse battery";
const TOKEN: &str = "sk-or-v1-0123456789abcdef";

struct Fixture {
    dir: TempDir,
    daemon: Daemon,
    t0: Instant,
}

impl Fixture {
    fn new() -> Self {
        Self::with_settings(Settings::default())
    }

    fn with_settings(settings: Settings) -> Self {
        let dir = TempDir::new().unwrap();
        let t0 = Instant::now();
        let daemon = Daemon::new(
            dir.path().join("vault").join("vault.kv"),
            Audit::new(dir.path().join("audit.jsonl")),
            settings,
            t0,
        );
        Self { dir, daemon, t0 }
    }

    fn initialized() -> Self {
        let mut f = Self::new();
        f.init();
        f
    }

    fn init(&mut self) {
        let response = self.control(
            Some(PASS),
            ControlCommand::Init {
                insecure_fast_kdf: true,
            },
        );
        assert_done(&response);
    }

    fn control(&mut self, passphrase: Option<&str>, command: ControlCommand) -> ControlResponse {
        self.control_at(self.t0, passphrase, command).0
    }

    fn control_at(
        &mut self,
        now: Instant,
        passphrase: Option<&str>,
        command: ControlCommand,
    ) -> (ControlResponse, After) {
        self.daemon.handle_control(
            ControlRequest {
                passphrase: passphrase.map(SecretText::new),
                token: None,
                command,
            },
            now,
        )
    }

    fn agent(&mut self, request: AgentRequest) -> AgentResponse {
        self.agent_at(self.t0, request)
    }

    fn agent_at(&mut self, now: Instant, request: AgentRequest) -> AgentResponse {
        match self.daemon.prepare(request, now) {
            Prepared::Reply(response) => response,
            Prepared::Http(_) | Prepared::Exec(_) => panic!("expected a reply, got a job"),
        }
    }

    fn handles(&mut self) -> Vec<String> {
        match self.agent(AgentRequest::ListHandles) {
            AgentResponse::Handles { handles } => handles.into_iter().map(|h| h.name).collect(),
            other => panic!("expected handles, got {other:?}"),
        }
    }

    #[cfg(unix)]
    fn vault_dir(&self) -> PathBuf {
        self.dir.path().join("vault")
    }
}

fn http_secret(name: &str) -> Secret {
    Secret {
        name: name.into(),
        description: "OpenRouter".into(),
        value: SecretValue::Http {
            token: SecretText::new(TOKEN),
            placement: AuthPlacement::Header {
                name: "Authorization".into(),
                template: "Bearer {}".into(),
            },
            base_url: None,
        },
        policy: Policy {
            allowed_hosts: vec!["openrouter.ai".into()],
            ..Policy::default()
        },
        created_at: 0,
        updated_at: 0,
    }
}

fn add(name: &str) -> ControlCommand {
    ControlCommand::Add {
        secret: http_secret(name),
        replace: false,
    }
}

fn assert_done(response: &ControlResponse) {
    assert!(
        matches!(response, ControlResponse::Done { .. }),
        "{response:?}"
    );
}

fn error_code(response: &ControlResponse) -> ControlErrorCode {
    match response {
        ControlResponse::Error { code, .. } => *code,
        other => panic!("expected an error, got {other:?}"),
    }
}

#[test]
fn list_before_init_reports_no_vault() {
    let mut f = Fixture::new();
    let response = f.agent(AgentRequest::ListHandles);
    assert!(matches!(
        response,
        AgentResponse::Error {
            code: AgentErrorCode::NoVault,
            ..
        }
    ));
}

#[test]
fn init_unlocks_and_add_shows_up_in_list() {
    let mut f = Fixture::initialized();
    assert!(f.daemon.is_unlocked());
    assert_done(&f.control(Some(PASS), add("openrouter")));
    assert_eq!(f.handles(), vec!["openrouter"]);
}

#[test]
fn init_refuses_an_existing_vault_and_a_short_passphrase() {
    let mut f = Fixture::initialized();
    let again = f.control(
        Some(PASS),
        ControlCommand::Init {
            insecure_fast_kdf: true,
        },
    );
    assert_eq!(error_code(&again), ControlErrorCode::VaultExists);

    let mut fresh = Fixture::new();
    let short = fresh.control(
        Some("short"),
        ControlCommand::Init {
            insecure_fast_kdf: true,
        },
    );
    assert_eq!(error_code(&short), ControlErrorCode::Invalid);
}

#[test]
fn control_commands_need_the_right_passphrase() {
    let mut f = Fixture::initialized();
    assert_eq!(
        error_code(&f.control(None, add("openrouter"))),
        ControlErrorCode::PassphraseRequired
    );
    assert_eq!(
        error_code(&f.control(Some("wrong horse battery"), add("openrouter"))),
        ControlErrorCode::WrongPassphrase
    );
    assert!(f.handles().is_empty());
}

#[test]
fn lock_needs_no_passphrase_and_unlock_needs_one() {
    let mut f = Fixture::initialized();
    assert_done(&f.control(None, ControlCommand::Lock));
    assert!(matches!(
        f.agent(AgentRequest::ListHandles),
        AgentResponse::Error {
            code: AgentErrorCode::VaultLocked,
            ..
        }
    ));
    assert_eq!(
        error_code(&f.control(None, ControlCommand::Unlock)),
        ControlErrorCode::PassphraseRequired
    );
    assert_done(&f.control(Some(PASS), ControlCommand::Unlock));
    assert!(f.daemon.is_unlocked());
}

#[test]
fn a_control_command_with_the_passphrase_unlocks_a_locked_vault() {
    let mut f = Fixture::initialized();
    assert_done(&f.control(None, ControlCommand::Lock));
    assert_done(&f.control(Some(PASS), add("openrouter")));
    assert!(f.daemon.is_unlocked());
}

#[test]
fn wrong_passphrases_back_off_even_for_the_right_one() {
    let mut f = Fixture::initialized();
    assert_done(&f.control(None, ControlCommand::Lock));
    for _ in 0..5 {
        let (response, _) = f.control_at(f.t0, Some("wrong horse battery"), ControlCommand::Unlock);
        assert_eq!(error_code(&response), ControlErrorCode::WrongPassphrase);
    }
    let (blocked, _) = f.control_at(f.t0, Some(PASS), ControlCommand::Unlock);
    assert_eq!(error_code(&blocked), ControlErrorCode::TooManyAttempts);
    assert!(!f.daemon.is_unlocked());

    let later = f.t0 + Duration::from_secs(2);
    let (allowed, _) = f.control_at(later, Some(PASS), ControlCommand::Unlock);
    assert_done(&allowed);
}

#[test]
fn add_needs_replace_to_overwrite() {
    let mut f = Fixture::initialized();
    assert_done(&f.control(Some(PASS), add("openrouter")));
    assert_eq!(
        error_code(&f.control(Some(PASS), add("openrouter"))),
        ControlErrorCode::HandleExists
    );
    let replace = ControlCommand::Add {
        secret: http_secret("openrouter"),
        replace: true,
    };
    assert_done(&f.control(Some(PASS), replace));
}

#[test]
fn add_rejects_unusable_values() {
    let mut f = Fixture::initialized();
    let mut no_placeholder = http_secret("bad-template");
    no_placeholder.value = SecretValue::Http {
        token: SecretText::new(TOKEN),
        placement: AuthPlacement::Header {
            name: "Authorization".into(),
            template: "Bearer".into(),
        },
        base_url: None,
    };
    let mut no_vars = http_secret("no-vars");
    no_vars.value = SecretValue::Env {
        vars: BTreeMap::new(),
    };
    let mut bad_name = http_secret("Bad Name");
    bad_name.policy = Policy::default();
    for secret in [no_placeholder, no_vars, bad_name] {
        let response = f.control(
            Some(PASS),
            ControlCommand::Add {
                secret,
                replace: false,
            },
        );
        assert_eq!(error_code(&response), ControlErrorCode::Invalid);
    }
    assert!(f.handles().is_empty());
}

#[test]
fn add_warns_about_short_values_and_empty_allow_lists() {
    let mut f = Fixture::initialized();
    let mut secret = http_secret("tiny");
    secret.value = SecretValue::Http {
        token: SecretText::new("abc"),
        placement: AuthPlacement::Query {
            param: "key".into(),
        },
        base_url: None,
    };
    secret.policy = Policy::default();
    let response = f.control(
        Some(PASS),
        ControlCommand::Add {
            secret,
            replace: false,
        },
    );
    let ControlResponse::Done { warnings } = response else {
        panic!("expected done, got {response:?}");
    };
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(warnings[0].contains("shorter than 8"));
    assert!(warnings[1].contains("no allowed hosts"));
}

#[test]
fn set_policy_and_remove_change_the_vault() {
    let mut f = Fixture::initialized();
    assert_done(&f.control(Some(PASS), add("openrouter")));
    let patch = PolicyPatch {
        mode: Some(Mode::Deny),
        ..PolicyPatch::default()
    };
    assert_done(&f.control(
        Some(PASS),
        ControlCommand::SetPolicy {
            name: "openrouter".into(),
            patch,
        },
    ));
    match f.agent(AgentRequest::ListHandles) {
        AgentResponse::Handles { handles } => assert_eq!(handles[0].mode, Mode::Deny),
        other => panic!("{other:?}"),
    }
    assert_done(&f.control(
        Some(PASS),
        ControlCommand::Remove {
            name: "openrouter".into(),
        },
    ));
    assert!(f.handles().is_empty());
    assert_eq!(
        error_code(&f.control(
            Some(PASS),
            ControlCommand::Remove {
                name: "openrouter".into()
            }
        )),
        ControlErrorCode::UnknownHandle
    );
}

#[test]
fn change_passphrase_takes_effect() {
    let mut f = Fixture::initialized();
    assert_done(&f.control(
        Some(PASS),
        ControlCommand::ChangePassphrase {
            new_passphrase: SecretText::new("a brand new passphrase"),
        },
    ));
    assert_eq!(
        error_code(&f.control(Some(PASS), ControlCommand::Unlock)),
        ControlErrorCode::WrongPassphrase
    );
    assert_done(&f.control(Some("a brand new passphrase"), ControlCommand::Unlock));
}

#[cfg(unix)]
#[test]
fn a_failed_save_leaves_the_vault_as_it_was() {
    use std::os::unix::fs::PermissionsExt;
    let mut f = Fixture::initialized();
    assert_done(&f.control(Some(PASS), add("keep")));
    let dir = f.vault_dir();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    let added = f.control(Some(PASS), add("new-one"));
    let removed = f.control(
        Some(PASS),
        ControlCommand::Remove {
            name: "keep".into(),
        },
    );
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(error_code(&added), ControlErrorCode::Internal);
    assert_eq!(error_code(&removed), ControlErrorCode::Internal);
    assert_eq!(f.handles(), vec!["keep"]);
}

#[test]
fn idle_vault_locks_and_status_polls_do_not_keep_it_open() {
    let mut f = Fixture::with_settings(Settings {
        idle_lock: Duration::from_secs(10),
        locked_exit: Duration::from_secs(600),
    });
    f.init();
    let status_at = f.t0 + Duration::from_secs(9);
    match f.agent_at(status_at, AgentRequest::Status) {
        AgentResponse::Status { status } => {
            assert!(!status.locked);
            assert_eq!(status.locks_in_secs, Some(1));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        f.daemon
            .tick(f.t0 + Duration::from_secs(11), SystemTime::now()),
        After::Continue
    );
    assert!(!f.daemon.is_unlocked());
}

#[test]
fn locked_daemon_exits_after_a_quiet_period() {
    let mut f = Fixture::with_settings(Settings {
        idle_lock: Duration::from_secs(10),
        locked_exit: Duration::from_secs(60),
    });
    assert_eq!(
        f.daemon
            .tick(f.t0 + Duration::from_secs(59), SystemTime::now()),
        After::Continue
    );
    f.agent_at(f.t0 + Duration::from_secs(59), AgentRequest::Status);
    assert_eq!(
        f.daemon
            .tick(f.t0 + Duration::from_secs(100), SystemTime::now()),
        After::Continue
    );
    assert_eq!(
        f.daemon
            .tick(f.t0 + Duration::from_secs(120), SystemTime::now()),
        After::Stop
    );
}

#[test]
fn stop_locks_and_asks_the_server_to_exit() {
    let mut f = Fixture::initialized();
    let (response, after) = f.control_at(f.t0, None, ControlCommand::Stop);
    assert_done(&response);
    assert_eq!(after, After::Stop);
    assert!(!f.daemon.is_unlocked());
}

#[test]
fn audit_log_records_actions_without_secret_values() {
    let mut f = Fixture::initialized();
    assert_done(&f.control(Some(PASS), add("openrouter")));
    f.handles();
    let log = fs::read_to_string(f.dir.path().join("audit.jsonl")).unwrap();
    assert!(log.contains(r#""action":"add""#), "{log}");
    assert!(log.contains(r#""handle":"openrouter""#), "{log}");
    assert!(log.contains(r#""action":"list_handles""#), "{log}");
    assert!(!log.contains(TOKEN), "{log}");
    assert!(!log.contains(PASS), "{log}");
}

#[test]
fn time_asleep_counts_toward_the_idle_lock() {
    let mut f = Fixture::with_settings(Settings {
        idle_lock: Duration::from_secs(8 * 3600),
        locked_exit: Duration::from_secs(600),
    });
    f.init();
    // One awake minute later, but the wall clock says the lid was shut all night.
    let awake = f.t0 + Duration::from_secs(60);
    let wall = SystemTime::now() + Duration::from_secs(16 * 3600);
    f.daemon.tick(awake, wall);
    assert!(!f.daemon.is_unlocked());
}

#[test]
fn a_wall_clock_set_backwards_does_not_keep_the_vault_open() {
    let mut f = Fixture::with_settings(Settings {
        idle_lock: Duration::from_secs(10),
        locked_exit: Duration::from_secs(600),
    });
    f.init();
    let wall = SystemTime::now() - Duration::from_secs(3600);
    f.daemon.tick(f.t0 + Duration::from_secs(11), wall);
    assert!(!f.daemon.is_unlocked());
}

fn base_url_secret(name: &str, base: &str) -> Secret {
    let mut secret = http_secret(name);
    secret.value = SecretValue::Http {
        token: SecretText::new(TOKEN),
        placement: AuthPlacement::Header {
            name: "Authorization".into(),
            template: "Bearer {}".into(),
        },
        base_url: Some(base.into()),
    };
    secret.policy = Policy::default();
    secret
}

fn add_secret(f: &mut Fixture, secret: Secret) -> ControlResponse {
    f.control(
        Some(PASS),
        ControlCommand::Add {
            secret,
            replace: false,
        },
    )
}

#[test]
fn add_rejects_unusable_base_urls() {
    let mut f = Fixture::initialized();
    for base in [
        "not a url",
        "ftp://files.example.com",
        "https://user:pw@dokploy.example.com",
        "https://dokploy.example.com/api?x=1",
        "https://dokploy.example.com/api#top",
    ] {
        let response = add_secret(&mut f, base_url_secret("dokploy", base));
        assert_eq!(error_code(&response), ControlErrorCode::Invalid, "{base}");
        if let ControlResponse::Error { message, .. } = &response {
            assert!(!message.contains("dokploy.example.com"), "{message}");
        }
    }
}

#[test]
fn a_base_url_handle_needs_no_allowed_hosts() {
    let mut f = Fixture::initialized();
    match add_secret(
        &mut f,
        base_url_secret("dokploy", "https://dokploy.example.com/api"),
    ) {
        ControlResponse::Done { warnings } => assert!(warnings.is_empty(), "{warnings:?}"),
        other => panic!("{other:?}"),
    }
    match add_secret(&mut f, base_url_secret("lan", "http://10.0.0.5:3000/api")) {
        ControlResponse::Done { warnings } => {
            assert_eq!(warnings.len(), 1, "{warnings:?}");
            assert!(warnings[0].contains("--allow-plain-http true"));
        }
        other => panic!("{other:?}"),
    }
}
