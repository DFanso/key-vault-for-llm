use std::collections::BTreeMap;

use kv_core::crypto::KdfParams;
use kv_core::secret::SecretKind;
use kv_core::secret::{AuthPlacement, SecretText, SecretValue};
use kv_core::share::{
    OpenRequest, REQUEST_PREFIX, Received, SHARE_PREFIX, ShareError, ShareRequest, SharedSecret,
    Shares, open, safety_code, seal, value_digest,
};
use kv_core::vault::Vault;

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 24 * 60 * 60;

fn request() -> OpenRequest {
    OpenRequest::new("staging db".into(), "iddhi".into(), NOW, DAY)
}

fn token(value: &str) -> SharedSecret {
    SharedSecret {
        name: "openrouter".into(),
        description: "OpenRouter key".into(),
        value: SecretValue::Http {
            token: SecretText::new(value),
            placement: AuthPlacement::Header {
                name: "Authorization".into(),
                template: "Bearer {}".into(),
            },
            base_url: None,
        },
        allowed_hosts: vec!["openrouter.ai".into()],
        allow_plain_http: false,
        allowed_methods: vec!["POST".into()],
        read_only: false,
        from: "leo".into(),
        note: "for the eval script".into(),
    }
}

#[test]
fn a_request_code_round_trips_without_the_private_key() {
    let open_request = request();
    let code = open_request.code();
    assert!(code.starts_with(REQUEST_PREFIX));
    let decoded = ShareRequest::decode(&code).unwrap();
    assert_eq!(decoded, open_request.request());
    assert_eq!(decoded.note, "staging db");
    assert_eq!(decoded.from, "iddhi");
    // The code is the public half only.
    let json = serde_json::to_string(&open_request).unwrap();
    let secret_key = serde_json::from_str::<serde_json::Value>(&json).unwrap()["secret_key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!code.contains(&secret_key));
    assert!(!format!("{open_request:?}").contains(&secret_key));
}

#[test]
fn a_request_code_is_found_inside_a_chat_message() {
    let code = request().code();
    let message = format!("hey, can you send me the key?\n\n`{code}`\nthanks");
    assert_eq!(
        ShareRequest::decode(&message).unwrap(),
        ShareRequest::decode(&code).unwrap()
    );
    assert_eq!(
        ShareRequest::decode("kv-request:v1:@@@"),
        Err(ShareError::NotARequest)
    );
    assert_eq!(
        ShareRequest::decode("no code here"),
        Err(ShareError::NotARequest)
    );
}

#[test]
fn only_the_requesting_vault_opens_a_share() {
    let mine = request();
    let theirs = OpenRequest::new(String::new(), String::new(), NOW, DAY);
    let sealed = seal(&mine.request(), &token("sk-or-v1-0123456789abcdef")).unwrap();
    assert!(sealed.starts_with(SHARE_PREFIX));
    assert!(!sealed.contains("sk-or-v1"));

    let (index, opened) = open(&sealed, &[theirs.clone(), mine.clone()]).unwrap();
    assert_eq!(index, 1);
    assert_eq!(opened, token("sk-or-v1-0123456789abcdef"));

    assert_eq!(
        open(&sealed, &[theirs]).unwrap_err(),
        ShareError::NoMatchingRequest
    );
    assert_eq!(
        open(&sealed, &[]).unwrap_err(),
        ShareError::NoMatchingRequest
    );
}

#[test]
fn a_share_survives_chat_formatting() {
    let mine = request();
    let sealed = seal(&mine.request(), &token("sk-or-v1-0123456789abcdef")).unwrap();
    let wrapped = format!("Here you go:\n```\n{sealed}\n```");
    assert!(open(&wrapped, std::slice::from_ref(&mine)).is_ok());
    // The standard base64 alphabet and padding are read too.
    let body = &sealed[SHARE_PREFIX.len()..];
    let standard = format!(
        "{SHARE_PREFIX}{}==",
        body.replace('-', "+").replace('_', "/")
    );
    assert!(open(&standard, std::slice::from_ref(&mine)).is_ok());
}

#[test]
fn a_changed_or_cut_share_does_not_open() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let mine = request();
    let sealed = seal(&mine.request(), &token("sk-or-v1-0123456789abcdef")).unwrap();
    let json = URL_SAFE_NO_PAD
        .decode(&sealed[SHARE_PREFIX.len()..])
        .unwrap();
    let mut wire: serde_json::Value = serde_json::from_slice(&json).unwrap();

    let mut ciphertext = URL_SAFE_NO_PAD.decode(wire["c"].as_str().unwrap()).unwrap();
    ciphertext[0] ^= 1;
    let mut changed = wire.clone();
    changed["c"] = URL_SAFE_NO_PAD.encode(&ciphertext).into();
    let text = format!(
        "{SHARE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&changed).unwrap())
    );
    assert_eq!(
        open(&text, std::slice::from_ref(&mine)).unwrap_err(),
        ShareError::Damaged
    );

    // A different ephemeral key is caught by the AEAD too.
    let other = OpenRequest::new(String::new(), String::new(), NOW, DAY);
    wire["e"] = other.public_key.clone().into();
    let text = format!(
        "{SHARE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&wire).unwrap())
    );
    assert_eq!(
        open(&text, std::slice::from_ref(&mine)).unwrap_err(),
        ShareError::Damaged
    );

    let cut = &sealed[..sealed.len() - 20];
    assert!(open(cut, std::slice::from_ref(&mine)).is_err());
    assert_eq!(
        open("hello", std::slice::from_ref(&mine)).unwrap_err(),
        ShareError::NotAShare
    );
}

#[test]
fn sealing_to_a_low_order_key_is_refused() {
    let zero = ShareRequest {
        public_key: [0; 32],
        note: String::new(),
        from: String::new(),
    };
    assert_eq!(
        seal(&zero, &token("sk-or-v1-0123456789abcdef")).unwrap_err(),
        ShareError::WeakKey
    );
}

#[test]
fn every_kind_of_value_round_trips() {
    let mine = request();
    let values = [
        SecretValue::Postgres {
            url: SecretText::new("postgres://app:pw@db.example.com/app"),
        },
        SecretValue::Redis {
            url: SecretText::new("rediss://:pw@cache.example.com:6380"),
        },
        SecretValue::Env {
            vars: BTreeMap::from([
                (
                    "AWS_ACCESS_KEY_ID".into(),
                    SecretText::new("AKIAEXAMPLEKEY0123456"),
                ),
                (
                    "AWS_SECRET_ACCESS_KEY".into(),
                    SecretText::new("wJalrXUtnFEMI/K7MDENG"),
                ),
            ]),
        },
        SecretValue::Http {
            token: SecretText::new("dokploy-key-0123456789"),
            placement: AuthPlacement::Query {
                param: "key".into(),
            },
            base_url: Some("https://dokploy.example.com/api".into()),
        },
    ];
    for value in values {
        let secret = SharedSecret {
            value: value.clone(),
            ..token("unused-0123456789")
        };
        let sealed = seal(&mine.request(), &secret).unwrap();
        let (_, opened) = open(&sealed, std::slice::from_ref(&mine)).unwrap();
        assert_eq!(opened.value, value);
    }
}

#[test]
fn safety_codes_are_short_stable_and_differ_per_key() {
    let a = request();
    let b = request();
    let code = a.safety_code();
    assert_eq!(code.len(), 9);
    assert_eq!(&code[4..5], "-");
    assert!(
        code.chars()
            .all(|c| c == '-' || c.is_ascii_digit() || c.is_ascii_uppercase())
    );
    assert_eq!(code, ShareRequest::decode(&a.code()).unwrap().safety_code());
    assert_eq!(code, safety_code(&a.request().public_key));
    assert_ne!(code, b.safety_code());
}

#[test]
fn requests_expire_and_hide_their_key_in_the_view() {
    let open_request = request();
    assert!(!open_request.is_expired(NOW + DAY - 1));
    assert!(open_request.is_expired(NOW + DAY));
    let shares = Shares {
        requests: vec![open_request.clone()],
        ..Shares::default()
    };
    let view = shares.view(NOW + DAY, |_| None);
    assert!(view.requests[0].expired);
    assert_eq!(view.requests[0].code, open_request.code());
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("secret_key"));
}

#[test]
fn a_received_value_is_viewable_only_while_the_handle_still_holds_it() {
    let value = token("sk-or-v1-0123456789abcdef").value;
    let digest = value_digest(&value);
    assert_eq!(digest, value_digest(&value.clone()));
    assert_ne!(
        digest,
        value_digest(&token("sk-or-v1-another-value-0").value)
    );
    let shares = Shares {
        received: vec![Received {
            id: "r1".into(),
            handle: "openrouter".into(),
            kind: SecretKind::Http,
            from: "leo".into(),
            note: String::new(),
            safety_code: "ABCD-EFGH".into(),
            received_at: NOW,
            value_digest: digest.clone(),
        }],
        ..Shares::default()
    };
    assert!(shares.holds_received("openrouter", &digest));
    assert!(!shares.holds_received("openrouter", "other"));
    assert!(!shares.holds_received("other", &digest));
    let same = shares.view(NOW, |_| Some(digest.clone()));
    assert!(same.received[0].viewable);
    let changed = shares.view(NOW, |_| Some("other".into()));
    assert!(!changed.received[0].viewable);
    let gone = shares.view(NOW, |_| None);
    assert!(!gone.received[0].viewable);
    // The digest stays in the vault.
    assert!(!serde_json::to_string(&same).unwrap().contains(&digest));
}

#[test]
fn forget_removes_by_id_from_any_list() {
    let mut shares = Shares {
        requests: vec![request(), request()],
        ..Shares::default()
    };
    let id = shares.requests[0].id.clone();
    assert!(shares.forget(&id));
    assert_eq!(shares.requests.len(), 1);
    assert!(!shares.forget(&id));
}

#[test]
fn the_vault_keeps_shares_and_reads_vaults_without_them() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("vault.kv");
    let fast = KdfParams {
        m_kib: 8,
        t: 1,
        p: 1,
    };
    let mut vault = Vault::create(&path, "correct horse battery", fast).unwrap();
    assert!(vault.shares().is_empty());
    let open_request = request();
    vault
        .replace_shares(Shares {
            requests: vec![open_request.clone()],
            ..Shares::default()
        })
        .unwrap();
    let reopened = Vault::unlock(&path, "correct horse battery").unwrap();
    assert_eq!(reopened.shares().requests, vec![open_request.clone()]);
    // The key still opens what is sealed to it after the round trip.
    let sealed = seal(&open_request.request(), &token("sk-or-v1-0123456789abcdef")).unwrap();
    assert!(open(&sealed, &reopened.shares().requests).is_ok());
}

fn file_share(value: SecretValue) -> SharedSecret {
    SharedSecret {
        name: "passwords".into(),
        value,
        ..token("unused-0123456789")
    }
}

#[test]
fn a_file_arrives_byte_for_byte_and_only_the_requester_opens_it() {
    use kv_core::share::MAX_FILE_TEXT_LEN;

    let mine = request();
    // Binary bytes, CRLF, a BOM and no trailing newline, well past the
    // 128 KiB a pasted share holds.
    let mut bytes: Vec<u8> = b"\xEF\xBB\xBFhunter2hunter\r\nsecond line".to_vec();
    bytes.extend((0..300_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8));
    let value = SecretValue::file("passwords.txt", &bytes).unwrap();
    let sealed = seal(&mine.request(), &file_share(value.clone())).unwrap();
    assert!(sealed.starts_with(SHARE_PREFIX));
    assert!(sealed.len() <= MAX_FILE_TEXT_LEN);
    assert!(!sealed.contains("hunter2"));

    let (_, opened) = open(&sealed, std::slice::from_ref(&mine)).unwrap();
    assert_eq!(opened.value, value);
    let (name, back) = opened.value.file_parts().unwrap();
    assert_eq!(name, "passwords.txt");
    assert_eq!(&back[..], &bytes[..]);

    let theirs = OpenRequest::new(String::new(), String::new(), NOW, DAY);
    assert_eq!(
        open(&sealed, &[theirs]).unwrap_err(),
        ShareError::NoMatchingRequest
    );
}

#[test]
fn a_share_of_a_file_holds_up_to_the_largest_file() {
    let mine = request();
    let bytes = vec![0xA5u8; kv_core::secret::MAX_FILE_LEN];
    let value = SecretValue::file("big.bin", &bytes).unwrap();
    let sealed = seal(&mine.request(), &file_share(value)).unwrap();
    let (_, opened) = open(&sealed, std::slice::from_ref(&mine)).unwrap();
    assert_eq!(&opened.value.file_parts().unwrap().1[..], &bytes[..]);
    // Other values keep the smaller limit.
    let long = SharedSecret {
        value: SecretValue::Postgres {
            url: SecretText::new(format!("postgres://u:{}@h/db", "p".repeat(200_000))),
        },
        ..token("unused-0123456789")
    };
    assert_eq!(
        seal(&mine.request(), &long).unwrap_err(),
        ShareError::TooLarge
    );
}

#[test]
fn a_file_that_does_not_match_its_checksum_is_refused_on_both_sides() {
    let mine = request();
    let good = SecretValue::file("list.txt", b"one-secret-line\n").unwrap();
    let SecretValue::File {
        file_name, sha256, ..
    } = good.clone()
    else {
        unreachable!()
    };
    let forged = |name: &str, data: &str, sum: &str| {
        file_share(SecretValue::File {
            file_name: name.into(),
            data: SecretText::new(data),
            sha256: sum.into(),
        })
    };
    // "one-secret-line\n" is b25lLXNlY3JldC1saW5lCg==; this one has a byte changed.
    let changed = "b25lLXNlY3JldC1saW5lCw==";
    for bad in [
        forged(&file_name, changed, &sha256),
        forged(&file_name, "b25lLXNlY3JldC1saW5lCg==", ""),
        forged(
            "../../.ssh/authorized_keys",
            "b25lLXNlY3JldC1saW5lCg==",
            &sha256,
        ),
    ] {
        // The sender will not seal it...
        assert_eq!(
            seal(&mine.request(), &bad).unwrap_err(),
            ShareError::BadFile
        );
    }
    // ...and a receiver refuses one sealed by a sender that did not check.
    let sealed = seal(&mine.request(), &file_share(good)).unwrap();
    assert!(open(&sealed, std::slice::from_ref(&mine)).is_ok());
}

#[test]
fn a_flipped_bit_in_a_sealed_file_is_damage_not_a_different_file() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let mine = request();
    let value = SecretValue::file("list.txt", &vec![7u8; 50_000]).unwrap();
    let sealed = seal(&mine.request(), &file_share(value)).unwrap();
    let json = URL_SAFE_NO_PAD
        .decode(&sealed[SHARE_PREFIX.len()..])
        .unwrap();
    let mut wire: serde_json::Value = serde_json::from_slice(&json).unwrap();
    let mut ciphertext = URL_SAFE_NO_PAD.decode(wire["c"].as_str().unwrap()).unwrap();
    let middle = ciphertext.len() / 2;
    ciphertext[middle] ^= 0x01;
    wire["c"] = URL_SAFE_NO_PAD.encode(&ciphertext).into();
    let text = format!(
        "{SHARE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&wire).unwrap())
    );
    assert_eq!(
        open(&text, std::slice::from_ref(&mine)).unwrap_err(),
        ShareError::Damaged
    );
    // Cut short, it is damage too.
    let cut = &sealed[..sealed.len() - 40];
    assert!(open(cut, std::slice::from_ref(&mine)).is_err());
}
