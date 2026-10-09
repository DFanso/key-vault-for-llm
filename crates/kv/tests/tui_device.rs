//! `kv tui` unlocking with Touch ID or Windows Hello, against a real daemon
//! in this process and a fake device.

mod fake;
mod live;

use std::sync::Arc;

use fake::Fake;
use kv::device::{self, Device};
use kv::tui::Driver;
use kv::tui::app::{Effect, Outcome};
use kv_core::proto::ControlCommand;
use kv_core::vault::DeviceKind;
use live::{Daemon, PASS};

async fn enrolled(daemon: &Daemon) -> Arc<Fake> {
    let fake = Arc::new(Fake::default());
    let (slot, key) = device::enroll(fake.as_ref()).unwrap();
    daemon
        .control(Some(PASS), device::enroll_command(slot, &key))
        .await;
    daemon.control(None, ControlCommand::Lock).await;
    fake
}

#[tokio::test(flavor = "multi_thread")]
async fn an_enrolled_device_opens_the_tui_session() {
    let daemon = Daemon::start().await;
    let fake = enrolled(&daemon).await;
    let mut driver = Driver::with_device(daemon.paths.clone(), Some(fake as Arc<dyn Device>));
    assert_eq!(driver.device(), Some(DeviceKind::TouchId));
    assert!(matches!(
        driver.run(Effect::DeviceUnlock).await,
        Outcome::Opened
    ));
    match driver.refresh().await {
        Some(Outcome::Overview(overview)) => {
            assert!(!overview.status.locked);
            assert_eq!(overview.status.devices, vec![DeviceKind::TouchId]);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_slot_the_tui_does_not_offer_the_device() {
    let daemon = Daemon::start().await;
    let fake: Arc<dyn Device> = Arc::new(Fake::default());
    let mut driver = Driver::with_device(daemon.paths.clone(), Some(fake));
    assert_eq!(driver.device(), None);
    match driver.run(Effect::DeviceUnlock).await {
        Outcome::Failed(message) => assert!(message.contains("kv biometric enable"), "{message}"),
        other => panic!("{other:?}"),
    }
    let mut driver = Driver::with_device(daemon.paths.clone(), None);
    assert_eq!(driver.device(), None);
    assert!(matches!(
        driver.run(Effect::DeviceUnlock).await,
        Outcome::Failed(_)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_or_wrong_device_key_leaves_the_tui_locked() {
    let daemon = Daemon::start().await;
    let fake = enrolled(&daemon).await;
    let mut driver =
        Driver::with_device(daemon.paths.clone(), Some(fake.clone() as Arc<dyn Device>));

    // The key the platform hands back no longer matches the vault.
    for key in fake.keys.lock().unwrap().values_mut() {
        *key = [7; 32];
    }
    match driver.run(Effect::DeviceUnlock).await {
        Outcome::Failed(message) => assert!(message.contains("not set up"), "{message}"),
        other => panic!("{other:?}"),
    }
    assert!(driver.refresh().await.is_none(), "no session");

    // The user cancels the prompt.
    fake.keys.lock().unwrap().clear();
    match driver.run(Effect::DeviceUnlock).await {
        Outcome::Failed(message) => {
            assert!(message.starts_with("Touch ID: "), "{message}");
            assert!(message.contains("passphrase"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}
