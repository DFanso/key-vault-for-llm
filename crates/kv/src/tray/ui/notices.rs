//! macOS: waiting requests as notifications with Allow and Deny buttons,
//! through the UserNotifications framework, as other menu bar apps do.
//!
//! macOS lets only an app bundle use that framework, but the tray must stay
//! the plain `kv` binary: Touch ID's record of the enrolled fingerprints and
//! the keychain's access list both depend on which app asks, and they were
//! set up by that binary. So the tray starts kv.app (see `tray::bundle`) as
//! a helper, `kv tray-notices`, which only posts notifications and passes
//! the user's answers back, as `tray::notices` messages over its standard
//! input and output. It holds no secret and no session. When the helper
//! cannot start or the user turned kv's notifications off, the worker posts
//! nothing and the daemon's plain notifications stand.

use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use block2::{DynBlock, RcBlock};
use kv_core::proto::Verdict;
use objc2::rc::Retained;
use objc2::runtime::{Bool, NSObjectProtocol, ProtocolObject};
use objc2::{AllocAnyThread, DefinedClass, define_class, msg_send};
use objc2_foundation::{NSArray, NSBundle, NSError, NSObject, NSSet, NSString};
use objc2_user_notifications::{
    UNAuthorizationOptions, UNAuthorizationStatus, UNMutableNotificationContent, UNNotification,
    UNNotificationAction, UNNotificationActionOptions, UNNotificationCategory,
    UNNotificationCategoryOptions, UNNotificationDefaultActionIdentifier,
    UNNotificationPresentationOptions, UNNotificationRequest, UNNotificationResponse,
    UNNotificationSettings, UNNotificationSound, UNUserNotificationCenter,
    UNUserNotificationCenterDelegate,
};
use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tokio::sync::mpsc::UnboundedSender;

use crate::tray::model::Action;
use crate::tray::notices::{self, ANSWERS, FromHelper, Notice, ToHelper, read_helper};

/// The categories: with Allow for this session, and without it.
const CATEGORY: &str = "kv-request";
const CATEGORY_ONCE: &str = "kv-request-once";
/// Groups kv's notifications together in Notification Center.
const THREAD: &str = "kv-requests";
/// How often the user's notification settings are read again: they may turn
/// kv's notifications on or off in System Settings at any time.
const RECHECK: Duration = Duration::from_secs(10);
/// How long the tray waits for the helper to take down what is on show and
/// exit, once told to stop, before it stops the helper itself.
const STOP_WAIT: Duration = Duration::from_secs(2);

/// The tray's side of the helper.
pub struct Helper {
    child: Mutex<Child>,
    input: Mutex<Option<ChildStdin>>,
    allowed: Arc<AtomicBool>,
}

impl Helper {
    /// Starts kv.app's `exe` as the helper; what the user answers goes to
    /// `actions`.
    pub fn start(exe: &Path, actions: UnboundedSender<Action>) -> io::Result<Helper> {
        let mut child = Command::new(exe)
            .arg("tray-notices")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let input = child.stdin.take();
        let output = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("no output"))?;
        let allowed = Arc::new(AtomicBool::new(false));
        let flag = allowed.clone();
        std::thread::spawn(move || {
            read_helper(BufReader::new(output), &flag, |key, verdict| {
                let _ = actions.send(Action::Notice { key, verdict });
            });
        });
        Ok(Helper {
            child: Mutex::new(child),
            input: Mutex::new(input),
            allowed,
        })
    }

    /// Whether the helper runs and the user lets kv post notifications.
    pub fn allowed(&self) -> bool {
        self.allowed.load(Ordering::Relaxed)
    }

    pub fn post(&self, notice: &Notice) {
        self.send(&ToHelper::Post(notice.clone()));
    }

    pub fn withdraw(&self, keys: &[String]) {
        self.send(&ToHelper::Withdraw {
            keys: keys.to_vec(),
        });
    }

    fn send(&self, message: &ToHelper) {
        let line = serde_json::to_string(message).expect("a message always serializes");
        let Ok(mut input) = self.input.lock() else {
            return;
        };
        let sent = input
            .as_mut()
            .is_some_and(|pipe| writeln!(pipe, "{line}").and_then(|()| pipe.flush()).is_ok());
        if !sent {
            // The helper is gone: nothing more can be posted.
            *input = None;
            self.allowed.store(false, Ordering::Relaxed);
        }
    }
}

impl Drop for Helper {
    /// Closes the helper's input, which tells it to finish what it was
    /// sent (the tray takes its notifications down as it quits) and exit.
    fn drop(&mut self) {
        if let Ok(mut input) = self.input.lock() {
            input.take();
        }
        let Ok(mut child) = self.child.lock() else {
            return;
        };
        let deadline = Instant::now() + STOP_WAIT;
        while Instant::now() < deadline {
            if let Ok(Some(_)) = child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// `kv tray-notices`: the helper itself, run from kv.app by the tray. Posts
/// and takes down what the tray sends until its input closes.
pub fn run_helper() -> io::Result<()> {
    let output = Arc::new(Mutex::new(io::stdout()));
    let say = {
        let output = output.clone();
        move |message: FromHelper| tell(&output, &message)
    };
    let answer = {
        let say = say.clone();
        move |key, verdict| say(FromHelper::Answer { key, verdict })
    };
    let center = Center::start(answer).ok_or_else(|| {
        io::Error::other("kv tray-notices runs only from kv.app, which kv tray starts")
    })?;
    let center = Arc::new(center);
    #[allow(unused_mut)]
    let mut event_loop = EventLoopBuilder::<()>::with_user_event().build();
    {
        use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
        // No Dock icon, no app menu.
        event_loop.set_activation_policy(ActivationPolicy::Accessory);
    }
    let proxy = event_loop.create_proxy();
    {
        let center = center.clone();
        std::thread::spawn(move || {
            for line in io::stdin().lock().lines() {
                let Ok(line) = line else { break };
                match serde_json::from_str(&line) {
                    Ok(ToHelper::Post(notice)) => center.post(&notice),
                    Ok(ToHelper::Withdraw { keys }) => center.withdraw(&keys),
                    Err(_) => {}
                }
            }
            // The tray closed its end: it quit.
            let _ = proxy.send_event(());
        });
    }
    std::thread::spawn(move || {
        let mut told = None;
        loop {
            let on = center.allowed();
            if told != Some(on) {
                say(FromHelper::Allowed { on });
                told = Some(on);
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
    event_loop.run(move |event, _, flow| {
        *flow = match event {
            Event::UserEvent(()) => ControlFlow::Exit,
            _ => ControlFlow::Wait,
        };
    })
}

/// Writes `message` to the tray as a line. With the tray gone there is no
/// one to answer for, so the helper ends.
fn tell(output: &Mutex<io::Stdout>, message: &FromHelper) {
    let line = serde_json::to_string(message).expect("a message always serializes");
    let written = output
        .lock()
        .map_err(|_| io::Error::other("poisoned"))
        .and_then(|mut out| writeln!(out, "{line}").and_then(|()| out.flush()));
    if written.is_err() {
        std::process::exit(0);
    }
}

pub struct Center {
    /// Whether the user lets kv post notifications, as last heard.
    allowed: Arc<AtomicBool>,
    checked: Mutex<Instant>,
}

impl Center {
    /// Sets up kv's notifications, asking the user the first time, and
    /// hands what they answer to `answer`. `None` outside kv.app.
    fn start(answer: impl Fn(String, Option<Verdict>) + Send + Sync + 'static) -> Option<Center> {
        if !in_app_bundle() {
            return None;
        }
        let center = UNUserNotificationCenter::currentNotificationCenter();
        let delegate = Delegate::new(Box::new(answer));
        center.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        // The center holds its delegate weakly; this one lives as long as
        // the helper does.
        std::mem::forget(delegate);
        center.setNotificationCategories(&categories());
        // Left by a tray that stopped: their requests are gone, and an
        // answer to one would reach no one.
        center.removeAllDeliveredNotifications();
        let allowed = Arc::new(AtomicBool::new(false));
        let flag = allowed.clone();
        let reply = RcBlock::new(move |granted: Bool, error: *mut NSError| {
            // SAFETY: the framework passes null or a live error.
            match unsafe { error.as_ref() } {
                Some(error) => eprintln!(
                    "kv: notifications with buttons are off: {}",
                    error.localizedDescription()
                ),
                None => eprintln!(
                    "kv: notifications with buttons are {}",
                    if granted.as_bool() {
                        "on"
                    } else {
                        "off in System Settings"
                    }
                ),
            }
            flag.store(granted.as_bool(), Ordering::Relaxed);
        });
        center.requestAuthorizationWithOptions_completionHandler(
            UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound,
            &reply,
        );
        Some(Center {
            allowed,
            checked: Mutex::new(Instant::now()),
        })
    }

    /// Whether the user lets kv post notifications.
    fn allowed(&self) -> bool {
        if let Ok(mut checked) = self.checked.lock()
            && checked.elapsed() >= RECHECK
        {
            *checked = Instant::now();
            let flag = self.allowed.clone();
            let reply = RcBlock::new(move |settings: NonNull<UNNotificationSettings>| {
                // SAFETY: the framework hands over a live settings object.
                let status = unsafe { settings.as_ref() }.authorizationStatus();
                let on = status == UNAuthorizationStatus::Authorized
                    || status == UNAuthorizationStatus::Provisional;
                if flag.swap(on, Ordering::Relaxed) != on {
                    eprintln!(
                        "kv: notifications with buttons are {}",
                        if on { "on" } else { "off in System Settings" }
                    );
                }
            });
            UNUserNotificationCenter::currentNotificationCenter()
                .getNotificationSettingsWithCompletionHandler(&reply);
        }
        self.allowed.load(Ordering::Relaxed)
    }

    fn post(&self, notice: &Notice) {
        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str(&notice.title));
        content.setSubtitle(&NSString::from_str(&notice.subtitle));
        content.setBody(&NSString::from_str(&notice.body));
        let category = if notice.can_grant {
            CATEGORY
        } else {
            CATEGORY_ONCE
        };
        content.setCategoryIdentifier(&NSString::from_str(category));
        content.setThreadIdentifier(&NSString::from_str(THREAD));
        content.setSound(Some(&UNNotificationSound::defaultSound()));
        let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
            &NSString::from_str(&notice.key),
            &content,
            None,
        );
        let done = RcBlock::new(|error: *mut NSError| {
            // SAFETY: the framework passes null or a live error.
            if let Some(error) = unsafe { error.as_ref() } {
                eprintln!(
                    "kv: could not post a notification: {}",
                    error.localizedDescription()
                );
            }
        });
        UNUserNotificationCenter::currentNotificationCenter()
            .addNotificationRequest_withCompletionHandler(&request, Some(&done));
    }

    fn withdraw(&self, keys: &[String]) {
        let keys: Vec<Retained<NSString>> =
            keys.iter().map(|key| NSString::from_str(key)).collect();
        let keys = NSArray::from_retained_slice(&keys);
        let center = UNUserNotificationCenter::currentNotificationCenter();
        center.removePendingNotificationRequestsWithIdentifiers(&keys);
        center.removeDeliveredNotificationsWithIdentifiers(&keys);
    }
}

/// Whether this process runs from an app bundle, which the framework needs:
/// without one it throws.
fn in_app_bundle() -> bool {
    let bundle = NSBundle::mainBundle();
    bundle.bundleIdentifier().is_some() && bundle.bundlePath().to_string().ends_with(".app")
}

fn categories() -> Retained<NSSet<UNNotificationCategory>> {
    let actions = |with_session: bool| {
        let actions: Vec<Retained<UNNotificationAction>> = ANSWERS
            .iter()
            .filter(|(.., verdict)| with_session || *verdict != Verdict::AllowSession)
            .map(|(id, label, verdict)| {
                let options = if *verdict == Verdict::Deny {
                    UNNotificationActionOptions::Destructive
                } else {
                    UNNotificationActionOptions::empty()
                };
                UNNotificationAction::actionWithIdentifier_title_options(
                    &NSString::from_str(id),
                    &NSString::from_str(label),
                    options,
                )
            })
            .collect();
        NSArray::from_retained_slice(&actions)
    };
    let category = |id: &str, with_session: bool| {
        UNNotificationCategory::categoryWithIdentifier_actions_intentIdentifiers_options(
            &NSString::from_str(id),
            &actions(with_session),
            &NSArray::new(),
            UNNotificationCategoryOptions::empty(),
        )
    };
    NSSet::from_retained_slice(&[category(CATEGORY, true), category(CATEGORY_ONCE, false)])
}

/// Hands an answer to the tray.
type Answer = Box<dyn Fn(String, Option<Verdict>) + Send + Sync>;

struct Ivars {
    answer: Answer,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements, and `Delegate` does
    // not implement `Drop`.
    #[unsafe(super(NSObject))]
    #[ivars = Ivars]
    struct Delegate;

    unsafe impl NSObjectProtocol for Delegate {}

    unsafe impl UNUserNotificationCenterDelegate for Delegate {
        /// An answer picked from a notification, or the notification
        /// itself clicked, which opens the request in kv's window.
        #[unsafe(method(userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:))]
        fn did_receive(
            &self,
            _center: &UNUserNotificationCenter,
            response: &UNNotificationResponse,
            done: &DynBlock<dyn Fn()>,
        ) {
            let key = response.notification().request().identifier().to_string();
            let answer = response.actionIdentifier();
            let verdict = notices::verdict(&answer.to_string());
            // SAFETY: a constant string the framework exports.
            let clicked = answer.isEqualToString(unsafe { UNNotificationDefaultActionIdentifier });
            if verdict.is_some() || clicked {
                (self.ivars().answer)(key, verdict);
            }
            done.call(());
        }

        /// Shown even while kv's window has the focus.
        #[unsafe(method(userNotificationCenter:willPresentNotification:withCompletionHandler:))]
        fn will_present(
            &self,
            _center: &UNUserNotificationCenter,
            _notification: &UNNotification,
            done: &DynBlock<dyn Fn(UNNotificationPresentationOptions)>,
        ) {
            done.call((UNNotificationPresentationOptions::Banner
                | UNNotificationPresentationOptions::List
                | UNNotificationPresentationOptions::Sound,));
        }
    }
);

impl Delegate {
    fn new(answer: Answer) -> Retained<Self> {
        let this = Self::alloc().set_ivars(Ivars { answer });
        // SAFETY: NSObject's `init`, on a fresh allocation.
        unsafe { msg_send![super(this), init] }
    }
}
