//! macOS: waiting requests as notifications with Allow and Deny buttons,
//! through the UserNotifications framework, as other menu bar apps do.
//! macOS lets only an app bundle use that framework, so this works only
//! while the tray runs from kv.app (see `tray::bundle`). Elsewhere
//! `Center::start` gives `None`, the worker posts nothing, and the daemon's
//! plain notifications stand.
//!
//! The framework calls the delegate on a queue of its own; the delegate
//! only hands the answer to the worker, as a menu click does.

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
use tokio::sync::mpsc::UnboundedSender;

use crate::tray::model::Action;
use crate::tray::notices::{self, ANSWERS, Notice};

/// The categories: with Allow for this session, and without it.
const CATEGORY: &str = "kv-request";
const CATEGORY_ONCE: &str = "kv-request-once";
/// Groups kv's notifications together in Notification Center.
const THREAD: &str = "kv-requests";
/// How often the user's notification settings are read again: they may turn
/// kv's notifications on or off in System Settings at any time.
const RECHECK: Duration = Duration::from_secs(10);

pub struct Center {
    /// Whether the user lets kv post notifications, as last heard.
    allowed: Arc<AtomicBool>,
    checked: Mutex<Instant>,
}

impl Center {
    /// Sets up kv's notifications, asking the user the first time, and
    /// sends what they answer to `actions`. `None` outside kv.app.
    pub fn start(actions: UnboundedSender<Action>) -> Option<Center> {
        if !in_app_bundle() {
            return None;
        }
        let center = UNUserNotificationCenter::currentNotificationCenter();
        let delegate = Delegate::new(actions);
        center.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        // The center holds its delegate weakly; this one lives as long as
        // the tray does.
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
    pub fn allowed(&self) -> bool {
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

    pub fn post(&self, notice: &Notice) {
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

    pub fn withdraw(&self, keys: &[String]) {
        let keys: Vec<Retained<NSString>> =
            keys.iter().map(|key| NSString::from_str(key)).collect();
        let keys = NSArray::from_retained_slice(&keys);
        let center = UNUserNotificationCenter::currentNotificationCenter();
        center.removePendingNotificationRequestsWithIdentifiers(&keys);
        center.removeDeliveredNotificationsWithIdentifiers(&keys);
    }
}

/// Whether this process runs from an app bundle, which the framework needs:
/// without one it throws, and the tray would stop.
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

struct Ivars {
    actions: UnboundedSender<Action>,
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
                let _ = self.ivars().actions.send(Action::Notice { key, verdict });
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
    fn new(actions: UnboundedSender<Action>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(Ivars { actions });
        // SAFETY: NSObject's `init`, on a fresh allocation.
        unsafe { msg_send![super(this), init] }
    }
}
