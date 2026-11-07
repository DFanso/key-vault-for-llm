//! The tray's main thread: the event loop, the icon, its menu and kv's
//! window. macOS wants all of them on the main thread, so the daemon side
//! runs on a thread of its own (`worker`) and sends each new `Model` and
//! each message for the page here through the event loop; menu clicks and
//! what the page sends go back to it as `Action`s.
//!
//! A click on the icon opens a small menu beside it, like a flyout (Open
//! kv, Lock, Start at login, Quit), and a second click hides it again; its
//! Open kv grows it into kv's full window. The system menu is on the other
//! button.

#[cfg(target_os = "macos")]
mod notices;
mod webview;

use std::fs::File;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tray_icon::menu::{
    CheckMenuItem, IsMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu,
};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use super::model::{Action, Edit, IconState, Item, Model, edits};
#[cfg(target_os = "macos")]
use super::notices::Notice;
use super::window::{Stays, Tab, ToPage};
use super::worker::{Desktop, Worker};
use super::{icon, login};
use crate::device;
use crate::notify;
use crate::paths::Paths;
use webview::{Anchor, KvWindow};

/// How soon after the window hid a click on the icon is the same click:
/// the click that took the focus away hid it, so it stays hidden.
const RECLICK: Duration = Duration::from_millis(400);

/// How long after the window shows a loss of focus does not hide it:
/// Windows may refuse the window the focus as it appears, and the user has
/// not clicked elsewhere yet.
const SETTLE: Duration = Duration::from_millis(600);

enum Message {
    Show(Model),
    /// Open kv's window, or bring it to the front. The worker sends the tab
    /// to the page itself.
    Open,
    Page(ToPage),
    /// The tray icon was clicked; it is here.
    Clicked(Anchor),
    /// The page asked to hide the window.
    Hide,
    /// The page's menu asked for the full window.
    Expand,
    /// The mouse went down on the page's title bar: move the window.
    Drag,
    /// The page is about to open the system's file panel.
    Picking,
    /// A dialog opened or closed in the page.
    Busy(bool),
    /// The worker has stopped.
    Quit,
}

/// Runs the event loop; returns only if it cannot start.
pub fn run(paths: Paths, lock: File) -> io::Result<()> {
    #[cfg(windows)]
    leave_own_console();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    #[allow(unused_mut)]
    let mut event_loop = EventLoopBuilder::<Message>::with_user_event().build();
    #[cfg(target_os = "macos")]
    {
        use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
        // A menu bar item only: no Dock icon, no app menu.
        event_loop.set_activation_policy(ActivationPolicy::Accessory);
    }

    let (actions, inbox) = tokio::sync::mpsc::unbounded_channel();
    let clicks = actions.clone();
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        if let Some(action) = Action::from_id(event.id.as_ref()) {
            let _ = clicks.send(action);
        }
    }));
    let proxy = event_loop.create_proxy();
    let clicked = proxy.clone();
    TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
        if let TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            rect,
            ..
        } = event
        {
            #[cfg(target_os = "macos")]
            let at = {
                let _ = rect;
                webview::pointer()
            };
            #[cfg(not(target_os = "macos"))]
            let at = Anchor {
                x: rect.position.x,
                y: rect.position.y,
                width: rect.size.width.into(),
                height: rect.size.height.into(),
            };
            let _ = clicked.send_event(Message::Clicked(at));
        }
    }));
    let pages = proxy.clone();
    let system = System {
        proxy: proxy.clone(),
        #[cfg(target_os = "macos")]
        notices: notices::Center::start(actions.clone()),
    };
    std::thread::spawn(move || {
        let worker = Worker::new(paths, device::platform().map(Arc::from), system);
        let show = proxy.clone();
        runtime.block_on(worker.run(inbox, move |model| {
            let _ = show.send_event(Message::Show(model));
        }));
        let _ = proxy.send_event(Message::Quit);
    });

    let mut tray: Option<Tray> = None;
    let mut window: Option<KvWindow> = None;
    // Where the icon was last clicked, which the window opens beside.
    let mut anchor: Option<Anchor> = None;
    // When the window last hid, and last showed.
    let mut hidden_at: Option<Instant> = None;
    let mut shown_at: Option<Instant> = None;
    // What keeps the window up when the focus leaves it: a device prompt or
    // the file panel takes the focus, and a dialog open in the page, or a
    // window the user moved, is not something to hide.
    let mut stays = Stays::default();
    // Whether the window shows the full page, not the small menu.
    let mut full = false;
    // A click on the icon asked the worker for the window: it opens as the
    // menu, not the full window.
    let mut want_menu = false;
    event_loop.run(move |event, target, flow| {
        // Held for as long as the loop runs.
        let _ = &lock;
        *flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => match Tray::new() {
                Ok(created) => tray = Some(created),
                Err(e) => {
                    eprintln!("kv: cannot show the tray icon: {e}");
                    *flow = ControlFlow::ExitWithCode(1);
                }
            },
            Event::UserEvent(Message::Show(model)) => {
                if let Some(tray) = &mut tray {
                    tray.show(model);
                }
            }
            Event::UserEvent(Message::Clicked(at)) => {
                anchor = Some(at);
                let just_hidden = hidden_at.is_some_and(|t| t.elapsed() < RECLICK);
                match &window {
                    Some(open) if open.is_visible() => {
                        open.hide();
                        hidden_at = Some(Instant::now());
                        stays.hidden();
                    }
                    Some(_) if just_hidden => {}
                    Some(open) => {
                        open.show_menu(anchor);
                        shown_at = Some(Instant::now());
                        full = false;
                        stays.shown_as_menu();
                    }
                    // The worker opens it, and the page gets its state.
                    None => {
                        want_menu = true;
                        let _ = actions.send(Action::Menu);
                    }
                }
            }
            Event::UserEvent(Message::Hide) => {
                if let Some(open) = &window {
                    open.hide();
                    hidden_at = Some(Instant::now());
                    stays.hidden();
                }
            }
            Event::UserEvent(Message::Expand) => {
                if let Some(open) = &window {
                    open.expand(anchor);
                    shown_at = Some(Instant::now());
                    full = true;
                }
            }
            // Only the full window has a title bar to drag. Once moved it is
            // the user's: it stays up when they click elsewhere.
            Event::UserEvent(Message::Drag) => {
                if full && let Some(open) = &window {
                    open.drag();
                    stays.moved = true;
                }
            }
            Event::UserEvent(Message::Picking) => stays.picking = true,
            Event::UserEvent(Message::Busy(on)) => stays.busy = on,
            // The file panel closed, or the user came back to the window.
            Event::WindowEvent {
                window_id,
                event: WindowEvent::Focused(true),
                ..
            } if window.as_ref().is_some_and(|open| open.id() == window_id) => {
                stays.gained_focus();
            }
            Event::WindowEvent {
                window_id,
                event: WindowEvent::Focused(false),
                ..
            } if window.as_ref().is_some_and(|open| open.id() == window_id) => {
                let settling = shown_at.is_some_and(|t| t.elapsed() < SETTLE);
                if let Some(open) = window.as_ref().filter(|open| open.is_visible()) {
                    if stays.any() {
                        // It stays up, but a secret it shows does not: the
                        // user has gone to something else, and anyone looking
                        // at their screen sees this window over it.
                        open.send(&ToPage::Blurred);
                    } else if !settling {
                        open.hide();
                        hidden_at = Some(Instant::now());
                        stays.hidden();
                    }
                }
            }
            Event::UserEvent(Message::Open) => match &window {
                Some(open) => {
                    if std::mem::take(&mut want_menu) {
                        open.show_menu(anchor);
                        full = false;
                        stays.shown_as_menu();
                    } else if stays.moved && full && open.is_visible() {
                        // The user put the window where they want it: it
                        // comes to the front there, not back to the icon.
                        open.raise();
                    } else {
                        open.show_full(anchor);
                        full = true;
                    }
                    shown_at = Some(Instant::now());
                }
                None => {
                    let menu = std::mem::take(&mut want_menu);
                    match KvWindow::open(target, actions.clone(), pages.clone(), anchor, menu) {
                        Ok(opened) => {
                            window = Some(opened);
                            full = !menu;
                            stays = Stays::default();
                            shown_at = Some(Instant::now());
                        }
                        Err(e) => {
                            eprintln!("kv: cannot open kv's window: {e}");
                            notify::tray(no_window(&e));
                            let _ = actions.send(Action::WindowClosed);
                        }
                    }
                }
            },
            Event::UserEvent(Message::Page(message)) => {
                if let ToPage::State {
                    waiting_for_device, ..
                } = &message
                {
                    // The prompt is over: the window takes the focus back,
                    // so a click elsewhere hides it again.
                    if stays.prompting
                        && !waiting_for_device
                        && let Some(open) = window.as_ref().filter(|open| open.is_visible())
                    {
                        open.raise();
                    }
                    stays.prompting = *waiting_for_device;
                }
                if let Some(open) = &window {
                    open.send(&message);
                }
            }
            Event::WindowEvent {
                window_id,
                event: WindowEvent::CloseRequested,
                ..
            } if window.as_ref().is_some_and(|open| open.id() == window_id) => {
                window = None;
                stays = Stays::default();
                let _ = actions.send(Action::WindowClosed);
            }
            Event::UserEvent(Message::Quit) => {
                window = None;
                tray = None;
                *flow = ControlFlow::Exit;
            }
            _ => {}
        }
    })
}

struct Tray {
    icon: TrayIcon,
    /// The icon's menu. It stays the same menu for the tray's life and
    /// `show` changes its items in place: on Windows a click on a menu that
    /// was replaced while open is lost, and on macOS the open menu closes.
    menu: Menu,
    /// What `menu` holds, item for item.
    items: Vec<Native>,
    shown: Option<Model>,
    /// The editing keys for kv's window.
    #[cfg(target_os = "macos")]
    _edit: Option<Menu>,
}

impl Tray {
    fn new() -> Result<Self, tray_icon::Error> {
        let menu = Menu::new();
        let builder = TrayIconBuilder::new()
            .with_menu(Box::new(menu.clone()))
            // A click opens kv's window; the menu is on the other button.
            .with_menu_on_left_click(false)
            .with_tooltip("kv");
        let image = image(IconState::Off);
        #[cfg(target_os = "macos")]
        let builder = builder.with_icon_templated(image);
        #[cfg(windows)]
        let builder = builder.with_icon(image);
        Ok(Self {
            icon: builder.build()?,
            menu,
            items: Vec::new(),
            shown: None,
            #[cfg(target_os = "macos")]
            _edit: webview::edit_menu(),
        })
    }

    fn show(&mut self, model: Model) {
        let shown = self.shown.take();
        if shown.as_ref().map(|s| s.icon) != Some(model.icon) {
            let image = image(model.icon);
            #[cfg(target_os = "macos")]
            let _ = self.icon.set_icon_templated(Some(image));
            #[cfg(windows)]
            let _ = self.icon.set_icon(Some(image));
        }
        if shown.as_ref().map(|s| &s.tooltip) != Some(&model.tooltip) {
            let _ = self.icon.set_tooltip(Some(&model.tooltip));
        }
        if shown.as_ref().map(|s| &s.title) != Some(&model.title) {
            self.icon.set_title(model.title.as_deref());
        }
        // Also run when nothing changed: `update` puts back a check mark
        // that a click flipped but that did not take.
        let before = shown.map(|s| s.menu).unwrap_or_default();
        for edit in edits(&before, &model.menu) {
            match edit {
                Edit::Keep { at, index } => self.items[at].update(&model.menu[index]),
                Edit::Insert { at, index } => {
                    let item = native(&model.menu[index]);
                    let _ = self.menu.insert(item.as_item(), at);
                    self.items.insert(at, item);
                }
                Edit::Remove { at } => {
                    let item = self.items.remove(at);
                    let _ = self.menu.remove(item.as_item());
                }
            }
        }
        self.shown = Some(model);
    }
}

/// The image for `state`. macOS shows the count beside the icon, so it
/// draws no badge.
fn image(state: IconState) -> Icon {
    let state = match state {
        IconState::Waiting(_) if cfg!(target_os = "macos") => IconState::Unlocked,
        other => other,
    };
    Icon::from_rgba(icon::rgba(state), icon::SIZE, icon::SIZE).expect("the icon is SIZE square")
}

/// A menu item on screen, kept to change it in place.
enum Native {
    Action(MenuItem),
    Check(CheckMenuItem),
    Text(MenuItem),
    Separator(PredefinedMenuItem),
    /// With its `Text` lines, in order.
    Submenu(Submenu, Vec<MenuItem>),
}

impl Native {
    fn as_item(&self) -> &dyn IsMenuItem {
        match self {
            Native::Action(item) | Native::Text(item) => item,
            Native::Check(item) => item,
            Native::Separator(item) => item,
            Native::Submenu(item, _) => item,
        }
    }

    /// Takes the text and check mark of `item`, which `edits` matched to
    /// this one.
    fn update(&self, item: &Item) {
        match (self, item) {
            (Native::Action(native), Item::Action { label, .. }) => set_text(native, label),
            (Native::Check(native), Item::Check { label, checked, .. }) => {
                if native.text() != *label {
                    native.set_text(label);
                }
                if native.is_checked() != *checked {
                    native.set_checked(*checked);
                }
            }
            (Native::Submenu(_, lines), Item::Submenu { items, .. }) => {
                let texts = items.iter().filter_map(|item| match item {
                    Item::Text(text) => Some(text),
                    _ => None,
                });
                for (line, text) in lines.iter().zip(texts) {
                    set_text(line, text);
                }
            }
            _ => {}
        }
    }
}

fn set_text(item: &MenuItem, text: &str) {
    if item.text() != text {
        item.set_text(text);
    }
}

fn native(item: &Item) -> Native {
    match item {
        Item::Action { label, action } => {
            Native::Action(MenuItem::with_id(action.id(), label, true, None))
        }
        Item::Check {
            label,
            checked,
            action,
        } => Native::Check(CheckMenuItem::with_id(
            action.id(),
            label,
            true,
            *checked,
            None,
        )),
        Item::Text(text) => Native::Text(MenuItem::new(text, false, None)),
        Item::Separator => Native::Separator(PredefinedMenuItem::separator()),
        Item::Submenu { id, label, items } => {
            let submenu = Submenu::with_id(id.as_str(), label, true);
            let mut lines = Vec::new();
            for item in items {
                let item = native(item);
                let _ = submenu.append(item.as_item());
                if let Native::Text(line) = item {
                    lines.push(line);
                }
            }
            Native::Submenu(submenu, lines)
        }
    }
}

/// What to tell the user when the window cannot open.
fn no_window(error: &str) -> String {
    if cfg!(windows) {
        // Almost always a missing runtime; the error is on stderr.
        let _ = error;
        "kv's window needs the Microsoft Edge WebView2 Runtime".to_owned()
    } else {
        format!("kv's window could not open: {error}")
    }
}

/// The real desktop: notifications, kv's window, the login item.
struct System {
    proxy: EventLoopProxy<Message>,
    /// Notifications the user can answer, while kv tray runs from kv.app.
    #[cfg(target_os = "macos")]
    notices: Option<notices::Center>,
}

impl Desktop for System {
    fn notify(&self, text: &str) {
        notify::tray(text.to_owned());
    }

    fn show_window(&self, _tab: Tab) {
        let _ = self.proxy.send_event(Message::Open);
    }

    fn page(&self, message: ToPage) {
        let _ = self.proxy.send_event(Message::Page(message));
    }

    fn login_is_on(&self) -> bool {
        login::is_on()
    }

    fn set_login(&self, on: bool) -> io::Result<()> {
        login::set(on)
    }

    #[cfg(target_os = "macos")]
    fn can_notify(&self) -> bool {
        self.notices.as_ref().is_some_and(notices::Center::allowed)
    }

    #[cfg(target_os = "macos")]
    fn post(&self, notice: &Notice) {
        if let Some(center) = &self.notices {
            center.post(notice);
        }
    }

    #[cfg(target_os = "macos")]
    fn withdraw(&self, keys: &[String]) {
        if let Some(center) = &self.notices {
            center.withdraw(keys);
        }
    }
}

/// Started from the Run key at login, Windows gives kv a console window of
/// its own; the tray lets it go so that no empty window stays open. Started
/// from a terminal, kv shares that terminal's console and keeps it.
#[cfg(windows)]
fn leave_own_console() {
    use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};

    let mut ids = [0u32; 2];
    // SAFETY: `ids` has room for the 2 ids asked for.
    if unsafe { GetConsoleProcessList(ids.as_mut_ptr(), 2) } == 1 {
        // SAFETY: no arguments; kv has a console to free.
        unsafe { FreeConsole() };
    }
}
