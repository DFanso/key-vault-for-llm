//! The tray's main thread: the event loop, the icon and its menu. macOS
//! wants the status item on the main thread, so the daemon side runs on a
//! thread of its own (`worker`) and sends each new `Model` here through the
//! event loop; menu clicks go back to it as `Action`s.

use std::fs::File;
use std::io;
use std::sync::Arc;

use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{
    CheckMenuItem, IsMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu,
};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use super::model::{Action, Edit, IconState, Item, Model, edits};
use super::window::{Tab, ToPage};
use super::worker::{Desktop, Worker};
use super::{icon, login};
use crate::device;
use crate::notify;
use crate::paths::Paths;

enum Message {
    Show(Model),
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
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        if let Some(action) = Action::from_id(event.id.as_ref()) {
            let _ = actions.send(action);
        }
    }));
    let proxy = event_loop.create_proxy();
    std::thread::spawn(move || {
        let worker = Worker::new(paths, device::platform().map(Arc::from), System);
        let show = proxy.clone();
        runtime.block_on(worker.run(inbox, move |model| {
            let _ = show.send_event(Message::Show(model));
        }));
        let _ = proxy.send_event(Message::Quit);
    });

    let mut tray: Option<Tray> = None;
    event_loop.run(move |event, _, flow| {
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
            Event::UserEvent(Message::Quit) => {
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
}

impl Tray {
    fn new() -> Result<Self, tray_icon::Error> {
        let menu = Menu::new();
        let builder = TrayIconBuilder::new()
            .with_menu(Box::new(menu.clone()))
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

/// The real desktop: notifications, kv's window, the login item.
struct System;

impl Desktop for System {
    fn notify(&self, text: &str) {
        notify::tray(text.to_owned());
    }

    // Task 5 draws the window.
    fn show_window(&self, _tab: Tab) {}

    fn page(&self, _message: ToPage) {}

    fn login_is_on(&self) -> bool {
        login::is_on()
    }

    fn set_login(&self, on: bool) -> io::Result<()> {
        login::set(on)
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
