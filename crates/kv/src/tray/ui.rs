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

use super::model::{Action, IconState, Item, Model, same_shape};
use super::worker::{Desktop, Worker};
use super::{icon, login, tui_command};
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
    shown: Option<Model>,
    /// The menu's `Text` lines in the order `texts` lists them, to change
    /// in place.
    lines: Vec<MenuItem>,
}

impl Tray {
    fn new() -> Result<Self, tray_icon::Error> {
        let builder = TrayIconBuilder::new()
            .with_menu(Box::new(Menu::new()))
            .with_tooltip("kv");
        let image = image(IconState::Off);
        #[cfg(target_os = "macos")]
        let builder = builder.with_icon_templated(image);
        #[cfg(windows)]
        let builder = builder.with_icon(image);
        Ok(Self {
            icon: builder.build()?,
            shown: None,
            lines: Vec::new(),
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
        match &shown {
            Some(shown) if shown.menu == model.menu => {}
            Some(shown) if same_shape(&shown.menu, &model.menu) => {
                let mut now = Vec::new();
                texts(&model.menu, &mut now);
                for (line, text) in self.lines.iter().zip(now) {
                    if line.text() != text {
                        line.set_text(text);
                    }
                }
            }
            _ => {
                let menu = Menu::new();
                self.lines.clear();
                for item in &model.menu {
                    let _ = menu.append(build(item, &mut self.lines).as_ref());
                }
                self.icon.set_menu(Some(Box::new(menu)));
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

fn build(item: &Item, lines: &mut Vec<MenuItem>) -> Box<dyn IsMenuItem> {
    match item {
        Item::Action { label, action } => {
            Box::new(MenuItem::with_id(action.id(), label, true, None))
        }
        Item::Check {
            label,
            checked,
            action,
        } => Box::new(CheckMenuItem::with_id(
            action.id(),
            label,
            true,
            *checked,
            None,
        )),
        Item::Text(text) => {
            let line = MenuItem::new(text, false, None);
            lines.push(line.clone());
            Box::new(line)
        }
        Item::Separator => Box::new(PredefinedMenuItem::separator()),
        Item::Submenu { id, label, items } => {
            let submenu = Submenu::with_id(id.as_str(), label, true);
            for item in items {
                let _ = submenu.append(build(item, lines).as_ref());
            }
            Box::new(submenu)
        }
    }
}

/// The text of every `Text` line, in the order `build` creates them.
fn texts(items: &[Item], out: &mut Vec<String>) {
    for item in items {
        match item {
            Item::Text(text) => out.push(text.clone()),
            Item::Submenu { items, .. } => texts(items, out),
            _ => {}
        }
    }
}

/// The real desktop: notifications, a terminal, the login item.
struct System;

impl Desktop for System {
    fn notify(&self, text: &str) {
        notify::tray(text.to_owned());
    }

    fn open_tui(&self) -> io::Result<()> {
        let mut child = tui_command(&std::env::current_exe()?).spawn()?;
        std::thread::spawn(move || child.wait());
        Ok(())
    }

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
