//! kv's window on screen: a tao window holding a wry webview that shows the
//! page `tray::window` carries, and nothing else. It opens like a flyout:
//! no frame, next to the tray icon, above the other windows, and it hides
//! when the user clicks elsewhere or presses Esc. A click on the icon opens
//! it small, as a menu; the menu's Open kv grows it into the full window.

use std::borrow::Cow;

use tao::dpi::LogicalSize;
#[cfg(not(target_os = "macos"))]
use tao::dpi::PhysicalPosition;
use tao::event_loop::{EventLoopProxy, EventLoopWindowTarget};
use tao::window::{Icon, Window, WindowBuilder, WindowId};
use tokio::sync::mpsc::UnboundedSender;
use wry::http::{Response, header};
use wry::{NewWindowResponse, WebView, WebViewBuilder};
use zeroize::Zeroizing;

use super::Message;
use crate::tray::icon;
use crate::tray::model::Action;
use crate::tray::window::{CSP, FromPage, PAGE_URL, ToPage, asset, is_page_url};

/// The full window's size, in logical pixels.
const WIDTH: f64 = 800.0;
const HEIGHT: f64 = 600.0;
/// The menu's size, in logical pixels: it fits the page's menu exactly.
const MENU_WIDTH: f64 = 300.0;
const MENU_HEIGHT: f64 = 330.0;
/// The space between the window and the tray icon or the screen's edge, in
/// physical pixels.
const GAP: i32 = 12;
/// How round the window's corners are on macOS, in points.
#[cfg(target_os = "macos")]
const CORNER_RADIUS: f64 = 16.0;

/// Where the tray icon is, in physical pixels: the window opens beside it.
/// On macOS it is the pointer, in points (see `pointer`): the icon's own
/// rectangle comes in a mix of scales that does not match the monitors on a
/// Mac with screens of different scales.
#[derive(Clone, Copy, Debug)]
pub struct Anchor {
    pub x: f64,
    pub y: f64,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub width: f64,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub height: f64,
}

pub struct KvWindow {
    // Declared first so it is dropped before the window it draws in.
    webview: WebView,
    window: Window,
}

impl KvWindow {
    /// Opens the window in front, beside `anchor`: as the small menu when
    /// `menu`, else the full window. What the page sends goes to `actions`,
    /// but a request to hide or grow the window goes to the event loop.
    pub fn open(
        target: &EventLoopWindowTarget<Message>,
        actions: UnboundedSender<Action>,
        proxy: EventLoopProxy<Message>,
        anchor: Option<Anchor>,
        menu: bool,
    ) -> Result<Self, String> {
        let logo = Icon::from_rgba(icon::logo_rgba(), icon::LOGO_SIZE, icon::LOGO_SIZE).ok();
        let builder = WindowBuilder::new()
            .with_title("kv")
            .with_inner_size(size(menu))
            .with_resizable(false)
            .with_decorations(false)
            .with_always_on_top(true)
            .with_visible(false)
            .with_window_icon(logo);
        #[cfg(windows)]
        let builder = {
            use tao::platform::windows::WindowBuilderExtWindows;
            // A flyout has no taskbar button; the shadow outlines it.
            builder
                .with_skip_taskbar(true)
                .with_undecorated_shadow(true)
        };
        let window = builder.build(target).map_err(|e| e.to_string())?;
        #[cfg(windows)]
        round_corners(&window);
        // WebView2 keeps its data in a folder; by default that is next to
        // kv.exe, which may not be writable.
        #[cfg(windows)]
        let mut context = wry::WebContext::new(Some(std::env::temp_dir().join("kv-webview")));
        #[cfg(windows)]
        let builder = {
            use wry::WebViewBuilderExtWindows;
            WebViewBuilder::new_with_web_context(&mut context).with_https_scheme(true)
        };
        #[cfg(not(windows))]
        let builder = WebViewBuilder::new();
        let webview = builder
            .with_custom_protocol("kv".into(), |_, request| serve(request.uri().path()))
            .with_ipc_handler(move |request| {
                let from_page = is_page_url(&request.uri().to_string());
                let body = Zeroizing::new(request.into_body());
                if from_page && let Some(message) = FromPage::parse(&body) {
                    let _ = match message {
                        FromPage::Hide => proxy.send_event(Message::Hide).ok(),
                        FromPage::Expand => proxy.send_event(Message::Expand).ok(),
                        FromPage::Drag => proxy.send_event(Message::Drag).ok(),
                        FromPage::Picking => proxy.send_event(Message::Picking).ok(),
                        FromPage::Busy { on } => proxy.send_event(Message::Busy(on)).ok(),
                        message => actions.send(Action::Window(message)).ok(),
                    };
                }
            })
            .with_navigation_handler(|url| is_page_url(&url))
            .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
            .with_incognito(true)
            .with_devtools(false)
            // The page reads the hash before the first message can reach it.
            .with_url(if menu {
                format!("{PAGE_URL}#menu")
            } else {
                PAGE_URL.to_owned()
            })
            .build(&window)
            .map_err(|e| e.to_string())?;
        #[cfg(target_os = "macos")]
        round_corners(&window);
        let opened = Self { webview, window };
        opened.show_at(anchor, menu);
        Ok(opened)
    }

    pub fn id(&self) -> WindowId {
        self.window.id()
    }

    pub fn is_visible(&self) -> bool {
        self.window.is_visible()
    }

    /// Brings the window to the front where it is.
    pub fn raise(&self) {
        self.window.set_minimized(false);
        self.window.set_visible(true);
        self.window.set_focus();
    }

    /// Moves the window beside `anchor` (or the pointer, without one) and
    /// brings it to the front.
    #[cfg(target_os = "macos")]
    pub fn show_at(&self, anchor: Option<Anchor>, menu: bool) {
        self.place_on_mac(anchor.unwrap_or_else(pointer), menu);
        self.raise();
        // The shadow follows the rounded outline at the new size.
        if let Some(ns_window) = ns_window(&self.window) {
            ns_window.invalidateShadow();
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn show_at(&self, anchor: Option<Anchor>, _menu: bool) {
        let anchor = anchor.or_else(|| {
            let at = self.window.cursor_position().ok()?;
            Some(Anchor {
                x: at.x,
                y: at.y,
                width: 0.0,
                height: 0.0,
            })
        });
        if let Some(anchor) = anchor {
            // Twice: moving to a monitor with other scaling resizes the
            // window, and the second place uses the new size.
            for _ in 0..2 {
                if let Some(at) = self.place(anchor) {
                    self.window.set_outer_position(at);
                }
            }
        }
        self.raise();
    }

    /// Shows the small menu beside `anchor`.
    pub fn show_menu(&self, anchor: Option<Anchor>) {
        self.send(&ToPage::Menu { on: true });
        self.window.set_inner_size(size(true));
        self.show_at(anchor, true);
    }

    /// Shows the full window beside `anchor`.
    pub fn show_full(&self, anchor: Option<Anchor>) {
        self.send(&ToPage::Menu { on: false });
        self.expand(anchor);
    }

    /// Grows the menu into the full window; the page has already switched.
    pub fn expand(&self, anchor: Option<Anchor>) {
        self.window.set_inner_size(size(false));
        self.show_at(anchor, false);
    }

    /// Starts moving the window with the mouse, which is down: the page's
    /// title bar asked for it, since a window without a frame has no other
    /// handle.
    pub fn drag(&self) {
        let _ = self.window.drag_window();
    }

    /// Hides the window; the page puts away whatever it showed of a secret.
    pub fn hide(&self) {
        self.window.set_visible(false);
        self.send(&ToPage::Hidden);
    }

    /// Puts the window under the menu bar of the screen `at` is on, centred
    /// on `at` and kept inside that screen's visible area, all in points.
    /// A window larger than the area shrinks to fit it. macOS has one
    /// coordinate space in points for every screen; the physical pixels
    /// `place` works in differ screen to screen, so it cannot place a window
    /// when the screens have different scales.
    #[cfg(target_os = "macos")]
    fn place_on_mac(&self, at: Anchor, menu: bool) {
        use objc2::MainThreadMarker;
        use objc2_app_kit::NSScreen;
        use tao::dpi::LogicalPosition;

        let Some(mtm) = MainThreadMarker::new() else {
            return;
        };
        let screens = NSScreen::screens(mtm);
        let on = |screen: &NSScreen| {
            let f = screen.frame();
            (f.origin.x..=f.origin.x + f.size.width).contains(&at.x)
                && (f.origin.y..=f.origin.y + f.size.height).contains(&at.y)
        };
        let Some(screen) = screens
            .iter()
            .find(|screen| on(screen))
            .or_else(|| NSScreen::mainScreen(mtm))
        else {
            return;
        };
        let area = screen.visibleFrame();
        let gap = f64::from(GAP) / 2.0;
        // The size the window is about to have, not the one it reports: it
        // takes the new size a moment after being asked, so reading it back
        // here would place a window of the old size.
        let wanted = size(menu);
        let (w, h) = (
            wanted.width.min(area.size.width - 2.0 * gap),
            wanted.height.min(area.size.height - 2.0 * gap),
        );
        self.window.set_inner_size(LogicalSize::new(w, h));
        let left = (at.x - w / 2.0).clamp(
            area.origin.x + gap,
            (area.origin.x + area.size.width - w - gap).max(area.origin.x + gap),
        );
        let top = area.origin.y + area.size.height - gap;
        // tao counts from the top of the main screen, which has the menu bar.
        let Some(main) = screens.iter().next() else {
            return;
        };
        let from_top = main.frame().size.height - top;
        self.window
            .set_outer_position(LogicalPosition::new(left, from_top));
    }

    /// Where the window's top left goes to sit beside `anchor`: above it
    /// when the icon is in the lower half of its screen (a taskbar at the
    /// bottom), below it otherwise (a menu bar or a taskbar at the top), and
    /// always on that screen.
    #[cfg(not(target_os = "macos"))]
    fn place(&self, anchor: Anchor) -> Option<PhysicalPosition<i32>> {
        let (cx, cy) = (
            anchor.x + anchor.width / 2.0,
            anchor.y + anchor.height / 2.0,
        );
        let monitor = self
            .window
            .available_monitors()
            .find(|m| {
                let (p, s) = (m.position(), m.size());
                (p.x as f64..p.x as f64 + s.width as f64).contains(&cx)
                    && (p.y as f64..p.y as f64 + s.height as f64).contains(&cy)
            })
            .or_else(|| self.window.primary_monitor())?;
        let (mx, my) = (monitor.position().x, monitor.position().y);
        let (mw, mh) = (monitor.size().width as i32, monitor.size().height as i32);
        let size = self.window.outer_size();
        let (w, h) = (size.width as i32, size.height as i32);
        let x = (cx as i32 - w / 2).clamp(mx + GAP, (mx + mw - w - GAP).max(mx + GAP));
        let y = if cy < (my + mh / 2) as f64 {
            (anchor.y + anchor.height) as i32 + GAP
        } else {
            anchor.y as i32 - h - GAP
        };
        let y = y.clamp(my + GAP, (my + mh - h - GAP).max(my + GAP));
        Some(PhysicalPosition::new(x, y))
    }

    pub fn send(&self, message: &ToPage) {
        let _ = self.webview.evaluate_script(&message.script());
    }
}

fn size(menu: bool) -> LogicalSize<f64> {
    if menu {
        LogicalSize::new(MENU_WIDTH, MENU_HEIGHT)
    } else {
        LogicalSize::new(WIDTH, HEIGHT)
    }
}

/// Where the pointer is now, in points from the bottom left of the main
/// screen: where the user clicked the tray icon.
#[cfg(target_os = "macos")]
pub fn pointer() -> Anchor {
    let at = objc2_app_kit::NSEvent::mouseLocation();
    Anchor {
        x: at.x,
        y: at.y,
        width: 0.0,
        height: 0.0,
    }
}

/// macOS gives a window without a frame square corners. Round them as it
/// rounds its own menu-bar windows: the window goes clear, its view clips
/// what it holds (the page) to a rounded rectangle with the continuous
/// curve, and the shadow takes the new outline.
#[cfg(target_os = "macos")]
fn round_corners(window: &Window) {
    use objc2_app_kit::{NSColor, NSView};
    use objc2_quartz_core::kCACornerCurveContinuous;
    use tao::platform::macos::WindowExtMacOS;

    let Some(ns_window) = ns_window(window) else {
        return;
    };
    // SAFETY: tao hands out its window's content view, an NSView that lives
    // as long as the window, which `window` borrows.
    let Some(view) = (unsafe { window.ns_view().cast::<NSView>().as_ref() }) else {
        return;
    };
    ns_window.setOpaque(false);
    ns_window.setBackgroundColor(Some(&NSColor::clearColor()));
    view.setWantsLayer(true);
    if let Some(layer) = view.layer() {
        layer.setCornerRadius(CORNER_RADIUS);
        // SAFETY: a constant Core Animation defines, read once.
        layer.setCornerCurve(unsafe { kCACornerCurveContinuous });
        layer.setMasksToBounds(true);
    }
    ns_window.invalidateShadow();
}

/// The NSWindow behind `window`.
#[cfg(target_os = "macos")]
fn ns_window(window: &Window) -> Option<&objc2_app_kit::NSWindow> {
    use tao::platform::macos::WindowExtMacOS;
    // SAFETY: tao hands out its NSWindow, which lives as long as `window`;
    // the reference borrows `window`.
    unsafe {
        window
            .ns_window()
            .cast::<objc2_app_kit::NSWindow>()
            .as_ref()
    }
}

/// Windows 11 rounds a window's corners only if it has a frame; ask for
/// them anyway, as its own flyouts have. Windows 10 ignores this.
#[cfg(windows)]
fn round_corners(window: &Window) {
    use tao::platform::windows::WindowExtWindows;
    use windows_sys::Win32::Graphics::Dwm::{
        DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DwmSetWindowAttribute,
    };

    let round = DWMWCP_ROUND;
    // SAFETY: the window is alive, and the attribute is a 4-byte value read
    // from `round`, which outlives the call.
    unsafe {
        DwmSetWindowAttribute(
            window.hwnd() as _,
            DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            (&round as *const i32).cast(),
            size_of::<i32>() as u32,
        );
    }
}

/// The page's file at `path`, or a 404, always with the policy.
fn serve(path: &str) -> Response<Cow<'static, [u8]>> {
    let response = Response::builder().header("Content-Security-Policy", CSP);
    let response = match asset(path) {
        Some(asset) => response
            .header(header::CONTENT_TYPE, asset.mime)
            .body(Cow::Borrowed(asset.body.as_bytes())),
        None => response.status(404).body(Cow::Borrowed(&[][..])),
    };
    response.unwrap_or_else(|_| Response::new(Cow::Borrowed(&[][..])))
}

/// The app menu macOS reads Cmd+C, Cmd+V and the other editing keys from.
/// An accessory app shows no menu bar, but without these items the keys do
/// nothing in the window's fields.
#[cfg(target_os = "macos")]
pub fn edit_menu() -> Option<tray_icon::menu::Menu> {
    use tray_icon::menu::{Menu, PredefinedMenuItem, Submenu};

    let app = Submenu::with_items("kv", true, &[&PredefinedMenuItem::close_window(None)]).ok()?;
    let edit = Submenu::with_items(
        "Edit",
        true,
        &[
            &PredefinedMenuItem::undo(None),
            &PredefinedMenuItem::redo(None),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::cut(None),
            &PredefinedMenuItem::copy(None),
            &PredefinedMenuItem::paste(None),
            &PredefinedMenuItem::select_all(None),
        ],
    )
    .ok()?;
    let menu = Menu::with_items(&[&app, &edit]).ok()?;
    menu.init_for_nsapp();
    Some(menu)
}
