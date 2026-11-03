//! kv's window on screen: a tao window holding a wry webview that shows the
//! page `tray::window` carries, and nothing else. It opens like a flyout:
//! no frame, next to the tray icon, above the other windows, and it hides
//! when the user clicks elsewhere or presses Esc.

use std::borrow::Cow;

use tao::dpi::{LogicalSize, PhysicalPosition};
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

/// The window's size, in logical pixels.
const WIDTH: f64 = 800.0;
const HEIGHT: f64 = 600.0;
/// The space between the window and the tray icon or the screen's edge, in
/// physical pixels.
const GAP: i32 = 12;

/// Where the tray icon is, in physical pixels: the window opens beside it.
#[derive(Clone, Copy, Debug)]
pub struct Anchor {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

pub struct KvWindow {
    // Declared first so it is dropped before the window it draws in.
    webview: WebView,
    window: Window,
}

impl KvWindow {
    /// Opens the window in front, beside `anchor`. What the page sends goes
    /// to `actions`, but a request to hide goes to the event loop.
    pub fn open(
        target: &EventLoopWindowTarget<Message>,
        actions: UnboundedSender<Action>,
        proxy: EventLoopProxy<Message>,
        anchor: Option<Anchor>,
    ) -> Result<Self, String> {
        let logo = Icon::from_rgba(icon::logo_rgba(), icon::LOGO_SIZE, icon::LOGO_SIZE).ok();
        let builder = WindowBuilder::new()
            .with_title("kv")
            .with_inner_size(LogicalSize::new(WIDTH, HEIGHT))
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
                    if message == FromPage::Hide {
                        let _ = proxy.send_event(Message::Hide);
                    } else {
                        let _ = actions.send(Action::Window(message));
                    }
                }
            })
            .with_navigation_handler(|url| is_page_url(&url))
            .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
            .with_incognito(true)
            .with_devtools(false)
            .with_url(PAGE_URL)
            .build(&window)
            .map_err(|e| e.to_string())?;
        let opened = Self { webview, window };
        opened.show_at(anchor);
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
    pub fn show_at(&self, anchor: Option<Anchor>) {
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

    /// Hides the window; the page puts away whatever it showed of a secret.
    pub fn hide(&self) {
        self.window.set_visible(false);
        self.send(&ToPage::Hidden);
    }

    /// Where the window's top left goes to sit beside `anchor`: above it
    /// when the icon is in the lower half of its screen (a taskbar at the
    /// bottom), below it otherwise (a menu bar or a taskbar at the top), and
    /// always on that screen.
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
