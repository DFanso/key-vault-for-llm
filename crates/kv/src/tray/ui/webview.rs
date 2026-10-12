//! kv's window on screen: a tao window holding a wry webview that shows the
//! page `tray::window` carries, and nothing else.

use std::borrow::Cow;

use tao::dpi::LogicalSize;
use tao::event_loop::EventLoopWindowTarget;
use tao::window::{Window, WindowBuilder, WindowId};
use tokio::sync::mpsc::UnboundedSender;
use wry::http::{Response, header};
use wry::{NewWindowResponse, WebView, WebViewBuilder};
use zeroize::Zeroizing;

use super::Message;
use crate::tray::model::Action;
use crate::tray::window::{CSP, FromPage, PAGE_URL, ToPage, asset, is_page_url};

pub struct KvWindow {
    // Declared first so it is dropped before the window it draws in.
    webview: WebView,
    window: Window,
}

impl KvWindow {
    /// Opens the window in front. What the page sends goes to `actions`.
    pub fn open(
        target: &EventLoopWindowTarget<Message>,
        actions: UnboundedSender<Action>,
    ) -> Result<Self, String> {
        let window = WindowBuilder::new()
            .with_title("kv")
            .with_inner_size(LogicalSize::new(760.0, 520.0))
            .with_min_inner_size(LogicalSize::new(520.0, 360.0))
            .build(target)
            .map_err(|e| e.to_string())?;
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
                    let _ = actions.send(Action::Window(message));
                }
            })
            .with_navigation_handler(|url| is_page_url(&url))
            .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
            .with_incognito(true)
            .with_devtools(false)
            .with_url(PAGE_URL)
            .build(&window)
            .map_err(|e| e.to_string())?;
        window.set_focus();
        Ok(Self { webview, window })
    }

    pub fn id(&self) -> WindowId {
        self.window.id()
    }

    /// Brings the window to the front.
    pub fn raise(&self) {
        self.window.set_minimized(false);
        self.window.set_visible(true);
        self.window.set_focus();
    }

    pub fn send(&self, message: &ToPage) {
        let _ = self.webview.evaluate_script(&message.script());
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
