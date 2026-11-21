//! The background process's presence on the desktop: the tray icon (always
//! there; the phone keeps working without a window) and the window, which
//! is a separate process (`--window`, see `ipc`): started when opened, gone
//! when closed, so the web view's memory is only used while it's on screen.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Wry};

static STATUS_ITEM: OnceLock<MenuItem<Wry>> = OnceLock::new();
/// The window process's pid while it runs (0: none).
static WINDOW_PID: AtomicU32 = AtomicU32::new(0);

/// Whether the window is open (so events reach a page).
pub fn window_open() -> bool {
    crate::ipc::window_connected()
}

/// Open the window: focus it if it's running, else start the window process.
pub fn open_window() {
    if WINDOW_PID.load(Ordering::SeqCst) != 0 {
        crate::ipc::focus_window();
        return;
    }
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("can't find this program to open its window: {e}");
            return;
        }
    };
    let _guard = tauri::async_runtime::handle().inner().enter();
    match tokio::process::Command::new(exe).arg("--window").stdin(std::process::Stdio::null()).spawn() {
        Ok(mut child) => {
            WINDOW_PID.store(child.id().unwrap_or(0), Ordering::SeqCst);
            // Collect it as soon as it exits (no zombie), then trim our heap.
            tokio::spawn(async move {
                let _ = child.wait().await;
                WINDOW_PID.store(0, Ordering::SeqCst);
                crate::util::release_memory();
            });
        }
        Err(e) => tracing::error!("can't open the window: {e}"),
    }
}

/// Close the window process (when quitting).
pub fn close_window() {
    let pid = WINDOW_PID.swap(0, Ordering::SeqCst);
    if pid != 0 {
        // SAFETY: signalling our own child process by pid.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
}

/// Tray icon with a small menu (Linux trays open the menu on click).
pub fn create_tray(app: &AppHandle) -> tauri::Result<()> {
    let status = MenuItem::with_id(app, "status", "Phone: not connected", false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open Olink", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&status, &PredefinedMenuItem::separator(app)?, &open, &quit])?;
    let _ = STATUS_ITEM.set(status);
    TrayIconBuilder::with_id("main")
        .icon(tauri::image::Image::from_bytes(include_bytes!("../icons/128x128.png"))?)
        .tooltip("Olink")
        .menu(&menu)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => open_window(),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|_, event| {
            // Where the tray reports clicks (not AppIndicator), a click opens the window.
            if let tauri::tray::TrayIconEvent::Click { button: tauri::tray::MouseButton::Left, button_state: tauri::tray::MouseButtonState::Up, .. } = event {
                open_window();
            }
        })
        .build(app)?;
    Ok(())
}

/// Keep the tray's status line current.
pub fn set_status(text: &str) {
    if let Some(item) = STATUS_ITEM.get() {
        let _ = item.set_text(text);
    }
}
