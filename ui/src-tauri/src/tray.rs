// SPDX-License-Identifier: GPL-3.0-or-later
//! Minimal system tray (design doc §9). Menu offers show/connect/disconnect/
//! quit — every action here also exists in the main window, per SPEC.md §9's
//! "never make the tray the only path" requirement.

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager};

pub fn setup(app: &tauri::App) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Show window", true, None::<&str>)?;
    let do_connect = MenuItem::with_id(app, "connect", "Connect", true, None::<&str>)?;
    let do_disconnect = MenuItem::with_id(app, "disconnect", "Disconnect", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[&show, &do_connect, &do_disconnect, &separator, &quit],
    )?;

    let mut builder = TrayIconBuilder::new()
        .menu(&menu)
        .show_menu_on_left_click(true);
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder
        .on_menu_event(|app: &AppHandle, event| match event.id.as_ref() {
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "connect" => {
                let _ = app.emit("tray-connect-requested", ());
            }
            "disconnect" => {
                let _ = app.emit("tray-disconnect-requested", ());
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;

    Ok(())
}
