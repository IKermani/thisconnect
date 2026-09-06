// SPDX-License-Identifier: GPL-3.0-or-later
//! Tauri application entry point (design doc `docs/superpowers/specs/2026-09-06-ui-design.md`,
//! SPEC.md §3, §7.4).

mod ipc_client;

#[tauri::command]
fn ping() -> &'static str {
    "pong"
}

// Tauri's own template uses exactly this `.expect` — this is the one
// exempted top-level startup-invariant panic, mirroring CLAUDE.md's carve-out
// for daemon startup checks. Everywhere else in this crate returns `Result`.
#[allow(clippy::expect_used)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![ping])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
