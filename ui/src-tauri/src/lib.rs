// SPDX-License-Identifier: GPL-3.0-or-later
//! Tauri application entry point (design doc `docs/superpowers/specs/2026-09-06-ui-design.md`,
//! SPEC.md §3, §7.4).

mod commands;
mod error;
mod ipc_client;
mod tray;

use tauri::{Emitter, Manager};

use ipc_client::{ActorEvent, DaemonUnreachableReason, EventSink};

struct AppHandleSink(tauri::AppHandle);

impl EventSink for AppHandleSink {
    fn send(&self, event: ActorEvent) {
        let emit_result = match event {
            ActorEvent::Daemon(evt) => self.0.emit("daemon-event", evt),
            ActorEvent::Prompt { prompt_id, prompt } => self.0.emit(
                "daemon-prompt",
                serde_json::json!({ "prompt_id": prompt_id, "prompt": prompt }),
            ),
            ActorEvent::PromptCancelled { prompt_id } => self.0.emit(
                "prompt-cancelled",
                serde_json::json!({ "prompt_id": prompt_id }),
            ),
            ActorEvent::ConnectionLost(reason) => {
                self.0.emit("connection-lost", reason_to_json(&reason))
            }
            ActorEvent::ConnectionRestored => self.0.emit("connection-restored", ()),
        };
        if let Err(err) = emit_result {
            tracing::warn!(%err, "failed to emit event to frontend");
        }
    }
}

fn reason_to_json(reason: &DaemonUnreachableReason) -> serde_json::Value {
    match reason {
        DaemonUnreachableReason::NotRunning => serde_json::json!({ "reason": "not_running" }),
        DaemonUnreachableReason::PermissionDenied => {
            serde_json::json!({ "reason": "permission_denied" })
        }
        DaemonUnreachableReason::ProtocolMismatch { daemon_version } => {
            serde_json::json!({ "reason": "protocol_mismatch", "daemon_version": daemon_version })
        }
    }
}

// This is the one exempted top-level startup-invariant panic, mirroring
// CLAUDE.md's carve-out for daemon startup checks. Everywhere else in this
// crate returns `Result`.
#[allow(clippy::expect_used)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let sink = AppHandleSink(app.handle().clone());
            let client = ipc_client::spawn(sink, ipc_client::socket_path());
            app.manage(client);
            tray::setup(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::profile_import,
            commands::profile_list,
            commands::profile_get,
            commands::profile_delete,
            commands::connect,
            commands::disconnect,
            commands::status,
            commands::proxy_info,
            commands::proxy_stats,
            commands::prompt_reply,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
