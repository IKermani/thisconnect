// SPDX-License-Identifier: GPL-3.0-or-later
//! Tauri commands: one thin wrapper per `Request` variant (design doc §4).
//! No business logic here — the daemon owns validation and state transitions.

use tauri::State;
use thisconnect_shared::ipc::{
    ConnectionStatus, ProfileId, ProfileSummary, PromptId, PromptReply, ProxyInfo,
    ProxySessionStats, Request, Response, Secret,
};

use crate::error::{unexpected_response, UiError};
use crate::ipc_client::{IpcClientError, IpcClientHandle};

async fn call(client: &IpcClientHandle, request: Request) -> Result<Response, UiError> {
    client.request(request).await.map_err(UiError::from)
}

#[tauri::command]
pub async fn profile_import(
    client: State<'_, IpcClientHandle>,
    name: String,
    config: String,
) -> Result<ProfileSummary, UiError> {
    match call(
        &client,
        Request::ProfileImport {
            name,
            config: Secret::new(config),
        },
    )
    .await?
    {
        Response::Profile { profile } => Ok(profile),
        other => Err(unexpected_response("profile_import", &other)),
    }
}

#[tauri::command]
pub async fn profile_list(
    client: State<'_, IpcClientHandle>,
) -> Result<Vec<ProfileSummary>, UiError> {
    match call(&client, Request::ProfileList).await? {
        Response::Profiles { profiles } => Ok(profiles),
        other => Err(unexpected_response("profile_list", &other)),
    }
}

#[tauri::command]
pub async fn profile_get(
    client: State<'_, IpcClientHandle>,
    profile_id: ProfileId,
) -> Result<ProfileSummary, UiError> {
    match call(&client, Request::ProfileGet { profile_id }).await? {
        Response::Profile { profile } => Ok(profile),
        other => Err(unexpected_response("profile_get", &other)),
    }
}

#[tauri::command]
pub async fn profile_delete(
    client: State<'_, IpcClientHandle>,
    profile_id: ProfileId,
) -> Result<(), UiError> {
    call(&client, Request::ProfileDelete { profile_id }).await?;
    Ok(())
}

#[tauri::command]
pub async fn connect(
    client: State<'_, IpcClientHandle>,
    profile_id: ProfileId,
) -> Result<(), UiError> {
    call(&client, Request::Connect { profile_id }).await?;
    Ok(())
}

#[tauri::command]
pub async fn disconnect(client: State<'_, IpcClientHandle>) -> Result<(), UiError> {
    call(&client, Request::Disconnect).await?;
    Ok(())
}

#[tauri::command]
pub async fn status(client: State<'_, IpcClientHandle>) -> Result<ConnectionStatus, UiError> {
    match call(&client, Request::Status).await? {
        Response::Status { status } => Ok(status),
        other => Err(unexpected_response("status", &other)),
    }
}

#[tauri::command]
pub async fn proxy_info(client: State<'_, IpcClientHandle>) -> Result<ProxyInfo, UiError> {
    match call(&client, Request::ProxyInfo).await? {
        Response::Proxy { proxy } => Ok(proxy),
        other => Err(unexpected_response("proxy_info", &other)),
    }
}

#[tauri::command]
pub async fn proxy_stats(client: State<'_, IpcClientHandle>) -> Result<ProxySessionStats, UiError> {
    match call(&client, Request::ProxyStats).await? {
        Response::ProxyStats { stats } => Ok(stats),
        other => Err(unexpected_response("proxy_stats", &other)),
    }
}

#[tauri::command]
pub fn prompt_reply(
    client: State<'_, IpcClientHandle>,
    prompt_id: PromptId,
    reply: PromptReply,
) -> Result<(), UiError> {
    client
        .prompt_reply(prompt_id, reply)
        .map_err(|e: IpcClientError| UiError::from(e))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::ipc_client::{spawn, ActorEvent};
    use tauri::test::{mock_builder, mock_context, noop_assets};
    use tokio::net::UnixListener;
    use tokio::sync::mpsc;

    async fn run_fixture_daemon(listener: UnixListener) {
        use thisconnect_shared::ipc::{decode_line, encode_line, ClientMessage, DaemonMessage};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let (stream, _) = listener.accept().await.expect("accept");
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read hello");
        let ClientMessage::Hello { id, .. } =
            decode_line::<ClientMessage>(line.trim_end()).expect("decode hello")
        else {
            panic!("expected hello");
        };
        let reply = encode_line(&DaemonMessage::Hello {
            id,
            protocol_version: thisconnect_shared::ipc::PROTOCOL_VERSION,
            daemon_version: "test-fixture".into(),
        })
        .expect("encode");
        write_half.write_all(reply.as_bytes()).await.expect("write");
        write_half.write_all(b"\n").await.expect("write nl");

        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await.expect("read") == 0 {
                return;
            }
            if let Ok(ClientMessage::Request { id, .. }) =
                decode_line::<ClientMessage>(line.trim_end())
            {
                let reply = encode_line(&DaemonMessage::Response {
                    id,
                    response: Response::Profiles { profiles: vec![] },
                })
                .expect("encode");
                write_half.write_all(reply.as_bytes()).await.expect("write");
                write_half.write_all(b"\n").await.expect("write nl");
            }
        }
    }

    // `tauri::test::get_ipc_response` blocks the calling thread on a
    // synchronous channel recv while the command's future (and this test's
    // own fixture daemon task) run on the same runtime — a single-threaded
    // `#[tokio::test]` would deadlock, so this needs real worker threads.
    #[tokio::test(flavor = "multi_thread")]
    async fn profile_list_command_round_trips_through_the_actor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fixture.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        tokio::spawn(run_fixture_daemon(listener));

        let (tx, mut rx) = mpsc::unbounded_channel::<ActorEvent>();
        let client = spawn(tx, path);
        tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("no timeout")
            .expect("connection restored");

        // `tauri::test::get_ipc_response` (tauri 2.11.5) dispatches against a
        // `Webview`, not the `App` directly, and command handlers must be
        // registered via `invoke_handler` on the mock builder before `build`
        // — the brief's sketch predates both of those; adapted here to match
        // the resolved crate version rather than guessed.
        let app = mock_builder()
            .invoke_handler(tauri::generate_handler![profile_list])
            .manage(client)
            .build(mock_context(noop_assets()))
            .expect("build mock app");
        let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("build mock webview");

        let profiles = tauri::test::get_ipc_response(
            &webview,
            tauri::webview::InvokeRequest {
                cmd: "profile_list".into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: if cfg!(any(windows, target_os = "android")) {
                    "http://tauri.localhost"
                } else {
                    "tauri://localhost"
                }
                .parse()
                .expect("url"),
                body: tauri::ipc::InvokeBody::default(),
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.to_string(),
            },
        );
        assert!(
            profiles.is_ok(),
            "profile_list should succeed: {profiles:?}"
        );
    }
}
