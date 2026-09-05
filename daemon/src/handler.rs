// SPDX-License-Identifier: GPL-3.0-or-later

//! Command dispatch: the IPC vocabulary in, the session orchestrator out.
//!
//! Nothing here decides policy; it translates, and the session state machine
//! refuses what must be refused.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use thisconnect_shared::ipc::{
    ClientMessage, DaemonMessage, ErrorCode, IpcError, PromptId, PromptReply, Request, RequestId,
    Response,
};
use tracing::{debug, warn};

use crate::auth::prompt::PromptError;
use crate::ipc::MessageHandler;
use crate::session::store::ProfileStore;
use crate::session::{SessionError, SessionManager};

pub struct SessionHandler {
    session: SessionManager,
    /// Profile CRUD is not session state: it outlives any one connection and is
    /// reachable while disconnected, so it hangs off the handler rather than
    /// being threaded through the connection state machine.
    catalog: Arc<dyn ProfileStore>,
}

impl SessionHandler {
    pub fn new(session: SessionManager, catalog: Arc<dyn ProfileStore>) -> Self {
        Self { session, catalog }
    }

    /// The GUI vocabulary. Every arm answers with exactly one message, so a
    /// client is never left waiting on a request the daemon silently dropped.
    pub async fn dispatch(&self, message: ClientMessage) -> DaemonMessage {
        match message {
            ClientMessage::Hello {
                id,
                protocol_version,
                ..
            } => hello(id, protocol_version),
            ClientMessage::Request { id, request } => self.request(id, request).await,
            ClientMessage::PromptReply {
                id,
                prompt_id,
                reply,
            } => self.prompt_reply(id, prompt_id, reply),
        }
    }

    async fn request(&self, id: RequestId, request: Request) -> DaemonMessage {
        match request {
            Request::Connect { profile_id } => match self.session.connect(profile_id).await {
                Ok(status) => ok(id, Response::Status { status }),
                Err(error) => fail(id, error),
            },
            Request::Disconnect => match self.session.disconnect().await {
                Ok(()) => ok(id, Response::Ack),
                Err(error) => fail(id, error),
            },
            Request::Status => ok(
                id,
                Response::Status {
                    status: self.session.status(),
                },
            ),
            Request::ProfileImport { name, config } => {
                match self.catalog.import(&name, config.expose()) {
                    Ok(profile) => ok(id, Response::Profile { profile }),
                    Err(error) => fail(id, error),
                }
            }
            Request::ProfileList => match self.catalog.list() {
                Ok(profiles) => ok(id, Response::Profiles { profiles }),
                Err(error) => fail(id, error),
            },
            Request::ProfileGet { profile_id } => match self.catalog.get(&profile_id) {
                Ok(profile) => ok(id, Response::Profile { profile }),
                Err(error) => fail(id, error),
            },
            Request::ProfileDelete { profile_id } => {
                // Disconnecting first is the user's job; silently tearing down
                // their tunnel because they tidied a list would be worse.
                if self.session.status().profile_id.as_ref() == Some(&profile_id) {
                    return fail(id, SessionError::AlreadyConnected);
                }
                match self.catalog.delete(&profile_id) {
                    Ok(()) => ok(id, Response::Ack),
                    Err(error) => fail(id, error),
                }
            }
            // Proxy credentials and statistics belong to the proxy listener,
            // which is not started yet; saying so beats inventing a shape the
            // GUI would cache.
            other => {
                debug!(request = ?other, "unimplemented request");
                error(
                    id,
                    IpcError::new(
                        ErrorCode::Internal,
                        "this request is not implemented in this build",
                    ),
                )
            }
        }
    }

    fn prompt_reply(
        &self,
        id: RequestId,
        prompt_id: PromptId,
        reply: PromptReply,
    ) -> DaemonMessage {
        match self.session.prompts().deliver(&prompt_id, reply) {
            Ok(()) => ok(id, Response::Ack),
            Err(PromptError::UnknownPrompt) => error(
                id,
                IpcError::new(
                    ErrorCode::PromptExpired,
                    "the daemon already withdrew that prompt",
                ),
            ),
            Err(prompt_error) => {
                warn!(%prompt_error, "could not deliver a prompt reply");
                error(
                    id,
                    IpcError::new(ErrorCode::Internal, "could not deliver the prompt reply"),
                )
            }
        }
    }
}

impl MessageHandler for SessionHandler {
    fn dispatch<'a>(
        &'a self,
        message: ClientMessage,
    ) -> Pin<Box<dyn Future<Output = DaemonMessage> + Send + 'a>> {
        Box::pin(self.dispatch(message))
    }
}

fn hello(id: RequestId, protocol_version: u32) -> DaemonMessage {
    match thisconnect_shared::ipc::check_protocol_version(protocol_version) {
        Ok(()) => DaemonMessage::Hello {
            id,
            protocol_version: thisconnect_shared::ipc::PROTOCOL_VERSION,
            daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        Err(mismatch) => error(id, mismatch),
    }
}

fn ok(id: RequestId, response: Response) -> DaemonMessage {
    DaemonMessage::Response { id, response }
}

fn error(id: RequestId, error: IpcError) -> DaemonMessage {
    DaemonMessage::Error { id, error }
}

fn fail(id: RequestId, error: SessionError) -> DaemonMessage {
    DaemonMessage::Error {
        id,
        error: IpcError::new(code_for(&error), error.user_facing()),
    }
}

/// Every failure the GUI must react to differently gets its own code; everything
/// else is `Internal`, whose detail is already user-facing text.
fn code_for(error: &SessionError) -> ErrorCode {
    match error {
        SessionError::AlreadyConnected => ErrorCode::AlreadyConnected,
        SessionError::NotConnected => ErrorCode::NotConnected,
        SessionError::Busy | SessionError::IllegalTransition { .. } => ErrorCode::Busy,
        SessionError::ProfileNotFound { .. } => ErrorCode::ProfileNotFound,
        SessionError::Profile(_) => ErrorCode::ProfileInvalid,
        SessionError::Auth(_) | SessionError::AuthRejected { .. } => ErrorCode::AuthFailed,
        SessionError::MissingTunnelAddress | SessionError::Policy(_) => ErrorCode::TunnelNotReady,
        _ => ErrorCode::Internal,
    }
}

/// Convenience for the IPC server: a handler behind an `Arc`.
pub fn shared(session: SessionManager, catalog: Arc<dyn ProfileStore>) -> Arc<SessionHandler> {
    Arc::new(SessionHandler::new(session, catalog))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use thisconnect_shared::ipc::{ConnectionState, PROTOCOL_VERSION};

    /// Profile CRUD has its own suite in `session::store`; these tests only need
    /// the catalog to exist, so it points at a directory that is never created.
    fn handler() -> SessionHandler {
        let pid = std::process::id();
        let root = std::env::temp_dir().join(format!("thisconnect-handler-{pid}"));
        SessionHandler::new(
            crate::session::tests::idle_manager(),
            Arc::new(crate::session::profiles::FileProfileStore::new(root)),
        )
    }

    fn id() -> RequestId {
        RequestId("1".to_owned())
    }

    #[tokio::test]
    async fn answers_a_matching_hello_with_its_own_version() {
        let reply = handler()
            .dispatch(ClientMessage::Hello {
                id: id(),
                protocol_version: PROTOCOL_VERSION,
                client_name: "gui".to_owned(),
            })
            .await;

        assert!(matches!(reply, DaemonMessage::Hello { .. }));
    }

    #[tokio::test]
    async fn refuses_a_client_speaking_another_protocol_revision() {
        let reply = handler()
            .dispatch(ClientMessage::Hello {
                id: id(),
                protocol_version: PROTOCOL_VERSION + 1,
                client_name: "gui".to_owned(),
            })
            .await;

        assert!(matches!(
            reply,
            DaemonMessage::Error {
                error: IpcError {
                    code: ErrorCode::ProtocolVersionMismatch,
                    ..
                },
                ..
            }
        ));
    }

    #[tokio::test]
    async fn reports_disconnected_status_before_anything_is_connected() {
        let reply = handler()
            .dispatch(ClientMessage::Request {
                id: id(),
                request: Request::Status,
            })
            .await;

        match reply {
            DaemonMessage::Response {
                response: Response::Status { status },
                ..
            } => assert_eq!(status.state, ConnectionState::Disconnected),
            other => panic!("unexpected reply: {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_a_disconnect_when_nothing_is_connected() {
        let reply = handler()
            .dispatch(ClientMessage::Request {
                id: id(),
                request: Request::Disconnect,
            })
            .await;

        assert!(matches!(
            reply,
            DaemonMessage::Error {
                error: IpcError {
                    code: ErrorCode::NotConnected,
                    ..
                },
                ..
            }
        ));
    }

    #[tokio::test]
    async fn reports_a_reply_to_an_unknown_prompt_as_expired() {
        let reply = handler()
            .dispatch(ClientMessage::PromptReply {
                id: id(),
                prompt_id: PromptId("nope".to_owned()),
                reply: PromptReply::Cancel,
            })
            .await;

        assert!(matches!(
            reply,
            DaemonMessage::Error {
                error: IpcError {
                    code: ErrorCode::PromptExpired,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn maps_a_second_connect_to_the_already_connected_code() {
        assert_eq!(
            code_for(&SessionError::AlreadyConnected),
            ErrorCode::AlreadyConnected
        );
    }

    #[test]
    fn maps_a_policy_failure_to_tunnel_not_ready_rather_than_a_generic_error() {
        let error = SessionError::MissingTunnelAddress;

        assert_eq!(code_for(&error), ErrorCode::TunnelNotReady);
    }
}
