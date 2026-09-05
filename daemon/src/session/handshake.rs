// SPDX-License-Identifier: GPL-3.0-or-later

//! Driving openvpn from `hold release` to a tunnel that is up (SPEC.md §4.3).
//!
//! Connected detection is `>STATE:*,CONNECTED,*` *and* a `>UPDOWN` block
//! carrying `dev=`, never one without the other: the state line has no device
//! name, and §5.3 egress binding has nothing to bind to without one.

use tokio::sync::{broadcast, watch};
use tokio::time::Instant;
use tracing::warn;

use thisconnect_shared::ovpn::Profile;

use crate::auth::{AuthError, MgmtAnswer};
use crate::mgmt::challenge::StaticChallengeFormat;
use crate::mgmt::event::{InfoMsg, PasswordEvent};
use crate::mgmt::{Event as MgmtEvent, TunnelIdentity, TunnelState};

use super::connect::{exited, Attempt, SessionResources};
use super::SessionError;

/// Answers openvpn's prompts until the tunnel reports itself up with an identity.
pub(crate) async fn authenticate(
    resources: &mut SessionResources,
    profile: &Profile,
    attempt: &Attempt<'_>,
) -> Result<TunnelIdentity, SessionError> {
    let mgmt = resources.mgmt.as_mut().ok_or(SessionError::Internal {
        detail: "no management channel".to_owned(),
    })?;
    // The receiver taken during `MgmtClient::connect`, not a fresh subscription:
    // the handshake released openvpn's hold, and openvpn answers that with
    // `>PASSWORD:` immediately. A subscription made here would be created after
    // that send and would miss it, leaving the connect stuck in Authenticating.
    // Take it rather than clone it: a tokio broadcast `Receiver` cannot be
    // rewound, and only the original carries the events buffered since before
    // the hold was released. The replacement keeps `Connected` well-formed for
    // anything that subscribes later.
    let mut events = std::mem::replace(&mut mgmt.events, mgmt.client.subscribe());
    let mut tunnel = mgmt.client.tunnel_state();
    let mut cancel = attempt.cancel.clone();
    let deadline = Instant::now() + attempt.config.connect_timeout;
    let format = super::connect::challenge_format(profile);

    loop {
        if let Some(identity) = ready(&tunnel) {
            return Ok(identity);
        }
        let event = tokio::select! {
            biased;
            exit = &mut resources.exit => return Err(exited(exit)),
            _ = cancel.changed() => return Err(SessionError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => return Err(SessionError::ManagementTimeout),
            changed = tunnel.changed() => {
                if changed.is_err() {
                    return Err(SessionError::Mgmt(crate::mgmt::MgmtError::Eof));
                }
                continue;
            }
            received = events.recv() => match received {
                Ok(event) => event,
                // The event feed is lossy by design; connectivity does not travel
                // on it, but a dropped prompt would stall until openvpn re-asks.
                Err(broadcast::error::RecvError::Lagged(dropped)) => {
                    warn!(dropped, "management event feed lagged");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(SessionError::Mgmt(crate::mgmt::MgmtError::Eof))
                }
            },
        };

        handle_event(event, resources, attempt, format).await?;
    }
}

fn ready(tunnel: &watch::Receiver<TunnelState>) -> Option<TunnelIdentity> {
    let state = tunnel.borrow();
    // Both halves are required: `>STATE:CONNECTED` alone has no device name, and
    // §5.3 has nothing to bind an egress socket to without one.
    state.connected.then(|| state.identity.clone()).flatten()
}

async fn handle_event(
    event: MgmtEvent,
    resources: &mut SessionResources,
    attempt: &Attempt<'_>,
    format: StaticChallengeFormat,
) -> Result<(), SessionError> {
    match event {
        MgmtEvent::Password(password) => {
            answer_password(password, resources, attempt, format).await
        }
        MgmtEvent::InfoMsg(InfoMsg::CrText(text)) => {
            let answer = race(attempt.flow.answer_cr_text(&text), resources, attempt).await?;
            send_answer(&answer, resources).await
        }
        MgmtEvent::Fatal(text) => Err(SessionError::OpenvpnFatal { detail: text }),
        MgmtEvent::ByteCount {
            bytes_in,
            bytes_out,
        } => {
            attempt
                .events
                .emit(thisconnect_shared::ipc::Event::ByteCount {
                    bytes_in,
                    bytes_out,
                });
            Ok(())
        }
        // `>LOG:` is deliberately not forwarded: openvpn redacts `password` but
        // not `username`, and raw log output is never persisted (SPEC.md §4.4).
        _ => Ok(()),
    }
}

async fn answer_password(
    password: PasswordEvent,
    resources: &mut SessionResources,
    attempt: &Attempt<'_>,
    format: StaticChallengeFormat,
) -> Result<(), SessionError> {
    let answer = match password {
        PasswordEvent::Need {
            kind,
            needs_username,
            needs_password,
            challenge,
        } => {
            let pending = attempt.flow.answer_need(
                &kind,
                needs_username,
                needs_password,
                challenge.as_ref(),
                format,
            );
            race(pending, resources, attempt).await?
        }
        PasswordEvent::VerificationFailed {
            kind,
            dynamic: Some(dynamic),
            ..
        } => {
            let pending = attempt.flow.answer_dynamic_challenge(&kind, &dynamic);
            race(pending, resources, attempt).await?
        }
        PasswordEvent::VerificationFailed { reason, .. } => {
            return Err(SessionError::AuthRejected {
                detail: reason.unwrap_or_else(|| "openvpn rejected the credentials".to_owned()),
            })
        }
        PasswordEvent::AuthToken | PasswordEvent::Other(_) => return Ok(()),
    };
    send_answer(&answer, resources).await
}

/// Waits for the user (or the keyring) while still noticing a dead openvpn or a
/// `Disconnect` that arrived mid-prompt.
async fn race<F>(
    pending: F,
    resources: &mut SessionResources,
    attempt: &Attempt<'_>,
) -> Result<MgmtAnswer, SessionError>
where
    F: std::future::Future<Output = Result<MgmtAnswer, AuthError>>,
{
    let mut cancel = attempt.cancel.clone();
    tokio::pin!(pending);
    tokio::select! {
        biased;
        exit = &mut resources.exit => Err(exited(exit)),
        _ = cancel.changed() => Err(SessionError::Cancelled),
        answered = &mut pending => answered.map_err(SessionError::Auth),
    }
}

async fn send_answer(
    answer: &MgmtAnswer,
    resources: &mut SessionResources,
) -> Result<(), SessionError> {
    let mgmt = resources.mgmt.as_ref().ok_or(SessionError::Internal {
        detail: "no management channel".to_owned(),
    })?;
    for line in answer.commands().map_err(SessionError::Mgmt)? {
        let reply = mgmt
            .client
            .send(line.as_str())
            .await
            .map_err(SessionError::Mgmt)?;
        if reply.is_error() {
            return Err(SessionError::AuthRejected { detail: reply.text });
        }
    }
    Ok(())
}
