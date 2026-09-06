// SPDX-License-Identifier: GPL-3.0-or-later

//! The connection state machine and the event sink both the orchestrator and the
//! auth flow report through.
//!
//! Every transition is checked. A daemon that believes it is `Connected` while
//! openvpn is gone would keep the proxy publishing a dead tunnel identity, which
//! is the fail-open leak SPEC.md §5.3 exists to prevent, so an illegal
//! transition is an error rather than a silent overwrite.

use std::sync::Mutex;

use thisconnect_shared::ipc::{ConnectionState, DaemonMessage, Event};
use tokio::sync::{mpsc, watch};
use tracing::warn;

use super::SessionError;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SessionState {
    #[default]
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Disconnecting,
    Failed,
}

impl SessionState {
    pub fn to_ipc(self) -> ConnectionState {
        match self {
            Self::Disconnected => ConnectionState::Disconnected,
            Self::Connecting => ConnectionState::Connecting,
            Self::Authenticating => ConnectionState::Authenticating,
            Self::Connected => ConnectionState::Connected,
            Self::Disconnecting => ConnectionState::Disconnecting,
            Self::Failed => ConnectionState::Failed,
        }
    }

    /// True while a connection attempt or a live connection owns the daemon's
    /// single v1 session slot.
    pub fn is_busy(self) -> bool {
        matches!(
            self,
            Self::Connecting | Self::Authenticating | Self::Connected | Self::Disconnecting
        )
    }

    fn permits(self, next: Self) -> bool {
        match (self, next) {
            // A failure is reachable from anywhere: teardown must never be blocked.
            (_, Self::Failed) => true,
            (Self::Disconnected | Self::Failed, Self::Connecting) => true,
            (Self::Connecting, Self::Authenticating | Self::Connected | Self::Disconnecting) => {
                true
            }
            (Self::Authenticating, Self::Connected | Self::Disconnecting) => true,
            (Self::Connected, Self::Disconnecting) => true,
            (Self::Disconnecting | Self::Failed, Self::Disconnected) => true,
            _ => false,
        }
    }
}

/// Fire-and-forget IPC event publication.
///
/// The channel is bounded and never awaited on: a GUI that stopped reading must
/// not be able to stall the privileged connect path, and a dropped byte-count is
/// harmless. Nothing fail-closed is derived from these events — the proxy learns
/// about a dead tunnel from the egress generation counter, not from here.
#[derive(Clone)]
pub struct EventSink {
    outbound: mpsc::Sender<DaemonMessage>,
}

impl EventSink {
    pub fn new(outbound: mpsc::Sender<DaemonMessage>) -> Self {
        Self { outbound }
    }

    pub fn emit(&self, event: Event) {
        if self
            .outbound
            .try_send(DaemonMessage::Event { event })
            .is_err()
        {
            warn!("dropped an IPC event: no client is reading");
        }
    }

    pub fn sender(&self) -> mpsc::Sender<DaemonMessage> {
        self.outbound.clone()
    }
}

/// The single authority on what the daemon believes about its one connection.
pub struct StateCell {
    current: Mutex<SessionState>,
    watch: watch::Sender<SessionState>,
    events: EventSink,
}

impl StateCell {
    pub fn new(events: EventSink) -> Self {
        let (watch, _) = watch::channel(SessionState::Disconnected);
        Self {
            current: Mutex::new(SessionState::Disconnected),
            watch,
            events,
        }
    }

    pub fn current(&self) -> SessionState {
        *lock(&self.current)
    }

    pub fn subscribe(&self) -> watch::Receiver<SessionState> {
        self.watch.subscribe()
    }

    /// Claims the session slot. Only one connection exists in v1, so a second
    /// `Connect` is a typed rejection and never a second openvpn.
    pub fn begin_connect(&self) -> Result<(), SessionError> {
        let mut current = lock(&self.current);
        match *current {
            SessionState::Connected => return Err(SessionError::AlreadyConnected),
            state if state.is_busy() => return Err(SessionError::Busy),
            _ => {}
        }
        self.commit(&mut current, SessionState::Connecting, None);
        Ok(())
    }

    /// Claims the slot for teardown, returning the state it was in.
    ///
    /// `Failed` is accepted too, even though `is_busy()` excludes it: a failure
    /// already owns the slot from the GUI's point of view (`ConnectionState`
    /// isn't `Disconnected`), so without this a failed session has no way back
    /// — `Connect` stays disabled and `Disconnect` returns `NotConnected`
    /// forever. `disconnect()`'s own teardown is a no-op when nothing is left
    /// to tear down, so this is safe regardless of whether the failure path
    /// already cleared `active`.
    pub fn begin_disconnect(&self) -> Result<SessionState, SessionError> {
        let mut current = lock(&self.current);
        let previous = *current;
        if !previous.is_busy() && previous != SessionState::Failed {
            return Err(SessionError::NotConnected);
        }
        if previous == SessionState::Disconnecting {
            return Err(SessionError::Busy);
        }
        self.commit(&mut current, SessionState::Disconnecting, None);
        Ok(previous)
    }

    pub fn advance(&self, next: SessionState) -> Result<(), SessionError> {
        self.advance_with(next, None)
    }

    pub fn advance_with(
        &self,
        next: SessionState,
        detail: Option<String>,
    ) -> Result<(), SessionError> {
        let mut current = lock(&self.current);
        if *current == next {
            return Ok(());
        }
        if !current.permits(next) {
            return Err(SessionError::IllegalTransition {
                from: *current,
                to: next,
            });
        }
        self.commit(&mut current, next, detail);
        Ok(())
    }

    /// Teardown paths must always land somewhere terminal, so this cannot fail.
    pub fn force(&self, next: SessionState, detail: Option<String>) {
        let mut current = lock(&self.current);
        if *current == next {
            return;
        }
        self.commit(&mut current, next, detail);
    }

    fn commit(&self, slot: &mut SessionState, next: SessionState, detail: Option<String>) {
        *slot = next;
        let _ = self.watch.send(next);
        self.events.emit(Event::State {
            state: next.to_ipc(),
            detail,
        });
    }
}

/// A poisoned state mutex means a panic happened while holding it. The daemon is
/// privileged, so it recovers the value rather than propagating the panic.
fn lock(cell: &Mutex<SessionState>) -> std::sync::MutexGuard<'_, SessionState> {
    cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn cell() -> (StateCell, mpsc::Receiver<DaemonMessage>) {
        let (tx, rx) = mpsc::channel(16);
        (StateCell::new(EventSink::new(tx)), rx)
    }

    #[test]
    fn starts_disconnected() {
        let (cell, _rx) = cell();

        assert_eq!(cell.current(), SessionState::Disconnected);
    }

    #[test]
    fn rejects_a_second_connect_while_one_is_already_up() {
        // Arrange
        let (cell, _rx) = cell();
        cell.begin_connect().expect("first connect");
        cell.advance(SessionState::Connected).expect("connected");

        // Act
        let second = cell.begin_connect();

        // Assert
        assert!(matches!(second, Err(SessionError::AlreadyConnected)));
    }

    #[test]
    fn rejects_a_second_connect_while_the_first_is_still_dialling() {
        let (cell, _rx) = cell();
        cell.begin_connect().expect("first connect");

        assert!(matches!(cell.begin_connect(), Err(SessionError::Busy)));
    }

    #[test]
    fn allows_connecting_again_after_a_failure() {
        // Arrange
        let (cell, _rx) = cell();
        cell.begin_connect().expect("connect");
        cell.force(SessionState::Failed, Some("boom".to_owned()));

        // Act / Assert
        assert!(cell.begin_connect().is_ok());
    }

    /// A user who never retries a failed connect has no other way back to
    /// `Disconnected` — `begin_disconnect()` must accept `Failed` as a starting
    /// state, or the GUI is left with Connect disabled (state isn't
    /// `disconnected`) and Disconnect permanently erroring `NotConnected`.
    #[test]
    fn allows_disconnecting_from_a_failed_state() {
        // Arrange
        let (cell, _rx) = cell();
        cell.begin_connect().expect("connect");
        cell.force(SessionState::Failed, Some("boom".to_owned()));

        // Act
        let previous = cell.begin_disconnect();

        // Assert
        assert!(matches!(previous, Ok(SessionState::Failed)));
    }

    #[test]
    fn refuses_to_jump_from_disconnected_straight_to_connected() {
        let (cell, _rx) = cell();

        let outcome = cell.advance(SessionState::Connected);

        assert!(matches!(
            outcome,
            Err(SessionError::IllegalTransition {
                from: SessionState::Disconnected,
                to: SessionState::Connected
            })
        ));
    }

    #[test]
    fn disconnect_is_rejected_when_nothing_is_connected() {
        let (cell, _rx) = cell();

        assert!(matches!(
            cell.begin_disconnect(),
            Err(SessionError::NotConnected)
        ));
    }

    #[test]
    fn disconnect_reports_the_state_it_interrupted() {
        let (cell, _rx) = cell();
        cell.begin_connect().expect("connect");
        cell.advance(SessionState::Authenticating).expect("auth");

        let previous = cell.begin_disconnect().expect("disconnect");

        assert_eq!(previous, SessionState::Authenticating);
    }

    #[test]
    fn emits_one_ipc_event_per_transition() {
        // Arrange
        let (cell, mut rx) = cell();

        // Act
        cell.begin_connect().expect("connect");
        cell.advance(SessionState::Authenticating).expect("auth");

        // Assert
        let first = rx.try_recv().expect("first event");
        let second = rx.try_recv().expect("second event");
        assert!(matches!(
            first,
            DaemonMessage::Event {
                event: Event::State {
                    state: ConnectionState::Connecting,
                    ..
                }
            }
        ));
        assert!(matches!(
            second,
            DaemonMessage::Event {
                event: Event::State {
                    state: ConnectionState::Authenticating,
                    ..
                }
            }
        ));
    }

    #[test]
    fn a_repeated_transition_emits_nothing() {
        let (cell, mut rx) = cell();
        cell.begin_connect().expect("connect");
        let _ = rx.try_recv();

        cell.advance(SessionState::Connecting).expect("idempotent");

        assert!(rx.try_recv().is_err());
    }
}
