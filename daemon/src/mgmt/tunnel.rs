// SPDX-License-Identifier: GPL-3.0-or-later

//! The tunnel state machine (SPEC.md §4.3 points 5 and 6) and its lossless publication.
//!
//! Connectivity must never travel on the lossy `broadcast` channel that carries `>LOG:` traffic:
//! a reconnect storm at `--verb 3` overruns it while a consumer is closing sessions, and a
//! dropped transition away from `CONNECTED` leaves egress sockets pinned to a dead utun — the
//! fail-open leak SPEC.md §5.3 exists to prevent. The tracker is therefore folded inside the
//! actor and the result published on a `watch`, whose latest value is always observable.

use tokio::sync::watch;

use super::event::{Event, TunnelIdentity, UpDown, UpDownCollector, UpDownOutcome};
use super::MgmtError;

/// Pure state machine over the event stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TunnelTracker {
    connected: bool,
    updown: UpDownCollector,
    identity: Option<TunnelIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelEvent {
    Connected,
    Disconnected,
    IdentityLearned(TunnelIdentity),
    IdentityLost,
}

/// The authoritative, always-observable tunnel state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TunnelState {
    pub connected: bool,
    pub identity: Option<TunnelIdentity>,
    /// Bumped on every entry into `CONNECTED`. A `watch` coalesces intermediate values, so a
    /// consumer that was busy during a down/up flap sees `connected == true` both before and
    /// after; a changed generation is what tells it the session it pinned sockets to is gone.
    pub generation: u64,
}

impl TunnelState {
    fn advanced_to(&self, tracker: &TunnelTracker) -> Self {
        let reconnected = tracker.is_connected() && !self.connected;
        Self {
            connected: tracker.is_connected(),
            identity: tracker.identity().cloned(),
            generation: if reconnected {
                self.generation.saturating_add(1)
            } else {
                self.generation
            },
        }
    }
}

/// Folds one event in and publishes the result. A fold error is fail-closed: subscribers are
/// told the tunnel is down before the error propagates and tears the actor down.
pub(crate) fn observe_and_publish(
    tracker: &TunnelTracker,
    event: &Event,
    sink: &watch::Sender<TunnelState>,
) -> Result<TunnelTracker, MgmtError> {
    match tracker.observe(event) {
        Ok((next, None)) => Ok(next),
        Ok((next, Some(_))) => {
            publish(sink, &next);
            Ok(next)
        }
        Err(err) => {
            publish_disconnected(sink);
            Err(err)
        }
    }
}

/// Announces that nothing is reachable any more. Used on every actor exit path, since a closed
/// management channel means the tun can vanish without another event ever arriving.
pub(crate) fn publish_disconnected(sink: &watch::Sender<TunnelState>) {
    publish(sink, &TunnelTracker::default());
}

fn publish(sink: &watch::Sender<TunnelState>, tracker: &TunnelTracker) {
    sink.send_if_modified(|state| {
        let next = state.advanced_to(tracker);
        if next == *state {
            return false;
        }
        *state = next;
        true
    });
}

impl TunnelTracker {
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn identity(&self) -> Option<&TunnelIdentity> {
        self.identity.as_ref()
    }

    /// Folds one event in, returning the next tracker and any transition it caused.
    pub fn observe(&self, event: &Event) -> Result<(Self, Option<TunnelEvent>), MgmtError> {
        match event {
            Event::State(state) => Ok(self.transition(state.is_connected())),
            Event::Fatal(_) => Ok(self.transition(false)),
            Event::UpDown(line) => self.fold_updown(line),
            _ => Ok((self.clone(), None)),
        }
    }

    fn transition(&self, connected: bool) -> (Self, Option<TunnelEvent>) {
        if connected == self.connected {
            return (self.clone(), None);
        }
        let signal = if connected {
            TunnelEvent::Connected
        } else {
            TunnelEvent::Disconnected
        };
        (
            Self {
                connected,
                updown: self.updown.clone(),
                // A stale identity is a leak vector: sockets must never be pinned to a dead tun.
                identity: if connected {
                    self.identity.clone()
                } else {
                    None
                },
            },
            Some(signal),
        )
    }

    fn fold_updown(&self, line: &UpDown) -> Result<(Self, Option<TunnelEvent>), MgmtError> {
        let (updown, outcome) = self.updown.observe(line);
        match outcome {
            None => Ok((
                Self {
                    updown,
                    ..self.clone()
                },
                None,
            )),
            Some(Ok(UpDownOutcome::Up(identity))) => Ok((
                Self {
                    connected: self.connected,
                    updown,
                    identity: Some(identity.clone()),
                },
                Some(TunnelEvent::IdentityLearned(identity)),
            )),
            Some(Ok(UpDownOutcome::Down)) => Ok((
                Self {
                    connected: self.connected,
                    updown,
                    identity: None,
                },
                Some(TunnelEvent::IdentityLost),
            )),
            Some(Err(err)) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::mgmt::event::{PasswordEvent, StateEvent};

    fn state(name: &str) -> Event {
        Event::State(StateEvent {
            name: name.to_owned(),
            ..StateEvent::default()
        })
    }

    fn identity() -> TunnelIdentity {
        TunnelIdentity {
            dev: "utun4".to_owned(),
            dev_type: None,
            ifconfig_local: Some("10.8.0.2".to_owned()),
            ifconfig_ipv6_local: None,
        }
    }

    fn up_block() -> Vec<Event> {
        vec![
            Event::UpDown(UpDown::Up),
            Event::UpDown(UpDown::parse("ENV,dev=utun4")),
            Event::UpDown(UpDown::parse("ENV,ifconfig_local=10.8.0.2")),
            Event::UpDown(UpDown::parse("ENV,END")),
        ]
    }

    fn track(events: &[Event]) -> (TunnelTracker, Vec<TunnelEvent>) {
        events.iter().fold(
            (TunnelTracker::default(), Vec::new()),
            |(tracker, signals), event| {
                let (next, signal) = tracker.observe(event).expect("tracked");
                (next, signals.into_iter().chain(signal).collect())
            },
        )
    }

    fn publish_all(events: &[Event]) -> (watch::Sender<TunnelState>, Result<(), MgmtError>) {
        let (sink, _keep) = watch::channel(TunnelState::default());
        let outcome = events
            .iter()
            .try_fold(TunnelTracker::default(), |tracker, event| {
                observe_and_publish(&tracker, event, &sink)
            });
        (sink, outcome.map(|_| ()))
    }

    #[test]
    fn signals_connected_only_on_the_connected_state() {
        let (tracker, signals) = track(&[
            state("WAIT"),
            state("AUTH"),
            state("GET_CONFIG"),
            state("ASSIGN_IP"),
            state("ADD_ROUTES"),
            state("CONNECTED"),
        ]);

        assert!(tracker.is_connected());
        assert_eq!(signals, vec![TunnelEvent::Connected]);
    }

    #[test]
    fn signals_disconnected_on_reconnecting_and_forgets_the_tunnel_identity() {
        let events: Vec<Event> = up_block()
            .into_iter()
            .chain([state("CONNECTED"), state("RECONNECTING")])
            .collect();

        let (tracker, signals) = track(&events);

        assert!(!tracker.is_connected());
        assert!(tracker.identity().is_none());
        assert_eq!(
            signals,
            vec![
                TunnelEvent::IdentityLearned(identity()),
                TunnelEvent::Connected,
                TunnelEvent::Disconnected,
            ]
        );
    }

    #[test]
    fn treats_a_fatal_event_as_a_disconnect() {
        let (tracker, signals) = track(&[
            state("CONNECTED"),
            Event::Fatal("Cannot open TUN/TAP dev".to_owned()),
        ]);

        assert!(!tracker.is_connected());
        assert_eq!(
            signals,
            vec![TunnelEvent::Connected, TunnelEvent::Disconnected]
        );
    }

    #[test]
    fn fails_hard_when_the_up_block_carries_no_dev() {
        let tracker = TunnelTracker::default();
        let (tracker, _) = tracker.observe(&Event::UpDown(UpDown::Up)).expect("up");
        let (tracker, _) = tracker
            .observe(&Event::UpDown(UpDown::parse("ENV,ifconfig_local=10.8.0.2")))
            .expect("env");

        let outcome = tracker.observe(&Event::UpDown(UpDown::parse("ENV,END")));

        assert!(matches!(outcome, Err(MgmtError::MissingDev)));
    }

    #[test]
    fn ignores_events_that_do_not_move_the_tunnel_state() {
        let (tracker, signals) = track(&[
            Event::ByteCount {
                bytes_in: 1,
                bytes_out: 2,
            },
            Event::Password(PasswordEvent::AuthToken),
        ]);

        assert_eq!(tracker, TunnelTracker::default());
        assert!(signals.is_empty());
    }

    #[test]
    fn publishes_the_connected_state_with_the_learned_identity() {
        let events: Vec<Event> = up_block().into_iter().chain([state("CONNECTED")]).collect();

        let (sink, outcome) = publish_all(&events);

        assert!(outcome.is_ok());
        assert_eq!(
            *sink.borrow(),
            TunnelState {
                connected: true,
                identity: Some(identity()),
                generation: 1,
            }
        );
    }

    /// The whole point of the `watch`: a consumer that never polled during the flap still sees a
    /// state it must act on, because the generation changed even though `connected` came back true.
    #[test]
    fn a_reconnect_flap_is_observable_to_a_consumer_that_never_polled() {
        let events: Vec<Event> = up_block()
            .into_iter()
            .chain([state("CONNECTED"), state("RECONNECTING")])
            .chain(up_block())
            .chain([state("CONNECTED")])
            .collect();

        let (sink, _) = publish_all(&events);

        let published = sink.borrow().clone();
        assert!(published.connected);
        assert_eq!(published.generation, 2);
    }

    #[test]
    fn publishes_a_disconnect_before_propagating_a_missing_dev_error() {
        let events = vec![
            state("CONNECTED"),
            Event::UpDown(UpDown::Up),
            Event::UpDown(UpDown::parse("ENV,END")),
        ];

        let (sink, outcome) = publish_all(&events);

        assert!(matches!(outcome, Err(MgmtError::MissingDev)));
        assert!(!sink.borrow().connected);
        assert!(sink.borrow().identity.is_none());
    }

    #[test]
    fn publish_disconnected_clears_a_live_identity() {
        let events: Vec<Event> = up_block().into_iter().chain([state("CONNECTED")]).collect();
        let (sink, _) = publish_all(&events);

        publish_disconnected(&sink);

        assert_eq!(
            *sink.borrow(),
            TunnelState {
                connected: false,
                identity: None,
                generation: 1,
            }
        );
    }

    #[test]
    fn does_not_republish_an_unchanged_state() {
        let (sink, receiver) = watch::channel(TunnelState::default());
        let tracker = TunnelTracker::default();

        let tracker = observe_and_publish(&tracker, &state("WAIT"), &sink).expect("wait");
        let _ = observe_and_publish(&tracker, &state("RECONNECTING"), &sink).expect("reconnecting");

        assert!(!receiver.has_changed().expect("open"));
    }
}
