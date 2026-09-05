// SPDX-License-Identifier: GPL-3.0-or-later

//! Asking the GUI for a credential and correlating the answer.
//!
//! The IPC protocol has no request/response pairing for daemon-initiated messages beyond the
//! `prompt_id`, so this broker owns that map. Every outstanding prompt is bounded: openvpn's
//! auth attempt cannot be left hanging on a GUI that went away.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use thisconnect_shared::ipc::{CredentialPrompt, DaemonMessage, Event, PromptId, PromptReply};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

/// Long enough to fetch a phone, short enough that openvpn's own retry does not overtake us.
pub const DEFAULT_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PromptError {
    #[error("the user cancelled the credential prompt")]
    Cancelled,

    #[error("no answer to the credential prompt within {0:?}")]
    TimedOut(Duration),

    /// Nothing is listening: no GUI is connected, or it disconnected mid-prompt. Distinct from
    /// a cancellation because it is not a user decision.
    #[error("no client is connected to answer the credential prompt")]
    NoClient,

    #[error("the reply does not answer the prompt that was asked")]
    MismatchedReply,

    #[error("no prompt is outstanding with that id")]
    UnknownPrompt,
}

/// What the user typed. Never `Debug`-printed with its contents: the secret half is `Zeroizing`
/// and the struct itself is not `Debug`.
pub enum PromptAnswer {
    UsernamePassword {
        username: String,
        password: Zeroizing<String>,
    },
    /// A static or dynamic challenge answer. Which one is fixed by the prompt that was sent.
    Challenge(Zeroizing<String>),
}

/// Hand-written so a `{answer:?}` anywhere cannot print what the user typed.
impl fmt::Debug for PromptAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UsernamePassword { username, .. } => f
                .debug_struct("UsernamePassword")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            Self::Challenge(_) => f.write_str("Challenge(<redacted>)"),
        }
    }
}

pub struct PromptBroker {
    outbound: mpsc::Sender<DaemonMessage>,
    pending: Mutex<HashMap<PromptId, oneshot::Sender<PromptReply>>>,
    sequence: AtomicU64,
    timeout: Duration,
}

impl PromptBroker {
    pub fn new(outbound: mpsc::Sender<DaemonMessage>, timeout: Duration) -> Self {
        Self {
            outbound,
            pending: Mutex::new(HashMap::new()),
            sequence: AtomicU64::new(1),
            timeout,
        }
    }

    /// Sends `prompt` to the GUI and waits for the matching `prompt_reply`.
    pub async fn ask(&self, prompt: CredentialPrompt) -> Result<PromptAnswer, PromptError> {
        let wants_username = matches!(prompt, CredentialPrompt::UsernamePassword { .. });
        let prompt_id = self.next_id();
        let (tx, rx) = oneshot::channel();
        lock(&self.pending).insert(prompt_id.clone(), tx);

        let message = DaemonMessage::Prompt {
            prompt_id: prompt_id.clone(),
            prompt,
        };
        if self.outbound.send(message).await.is_err() {
            self.withdraw(&prompt_id);
            return Err(PromptError::NoClient);
        }

        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(reply)) => into_answer(reply, wants_username),
            // The sender is only dropped by a withdrawal, which is a teardown, not an answer.
            Ok(Err(_)) => Err(PromptError::NoClient),
            Err(_) => {
                self.withdraw(&prompt_id);
                self.announce(Event::PromptCancelled { prompt_id }).await;
                Err(PromptError::TimedOut(self.timeout))
            }
        }
    }

    /// Called by the IPC server when a `prompt_reply` arrives. An id that is not outstanding is
    /// rejected rather than ignored, so the GUI can render `prompt_expired`.
    pub fn deliver(&self, prompt_id: &PromptId, reply: PromptReply) -> Result<(), PromptError> {
        let sender = lock(&self.pending)
            .remove(prompt_id)
            .ok_or(PromptError::UnknownPrompt)?;
        sender.send(reply).map_err(|_| PromptError::UnknownPrompt)
    }

    /// Drops every outstanding prompt. Used when the connection attempt is abandoned or the GUI
    /// disconnects: an unanswered prompt must not outlive the attempt it belongs to.
    pub async fn withdraw_all(&self) {
        let outstanding: Vec<PromptId> = lock(&self.pending).drain().map(|(id, _)| id).collect();
        for prompt_id in outstanding {
            self.announce(Event::PromptCancelled { prompt_id }).await;
        }
    }

    /// Surfaces a daemon-side notice — the short-seed warning among them — to the GUI.
    pub async fn announce(&self, event: Event) {
        // A closed channel means no GUI is attached; losing a notification is not fatal.
        let _ = self.outbound.send(DaemonMessage::Event { event }).await;
    }

    fn withdraw(&self, prompt_id: &PromptId) {
        lock(&self.pending).remove(prompt_id);
    }

    fn next_id(&self) -> PromptId {
        PromptId(format!(
            "prompt-{}",
            self.sequence.fetch_add(1, Ordering::Relaxed)
        ))
    }
}

/// A reply of the wrong shape is a protocol error, not something to coerce: silently reading a
/// challenge answer as a password would send the one-time code as the account password.
fn into_answer(reply: PromptReply, wants_username: bool) -> Result<PromptAnswer, PromptError> {
    match reply {
        PromptReply::Cancel => Err(PromptError::Cancelled),
        PromptReply::UsernamePassword { username, password } if wants_username => {
            Ok(PromptAnswer::UsernamePassword {
                username,
                password: Zeroizing::new(password.expose().to_owned()),
            })
        }
        PromptReply::ChallengeResponse { response } if !wants_username => Ok(
            PromptAnswer::Challenge(Zeroizing::new(response.expose().to_owned())),
        ),
        _ => Err(PromptError::MismatchedReply),
    }
}

/// A poisoned lock means another task panicked while holding it. The map is still structurally
/// sound and this daemon runs privileged: recovering beats a second panic.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use thisconnect_shared::ipc::{ProfileId, Secret};

    use super::*;

    fn broker(timeout: Duration) -> (Arc<PromptBroker>, mpsc::Receiver<DaemonMessage>) {
        let (tx, rx) = mpsc::channel(8);
        (Arc::new(PromptBroker::new(tx, timeout)), rx)
    }

    fn username_prompt() -> CredentialPrompt {
        CredentialPrompt::UsernamePassword {
            profile_id: ProfileId("p1".to_owned()),
            username_hint: None,
        }
    }

    fn challenge_prompt() -> CredentialPrompt {
        CredentialPrompt::StaticChallenge {
            profile_id: ProfileId("p1".to_owned()),
            challenge_text: "Enter token".to_owned(),
            echo: false,
        }
    }

    async fn next_prompt_id(rx: &mut mpsc::Receiver<DaemonMessage>) -> PromptId {
        match rx.recv().await {
            Some(DaemonMessage::Prompt { prompt_id, .. }) => prompt_id,
            other => panic!("expected a prompt, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn returns_the_username_and_password_the_user_typed() {
        let (broker, mut rx) = broker(DEFAULT_PROMPT_TIMEOUT);
        let asking = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.ask(username_prompt()).await }
        });

        let prompt_id = next_prompt_id(&mut rx).await;
        broker
            .deliver(
                &prompt_id,
                PromptReply::UsernamePassword {
                    username: "alice".to_owned(),
                    password: Secret::new("hunter2"),
                },
            )
            .expect("deliver");

        match asking.await.expect("join").expect("answer") {
            PromptAnswer::UsernamePassword { username, password } => {
                assert_eq!(username, "alice");
                assert_eq!(password.as_str(), "hunter2");
            }
            PromptAnswer::Challenge(_) => panic!("wrong answer shape"),
        }
    }

    #[tokio::test]
    async fn a_cancelled_prompt_aborts_instead_of_returning_an_empty_credential() {
        let (broker, mut rx) = broker(DEFAULT_PROMPT_TIMEOUT);
        let asking = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.ask(username_prompt()).await }
        });

        let prompt_id = next_prompt_id(&mut rx).await;
        broker
            .deliver(&prompt_id, PromptReply::Cancel)
            .expect("deliver");

        assert_eq!(
            asking.await.expect("join").unwrap_err(),
            PromptError::Cancelled
        );
    }

    #[tokio::test]
    async fn an_unanswered_prompt_times_out_and_is_withdrawn() {
        let (broker, mut rx) = broker(Duration::from_millis(20));
        let asking = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.ask(challenge_prompt()).await }
        });

        let prompt_id = next_prompt_id(&mut rx).await;
        let error = asking.await.expect("join").unwrap_err();

        assert!(matches!(error, PromptError::TimedOut(_)));
        match rx.recv().await {
            Some(DaemonMessage::Event {
                event: Event::PromptCancelled { prompt_id: id },
            }) => assert_eq!(id, prompt_id),
            other => panic!("expected a withdrawal, got {other:?}"),
        }
        assert_eq!(
            broker.deliver(&prompt_id, PromptReply::Cancel),
            Err(PromptError::UnknownPrompt)
        );
    }

    #[tokio::test]
    async fn refuses_a_reply_whose_shape_does_not_match_the_prompt() {
        let (broker, mut rx) = broker(DEFAULT_PROMPT_TIMEOUT);
        let asking = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.ask(challenge_prompt()).await }
        });

        let prompt_id = next_prompt_id(&mut rx).await;
        broker
            .deliver(
                &prompt_id,
                PromptReply::UsernamePassword {
                    username: "alice".to_owned(),
                    password: Secret::new("hunter2"),
                },
            )
            .expect("deliver");

        assert_eq!(
            asking.await.expect("join").unwrap_err(),
            PromptError::MismatchedReply
        );
    }

    #[tokio::test]
    async fn reports_no_client_when_nothing_is_reading_the_outbound_channel() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let broker = PromptBroker::new(tx, DEFAULT_PROMPT_TIMEOUT);

        assert_eq!(
            broker.ask(username_prompt()).await.unwrap_err(),
            PromptError::NoClient
        );
    }

    #[tokio::test]
    async fn prompt_ids_are_unique_so_two_replies_cannot_collide() {
        let (broker, mut rx) = broker(DEFAULT_PROMPT_TIMEOUT);
        let first = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.ask(username_prompt()).await }
        });
        let first_id = next_prompt_id(&mut rx).await;
        let second = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.ask(challenge_prompt()).await }
        });
        let second_id = next_prompt_id(&mut rx).await;

        assert_ne!(first_id, second_id);

        broker.deliver(&first_id, PromptReply::Cancel).expect("one");
        broker
            .deliver(&second_id, PromptReply::Cancel)
            .expect("two");
        assert!(first.await.expect("join").is_err());
        assert!(second.await.expect("join").is_err());
    }
}
