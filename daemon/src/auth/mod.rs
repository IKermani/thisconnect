// SPDX-License-Identifier: GPL-3.0-or-later

//! Deciding what to answer openvpn's credential prompts (SPEC.md §4.3 point 7, §8).
//!
//! `mgmt` parses the four prompt shapes; this module decides what goes back and where the
//! secrets came from. Nothing here logs a credential, and every secret leaves as `Zeroizing`.

// The supervisor does not construct `AuthFlow` yet, so the storage-writing and
// autofill-enabling half of this module is reached only from tests. Remove once wired.
#![allow(dead_code)]

pub mod prompt;
pub mod store;
pub mod totp;

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use thisconnect_shared::ipc::{CredentialPrompt, Event, LogLevel, ProfileId};
use zeroize::Zeroizing;

use crate::mgmt::challenge::{
    encode_cr_response, encode_dynamic_response, encode_static_response, DynamicChallenge,
    StaticChallenge, StaticChallengeFormat,
};
use crate::mgmt::{build_command, MgmtError};
use prompt::{PromptAnswer, PromptBroker, PromptError};
use store::{CredentialKey, SecretStore, StoreError};
use totp::{ReplayGuard, SeedCompliance, TotpError, TotpGenerator, TotpSettings};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error(transparent)]
    Prompt(#[from] PromptError),

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error(transparent)]
    Totp(#[from] TotpError),

    #[error("cannot encode the challenge response: {0}")]
    Challenge(#[from] MgmtError),

    #[error("openvpn asked for neither a username nor a password")]
    NothingToAnswer,

    #[error("the challenge does not say which account it belongs to")]
    UnknownUsername,

    #[error("the system clock is before the unix epoch")]
    Clock,
}

/// What to send on the management channel. Rendering to wire form is [`Self::commands`] so the
/// escaping rules live in exactly one place (SPEC.md §4.3 point 8).
pub enum MgmtAnswer {
    /// `username "<kind>" <name>` then `password "<kind>" <value>`.
    Credentials {
        kind: String,
        username: Option<String>,
        password: Zeroizing<String>,
    },
    /// `cr-response <base64>`, answering `>INFOMSG:CR_TEXT:`.
    CrResponse { value: Zeroizing<String> },
}

/// Hand-written: every variant carries a credential, and a derived `Debug` would print it.
impl fmt::Debug for MgmtAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Credentials { kind, username, .. } => f
                .debug_struct("Credentials")
                .field("kind", kind)
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            Self::CrResponse { .. } => f.write_str("CrResponse(<redacted>)"),
        }
    }
}

impl MgmtAnswer {
    pub fn commands(&self) -> Result<Vec<Zeroizing<String>>, MgmtError> {
        match self {
            Self::Credentials {
                kind,
                username,
                password,
            } => {
                let mut lines = Vec::with_capacity(2);
                if let Some(name) = username {
                    lines.push(Zeroizing::new(build_command(
                        "username",
                        &[kind.as_str(), name.as_str()],
                    )?));
                }
                lines.push(Zeroizing::new(build_command(
                    "password",
                    &[kind.as_str(), password.as_str()],
                )?));
                Ok(lines)
            }
            Self::CrResponse { value } => Ok(vec![Zeroizing::new(build_command(
                "cr-response",
                &[value.as_str()],
            )?)]),
        }
    }
}

/// Injectable so the replay and expiry branches are testable without sleeping.
#[derive(Clone, Copy, Debug)]
pub enum Clock {
    System,
    #[cfg(test)]
    Fixed(u64),
}

impl Clock {
    fn now(self) -> Result<u64, AuthError> {
        match self {
            Self::System => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|delta| delta.as_secs())
                .map_err(|_| AuthError::Clock),
            #[cfg(test)]
            Self::Fixed(secs) => Ok(secs),
        }
    }
}

#[derive(Default)]
struct FlowState {
    /// Prefill only. A password is never remembered here.
    username: Option<String>,
    /// The stored password was already handed to openvpn in this flow. Set once, never cleared.
    stored_password_offered: bool,
    replay: ReplayGuard,
    warned_short_seed: bool,
}

pub struct AuthFlow {
    profile_id: ProfileId,
    store: Arc<dyn SecretStore>,
    prompts: Arc<PromptBroker>,
    totp: TotpSettings,
    clock: Clock,
    state: Mutex<FlowState>,
}

impl AuthFlow {
    pub fn new(
        profile_id: ProfileId,
        store: Arc<dyn SecretStore>,
        prompts: Arc<PromptBroker>,
        totp: TotpSettings,
    ) -> Self {
        Self {
            profile_id,
            store,
            prompts,
            totp,
            clock: Clock::System,
            state: Mutex::new(FlowState::default()),
        }
    }

    #[cfg(test)]
    fn with_clock(self, clock: Clock) -> Self {
        Self { clock, ..self }
    }

    /// Answers `>PASSWORD:Need '<kind>' username/password [SC:<echo>,<text>]`.
    pub async fn answer_need(
        &self,
        kind: &str,
        needs_username: bool,
        needs_password: bool,
        challenge: Option<&StaticChallenge>,
        format: StaticChallengeFormat,
    ) -> Result<MgmtAnswer, AuthError> {
        if !needs_username && !needs_password {
            return Err(AuthError::NothingToAnswer);
        }

        let (username, password) = self.username_password().await?;
        let password = match challenge {
            None => password,
            Some(challenge) => {
                let response = self
                    .second_factor(CredentialPrompt::StaticChallenge {
                        profile_id: self.profile_id.clone(),
                        challenge_text: challenge.text.clone(),
                        echo: challenge.echo,
                    })
                    .await?;
                encode_static_response(&password, &response, format)
            }
        };

        Ok(MgmtAnswer::Credentials {
            kind: kind.to_owned(),
            username: needs_username.then_some(username),
            password,
        })
    }

    /// Answers a CRV1 dynamic challenge. The password field carries `CRV1::<state>::<response>`;
    /// the username stays the account name, never the response.
    pub async fn answer_dynamic_challenge(
        &self,
        kind: &str,
        challenge: &DynamicChallenge,
    ) -> Result<MgmtAnswer, AuthError> {
        let username = challenge
            .username()
            .or_else(|| lock(&self.state).username.clone())
            .ok_or(AuthError::UnknownUsername)?;

        let response = self
            .second_factor(CredentialPrompt::DynamicChallenge {
                profile_id: self.profile_id.clone(),
                state_id: challenge.state_id.clone(),
                challenge_text: challenge.challenge_text.clone(),
                echo: challenge.echo(),
            })
            .await?;

        Ok(MgmtAnswer::Credentials {
            kind: kind.to_owned(),
            username: Some(username),
            password: encode_dynamic_response(&challenge.state_id, &response)?,
        })
    }

    /// Answers `>INFOMSG:CR_TEXT:<text>`. There is no state id in this shape, so the response is
    /// base64 on its own.
    pub async fn answer_cr_text(&self, text: &str) -> Result<MgmtAnswer, AuthError> {
        let response = self
            .second_factor(CredentialPrompt::StaticChallenge {
                profile_id: self.profile_id.clone(),
                challenge_text: text.to_owned(),
                echo: false,
            })
            .await?;

        Ok(MgmtAnswer::CrResponse {
            value: encode_cr_response(&response),
        })
    }

    /// The stored password is used only alongside a remembered username: half a credential pair
    /// is worse than none, because it burns an auth attempt against the wrong account.
    async fn username_password(&self) -> Result<(String, Zeroizing<String>), AuthError> {
        let (remembered, already_offered) = {
            let state = lock(&self.state);
            (state.username.clone(), state.stored_password_offered)
        };
        // A repeat prompt means the server rejected what we sent. `--auth-retry interact`
        // re-asks after every failure, so re-offering the same stored password would hammer the
        // account until it locks (SPEC.md 4.1); the retry has to reach the user instead.
        if let (Some(username), false) = (remembered.clone(), already_offered) {
            match self
                .store
                .load(&CredentialKey::password(self.profile_id.clone()))
            {
                Ok(password) => {
                    lock(&self.state).stored_password_offered = true;
                    return Ok((username, password));
                }
                Err(StoreError::NotFound { .. }) => {}
                Err(error) => return Err(error.into()),
            }
        }

        let answer = self
            .prompts
            .ask(CredentialPrompt::UsernamePassword {
                profile_id: self.profile_id.clone(),
                username_hint: remembered,
            })
            .await?;
        match answer {
            PromptAnswer::UsernamePassword { username, password } => {
                lock(&self.state).username = Some(username.clone());
                Ok((username, password))
            }
            PromptAnswer::Challenge(_) => Err(PromptError::MismatchedReply.into()),
        }
    }

    /// The one-time value. TOTP autofill is consulted only when it is switched on and a seed is
    /// actually stored; everything else falls back to asking the user, which is the default.
    async fn second_factor(
        &self,
        prompt: CredentialPrompt,
    ) -> Result<Zeroizing<String>, AuthError> {
        if !self.totp.enabled {
            return self.ask_for_response(prompt).await;
        }

        let seed = match self
            .store
            .load(&CredentialKey::totp_seed(self.profile_id.clone()))
        {
            Ok(seed) => seed,
            Err(StoreError::NotFound { .. }) => return self.ask_for_response(prompt).await,
            Err(error) => return Err(error.into()),
        };

        let generator = TotpGenerator::from_base32_seed(&seed, &self.totp)?;
        self.warn_about_short_seed(generator.compliance()).await;

        let now = self.clock.now()?;
        let step = generator.step_at(now);
        let admitted = {
            let mut state = lock(&self.state);
            match state.replay.admit(step, generator.step_seconds(), now) {
                Ok(next) => {
                    state.replay = next;
                    Ok(())
                }
                Err(error) => Err(error),
            }
        };

        match admitted {
            Ok(()) => Ok(generator.code_at(now)),
            Err(TotpError::AlreadyConsumed { seconds }) => {
                self.log(
                    LogLevel::Warn,
                    format!(
                        "The generated one-time code was already sent to the server. \
                         Waiting {seconds}s would replay it, so you are being asked instead."
                    ),
                )
                .await;
                self.ask_for_response(prompt).await
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn ask_for_response(
        &self,
        prompt: CredentialPrompt,
    ) -> Result<Zeroizing<String>, AuthError> {
        match self.prompts.ask(prompt).await? {
            PromptAnswer::Challenge(response) => Ok(response),
            PromptAnswer::UsernamePassword { .. } => Err(PromptError::MismatchedReply.into()),
        }
    }

    /// Once per flow: a warning repeated on every retry is a warning nobody reads.
    async fn warn_about_short_seed(&self, compliance: SeedCompliance) {
        let Some(warning) = compliance.warning() else {
            return;
        };
        let already_warned = {
            let mut state = lock(&self.state);
            let seen = state.warned_short_seed;
            state.warned_short_seed = true;
            seen
        };
        if !already_warned {
            self.log(LogLevel::Warn, warning).await;
        }
    }

    async fn log(&self, level: LogLevel, message: String) {
        let unix_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |delta| {
                u64::try_from(delta.as_millis()).unwrap_or(u64::MAX)
            });
        self.prompts
            .announce(Event::Log {
                level,
                message,
                unix_millis,
            })
            .await;
    }
}

/// See `prompt::lock`: a privileged daemon recovers from a poisoned lock rather than panicking.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use thisconnect_shared::ipc::{DaemonMessage, PromptReply, Secret};
    use tokio::sync::mpsc;

    use super::store::testing::MemoryStore;
    use super::*;

    /// 80-bit seed: the shape `build()` rejects and `build_noncompliant()` accepts.
    const SHORT_SEED: &str = "GEZDGNBVGY3TQOJQ";

    fn profile() -> ProfileId {
        ProfileId("p1".to_owned())
    }

    fn flow(
        store: MemoryStore,
        totp: TotpSettings,
    ) -> (Arc<PromptBroker>, mpsc::Receiver<DaemonMessage>, AuthFlow) {
        let (tx, rx) = mpsc::channel(8);
        let broker = Arc::new(PromptBroker::new(tx, prompt::DEFAULT_PROMPT_TIMEOUT));
        let flow = AuthFlow::new(profile(), Arc::new(store), Arc::clone(&broker), totp)
            .with_clock(Clock::Fixed(1_700_000_000));
        (broker, rx, flow)
    }

    /// Answers prompts in order as they arrive, skipping any events in between.
    async fn respond(
        broker: &PromptBroker,
        rx: &mut mpsc::Receiver<DaemonMessage>,
        replies: Vec<PromptReply>,
    ) {
        for reply in replies {
            loop {
                match rx.recv().await {
                    Some(DaemonMessage::Prompt { prompt_id, .. }) => {
                        broker.deliver(&prompt_id, reply.clone()).expect("deliver");
                        break;
                    }
                    Some(_) => continue,
                    None => return,
                }
            }
        }
    }

    fn credentials(username: &str, password: &str) -> PromptReply {
        PromptReply::UsernamePassword {
            username: username.to_owned(),
            password: Secret::new(password),
        }
    }

    fn challenge_reply(response: &str) -> PromptReply {
        PromptReply::ChallengeResponse {
            response: Secret::new(response),
        }
    }

    fn rendered(answer: &MgmtAnswer) -> Vec<String> {
        answer
            .commands()
            .expect("commands")
            .iter()
            .map(|line| line.to_string())
            .collect()
    }

    #[tokio::test]
    async fn answers_a_plain_need_with_the_username_and_password_the_user_typed() {
        let (broker, mut rx, flow) = flow(MemoryStore::new(), TotpSettings::default());

        let (answer, ()) = tokio::join!(
            flow.answer_need("Auth", true, true, None, StaticChallengeFormat::Scrv1),
            respond(&broker, &mut rx, vec![credentials("alice", "hunter2")])
        );

        let lines = rendered(&answer.expect("answer"));
        assert_eq!(
            lines,
            vec![
                "username \"Auth\" \"alice\"".to_owned(),
                "password \"Auth\" \"hunter2\"".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn never_puts_the_secret_in_the_username_field() {
        let (broker, mut rx, flow) = flow(MemoryStore::new(), TotpSettings::default());

        let (answer, ()) = tokio::join!(
            flow.answer_need("Auth", true, true, None, StaticChallengeFormat::Scrv1),
            respond(&broker, &mut rx, vec![credentials("alice", "hunter2")])
        );

        let lines = rendered(&answer.expect("answer"));
        assert!(!lines[0].contains("hunter2"));
    }

    #[tokio::test]
    async fn encodes_a_format_zero_static_challenge_as_scrv1() {
        let (broker, mut rx, flow) = flow(MemoryStore::new(), TotpSettings::default());
        let challenge = StaticChallenge {
            echo: false,
            text: "Enter token".to_owned(),
        };

        let (answer, ()) = tokio::join!(
            flow.answer_need(
                "Auth",
                true,
                true,
                Some(&challenge),
                StaticChallengeFormat::Scrv1
            ),
            respond(
                &broker,
                &mut rx,
                vec![credentials("alice", "pass"), challenge_reply("123456")]
            )
        );

        let lines = rendered(&answer.expect("answer"));
        assert_eq!(lines[1], "password \"Auth\" \"SCRV1:cGFzcw==:MTIzNDU2\"");
    }

    #[tokio::test]
    async fn encodes_a_format_one_static_challenge_as_a_plain_concatenation() {
        let (broker, mut rx, flow) = flow(MemoryStore::new(), TotpSettings::default());
        let challenge = StaticChallenge {
            echo: true,
            text: "PIN".to_owned(),
        };

        let (answer, ()) = tokio::join!(
            flow.answer_need(
                "Auth",
                true,
                true,
                Some(&challenge),
                StaticChallengeFormat::Concat
            ),
            respond(
                &broker,
                &mut rx,
                vec![credentials("alice", "pass"), challenge_reply("123456")]
            )
        );

        let lines = rendered(&answer.expect("answer"));
        assert_eq!(lines[1], "password \"Auth\" \"pass123456\"");
    }

    #[tokio::test]
    async fn answers_a_crv1_challenge_with_the_state_id_and_the_account_from_the_challenge() {
        let (broker, mut rx, flow) = flow(MemoryStore::new(), TotpSettings::default());
        let challenge =
            DynamicChallenge::parse("CRV1:R,E:Sf23fks9:YWxpY2U=:Enter token").expect("crv1");

        let (answer, ()) = tokio::join!(
            flow.answer_dynamic_challenge("Auth", &challenge),
            respond(&broker, &mut rx, vec![challenge_reply("987654")])
        );

        let lines = rendered(&answer.expect("answer"));
        assert_eq!(
            lines,
            vec![
                "username \"Auth\" \"alice\"".to_owned(),
                "password \"Auth\" \"CRV1::Sf23fks9::987654\"".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn answers_cr_text_with_a_base64_cr_response() {
        let (broker, mut rx, flow) = flow(MemoryStore::new(), TotpSettings::default());

        let (answer, ()) = tokio::join!(
            flow.answer_cr_text("Enter token"),
            respond(&broker, &mut rx, vec![challenge_reply("123456")])
        );

        assert_eq!(
            rendered(&answer.expect("answer")),
            vec!["cr-response \"MTIzNDU2\"".to_owned()]
        );
    }

    #[tokio::test]
    async fn prompts_rather_than_autofilling_when_totp_is_left_at_its_default() {
        let store =
            MemoryStore::new().with_secret(&CredentialKey::totp_seed(profile()), SHORT_SEED);
        let (broker, mut rx, flow) = flow(store, TotpSettings::default());

        let (answer, ()) = tokio::join!(
            flow.answer_cr_text("Enter token"),
            respond(&broker, &mut rx, vec![challenge_reply("111111")])
        );

        assert_eq!(
            rendered(&answer.expect("answer")),
            vec!["cr-response \"MTExMTEx\"".to_owned()]
        );
    }

    #[tokio::test]
    async fn autofills_a_short_seed_and_warns_the_user_that_it_is_weak() {
        let store =
            MemoryStore::new().with_secret(&CredentialKey::totp_seed(profile()), SHORT_SEED);
        let (_broker, mut rx, flow) = flow(store, TotpSettings::enabled());

        let answer = flow.answer_cr_text("Enter token").await.expect("answer");

        match rx.recv().await {
            Some(DaemonMessage::Event {
                event: Event::Log { level, message, .. },
            }) => {
                assert_eq!(level, LogLevel::Warn);
                assert!(message.contains("80 bits"));
            }
            other => panic!("expected a short-seed warning, got {other:?}"),
        }
        assert!(matches!(answer, MgmtAnswer::CrResponse { .. }));
    }

    #[tokio::test]
    async fn surfaces_a_missing_secret_service_instead_of_prompting_or_panicking() {
        let (_broker, _rx, flow) = flow(MemoryStore::unavailable(), TotpSettings::enabled());

        let error = flow.answer_cr_text("Enter token").await.unwrap_err();

        assert!(matches!(
            error,
            AuthError::Store(StoreError::Unavailable { .. })
        ));
    }

    #[tokio::test]
    async fn a_cancelled_prompt_aborts_the_auth_attempt() {
        let (broker, mut rx, flow) = flow(MemoryStore::new(), TotpSettings::default());

        let (answer, ()) = tokio::join!(
            flow.answer_need("Auth", true, true, None, StaticChallengeFormat::Scrv1),
            respond(&broker, &mut rx, vec![PromptReply::Cancel])
        );

        assert!(matches!(
            answer.unwrap_err(),
            AuthError::Prompt(PromptError::Cancelled)
        ));
    }

    /// SPEC.md 4.1: `--auth-retry interact` re-prompts after every rejection. Replaying the
    /// stored password would spend attempts until the account locks.
    #[tokio::test]
    async fn offers_a_stored_password_once_and_asks_the_user_on_the_retry() {
        let store = MemoryStore::new().with_secret(&CredentialKey::password(profile()), "stored");
        let (broker, mut rx, flow) = flow(store, TotpSettings::default());

        // First call has no remembered username, so it prompts and learns one.
        let (first, ()) = tokio::join!(
            flow.answer_need("Auth", true, true, None, StaticChallengeFormat::Scrv1),
            respond(&broker, &mut rx, vec![credentials("alice", "typed")])
        );
        // Second call may use the stored password, now that the account is known.
        let second = flow
            .answer_need("Auth", true, true, None, StaticChallengeFormat::Scrv1)
            .await;
        // Third call is a retry after a rejection: it must reach the user.
        let (third, ()) = tokio::join!(
            flow.answer_need("Auth", true, true, None, StaticChallengeFormat::Scrv1),
            respond(&broker, &mut rx, vec![credentials("alice", "corrected")])
        );

        assert_eq!(
            rendered(&first.expect("first"))[1],
            "password \"Auth\" \"typed\""
        );
        assert_eq!(
            rendered(&second.expect("second"))[1],
            "password \"Auth\" \"stored\""
        );
        assert_eq!(
            rendered(&third.expect("third"))[1],
            "password \"Auth\" \"corrected\""
        );
    }

    /// The remembered account name is still a useful prefill on the retry.
    #[tokio::test]
    async fn the_retry_prompt_carries_the_remembered_username_as_a_hint() {
        let store = MemoryStore::new().with_secret(&CredentialKey::password(profile()), "stored");
        let (broker, mut rx, flow) = flow(store, TotpSettings::default());

        let (_first, ()) = tokio::join!(
            flow.answer_need("Auth", true, true, None, StaticChallengeFormat::Scrv1),
            respond(&broker, &mut rx, vec![credentials("alice", "typed")])
        );
        let _second = flow
            .answer_need("Auth", true, true, None, StaticChallengeFormat::Scrv1)
            .await
            .expect("second");

        let retry = flow.answer_need("Auth", true, true, None, StaticChallengeFormat::Scrv1);
        let observe = async {
            loop {
                match rx.recv().await {
                    Some(DaemonMessage::Prompt {
                        prompt_id, prompt, ..
                    }) => {
                        broker
                            .deliver(&prompt_id, credentials("alice", "corrected"))
                            .expect("deliver");
                        return prompt;
                    }
                    Some(_) => continue,
                    None => panic!("the retry never reached the user"),
                }
            }
        };
        let (_answer, prompt) = tokio::join!(retry, observe);

        match prompt {
            CredentialPrompt::UsernamePassword { username_hint, .. } => {
                assert_eq!(username_hint, Some("alice".to_owned()));
            }
            other => panic!("expected a username/password prompt, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn never_replays_a_consumed_code_and_asks_the_user_on_the_retry() {
        let store =
            MemoryStore::new().with_secret(&CredentialKey::totp_seed(profile()), SHORT_SEED);
        let (broker, mut rx, flow) = flow(store, TotpSettings::enabled());

        let first = rendered(&flow.answer_cr_text("Enter token").await.expect("first"));
        // The clock is fixed, so a second autofill would emit the very same code; the retry must
        // reach the user instead.
        let (second, ()) = tokio::join!(
            flow.answer_cr_text("Enter token"),
            respond(&broker, &mut rx, vec![challenge_reply("222222")])
        );
        let second = rendered(&second.expect("second"));

        assert_eq!(second, vec!["cr-response \"MjIyMjIy\"".to_owned()]);
        assert_ne!(first, second);
    }
}
