// SPDX-License-Identifier: GPL-3.0-or-later

//! IPC protocol types for the GUI ↔ daemon control channel (SPEC.md §7.4).
//!
//! Framing is line-delimited JSON: one JSON object per line, no embedded newlines.
//! Every message carries a `type` tag, and the connection opens with a version
//! handshake so a GUI built against a different protocol revision fails loudly
//! instead of misinterpreting fields it does not understand.
//!
//! Wire reference and examples live in `docs/IPC.md`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Bumped on any incompatible change to the types in this module.
pub const PROTOCOL_VERSION: u32 = 1;

/// A profile import carries a whole `.ovpn` file, so the cap is generous; it
/// still exists because the peer is untrusted input to a privileged process.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/// A string that must never reach a log, a `Debug` dump, or a core file intact.
///
/// `Debug` is implemented by hand: deriving it would print the password the
/// moment any enclosing type is logged. Enclosing types may therefore derive
/// `Debug` freely — the redaction happens here, once.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Read the plaintext. Every call site is a place a secret can escape.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// Client-generated correlation id. Responses echo it verbatim.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(pub String);

/// Daemon-generated correlation id for a daemon-initiated credential prompt.
/// The GUI echoes it in [`ClientMessage::PromptReply`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PromptId(pub String);

/// Opaque handle to a stored, already-validated profile. The GUI sends this to
/// connect — never a raw config (SPEC.md §3.1.4).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileId(pub String);

macro_rules! impl_id_display {
    ($($t:ty),*) => {$(
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl From<String> for $t {
            fn from(value: String) -> Self { Self(value) }
        }
    )*};
}
impl_id_display!(RequestId, PromptId, ProfileId);

// ---------------------------------------------------------------------------
// GUI → daemon
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// First message on every connection. Nothing else is accepted before it.
    Hello {
        id: RequestId,
        protocol_version: u32,
        client_name: String,
    },
    Request {
        id: RequestId,
        request: Request,
    },
    /// Answer to a daemon-initiated [`DaemonMessage::Prompt`].
    PromptReply {
        id: RequestId,
        prompt_id: PromptId,
        reply: PromptReply,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Raw `.ovpn` text, validated and canonicalised by the daemon (SPEC.md §6).
    /// This is the only message that ever carries a config body.
    ProfileImport {
        name: String,
        config: Secret,
    },
    ProfileList,
    ProfileGet {
        profile_id: ProfileId,
    },
    ProfileDelete {
        profile_id: ProfileId,
    },
    Connect {
        profile_id: ProfileId,
    },
    Disconnect,
    Status,
    /// Listener address and generated proxy credentials (SPEC.md §5.6 L2).
    ProxyInfo,
    ProxyStats,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PromptReply {
    UsernamePassword {
        username: String,
        password: Secret,
    },
    /// Static challenge (`SC:`) and CRV1 dynamic challenge both answer with one
    /// opaque string; which one is being answered is fixed by the prompt id.
    ChallengeResponse {
        response: Secret,
    },
    /// User dismissed the prompt: the daemon aborts the auth attempt rather
    /// than retrying with stale credentials.
    Cancel,
}

// ---------------------------------------------------------------------------
// Daemon → GUI
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonMessage {
    Hello {
        id: RequestId,
        protocol_version: u32,
        daemon_version: String,
    },
    Response {
        id: RequestId,
        response: Response,
    },
    Error {
        id: RequestId,
        error: IpcError,
    },
    /// Daemon-initiated request. The GUI must answer with a `prompt_reply`
    /// carrying this `prompt_id`, or the auth attempt times out.
    Prompt {
        prompt_id: PromptId,
        prompt: CredentialPrompt,
    },
    /// Unsolicited state change. Carries no correlation id.
    Event {
        event: Event,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Ack,
    Profile { profile: ProfileSummary },
    Profiles { profiles: Vec<ProfileSummary> },
    Status { status: ConnectionStatus },
    Proxy { proxy: ProxyInfo },
    ProxyStats { stats: ProxySessionStats },
}

// ---------------------------------------------------------------------------
// Credential prompts
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialPrompt {
    /// openvpn asked `Need 'Auth' username/password`.
    UsernamePassword {
        profile_id: ProfileId,
        /// Last username the daemon used, so the GUI can prefill. Never a password.
        username_hint: Option<String>,
    },
    /// `static-challenge` from the profile, presented before the first attempt.
    StaticChallenge {
        profile_id: ProfileId,
        challenge_text: String,
        /// `false` means mask the input (TOTP-style one-time value).
        echo: bool,
    },
    /// CRV1 dynamic challenge parsed out of `Verification Failed`. The daemon
    /// keeps `state_id` to build the response; it is surfaced for diagnostics.
    DynamicChallenge {
        profile_id: ProfileId,
        state_id: String,
        challenge_text: String,
        echo: bool,
    },
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub id: ProfileId,
    pub name: String,
    pub remotes: Vec<RemoteSummary>,
    pub requires_username_password: bool,
    pub static_challenge: Option<StaticChallengeSummary>,
    pub has_inline_ca: bool,
    pub has_inline_cert: bool,
    pub has_inline_key: bool,
    /// Digest of the canonical config, so the GUI can show that a stored
    /// profile has not silently changed underneath it.
    pub canonical_sha256: String,
    pub imported_unix_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSummary {
    pub host: String,
    pub port: u16,
    pub transport: Transport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticChallengeSummary {
    pub text: String,
    pub echo: bool,
}

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Authenticating,
    /// `>STATE:*,CONNECTED,*` seen and tunnel policy installed (SPEC.md §4.3.5).
    Connected,
    Reconnecting,
    Disconnecting,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionStatus {
    pub state: ConnectionState,
    pub profile_id: Option<ProfileId>,
    pub connected_since_unix_secs: Option<u64>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub tunnel: Option<TunnelInfo>,
    /// Redacted, user-facing text. Never raw `>LOG:` output.
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelInfo {
    /// From `>UPDOWN:ENV` `dev=`; a missing device is a hard error upstream.
    pub device: String,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub mtu: Option<u32>,
    /// v4-only tunnels must reject AAAA and `ATYP=0x04` (SPEC.md §5.5).
    pub tunnel_has_v6: bool,
    pub dns_servers: Vec<IpAddr>,
    pub dns_source: DnsSource,
    pub search_domains: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsSource {
    /// Captured from `PUSH_REPLY` — the VPN's own resolver.
    Pushed,
    /// User-configured `tunnel_fallback_dns`, queried through the tun. The GUI
    /// must say plainly that a third party is seeing the queries (SPEC.md §5.4 D4).
    TunnelFallback,
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyInfo {
    pub listen_addrs: Vec<SocketAddr>,
    pub auth: ProxyAuth,
    /// Non-loopback binds drive a permanent UI banner (SPEC.md §5.6 L4).
    pub is_loopback_only: bool,
    pub allowed_cidrs: Vec<String>,
    /// Ready-to-copy `socks5h://` URL. `socks5://` resolves locally and leaks,
    /// so the copy button must never emit it (SPEC.md §5.4 D8).
    pub socks5h_url: Secret,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProxyAuth {
    /// Only reachable if the user explicitly turned auth off on loopback.
    Disabled,
    Credentials {
        username: String,
        password: Secret,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxySessionStats {
    pub active_sessions: u32,
    pub total_sessions: u64,
    pub bytes_to_tunnel: u64,
    pub bytes_from_tunnel: u64,
    /// Names resolved through the tunnel-pinned resolver this session.
    pub tunnel_dns_lookups: u64,
    /// Leak proof shown verbatim in the GUI: any value but 0 is a bug
    /// (SPEC.md §5.4 D7).
    pub local_dns_lookups: u64,
    pub auth_failures: u64,
    /// Distinct remote peers seen on a non-loopback listener (SPEC.md §5.6 L4).
    pub distinct_remote_peers: u32,
    pub tunnel_has_v6: bool,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    State {
        state: ConnectionState,
        detail: Option<String>,
    },
    ByteCount {
        bytes_in: u64,
        bytes_out: u64,
    },
    Log {
        level: LogLevel,
        message: String,
        unix_millis: u64,
    },
    TunnelUp {
        tunnel: TunnelInfo,
    },
    TunnelDown {
        reason: String,
    },
    ProxyListenerUp {
        listen_addrs: Vec<SocketAddr>,
    },
    ProxyListenerDown {
        reason: String,
    },
    /// The daemon withdrew a prompt (timeout, or the connection gave up). A
    /// reply arriving afterwards is answered with `prompt_expired`.
    PromptCancelled {
        prompt_id: PromptId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcError {
    pub code: ErrorCode,
    /// Human-readable, already safe to display. Never contains credentials.
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<ValidationError>,
}

impl IpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            validation: None,
        }
    }

    pub fn validation(message: impl Into<String>, validation: ValidationError) -> Self {
        Self {
            code: ErrorCode::ProfileInvalid,
            message: message.into(),
            validation: Some(validation),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Handshake failed: the GUI speaks a different protocol revision.
    ProtocolVersionMismatch,
    /// A request arrived before a successful `hello`.
    HandshakeRequired,
    MalformedMessage,
    ProfileInvalid,
    ProfileNotFound,
    AlreadyConnected,
    NotConnected,
    /// Another connect/disconnect is already in flight.
    Busy,
    AuthFailed,
    /// The proxy listener is not up yet; there is nothing to report.
    TunnelNotReady,
    /// Reply arrived for a prompt the daemon has already withdrawn.
    PromptExpired,
    Unauthorized,
    Internal,
}

/// Structured rejection from the allowlist validator (SPEC.md §6). The GUI
/// names the offending line rather than showing a generic failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationError {
    pub reason: ValidationReason,
    /// 1-based line number in the submitted config, when known.
    pub line: Option<u32>,
    /// The directive or inline tag that caused the rejection, never its value:
    /// values can be key material.
    pub directive: Option<String>,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationReason {
    /// Not on the allowlist. Unknown is rejected, never passed through.
    UnknownDirective,
    /// On the hard-reject list: code loading, script hook, path or env hijack.
    ForbiddenDirective,
    /// A `<tag>` block outside the accepted inline-material set.
    UnknownInlineTag,
    /// Directive allowed, argument is not: traversal, metacharacter, out of range.
    InvalidArgument,
    MissingRequiredDirective,
    FileTooLarge,
    TooManyDirectives,
    NotUtf8,
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("message is {0} bytes, over the {MAX_MESSAGE_BYTES} byte limit")]
    TooLarge(usize),
    #[error("encoded message contains a newline, which would break framing")]
    EmbeddedNewline,
    #[error("malformed IPC message")]
    Json(#[from] serde_json::Error),
}

/// Encode one message as a single framing line (no trailing newline: the
/// `LinesCodec` on the socket adds it).
pub fn encode_line<T: Serialize>(message: &T) -> Result<String, CodecError> {
    let line = serde_json::to_string(message)?;
    if line.len() > MAX_MESSAGE_BYTES {
        return Err(CodecError::TooLarge(line.len()));
    }
    // serde_json escapes newlines inside strings, so this can only trip if a
    // future custom Serialize impl misbehaves. Cheap, and framing is load-bearing.
    if line.contains('\n') || line.contains('\r') {
        return Err(CodecError::EmbeddedNewline);
    }
    Ok(line)
}

/// Decode one framing line. The peer is untrusted: oversize input is rejected
/// before it reaches the JSON parser.
pub fn decode_line<T: DeserializeOwned>(line: &str) -> Result<T, CodecError> {
    if line.len() > MAX_MESSAGE_BYTES {
        return Err(CodecError::TooLarge(line.len()));
    }
    Ok(serde_json::from_str(line)?)
}

/// Handshake check. A mismatched GUI is refused outright rather than served a
/// subset of the protocol it may silently misread.
pub fn check_protocol_version(peer_version: u32) -> Result<(), IpcError> {
    if peer_version == PROTOCOL_VERSION {
        return Ok(());
    }
    Err(IpcError::new(
        ErrorCode::ProtocolVersionMismatch,
        format!("daemon speaks protocol {PROTOCOL_VERSION}, client speaks {peer_version}"),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn roundtrip<T: Serialize + DeserializeOwned>(value: &T) -> T {
        let line = encode_line(value).unwrap();
        decode_line(&line).unwrap()
    }

    fn json_of<T: Serialize>(value: &T) -> Value {
        serde_json::from_str(&encode_line(value).unwrap()).unwrap()
    }

    fn tunnel_fixture() -> TunnelInfo {
        TunnelInfo {
            device: "utun7".into(),
            ipv4: Some(Ipv4Addr::new(10, 8, 0, 2)),
            ipv6: None,
            mtu: Some(1240),
            tunnel_has_v6: false,
            dns_servers: vec![IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))],
            dns_source: DnsSource::Pushed,
            search_domains: vec!["corp.example".into()],
        }
    }

    fn profile_fixture() -> ProfileSummary {
        ProfileSummary {
            id: ProfileId("p1".into()),
            name: "work".into(),
            remotes: vec![RemoteSummary {
                host: "vpn.example".into(),
                port: 1194,
                transport: Transport::Udp,
            }],
            requires_username_password: true,
            static_challenge: Some(StaticChallengeSummary {
                text: "TOTP code".into(),
                echo: false,
            }),
            has_inline_ca: true,
            has_inline_cert: false,
            has_inline_key: false,
            canonical_sha256: "a".repeat(64),
            imported_unix_secs: 1_757_000_000,
        }
    }

    fn status_fixture() -> ConnectionStatus {
        ConnectionStatus {
            state: ConnectionState::Connected,
            profile_id: Some(ProfileId("p1".into())),
            connected_since_unix_secs: Some(1_757_000_100),
            bytes_in: 42,
            bytes_out: 7,
            tunnel: Some(tunnel_fixture()),
            last_error: None,
        }
    }

    // -- secrets ------------------------------------------------------------

    #[test]
    fn debug_of_secret_does_not_print_the_plaintext() {
        // Arrange
        let secret = Secret::new("hunter2");

        // Act
        let rendered = format!("{secret:?}");

        // Assert
        assert_eq!(rendered, "Secret(<redacted>)");
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn debug_of_message_containing_secret_redacts_it() {
        // Arrange
        let message = ClientMessage::PromptReply {
            id: RequestId("7".into()),
            prompt_id: PromptId("cr-1".into()),
            reply: PromptReply::UsernamePassword {
                username: "alice".into(),
                password: Secret::new("hunter2"),
            },
        };

        // Act
        let rendered = format!("{message:?}");

        // Assert
        assert!(!rendered.contains("hunter2"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn secret_serializes_transparently_as_a_json_string() {
        // Arrange
        let secret = Secret::new("s3cr3t");

        // Act
        let json = json_of(&secret);

        // Assert
        assert_eq!(json, Value::String("s3cr3t".into()));
        assert_eq!(roundtrip(&secret).expose(), "s3cr3t");
    }

    #[test]
    fn debug_of_proxy_info_redacts_credentials_and_url() {
        // Arrange
        let info = ProxyInfo {
            listen_addrs: vec!["127.0.0.1:1080".parse().unwrap()],
            auth: ProxyAuth::Credentials {
                username: "tc".into(),
                password: Secret::new("pw-abc"),
            },
            is_loopback_only: true,
            allowed_cidrs: vec![],
            socks5h_url: Secret::new("socks5h://tc:pw-abc@127.0.0.1:1080"),
        };

        // Act
        let rendered = format!("{info:?}");

        // Assert
        assert!(!rendered.contains("pw-abc"));
    }

    // -- client messages ----------------------------------------------------

    #[test]
    fn client_hello_round_trips_with_protocol_version() {
        // Arrange
        let message = ClientMessage::Hello {
            id: RequestId("1".into()),
            protocol_version: PROTOCOL_VERSION,
            client_name: "thisconnect-gui".into(),
        };

        // Act
        let json = json_of(&message);
        let decoded = roundtrip(&message);

        // Assert
        assert_eq!(json["type"], "hello");
        assert_eq!(json["protocol_version"], PROTOCOL_VERSION);
        assert!(matches!(decoded, ClientMessage::Hello { .. }));
    }

    #[test]
    fn every_request_variant_round_trips() {
        // Arrange
        let requests = vec![
            Request::ProfileImport {
                name: "work".into(),
                config: Secret::new("client\nremote vpn.example 1194 udp\n"),
            },
            Request::ProfileList,
            Request::ProfileGet {
                profile_id: ProfileId("p1".into()),
            },
            Request::ProfileDelete {
                profile_id: ProfileId("p1".into()),
            },
            Request::Connect {
                profile_id: ProfileId("p1".into()),
            },
            Request::Disconnect,
            Request::Status,
            Request::ProxyInfo,
            Request::ProxyStats,
        ];

        for request in requests {
            // Act
            let message = ClientMessage::Request {
                id: RequestId("9".into()),
                request,
            };
            let json = json_of(&message);
            let decoded = roundtrip(&message);

            // Assert
            assert_eq!(json["type"], "request");
            assert!(json["request"]["type"].is_string());
            assert!(matches!(decoded, ClientMessage::Request { .. }));
        }
    }

    #[test]
    fn imported_config_body_is_a_secret_and_stays_out_of_debug() {
        // Arrange
        let request = Request::ProfileImport {
            name: "work".into(),
            config: Secret::new("<key>PRIVATE-MATERIAL</key>"),
        };

        // Act
        let rendered = format!("{request:?}");
        let decoded = roundtrip(&request);

        // Assert
        assert!(!rendered.contains("PRIVATE-MATERIAL"));
        match decoded {
            Request::ProfileImport { config, .. } => {
                assert_eq!(config.expose(), "<key>PRIVATE-MATERIAL</key>");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn every_prompt_reply_variant_round_trips_and_preserves_the_secret() {
        // Arrange
        let replies = vec![
            PromptReply::UsernamePassword {
                username: "alice".into(),
                password: Secret::new("pw"),
            },
            PromptReply::ChallengeResponse {
                response: Secret::new("123456"),
            },
            PromptReply::Cancel,
        ];

        for reply in replies {
            // Act
            let decoded = roundtrip(&reply);

            // Assert
            match (&reply, &decoded) {
                (
                    PromptReply::UsernamePassword { password: a, .. },
                    PromptReply::UsernamePassword { password: b, .. },
                ) => assert_eq!(a.expose(), b.expose()),
                (
                    PromptReply::ChallengeResponse { response: a },
                    PromptReply::ChallengeResponse { response: b },
                ) => assert_eq!(a.expose(), b.expose()),
                (PromptReply::Cancel, PromptReply::Cancel) => {}
                _ => panic!("variant changed across round trip"),
            }
        }
    }

    #[test]
    fn prompt_reply_echoes_the_daemon_prompt_id() {
        // Arrange
        let message = ClientMessage::PromptReply {
            id: RequestId("11".into()),
            prompt_id: PromptId("prompt-3".into()),
            reply: PromptReply::Cancel,
        };

        // Act
        let json = json_of(&message);

        // Assert
        assert_eq!(json["type"], "prompt_reply");
        assert_eq!(json["prompt_id"], "prompt-3");
        assert_eq!(json["id"], "11");
    }

    // -- daemon messages ----------------------------------------------------

    #[test]
    fn every_response_variant_round_trips() {
        // Arrange
        let responses = vec![
            Response::Ack,
            Response::Profile {
                profile: profile_fixture(),
            },
            Response::Profiles {
                profiles: vec![profile_fixture()],
            },
            Response::Status {
                status: status_fixture(),
            },
            Response::Proxy {
                proxy: ProxyInfo {
                    listen_addrs: vec![
                        "127.0.0.1:1080".parse().unwrap(),
                        "[::1]:1080".parse().unwrap(),
                    ],
                    auth: ProxyAuth::Credentials {
                        username: "tc".into(),
                        password: Secret::new("pw"),
                    },
                    is_loopback_only: true,
                    allowed_cidrs: vec![],
                    socks5h_url: Secret::new("socks5h://tc:pw@127.0.0.1:1080"),
                },
            },
            Response::ProxyStats {
                stats: ProxySessionStats::default(),
            },
        ];

        for response in responses {
            // Act
            let message = DaemonMessage::Response {
                id: RequestId("4".into()),
                response,
            };
            let json = json_of(&message);
            let decoded = roundtrip(&message);

            // Assert
            assert_eq!(json["type"], "response");
            assert_eq!(json["id"], "4");
            assert!(matches!(decoded, DaemonMessage::Response { .. }));
        }
    }

    #[test]
    fn proxy_auth_disabled_round_trips_distinctly_from_credentials() {
        // Arrange
        let disabled = ProxyAuth::Disabled;

        // Act
        let json = json_of(&disabled);
        let decoded = roundtrip(&disabled);

        // Assert
        assert_eq!(json["type"], "disabled");
        assert!(matches!(decoded, ProxyAuth::Disabled));
    }

    #[test]
    fn proxy_stats_expose_the_local_dns_leak_counter() {
        // Arrange
        let stats = ProxySessionStats {
            local_dns_lookups: 0,
            tunnel_dns_lookups: 12,
            ..Default::default()
        };

        // Act
        let json = json_of(&stats);

        // Assert
        assert_eq!(json["local_dns_lookups"], 0);
        assert_eq!(json["tunnel_dns_lookups"], 12);
        assert_eq!(json["tunnel_has_v6"], false);
        assert_eq!(roundtrip(&stats), stats);
    }

    #[test]
    fn every_credential_prompt_variant_round_trips_with_echo_flag() {
        // Arrange
        let prompts = vec![
            CredentialPrompt::UsernamePassword {
                profile_id: ProfileId("p1".into()),
                username_hint: Some("alice".into()),
            },
            CredentialPrompt::StaticChallenge {
                profile_id: ProfileId("p1".into()),
                challenge_text: "Enter TOTP".into(),
                echo: false,
            },
            CredentialPrompt::DynamicChallenge {
                profile_id: ProfileId("p1".into()),
                state_id: "abc".into(),
                // CRV1 challenge text may itself contain colons.
                challenge_text: "Token: press 1:2".into(),
                echo: true,
            },
        ];

        for prompt in prompts {
            // Act
            let message = DaemonMessage::Prompt {
                prompt_id: PromptId("prompt-1".into()),
                prompt: prompt.clone(),
            };
            let json = json_of(&message);
            let decoded: DaemonMessage = roundtrip(&message);

            // Assert
            assert_eq!(json["type"], "prompt");
            assert_eq!(json["prompt_id"], "prompt-1");
            match decoded {
                DaemonMessage::Prompt { prompt: got, .. } => assert_eq!(got, prompt),
                other => panic!("wrong variant: {other:?}"),
            }
        }
    }

    #[test]
    fn every_event_variant_round_trips() {
        // Arrange
        let events = vec![
            Event::State {
                state: ConnectionState::Reconnecting,
                detail: Some("wait".into()),
            },
            Event::ByteCount {
                bytes_in: 1,
                bytes_out: 2,
            },
            Event::Log {
                level: LogLevel::Warn,
                message: "tunnel resolver unreachable".into(),
                unix_millis: 1_757_000_000_000,
            },
            Event::TunnelUp {
                tunnel: tunnel_fixture(),
            },
            Event::TunnelDown {
                reason: "EXITING".into(),
            },
            Event::ProxyListenerUp {
                listen_addrs: vec!["127.0.0.1:1080".parse().unwrap()],
            },
            Event::ProxyListenerDown {
                reason: "state left CONNECTED".into(),
            },
            Event::PromptCancelled {
                prompt_id: PromptId("prompt-1".into()),
            },
        ];

        for event in events {
            // Act
            let message = DaemonMessage::Event {
                event: event.clone(),
            };
            let json = json_of(&message);
            let decoded = roundtrip(&message);

            // Assert
            assert_eq!(json["type"], "event");
            assert!(json["event"]["type"].is_string());
            match decoded {
                DaemonMessage::Event { event: got } => assert_eq!(got, event),
                other => panic!("wrong variant: {other:?}"),
            }
        }
    }

    #[test]
    fn tunnel_up_event_carries_device_name_and_addresses() {
        // Arrange
        let event = Event::TunnelUp {
            tunnel: tunnel_fixture(),
        };

        // Act
        let json = json_of(&event);

        // Assert
        assert_eq!(json["tunnel"]["device"], "utun7");
        assert_eq!(json["tunnel"]["ipv4"], "10.8.0.2");
        assert_eq!(json["tunnel"]["tunnel_has_v6"], false);
        assert_eq!(json["tunnel"]["dns_source"], "pushed");
    }

    #[test]
    fn every_connection_state_round_trips() {
        // Arrange
        let states = [
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::Authenticating,
            ConnectionState::Connected,
            ConnectionState::Reconnecting,
            ConnectionState::Disconnecting,
            ConnectionState::Failed,
        ];

        for state in states {
            // Act
            let decoded = roundtrip(&state);

            // Assert
            assert_eq!(decoded, state);
        }
    }

    // -- errors -------------------------------------------------------------

    #[test]
    fn error_without_validation_omits_the_field() {
        // Arrange
        let error = IpcError::new(ErrorCode::NotConnected, "no active tunnel");

        // Act
        let json = json_of(&error);

        // Assert
        assert_eq!(json["code"], "not_connected");
        assert!(json.get("validation").is_none());
        assert_eq!(roundtrip(&error), error);
    }

    #[test]
    fn validation_error_names_the_offending_directive_and_line() {
        // Arrange
        let error = IpcError::validation(
            "profile rejected",
            ValidationError {
                reason: ValidationReason::ForbiddenDirective,
                line: Some(12),
                directive: Some("plugin".into()),
                detail: "code-loading directives are rejected at parse time".into(),
            },
        );

        // Act
        let json = json_of(&error);
        let decoded = roundtrip(&error);

        // Assert
        assert_eq!(json["code"], "profile_invalid");
        assert_eq!(json["validation"]["reason"], "forbidden_directive");
        assert_eq!(json["validation"]["line"], 12);
        assert_eq!(json["validation"]["directive"], "plugin");
        assert_eq!(decoded, error);
    }

    #[test]
    fn every_validation_reason_round_trips() {
        // Arrange
        let reasons = [
            ValidationReason::UnknownDirective,
            ValidationReason::ForbiddenDirective,
            ValidationReason::UnknownInlineTag,
            ValidationReason::InvalidArgument,
            ValidationReason::MissingRequiredDirective,
            ValidationReason::FileTooLarge,
            ValidationReason::TooManyDirectives,
            ValidationReason::NotUtf8,
        ];

        for reason in reasons {
            // Act / Assert
            assert_eq!(roundtrip(&reason), reason);
        }
    }

    #[test]
    fn every_error_code_round_trips() {
        // Arrange
        let codes = [
            ErrorCode::ProtocolVersionMismatch,
            ErrorCode::HandshakeRequired,
            ErrorCode::MalformedMessage,
            ErrorCode::ProfileInvalid,
            ErrorCode::ProfileNotFound,
            ErrorCode::AlreadyConnected,
            ErrorCode::NotConnected,
            ErrorCode::Busy,
            ErrorCode::AuthFailed,
            ErrorCode::TunnelNotReady,
            ErrorCode::PromptExpired,
            ErrorCode::Unauthorized,
            ErrorCode::Internal,
        ];

        for code in codes {
            // Act / Assert
            assert_eq!(roundtrip(&code), code);
        }
    }

    // -- handshake and framing ---------------------------------------------

    #[test]
    fn matching_protocol_version_is_accepted() {
        // Arrange / Act
        let result = check_protocol_version(PROTOCOL_VERSION);

        // Assert
        assert!(result.is_ok());
    }

    #[test]
    fn mismatched_protocol_version_is_rejected_with_a_distinct_code() {
        // Arrange / Act
        let error = check_protocol_version(PROTOCOL_VERSION + 1).unwrap_err();

        // Assert
        assert_eq!(error.code, ErrorCode::ProtocolVersionMismatch);
    }

    #[test]
    fn encoded_line_never_contains_a_raw_newline() {
        // Arrange
        let message = DaemonMessage::Event {
            event: Event::Log {
                level: LogLevel::Info,
                message: "line one\nline two\r\n".into(),
                unix_millis: 0,
            },
        };

        // Act
        let line = encode_line(&message).unwrap();

        // Assert
        assert!(!line.contains('\n'));
        assert!(!line.contains('\r'));
        match decode_line::<DaemonMessage>(&line).unwrap() {
            DaemonMessage::Event {
                event: Event::Log { message, .. },
            } => {
                assert_eq!(message, "line one\nline two\r\n");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn oversize_line_is_rejected_before_parsing() {
        // Arrange
        let line = "x".repeat(MAX_MESSAGE_BYTES + 1);

        // Act
        let error = decode_line::<ClientMessage>(&line).unwrap_err();

        // Assert
        assert!(matches!(error, CodecError::TooLarge(_)));
    }

    #[test]
    fn unknown_message_type_is_rejected() {
        // Arrange
        let line = r#"{"type":"exec_shell","id":"1"}"#;

        // Act
        let error = decode_line::<ClientMessage>(line).unwrap_err();

        // Assert
        assert!(matches!(error, CodecError::Json(_)));
    }

    #[test]
    fn truncated_json_is_rejected() {
        // Arrange
        let line = r#"{"type":"request","id":"1","request":{"type":"con"#;

        // Act
        let error = decode_line::<ClientMessage>(line).unwrap_err();

        // Assert
        assert!(matches!(error, CodecError::Json(_)));
    }

    #[test]
    fn daemon_hello_and_error_round_trip() {
        // Arrange
        let hello = DaemonMessage::Hello {
            id: RequestId("1".into()),
            protocol_version: PROTOCOL_VERSION,
            daemon_version: "0.1.0".into(),
        };
        let error = DaemonMessage::Error {
            id: RequestId("1".into()),
            error: IpcError::new(ErrorCode::HandshakeRequired, "hello first"),
        };

        // Act
        let hello_json = json_of(&hello);
        let error_json = json_of(&error);

        // Assert
        assert_eq!(hello_json["type"], "hello");
        assert_eq!(hello_json["daemon_version"], "0.1.0");
        assert_eq!(error_json["type"], "error");
        assert_eq!(error_json["error"]["code"], "handshake_required");
        assert!(matches!(roundtrip(&hello), DaemonMessage::Hello { .. }));
        assert!(matches!(roundtrip(&error), DaemonMessage::Error { .. }));
    }
}
