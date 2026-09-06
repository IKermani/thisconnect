// SPDX-License-Identifier: GPL-3.0-or-later
// Hand-mirrored from shared/src/ipc.rs (design doc §7). Every Rust enum here
// uses #[serde(tag = "type", rename_all = "snake_case")]; the TS shapes below
// are a direct, mechanical transcription of that wire format.

export type ProfileId = string;
export type PromptId = string;

export interface RemoteSummary {
  host: string;
  port: number;
  transport: 'udp' | 'tcp';
}

export interface StaticChallengeSummary {
  text: string;
  echo: boolean;
}

export interface ProfileSummary {
  id: ProfileId;
  name: string;
  remotes: RemoteSummary[];
  requires_username_password: boolean;
  static_challenge: StaticChallengeSummary | null;
  has_inline_ca: boolean;
  has_inline_cert: boolean;
  has_inline_key: boolean;
  canonical_sha256: string;
  imported_unix_secs: number;
}

export type ConnectionState =
  | 'disconnected'
  | 'connecting'
  | 'authenticating'
  | 'connected'
  | 'reconnecting'
  | 'disconnecting'
  | 'failed';

export type DnsSource = 'pushed' | 'tunnel_fallback';

export interface TunnelInfo {
  device: string;
  ipv4: string | null;
  ipv6: string | null;
  mtu: number | null;
  tunnel_has_v6: boolean;
  dns_servers: string[];
  dns_source: DnsSource;
  search_domains: string[];
}

export interface ConnectionStatus {
  state: ConnectionState;
  profile_id: ProfileId | null;
  connected_since_unix_secs: number | null;
  bytes_in: number;
  bytes_out: number;
  tunnel: TunnelInfo | null;
  last_error: string | null;
}

export interface ProxyInfo {
  listen_addrs: string[];
  auth: { type: 'disabled' } | { type: 'credentials'; username: string; password: string };
  is_loopback_only: boolean;
  allowed_cidrs: string[];
  socks5h_url: string;
}

export interface ProxySessionStats {
  active_sessions: number;
  total_sessions: number;
  bytes_to_tunnel: number;
  bytes_from_tunnel: number;
  tunnel_dns_lookups: number;
  local_dns_lookups: number;
  auth_failures: number;
  distinct_remote_peers: number;
  tunnel_has_v6: boolean;
}

export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error';

export type DaemonEvent =
  | { type: 'state'; state: ConnectionState; detail: string | null }
  | { type: 'byte_count'; bytes_in: number; bytes_out: number }
  | { type: 'log'; level: LogLevel; message: string; unix_millis: number }
  | { type: 'tunnel_up'; tunnel: TunnelInfo }
  | { type: 'tunnel_down'; reason: string }
  | { type: 'proxy_listener_up'; listen_addrs: string[] }
  | { type: 'proxy_listener_down'; reason: string }
  | { type: 'prompt_cancelled'; prompt_id: PromptId };

export type CredentialPrompt =
  | { type: 'username_password'; profile_id: ProfileId; username_hint: string | null }
  | {
      type: 'static_challenge';
      profile_id: ProfileId;
      challenge_text: string;
      echo: boolean;
    }
  | {
      type: 'dynamic_challenge';
      profile_id: ProfileId;
      state_id: string;
      challenge_text: string;
      echo: boolean;
    };

export type PromptReply =
  | { type: 'username_password'; username: string; password: string }
  | { type: 'challenge_response'; response: string }
  | { type: 'cancel' };

export type ValidationReason =
  | 'unknown_directive'
  | 'forbidden_directive'
  | 'unknown_inline_tag'
  | 'invalid_argument'
  | 'missing_required_directive'
  | 'file_too_large'
  | 'too_many_directives'
  | 'not_utf8';

export interface ValidationError {
  reason: ValidationReason;
  line: number | null;
  directive: string | null;
  detail: string;
}

export type ErrorCode =
  | 'protocol_version_mismatch'
  | 'handshake_required'
  | 'malformed_message'
  | 'profile_invalid'
  | 'profile_not_found'
  | 'already_connected'
  | 'not_connected'
  | 'busy'
  | 'auth_failed'
  | 'tunnel_not_ready'
  | 'prompt_expired'
  | 'unauthorized'
  | 'internal';

export interface IpcError {
  code: ErrorCode;
  message: string;
  validation: ValidationError | null;
}

export type DaemonUnreachableReason =
  | { reason: 'not_running' }
  | { reason: 'permission_denied' }
  | { reason: 'protocol_mismatch'; daemon_version: string };

export type UiError =
  | ({ type: 'daemon' } & IpcError)
  | { type: 'daemon_unreachable'; reason: DaemonUnreachableReason }
  | { type: 'timeout' }
  | { type: 'internal'; message: string };

export type ReachabilityWire =
  | { type: 'reachable' }
  | { type: 'unreachable'; reason: DaemonUnreachableReason };
