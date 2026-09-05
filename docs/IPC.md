# thisconnect IPC protocol

Reference for the control channel between the unprivileged GUI and `thisconnectd`.
Types are defined in `shared/src/ipc.rs`; this document is the wire contract.

Protocol version: **1** (`PROTOCOL_VERSION`).

## 1. Transport and framing

- `AF_UNIX` `SOCK_STREAM`. Linux: `/run/thisconnect/thisconnectd.sock` (`root:thisconnect`, 0660).
  macOS: `/var/run/thisconnect.sock`, mode 0666 with mandatory peer authentication (SPEC.md §7.2).
- The daemon authenticates the peer **before** reading any message (SPEC.md §7.3). An
  unauthenticated peer is disconnected without a reply — no error object, because there is no
  authenticated party to tell.
- **Line-delimited JSON.** One JSON object per line, `\n`-terminated, UTF-8
  (`tokio_util::codec::LinesCodec`). No JSON-RPC envelope, no batching, no pretty printing.
- Messages are hard-capped at **1 MiB** (`MAX_MESSAGE_BYTES`); the cap is that large only because
  `profile_import` carries a whole `.ovpn`. Oversize lines are rejected before parsing.
- Encoders reject any serialized line containing `\n` or `\r`. JSON string escaping already
  guarantees this; the check exists because framing is load-bearing.
- Both directions are fully asynchronous. Responses may arrive out of order relative to requests,
  and events and prompts may interleave anywhere. Correlate by `id`, never by arrival order.

Every message has a `"type"` discriminator. Unknown `"type"` values are a protocol error, not
something to ignore.

## 2. Correlation

| Field | Direction | Meaning |
|---|---|---|
| `id` | GUI → daemon | Client-generated, unique per connection. Echoed by exactly one `response` or `error`. |
| `id` | daemon → GUI | Echo of the request `id`. `hello` echoes the client's handshake `id`. |
| `prompt_id` | daemon → GUI | Daemon-generated id for a daemon-initiated credential prompt. |
| `prompt_id` | GUI → daemon | Echo of the prompt the GUI is answering. |

`event` messages carry no `id`: they are unsolicited.

## 3. Handshake

The GUI sends `hello` first. Nothing else is accepted before it — an early request is answered
with `handshake_required` and the connection is closed.

```json
{"type":"hello","id":"1","protocol_version":1,"client_name":"thisconnect-gui"}
```

```json
{"type":"hello","id":"1","protocol_version":1,"daemon_version":"0.1.0"}
```

On mismatch the daemon replies with an error and closes. Failing loudly here is the point: a GUI
that speaks a different revision would otherwise silently misread fields such as leak counters.

```json
{"type":"error","id":"1","error":{"code":"protocol_version_mismatch","message":"daemon speaks protocol 1, client speaks 2"}}
```

## 4. GUI → daemon

### 4.1 `request`

`{"type":"request","id":"<id>","request":{"type":"<request type>", ...}}`

| `request.type` | Fields | Response |
|---|---|---|
| `profile_import` | `name`, `config` (raw `.ovpn` text) | `profile`, or `error` with `validation` |
| `profile_list` | — | `profiles` |
| `profile_get` | `profile_id` | `profile` |
| `profile_delete` | `profile_id` | `ack` |
| `connect` | `profile_id` | `ack` (connection progress arrives as events) |
| `disconnect` | — | `ack` |
| `status` | — | `status` |
| `proxy_info` | — | `proxy` |
| `proxy_stats` | — | `proxy_stats` |

`profile_import` is the **only** message that ever carries config text. Connecting takes a
`profile_id` referring to an already-validated, canonicalised profile (SPEC.md §3.1.4). The daemon
does not accept a config on connect, ever.

```json
{"type":"request","id":"2","request":{"type":"profile_import","name":"work","config":"client\npull\nremote vpn.example 1194 udp\n"}}
```

```json
{"type":"request","id":"3","request":{"type":"connect","profile_id":"p1"}}
```

### 4.2 `prompt_reply`

Answers a daemon-initiated prompt. See §6.

```json
{"type":"prompt_reply","id":"4","prompt_id":"prompt-1","reply":{"type":"username_password","username":"alice","password":"hunter2"}}
```

```json
{"type":"prompt_reply","id":"5","prompt_id":"prompt-2","reply":{"type":"challenge_response","response":"481920"}}
```

```json
{"type":"prompt_reply","id":"6","prompt_id":"prompt-2","reply":{"type":"cancel"}}
```

`cancel` aborts the authentication attempt. The daemon does not retry with stale credentials —
`--auth-retry nointeract` would replay a consumed TOTP, which is why the spawn line uses
`interact` (SPEC.md §4.1).

## 5. Daemon → GUI

### 5.1 `response`

`{"type":"response","id":"<id>","response":{"type":"<response type>", ...}}`

`ack`, `profile`, `profiles`, `status`, `proxy`, `proxy_stats`.

```json
{"type":"response","id":"2","response":{"type":"profile","profile":{"id":"p1","name":"work","remotes":[{"host":"vpn.example","port":1194,"transport":"udp"}],"requires_username_password":true,"static_challenge":{"text":"TOTP code","echo":false},"has_inline_ca":true,"has_inline_cert":false,"has_inline_key":false,"canonical_sha256":"3b1f...","imported_unix_secs":1757000000}}}
```

```json
{"type":"response","id":"7","response":{"type":"status","status":{"state":"connected","profile_id":"p1","connected_since_unix_secs":1757000100,"bytes_in":81920,"bytes_out":10240,"tunnel":{"device":"utun7","ipv4":"10.8.0.2","ipv6":null,"mtu":1240,"tunnel_has_v6":false,"dns_servers":["10.8.0.1"],"dns_source":"pushed","search_domains":["corp.example"]},"last_error":null}}}
```

`state` is one of `disconnected`, `connecting`, `authenticating`, `connected`, `reconnecting`,
`disconnecting`, `failed`. `connected` means `>STATE:...,CONNECTED` **and** tunnel policy
installed — never `get_config`, `assign_ip`, or `add_routes`, which may not fire at all under
`--route-noexec` (SPEC.md §4.3.5).

`dns_source` is `pushed` (the VPN's own resolver, captured from `PUSH_REPLY`) or `tunnel_fallback`
(the user-configured fallback, queried through the tun). The GUI must say plainly when it is
`tunnel_fallback` that a third party sees the queries (SPEC.md §5.4 D4). There is no value for
"system resolver": that path does not exist.

`tunnel_has_v6` is not cosmetic. A false value means the proxy answers `A` only, discards AAAA,
and rejects `ATYP=0x04` (SPEC.md §5.5); the GUI surfaces it so a v6-only destination failure reads
as a real limitation rather than a bug.

#### `proxy`

```json
{"type":"response","id":"8","response":{"type":"proxy","proxy":{"listen_addrs":["127.0.0.1:1080","[::1]:1080"],"auth":{"type":"credentials","username":"thisconnect","password":"Xk3..."},"is_loopback_only":true,"allowed_cidrs":[],"socks5h_url":"socks5h://thisconnect:Xk3...@127.0.0.1:1080"}}}
```

`auth` is `{"type":"disabled"}` or `{"type":"credentials","username":...,"password":...}`. The URL
is `socks5h://` deliberately: `socks5://` resolves locally and leaks every hostname (SPEC.md
§5.4 D8), so the copy button must never emit it.

#### `proxy_stats`

```json
{"type":"response","id":"9","response":{"type":"proxy_stats","stats":{"active_sessions":3,"total_sessions":94,"bytes_to_tunnel":184320,"bytes_from_tunnel":2097152,"tunnel_dns_lookups":41,"local_dns_lookups":0,"auth_failures":0,"distinct_remote_peers":0,"tunnel_has_v6":false}}}
```

`local_dns_lookups` is the leak counter from SPEC.md §5.4 D7 and is shown verbatim in the GUI
("0 local DNS lookups this session"). Any non-zero value is a bug, not a statistic.
`distinct_remote_peers` feeds the non-loopback banner (SPEC.md §5.6 L4).

### 5.2 `error`

```json
{"type":"error","id":"2","error":{"code":"profile_invalid","message":"profile rejected at line 12","validation":{"reason":"forbidden_directive","line":12,"directive":"plugin","detail":"code-loading directives are rejected at parse time"}}}
```

`validation` is present only for `profile_invalid`, and it never carries the argument of the
offending directive — an argument can be key material.

| `code` | Meaning |
|---|---|
| `protocol_version_mismatch` | Handshake refused. |
| `handshake_required` | A request arrived before `hello`. |
| `malformed_message` | Unparseable, oversize, or unknown `type`. |
| `profile_invalid` | Validator rejected the config. Carries `validation`. |
| `profile_not_found` | No such `profile_id`. |
| `already_connected` / `not_connected` | Wrong connection state for the request. |
| `busy` | Another connect/disconnect is in flight. |
| `auth_failed` | Server rejected the credentials. |
| `tunnel_not_ready` | Proxy listener is not up; nothing to report. |
| `prompt_expired` | Reply for a prompt the daemon already withdrew. |
| `unauthorized` | Peer failed authorisation for this operation. |
| `internal` | Bug. Message is redacted and safe to display. |

`validation.reason` is one of `unknown_directive`, `forbidden_directive`, `unknown_inline_tag`,
`invalid_argument`, `missing_required_directive`, `file_too_large`, `too_many_directives`,
`not_utf8`. `unknown_directive` and `unknown_inline_tag` exist because validation is an allowlist:
anything not explicitly permitted is refused, including inline tags such as `<auth-user-pass>`
(SPEC.md §6).

### 5.3 `event`

`{"type":"event","event":{"type":"<event type>", ...}}`

| `event.type` | Fields |
|---|---|
| `state` | `state`, `detail` |
| `byte_count` | `bytes_in`, `bytes_out` |
| `log` | `level` (`debug`/`info`/`warn`/`error`), `message`, `unix_millis` |
| `tunnel_up` | `tunnel` (same shape as `status.tunnel`) |
| `tunnel_down` | `reason` |
| `proxy_listener_up` | `listen_addrs` |
| `proxy_listener_down` | `reason` |
| `prompt_cancelled` | `prompt_id` |

```json
{"type":"event","event":{"type":"state","state":"authenticating","detail":null}}
```

```json
{"type":"event","event":{"type":"tunnel_up","tunnel":{"device":"utun7","ipv4":"10.8.0.2","ipv6":null,"mtu":1240,"tunnel_has_v6":false,"dns_servers":["10.8.0.1"],"dns_source":"pushed","search_domains":[]}}}
```

```json
{"type":"event","event":{"type":"log","level":"warn","message":"tunnel resolver 10.8.0.1 timed out","unix_millis":1757000000000}}
```

`log` messages are daemon-authored and redacted. Raw openvpn `>LOG:` output is never forwarded or
persisted: it redacts `password` but **not** `username` (SPEC.md §4.4).

`proxy_listener_down` follows any state transition away from `connected`; the listener closes and
all live sessions are killed (SPEC.md §5.6 L6). The GUI should treat it as authoritative rather
than inferring listener state from `state` events.

## 6. Credential prompts

Prompts are **daemon-initiated requests**. openvpn asks for credentials over its management
interface mid-connect, so the daemon must be able to ask the GUI a question and wait for the
answer. Modelled as `prompt` + correlated `prompt_reply`.

```
GUI                                   daemon                              openvpn
 |                                      |                                    |
 |-- request connect(profile_id) ------>|                                    |
 |<-- response ack ---------------------|                                    |
 |                                      |-- spawn, hold release ------------>|
 |<-- event state=connecting -----------|                                    |
 |                                      |<-- >PASSWORD:Need 'Auth' user/pass |
 |<-- prompt prompt-1 ------------------|                                    |
 |      username_password               |                                    |
 |                                      |                                    |
 |-- prompt_reply prompt-1 ------------>|                                    |
 |      username + password             |-- username/password (escaped) ---->|
 |<-- event state=authenticating -------|                                    |
 |                                      |                                    |
 |                                      |<-- Verification Failed: CRV1:...   |
 |<-- prompt prompt-2 ------------------|                                    |
 |      dynamic_challenge, echo=false   |                                    |
 |-- prompt_reply prompt-2 ------------>|                                    |
 |      challenge_response              |-- cr-response <base64> ----------->|
 |                                      |<-- >STATE:...,CONNECTED            |
 |<-- event tunnel_up ------------------|                                    |
 |<-- event state=connected ------------|                                    |
 |<-- event proxy_listener_up ----------|                                    |
```

If the user dismisses the dialog, the GUI replies `{"type":"cancel"}` and the daemon aborts the
attempt. If the daemon gives up first (timeout, connection torn down) it emits
`prompt_cancelled`; a reply arriving after that is answered with `prompt_expired`.

### Prompt shapes

```json
{"type":"prompt","prompt_id":"prompt-1","prompt":{"type":"username_password","profile_id":"p1","username_hint":"alice"}}
```

```json
{"type":"prompt","prompt_id":"prompt-2","prompt":{"type":"static_challenge","profile_id":"p1","challenge_text":"Enter your TOTP code","echo":false}}
```

```json
{"type":"prompt","prompt_id":"prompt-3","prompt":{"type":"dynamic_challenge","profile_id":"p1","state_id":"aBc123","challenge_text":"Enter the code sent to your phone","echo":true}}
```

- `username_hint` is the last username used, for prefill. It is never a password.
- `echo` comes from the challenge's own flag: `false` means mask the field, which is the case for
  one-time values. The GUI must honour it — a shoulder-surfed TOTP is a real loss.
- `state_id` on a CRV1 dynamic challenge is surfaced for diagnostics; the daemon owns the
  response construction. CRV1 is parsed with `splitn(5, ':')` because the challenge text may
  contain colons while the state id may not (SPEC.md §4.3.7).
- Both challenge shapes are answered with `challenge_response`; which challenge is being answered
  is fixed by `prompt_id`, not by the reply shape.

## 7. Secret handling

`password`, `challenge_response.response`, `proxy.auth.password`, `proxy.socks5h_url`, and the
`profile_import` config body are `Secret` in Rust: zeroized on drop, and `Debug`-redacted as
`Secret(<redacted>)` so that logging any enclosing message cannot print them. On the wire they are
plain JSON strings — confidentiality comes from the socket's permissions and peer authentication,
not from the encoding. Consequently:

- Never log a raw IPC line. Log the message `type` and `id`.
- Never persist a transcript of the channel.
