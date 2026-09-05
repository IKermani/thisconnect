// SPDX-License-Identifier: GPL-3.0-or-later

//! The allowlist, the hard-reject table, and per-directive classification.
//!
//! Allowlist, never denylist: a directive that is not recognised here is a parse failure, because
//! a denylist drifts every time OpenVPN gains an option and the profile is untrusted input handed
//! to a privileged process. The hard-reject table exists only to give a better error message for
//! the dangerous options users are most likely to have in a profile.

use super::args::{self, Ctx};
use super::error::ValidationError;
use super::lexer::RawDirective;
use super::profile::{
    DhcpOption, EmittedDirective, RedirectGateway, Remote, RouteDirective, StaticChallenge,
};

/// Inline material accepted as `<tag>` blocks. Any other tag is rejected *before* directive
/// classification: `<auth-user-pass>`, `<http-proxy-user-pass>` and `<auth-token-secret-file>` are
/// real OpenVPN inline forms, so a scalar-only check on those names is a bypass.
pub const INLINE_MATERIAL: &[&str] = &[
    "ca",
    "cert",
    "key",
    "dh",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "pkcs12",
    "crl-verify",
    "extra-certs",
];

/// Directives refused with a specific reason. Everything not listed here and not allowlisted is
/// refused anyway, as an unknown directive.
const HARD_REJECT: &[(&str, &str)] = &[
    ("plugin", "loads code into the privileged process"),
    ("pkcs11-providers", "loads code into the privileged process"),
    ("pkcs11-id", "loads code into the privileged process"),
    (
        "pkcs11-id-management",
        "loads code into the privileged process",
    ),
    (
        "pkcs11-cert-private",
        "loads code into the privileged process",
    ),
    (
        "pkcs11-private-mode",
        "loads code into the privileged process",
    ),
    (
        "pkcs11-protected-authentication",
        "loads code into the privileged process",
    ),
    ("pkcs11-pin-cache", "loads code into the privileged process"),
    ("cryptoapicert", "loads code into the privileged process"),
    ("engine", "loads code into the privileged process"),
    ("providers", "loads code into the privileged process"),
    ("up", "runs a script"),
    ("down", "runs a script"),
    ("route-up", "runs a script"),
    ("route-pre-down", "runs a script"),
    ("ipchange", "runs a script"),
    ("tls-verify", "runs a script"),
    ("auth-user-pass-verify", "runs a script"),
    ("client-connect", "runs a script"),
    ("client-disconnect", "runs a script"),
    ("learn-address", "runs a script"),
    ("tls-export-cert", "runs a script"),
    ("client-crresponse", "runs a script"),
    ("tls-crypt-v2-verify", "runs a script"),
    ("auth-gen-token-secret", "runs a script"),
    ("log", "writes to a path of the profile's choosing"),
    ("log-append", "writes to a path of the profile's choosing"),
    ("status", "writes to a path of the profile's choosing"),
    (
        "status-version",
        "writes to a path of the profile's choosing",
    ),
    ("writepid", "writes to a path of the profile's choosing"),
    ("tmp-dir", "writes to a path of the profile's choosing"),
    ("cd", "changes the privileged process working directory"),
    ("chroot", "changes the privileged process root"),
    (
        "client-config-dir",
        "reads a path of the profile's choosing",
    ),
    ("ccd-exclusive", "reads a path of the profile's choosing"),
    ("iproute", "substitutes the command the daemon executes"),
    ("setcon", "changes the security context"),
    ("askpass", "reads a path of the profile's choosing"),
    ("capath", "reads a path of the profile's choosing"),
    ("setenv", "injects environment into the privileged process"),
    (
        "setenv-safe",
        "injects environment into the privileged process",
    ),
    ("config", "nested includes are flattened, not followed"),
    ("http-proxy-user-pass", "reads credentials from a path"),
    (
        "auth-token-secret-file",
        "reads a path of the profile's choosing",
    ),
];

/// Directives valid inside a `<connection>` block.
const CONNECTION_SCOPED: &[&str] = &[
    "remote",
    "proto",
    "port",
    "lport",
    "rport",
    "nobind",
    "float",
    "connect-retry",
    "connect-retry-max",
    "connect-timeout",
    "explicit-exit-notify",
    "http-proxy",
    "socks-proxy",
    "tun-mtu",
    "tun-mtu-extra",
    "fragment",
    "mssfix",
];

/// What the validator decided about one directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    /// Emitted into the canonical config verbatim.
    Emit(EmittedDirective),
    Remote(Remote),
    /// Retained for the proxy's egress logic, never emitted.
    Route(RouteDirective),
    RedirectGateway(RedirectGateway),
    DhcpOption(DhcpOption),
    AuthUserPass,
    StaticChallenge(StaticChallenge),
    /// Accepted and deliberately dropped: the daemon supplies its own flag.
    Ignored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    TopLevel,
    Connection,
}

pub fn is_inline_material(tag: &str) -> bool {
    INLINE_MATERIAL.contains(&tag)
}

/// Classify one directive, or reject the profile.
pub fn classify(raw: &RawDirective, scope: Scope) -> Result<Classified, ValidationError> {
    let ctx = Ctx {
        line: raw.line,
        name: &raw.name,
    };
    reject_dangerous(ctx, &raw.name, &raw.args)?;
    args::check_charset(ctx, &raw.args)?;
    if scope == Scope::Connection && !CONNECTION_SCOPED.contains(&raw.name.as_str()) {
        return Err(ValidationError::ForbiddenDirective {
            line: raw.line,
            directive: raw.name.clone(),
            reason: "not valid inside a <connection> block".into(),
        });
    }

    let handlers = [as_flag, as_number, as_keyword, as_crypto, as_typed];
    for handler in handlers {
        if let Some(result) = handler(ctx, &raw.name, &raw.args) {
            return result;
        }
    }
    Err(ValidationError::UnknownDirective {
        line: raw.line,
        directive: raw.name.clone(),
    })
}

/// `dns-updown` is only tolerable with the exact value `disable`; the built-in handler runs as
/// root even at script-security 1.
fn reject_dangerous(ctx: Ctx<'_>, name: &str, args: &[String]) -> Result<(), ValidationError> {
    let reason = if name.starts_with("management") {
        Some("hijacks the daemon's control channel")
    } else if name == "dns-updown" && args.first().map(String::as_str) != Some("disable") {
        Some("runs the built-in dns handler as root")
    } else if name == "dev" && args.first().map(String::as_str) == Some("tap") {
        Some("tap devices are not supported")
    } else {
        HARD_REJECT
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, reason)| *reason)
    };
    match reason {
        Some(reason) => Err(ValidationError::ForbiddenDirective {
            line: ctx.line,
            directive: name.to_owned(),
            reason: reason.to_owned(),
        }),
        None => Ok(()),
    }
}

type Outcome = Option<Result<Classified, ValidationError>>;

fn emit(name: &str, args: Vec<String>) -> Outcome {
    Some(Ok(Classified::Emit(EmittedDirective::new(name, args))))
}

/// Argument-free switches. `client` and `pull` live here: without them essentially every
/// real-world profile is rejected, and without `pull` no tunnel comes up at all.
fn as_flag(ctx: Ctx<'_>, name: &str, args: &[String]) -> Outcome {
    const FLAGS: &[&str] = &[
        "client",
        "pull",
        "tls-client",
        "nobind",
        "float",
        "remote-random",
        "persist-key",
        "persist-tun",
        "auth-nocache",
        "mute-replay-warnings",
    ];
    if name == "auth-user-pass" {
        if !args.is_empty() {
            return Some(Err(ctx.invalid(
                "must be bare; credential files are supplied by the daemon",
            )));
        }
        return Some(Ok(Classified::AuthUserPass));
    }
    if !FLAGS.contains(&name) {
        return None;
    }
    if let Err(err) = args::expect_no_args(ctx, args) {
        return Some(Err(err));
    }
    emit(name, Vec::new())
}

/// Range-checked numeric directives. `verb` is clamped rather than rejected: a noisy profile is
/// not a security failure, but verbose openvpn logging can carry credentials.
fn as_number(ctx: Ctx<'_>, name: &str, args: &[String]) -> Outcome {
    const MAX_SECONDS: u32 = 86_400;
    const RANGES: &[(&str, u32, u32)] = &[
        ("port", 1, 65535),
        ("lport", 0, 65535),
        ("rport", 1, 65535),
        ("reneg-sec", 0, MAX_SECONDS),
        ("ping", 1, MAX_SECONDS),
        ("ping-restart", 1, MAX_SECONDS),
        ("tun-mtu", 68, 65536),
        ("tun-mtu-extra", 0, 65536),
        ("fragment", 0, 65536),
        ("mssfix", 0, 9000),
        ("sndbuf", 0, 16_777_216),
        ("rcvbuf", 0, 16_777_216),
        ("mute", 0, 1000),
        ("connect-timeout", 1, 600),
        ("connect-retry-max", 0, 1000),
    ];
    match name {
        "verb" => {
            let raw = match args::expect_arity(ctx, args, 1, 1)
                .and_then(|()| args::parse_u32_in(ctx, &args[0], 0, 11))
            {
                Ok(v) => v,
                Err(err) => return Some(Err(err)),
            };
            emit(name, vec![raw.min(4).to_string()])
        }
        "keepalive" | "connect-retry" => {
            if let Err(err) = args::expect_arity(ctx, args, 1, 2) {
                return Some(Err(err));
            }
            for arg in args {
                if let Err(err) = args::parse_u32_in(ctx, arg, 0, MAX_SECONDS) {
                    return Some(Err(err));
                }
            }
            emit(name, args.to_vec())
        }
        "resolv-retry" => {
            if let Err(err) = args::expect_arity(ctx, args, 1, 1) {
                return Some(Err(err));
            }
            if args[0] != "infinite" {
                if let Err(err) = args::parse_u32_in(ctx, &args[0], 0, MAX_SECONDS) {
                    return Some(Err(err));
                }
            }
            emit(name, args.to_vec())
        }
        "explicit-exit-notify" => {
            if let Err(err) = args::expect_arity(ctx, args, 0, 1) {
                return Some(Err(err));
            }
            if let Some(arg) = args.first() {
                if let Err(err) = args::parse_u32_in(ctx, arg, 0, 2) {
                    return Some(Err(err));
                }
            }
            emit(name, args.to_vec())
        }
        _ => {
            let (_, lo, hi) = RANGES.iter().find(|(n, _, _)| *n == name)?;
            if let Err(err) = args::expect_arity(ctx, args, 1, 2) {
                return Some(Err(err));
            }
            if args[0] != "infinite" {
                if let Err(err) = args::parse_u32_in(ctx, &args[0], *lo, *hi) {
                    return Some(Err(err));
                }
            }
            emit(name, args.to_vec())
        }
    }
}

/// Directives whose argument is drawn from a fixed set.
fn as_keyword(ctx: Ctx<'_>, name: &str, args: &[String]) -> Outcome {
    const CHOICES: &[(&str, &[&str])] = &[
        ("dev-type", &["tun"]),
        ("topology", &["subnet", "net30", "p2p"]),
        ("remote-cert-tls", &["server"]),
        ("ns-cert-type", &["server"]),
        ("key-direction", &["0", "1"]),
        ("route-method", &["exe", "ipapi", "adaptive"]),
        ("tls-version-min", &["1.0", "1.1", "1.2", "1.3"]),
        ("tls-version-max", &["1.0", "1.1", "1.2", "1.3"]),
    ];
    match name {
        "dns-updown" => Some(Ok(Classified::Ignored)),
        "proto" => Some(
            args::parse_proto(ctx, args)
                .map(|p| Classified::Emit(EmittedDirective::new(name, vec![p]))),
        ),
        "dev" => Some(
            args::parse_dev(ctx, args)
                .map(|d| Classified::Emit(EmittedDirective::new(name, vec![d]))),
        ),
        _ => {
            let (_, allowed) = CHOICES.iter().find(|(n, _)| *n == name)?;
            let max = if name == "tls-version-min" { 2 } else { 1 };
            if let Err(err) = args::expect_arity(ctx, args, 1, max) {
                return Some(Err(err));
            }
            if let Err(err) = args::expect_one_of(ctx, &args[0], allowed) {
                return Some(Err(err));
            }
            if let Some(second) = args.get(1) {
                if let Err(err) = args::expect_one_of(ctx, second, &["or-highest"]) {
                    return Some(Err(err));
                }
            }
            emit(name, args.to_vec())
        }
    }
}

/// Cipher, digest and certificate-verification directives: token lists, no paths.
fn as_crypto(ctx: Ctx<'_>, name: &str, args: &[String]) -> Outcome {
    // `cipher` is ignored in TLS mode from OpenVPN 2.6 on, but it appears in the overwhelming
    // majority of profiles written before then. Rejecting it would reject most real-world
    // profiles; emitting a charset-validated cipher name costs nothing and keeps the
    // negotiation fallback working against older servers.
    const TOKEN_LISTS: &[&str] = &[
        "cipher",
        "data-ciphers",
        "data-ciphers-fallback",
        "auth",
        "tls-cipher",
        "tls-ciphersuites",
        "remote-cert-eku",
        "remote-cert-ku",
    ];
    match name {
        "peer-fingerprint" => Some(
            args::parse_peer_fingerprint(ctx, args)
                .map(|fp| Classified::Emit(EmittedDirective::new(name, vec![fp]))),
        ),
        "verify-x509-name" => {
            if let Err(err) = args::expect_arity(ctx, args, 1, 2) {
                return Some(Err(err));
            }
            if let Some(kind) = args.get(1) {
                if let Err(err) =
                    args::expect_one_of(ctx, kind, &["name", "name-prefix", "subject"])
                {
                    return Some(Err(err));
                }
            }
            emit(name, args.to_vec())
        }
        _ => {
            if !TOKEN_LISTS.contains(&name) {
                return None;
            }
            let max = if name == "remote-cert-ku" { 8 } else { 1 };
            if let Err(err) = args::expect_arity(ctx, args, 1, max) {
                return Some(Err(err));
            }
            emit(name, args.to_vec())
        }
    }
}

/// Directives parsed into typed values: the remotes we dial, and the three retained-but-never-
/// emitted routing directives.
fn as_typed(ctx: Ctx<'_>, name: &str, args: &[String]) -> Outcome {
    match name {
        "remote" => Some(args::parse_remote(ctx, args).map(Classified::Remote)),
        "route" => Some(args::parse_route(ctx, args).map(Classified::Route)),
        "redirect-gateway" => Some(Ok(Classified::RedirectGateway(RedirectGateway {
            flags: args.to_vec(),
        }))),
        "dhcp-option" => Some(args::parse_dhcp_option(ctx, args).map(Classified::DhcpOption)),
        "static-challenge" => {
            Some(args::parse_static_challenge(ctx, args).map(Classified::StaticChallenge))
        }
        "http-proxy" | "socks-proxy" => Some(
            args::parse_proxy(ctx, args).map(|a| Classified::Emit(EmittedDirective::new(name, a))),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn raw(line: &str) -> RawDirective {
        let mut parts = line.split_whitespace().map(str::to_owned);
        let name = parts.next().unwrap_or_default();
        RawDirective {
            line: 1,
            name,
            args: parts.collect(),
        }
    }

    fn classify_top(line: &str) -> Result<Classified, ValidationError> {
        classify(&raw(line), Scope::TopLevel)
    }

    #[test]
    fn accepts_client_and_pull() {
        // Arrange / Act / Assert
        assert_eq!(
            classify_top("client"),
            Ok(Classified::Emit(EmittedDirective::bare("client")))
        );
        assert_eq!(
            classify_top("pull"),
            Ok(Classified::Emit(EmittedDirective::bare("pull")))
        );
    }

    #[test]
    fn rejects_plugin_even_though_script_security_would_be_one() {
        // Arrange / Act
        let err = classify_top("plugin /tmp/evil.so").unwrap_err();

        // Assert
        assert!(matches!(err, ValidationError::ForbiddenDirective { .. }));
        assert_eq!(err.directive(), Some("plugin"));
    }

    #[test]
    fn rejects_every_hard_reject_directive() {
        // Arrange
        let names: Vec<&str> = HARD_REJECT.iter().map(|(n, _)| *n).collect();

        // Act / Assert
        for name in names {
            let err = classify_top(&format!("{name} value")).unwrap_err();
            assert!(
                matches!(err, ValidationError::ForbiddenDirective { .. }),
                "{name} was not hard-rejected"
            );
        }
    }

    #[test]
    fn rejects_any_management_directive_by_prefix() {
        // Arrange / Act / Assert
        for line in [
            "management 127.0.0.1 7505",
            "management-query-passwords",
            "management-client-user root",
            "management-external-key",
        ] {
            assert!(matches!(
                classify_top(line).unwrap_err(),
                ValidationError::ForbiddenDirective { .. }
            ));
        }
    }

    #[test]
    fn accepts_legacy_cipher_because_most_real_profiles_carry_it() {
        // Arrange / Act / Assert
        assert!(matches!(
            classify_top("cipher AES-256-CBC"),
            Ok(Classified::Emit(_))
        ));
    }

    #[test]
    fn rejects_cipher_argument_carrying_injection() {
        // Arrange / Act / Assert
        assert!(classify_top("cipher AES-256-CBC\nup /bin/sh").is_err());
        assert!(classify_top("cipher ../../etc/passwd").is_err());
    }

    #[test]
    fn accepts_common_benign_flags_and_tls_version_max() {
        // Arrange / Act / Assert
        assert!(matches!(
            classify_top("mute-replay-warnings"),
            Ok(Classified::Emit(_))
        ));
        assert!(matches!(
            classify_top("tls-version-max 1.3"),
            Ok(Classified::Emit(_))
        ));
        assert!(classify_top("tls-version-max 9.9").is_err());
    }

    #[test]
    fn rejects_unknown_directive_instead_of_passing_it_through() {
        // Arrange / Act
        let err = classify_top("totally-new-openvpn-option 1").unwrap_err();

        // Assert
        assert!(matches!(err, ValidationError::UnknownDirective { .. }));
    }

    #[test]
    fn rejects_dev_tap_but_accepts_tun_and_utun() {
        // Arrange / Act / Assert
        assert!(matches!(
            classify_top("dev tap").unwrap_err(),
            ValidationError::ForbiddenDirective { .. }
        ));
        assert!(classify_top("dev tun").is_ok());
        assert!(classify_top("dev utun7").is_ok());
    }

    #[test]
    fn rejects_dns_updown_unless_value_is_disable() {
        // Arrange / Act / Assert
        assert!(matches!(
            classify_top("dns-updown /usr/local/bin/hook").unwrap_err(),
            ValidationError::ForbiddenDirective { .. }
        ));
        assert_eq!(classify_top("dns-updown disable"), Ok(Classified::Ignored));
    }

    #[test]
    fn treats_key_direction_and_peer_fingerprint_as_scalars() {
        // Arrange / Act
        let key_direction = classify_top("key-direction 1").unwrap();
        let fingerprint = classify_top("peer-fingerprint aa:bb:cc:dd:ee:ff").unwrap();

        // Assert
        assert_eq!(
            key_direction,
            Classified::Emit(EmittedDirective::new("key-direction", vec!["1".into()]))
        );
        assert!(matches!(fingerprint, Classified::Emit(_)));
        assert!(classify_top("key-direction 2").is_err());
    }

    #[test]
    fn clamps_verb_to_four() {
        // Arrange / Act
        let got = classify_top("verb 9").unwrap();

        // Assert
        assert_eq!(
            got,
            Classified::Emit(EmittedDirective::new("verb", vec!["4".into()]))
        );
    }

    #[test]
    fn rejects_out_of_range_numeric_arguments() {
        // Arrange / Act / Assert
        assert!(classify_top("port 0").is_err());
        assert!(classify_top("port 70000").is_err());
        assert!(classify_top("tun-mtu 12").is_err());
        assert!(classify_top("connect-timeout abc").is_err());
    }

    #[test]
    fn rejects_argument_injection_in_remote() {
        // Arrange / Act / Assert
        assert!(matches!(
            classify_top("remote vpn.example.com$(id) 1194").unwrap_err(),
            ValidationError::UnsafeArgument { .. }
        ));
        assert!(matches!(
            classify_top("remote ../../etc/passwd 1194").unwrap_err(),
            ValidationError::UnsafeArgument { .. }
        ));
    }

    #[test]
    fn rejects_auth_user_pass_with_a_file_path() {
        // Arrange / Act / Assert
        assert_eq!(classify_top("auth-user-pass"), Ok(Classified::AuthUserPass));
        assert!(matches!(
            classify_top("auth-user-pass creds.txt").unwrap_err(),
            ValidationError::InvalidArgument { .. }
        ));
    }

    #[test]
    fn retains_route_redirect_gateway_and_dhcp_option() {
        // Arrange / Act
        let route = classify_top("route 10.0.0.0 255.0.0.0").unwrap();
        let redirect = classify_top("redirect-gateway def1 bypass-dhcp").unwrap();
        let dns = classify_top("dhcp-option DNS 10.8.0.1").unwrap();

        // Assert
        assert!(matches!(route, Classified::Route(_)));
        assert!(matches!(redirect, Classified::RedirectGateway(_)));
        assert_eq!(
            dns,
            Classified::DhcpOption(DhcpOption {
                kind: "DNS".into(),
                values: vec!["10.8.0.1".into()],
            })
        );
    }

    #[test]
    fn rejects_top_level_only_directive_inside_a_connection_block() {
        // Arrange / Act
        let err = classify(&raw("persist-key"), Scope::Connection).unwrap_err();

        // Assert
        assert!(matches!(err, ValidationError::ForbiddenDirective { .. }));
        assert!(classify(&raw("remote a.example.com 443 tcp"), Scope::Connection).is_ok());
    }

    #[test]
    fn inline_material_set_excludes_credential_tags() {
        // Arrange / Act / Assert
        assert!(is_inline_material("tls-crypt"));
        assert!(!is_inline_material("auth-user-pass"));
        assert!(!is_inline_material("http-proxy-user-pass"));
        assert!(!is_inline_material("auth-token-secret-file"));
    }
}
