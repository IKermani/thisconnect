// SPDX-License-Identifier: GPL-3.0-or-later

//! Typed argument validation.
//!
//! Name allowlisting alone is not a boundary: `remote` and `dev` can still carry traversal or
//! metacharacter payloads into a privileged process, so every accepted directive's arguments are
//! parsed into a type or rejected.

use std::net::IpAddr;

use super::error::ValidationError;
use super::profile::{
    DhcpOption, Remote, RemoteHost, RouteDirective, StaticChallenge, TransportProto,
};

/// Characters an argument may contain. This is an allowlist, so every shell metacharacter,
/// control character and quote is excluded by construction rather than by enumeration.
const ALLOWED_PUNCTUATION: &str = "._-:/,=+@[]% ";

const MAX_HOSTNAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Directive name plus line, so a validator can build a precise rejection.
#[derive(Debug, Clone, Copy)]
pub struct Ctx<'a> {
    pub line: usize,
    pub name: &'a str,
}

impl Ctx<'_> {
    pub fn invalid(&self, detail: impl Into<String>) -> ValidationError {
        ValidationError::InvalidArgument {
            line: self.line,
            directive: self.name.to_owned(),
            detail: detail.into(),
        }
    }

    fn unsafe_arg(&self, detail: impl Into<String>) -> ValidationError {
        ValidationError::UnsafeArgument {
            line: self.line,
            directive: self.name.to_owned(),
            detail: detail.into(),
        }
    }
}

/// Reject NUL, newlines, shell metacharacters and `..` before any directive-specific parsing.
pub fn check_charset(ctx: Ctx<'_>, args: &[String]) -> Result<(), ValidationError> {
    for arg in args {
        if arg.contains("..") {
            return Err(ctx.unsafe_arg("contains `..`"));
        }
        if let Some(bad) = arg
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || ALLOWED_PUNCTUATION.contains(*c)))
        {
            return Err(ctx.unsafe_arg(format!("character {:?} is not permitted", bad)));
        }
    }
    Ok(())
}

pub fn expect_no_args(ctx: Ctx<'_>, args: &[String]) -> Result<(), ValidationError> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(ctx.invalid("takes no arguments"))
    }
}

pub fn expect_arity(
    ctx: Ctx<'_>,
    args: &[String],
    min: usize,
    max: usize,
) -> Result<(), ValidationError> {
    if args.len() < min || args.len() > max {
        return Err(ctx.invalid(format!(
            "expects between {min} and {max} arguments, got {}",
            args.len()
        )));
    }
    Ok(())
}

pub fn parse_u32_in(ctx: Ctx<'_>, arg: &str, lo: u32, hi: u32) -> Result<u32, ValidationError> {
    let value: u32 = arg
        .parse()
        .map_err(|_| ctx.invalid(format!("`{arg}` is not a non-negative integer")))?;
    if value < lo || value > hi {
        return Err(ctx.invalid(format!("`{arg}` is outside {lo}..={hi}")));
    }
    Ok(value)
}

pub fn parse_port(ctx: Ctx<'_>, arg: &str) -> Result<u16, ValidationError> {
    let port = parse_u32_in(ctx, arg, 1, u16::MAX as u32)?;
    u16::try_from(port).map_err(|_| ctx.invalid("port out of range"))
}

pub fn expect_one_of(ctx: Ctx<'_>, arg: &str, allowed: &[&str]) -> Result<(), ValidationError> {
    if allowed.contains(&arg) {
        Ok(())
    } else {
        Err(ctx.invalid(format!("`{arg}` is not one of {allowed:?}")))
    }
}

/// RFC1123 hostname: labels of alphanumerics and hyphens, hyphen never leading or trailing.
pub fn is_rfc1123_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOSTNAME_LEN {
        return false;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LEN
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

pub fn parse_host(ctx: Ctx<'_>, arg: &str) -> Result<RemoteHost, ValidationError> {
    if let Ok(ip) = arg.parse::<IpAddr>() {
        return Ok(RemoteHost::Ip(ip));
    }
    if is_rfc1123_hostname(arg) {
        return Ok(RemoteHost::Name(arg.to_owned()));
    }
    Err(ctx.invalid(format!("`{arg}` is neither an IP nor an RFC1123 hostname")))
}

fn parse_transport(ctx: Ctx<'_>, arg: &str) -> Result<TransportProto, ValidationError> {
    match arg {
        "udp" => Ok(TransportProto::Udp),
        "udp4" => Ok(TransportProto::Udp4),
        "udp6" => Ok(TransportProto::Udp6),
        // The `-client` spellings mean the same thing to a client and are
        // normalised, since openvpn accepts the short form everywhere.
        "tcp" | "tcp-client" => Ok(TransportProto::Tcp),
        "tcp4" | "tcp4-client" => Ok(TransportProto::Tcp4),
        "tcp6" | "tcp6-client" => Ok(TransportProto::Tcp6),
        other => Err(ctx.invalid(format!("`{other}` is not a supported transport"))),
    }
}

/// `remote <host> [port] [proto]`.
pub fn parse_remote(ctx: Ctx<'_>, args: &[String]) -> Result<Remote, ValidationError> {
    expect_arity(ctx, args, 1, 3)?;
    let host = parse_host(ctx, &args[0])?;
    let port = match args.get(1) {
        Some(p) => parse_port(ctx, p)?,
        None => 1194,
    };
    let proto = match args.get(2) {
        Some(p) => Some(parse_transport(ctx, p)?),
        None => None,
    };
    Ok(Remote { host, port, proto })
}

/// `proto udp|tcp-client|…`. Normalised to the argument openvpn expects back.
pub fn parse_proto(ctx: Ctx<'_>, args: &[String]) -> Result<String, ValidationError> {
    expect_arity(ctx, args, 1, 1)?;
    expect_one_of(
        ctx,
        &args[0],
        &[
            "udp",
            "udp4",
            "udp6",
            "tcp",
            "tcp4",
            "tcp6",
            "tcp-client",
            "tcp4-client",
            "tcp6-client",
        ],
    )?;
    Ok(args[0].clone())
}

/// `dev tun|utun[0-9]*`. `tap` is refused by the hard-reject table before this runs.
pub fn parse_dev(ctx: Ctx<'_>, args: &[String]) -> Result<String, ValidationError> {
    expect_arity(ctx, args, 1, 1)?;
    let dev = &args[0];
    let is_tun = dev == "tun" || dev.strip_prefix("tun").is_some_and(is_all_digits);
    let is_utun = dev == "utun" || dev.strip_prefix("utun").is_some_and(is_all_digits);
    if is_tun || is_utun {
        Ok(dev.clone())
    } else {
        Err(ctx.invalid(format!("`{dev}` is not a tun or utun device")))
    }
}

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// `peer-fingerprint AA:BB:…` — a scalar directive, not inline material.
pub fn parse_peer_fingerprint(ctx: Ctx<'_>, args: &[String]) -> Result<String, ValidationError> {
    expect_arity(ctx, args, 1, 1)?;
    let value = &args[0];
    let bytes: Vec<&str> = value.split(':').collect();
    let looks_hex = bytes.len() >= 2
        && bytes
            .iter()
            .all(|b| b.len() == 2 && b.chars().all(|c| c.is_ascii_hexdigit()));
    if looks_hex {
        Ok(value.to_ascii_uppercase())
    } else {
        Err(ctx.invalid("expects a colon-separated hex fingerprint"))
    }
}

/// `static-challenge "<prompt>" <0|1> [format-flags]`.
pub fn parse_static_challenge(
    ctx: Ctx<'_>,
    args: &[String],
) -> Result<StaticChallenge, ValidationError> {
    expect_arity(ctx, args, 2, 3)?;
    let echo = parse_u32_in(ctx, &args[1], 0, 1)? == 1;
    let format_flags = match args.get(2) {
        Some(f) => Some(u8::try_from(parse_u32_in(ctx, f, 0, 255)?).unwrap_or_default()),
        None => None,
    };
    Ok(StaticChallenge {
        prompt: args[0].clone(),
        echo,
        format_flags,
    })
}

/// `route <network> [netmask] [gateway] [metric]` — retained, never emitted.
pub fn parse_route(ctx: Ctx<'_>, args: &[String]) -> Result<RouteDirective, ValidationError> {
    expect_arity(ctx, args, 1, 4)?;
    let metric = match args.get(3) {
        Some(m) => Some(parse_u32_in(ctx, m, 0, 65535)?),
        None => None,
    };
    Ok(RouteDirective {
        network: args[0].clone(),
        netmask: args.get(1).cloned(),
        gateway: args.get(2).cloned(),
        metric,
    })
}

/// `dhcp-option <TYPE> [value…]` — retained, never emitted.
pub fn parse_dhcp_option(ctx: Ctx<'_>, args: &[String]) -> Result<DhcpOption, ValidationError> {
    expect_arity(ctx, args, 1, 8)?;
    Ok(DhcpOption {
        kind: args[0].to_ascii_uppercase(),
        values: args[1..].to_vec(),
    })
}

/// `http-proxy`/`socks-proxy <host> <port> [auto|auto-nct] [method]`. A third argument that is not
/// a keyword is an authfile path, which is a file-read primitive and is refused.
pub fn parse_proxy(ctx: Ctx<'_>, args: &[String]) -> Result<Vec<String>, ValidationError> {
    expect_arity(ctx, args, 2, 4)?;
    let host = parse_host(ctx, &args[0])?;
    let port = parse_port(ctx, &args[1])?;
    let mut out = vec![host.to_string(), port.to_string()];
    if let Some(third) = args.get(2) {
        expect_one_of(ctx, third, &["auto", "auto-nct"])
            .map_err(|_| ctx.invalid("proxy credentials must not be a file path"))?;
        out.push(third.clone());
    }
    if let Some(fourth) = args.get(3) {
        expect_one_of(ctx, fourth, &["basic", "digest", "ntlm2", "none"])?;
        out.push(fourth.clone());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn ctx() -> Ctx<'static> {
        Ctx {
            line: 7,
            name: "remote",
        }
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn rejects_argument_with_shell_metacharacter() {
        // Arrange
        let input = args(&["vpn.example.com;id"]);

        // Act
        let err = check_charset(ctx(), &input).unwrap_err();

        // Assert
        assert!(matches!(err, ValidationError::UnsafeArgument { .. }));
    }

    #[test]
    fn rejects_argument_with_parent_directory_traversal() {
        // Arrange / Act
        let err = check_charset(ctx(), &args(&["../../etc/passwd"])).unwrap_err();

        // Assert
        assert!(matches!(err, ValidationError::UnsafeArgument { .. }));
    }

    #[test]
    fn rejects_argument_with_backtick_or_dollar() {
        // Arrange / Act / Assert
        assert!(check_charset(ctx(), &args(&["`id`"])).is_err());
        assert!(check_charset(ctx(), &args(&["$(id)"])).is_err());
        assert!(check_charset(ctx(), &args(&["a|b"])).is_err());
        assert!(check_charset(ctx(), &args(&["a&b"])).is_err());
        assert!(check_charset(ctx(), &args(&["a>b"])).is_err());
    }

    #[test]
    fn accepts_ordinary_hostname_and_cipher_list_characters() {
        // Arrange / Act / Assert
        assert!(check_charset(ctx(), &args(&["vpn-1.example.com"])).is_ok());
        assert!(check_charset(ctx(), &args(&["AES-256-GCM:AES-128-GCM"])).is_ok());
        assert!(check_charset(ctx(), &args(&["C=US, O=Example"])).is_ok());
    }

    #[test]
    fn parses_remote_with_host_port_and_proto() {
        // Arrange / Act
        let remote = parse_remote(ctx(), &args(&["vpn.example.com", "1194", "udp"])).unwrap();

        // Assert
        assert_eq!(remote.port, 1194);
        assert_eq!(remote.proto, Some(TransportProto::Udp));
        assert_eq!(remote.host, RemoteHost::Name("vpn.example.com".into()));
    }

    #[test]
    fn defaults_remote_port_to_1194_when_absent() {
        // Arrange / Act
        let remote = parse_remote(ctx(), &args(&["203.0.113.7"])).unwrap();

        // Assert
        assert_eq!(remote.port, 1194);
        assert!(matches!(remote.host, RemoteHost::Ip(_)));
    }

    #[test]
    fn rejects_remote_port_zero_and_above_65535() {
        // Arrange / Act / Assert
        assert!(parse_remote(ctx(), &args(&["a.example.com", "0"])).is_err());
        assert!(parse_remote(ctx(), &args(&["a.example.com", "65536"])).is_err());
    }

    #[test]
    fn rejects_hostname_with_leading_hyphen_label() {
        // Arrange / Act / Assert
        assert!(!is_rfc1123_hostname("-bad.example.com"));
        assert!(!is_rfc1123_hostname("bad-.example.com"));
        assert!(!is_rfc1123_hostname("a..b"));
        assert!(is_rfc1123_hostname("a-b.example.com."));
    }

    #[test]
    fn parses_only_tun_or_utun_devices() {
        // Arrange / Act / Assert
        assert!(parse_dev(ctx(), &args(&["tun"])).is_ok());
        assert!(parse_dev(ctx(), &args(&["utun3"])).is_ok());
        assert!(parse_dev(ctx(), &args(&["tap0"])).is_err());
        assert!(parse_dev(ctx(), &args(&["tunX"])).is_err());
    }

    #[test]
    fn parses_colon_hex_peer_fingerprint_as_scalar() {
        // Arrange / Act
        let got = parse_peer_fingerprint(ctx(), &args(&["aa:bb:cc:dd"])).unwrap();

        // Assert
        assert_eq!(got, "AA:BB:CC:DD");
        assert!(parse_peer_fingerprint(ctx(), &args(&["not-a-fingerprint"])).is_err());
    }

    #[test]
    fn rejects_proxy_authfile_path() {
        // Arrange / Act
        let err = parse_proxy(ctx(), &args(&["proxy.example.com", "8080", "/etc/creds"]));

        // Assert
        assert!(err.is_err());
        assert!(parse_proxy(ctx(), &args(&["proxy.example.com", "8080", "auto"])).is_ok());
    }
}
