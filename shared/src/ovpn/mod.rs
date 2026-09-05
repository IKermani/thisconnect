// SPDX-License-Identifier: GPL-3.0-or-later

//! `.ovpn` import: lex, validate against an allowlist, and re-emit a canonical config.
//!
//! An imported profile is untrusted input that ends up in front of a privileged process, so the
//! only thing that ever reaches openvpn is what this module understood well enough to rebuild.

pub mod args;
pub mod directive;
pub mod error;
pub mod lexer;
pub mod profile;

pub mod summary;

pub use error::ValidationError;
pub use profile::{
    ConnectionBlock, DhcpOption, EmittedDirective, InlineMaterial, Profile, Remote, RemoteHost,
    RouteDirective, StaticChallenge, TransportProto,
};
pub use summary::{canonical_digest, summarise};

use directive::{classify, Classified, Scope};
use lexer::{Item, RawBlock};
use profile::ProfileParts;

/// Caps. A profile is a small text file; anything larger is either a mistake or an attempt to
/// exhaust memory in a privileged process.
pub const MAX_FILE_BYTES: usize = 256 * 1024;
pub const MAX_DIRECTIVES: usize = 256;
pub const MAX_LINE_BYTES: usize = 4096;
pub const MAX_INLINE_BYTES: usize = 128 * 1024;
pub const MAX_INLINE_BLOCKS: usize = 16;
pub const MAX_ARGS: usize = 16;

const CONNECTION_TAG: &str = "connection";

/// Parse and validate a profile, or reject it naming the offending line.
pub fn parse_profile(input: &str) -> Result<Profile, ValidationError> {
    if input.len() > MAX_FILE_BYTES {
        return Err(ValidationError::FileTooLarge {
            size: input.len(),
            max: MAX_FILE_BYTES,
        });
    }

    let mut parts = empty_parts();
    let mut directive_count = 0usize;

    for item in lexer::lex(input, 1)? {
        match item {
            Item::Directive(raw) => {
                directive_count += 1;
                if directive_count > MAX_DIRECTIVES {
                    return Err(ValidationError::TooManyDirectives {
                        max: MAX_DIRECTIVES,
                    });
                }
                absorb(&mut parts, classify(&raw, Scope::TopLevel)?);
            }
            Item::Block(block) if block.tag == CONNECTION_TAG => {
                let connection = parse_connection(&block, &mut directive_count)?;
                parts.connections.push(connection);
            }
            Item::Block(block) => {
                if !directive::is_inline_material(&block.tag) {
                    return Err(ValidationError::ForbiddenInlineTag {
                        line: block.line,
                        tag: block.tag,
                    });
                }
                if parts.inline.iter().any(|m| m.tag == block.tag) {
                    return Err(ValidationError::DuplicateInlineTag {
                        line: block.line,
                        tag: block.tag,
                    });
                }
                parts.inline.push(InlineMaterial {
                    tag: block.tag,
                    body: block.body,
                });
            }
        }
    }

    if directive_count == 0 && parts.inline.is_empty() {
        return Err(ValidationError::EmptyProfile);
    }
    let has_remote =
        !parts.remotes.is_empty() || parts.connections.iter().any(|c| !c.remotes.is_empty());
    if !has_remote {
        return Err(ValidationError::MissingRemote);
    }
    Ok(Profile::from_parts(parts))
}

fn empty_parts() -> ProfileParts {
    ProfileParts {
        directives: Vec::new(),
        connections: Vec::new(),
        inline: Vec::new(),
        remotes: Vec::new(),
        routes: Vec::new(),
        redirect_gateway: Vec::new(),
        dhcp_options: Vec::new(),
        needs_auth_user_pass: false,
        static_challenge: None,
    }
}

/// Route the classifier's verdict into the profile. `route`, `redirect-gateway` and `dhcp-option`
/// land in retained fields only: emitting them buys nothing, and `dhcp-option DNS` is exactly what
/// feeds openvpn's root dns-updown path.
fn absorb(parts: &mut ProfileParts, classified: Classified) {
    match classified {
        Classified::Emit(directive) => parts.directives.push(directive),
        Classified::Remote(remote) => {
            parts.directives.push(remote.to_directive());
            parts.remotes.push(remote);
        }
        Classified::AuthUserPass => {
            parts.needs_auth_user_pass = true;
            parts
                .directives
                .push(EmittedDirective::bare("auth-user-pass"));
        }
        Classified::StaticChallenge(challenge) => {
            parts.directives.push(challenge.to_directive());
            parts.static_challenge = Some(challenge);
        }
        Classified::Route(route) => parts.routes.push(route),
        Classified::RedirectGateway(redirect) => parts.redirect_gateway.push(redirect),
        Classified::DhcpOption(option) => parts.dhcp_options.push(option),
        Classified::Ignored => {}
    }
}

fn parse_connection(
    block: &RawBlock,
    directive_count: &mut usize,
) -> Result<ConnectionBlock, ValidationError> {
    let mut directives = Vec::new();
    let mut remotes = Vec::new();

    for item in lexer::lex(&block.body, block.line + 1)? {
        let raw = match item {
            Item::Directive(raw) => raw,
            Item::Block(inner) => {
                return Err(ValidationError::NestedInlineBlock {
                    line: inner.line,
                    tag: inner.tag,
                })
            }
        };
        *directive_count += 1;
        if *directive_count > MAX_DIRECTIVES {
            return Err(ValidationError::TooManyDirectives {
                max: MAX_DIRECTIVES,
            });
        }
        match classify(&raw, Scope::Connection)? {
            Classified::Emit(directive) => directives.push(directive),
            Classified::Remote(remote) => {
                directives.push(remote.to_directive());
                remotes.push(remote);
            }
            _ => {
                return Err(ValidationError::ForbiddenDirective {
                    line: raw.line,
                    directive: raw.name,
                    reason: "not valid inside a <connection> block".into(),
                })
            }
        }
    }
    Ok(ConnectionBlock {
        directives,
        remotes,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    const REAL_WORLD: &str = include_str!("../../../testdata/realworld.ovpn");
    const HOSTILE: &str = include_str!("../../../testdata/hostile.ovpn");

    const MINIMAL: &str = "client\ndev tun\nremote vpn.example.com 1194 udp\n";

    fn parse_minimal_plus(extra: &str) -> Result<Profile, ValidationError> {
        parse_profile(&format!("{MINIMAL}{extra}\n"))
    }

    #[test]
    fn accepts_a_realistic_real_world_profile() {
        // Arrange / Act
        let profile = parse_profile(REAL_WORLD).unwrap();

        // Assert
        assert_eq!(profile.remotes().len(), 2);
        assert_eq!(profile.connections().len(), 1);
        assert!(profile.needs_auth_user_pass());
        assert!(profile.static_challenge().is_some());
        let tags: Vec<&str> = profile.inline().iter().map(|m| m.tag.as_str()).collect();
        assert_eq!(tags, vec!["ca", "cert", "key", "tls-auth"]);
    }

    #[test]
    fn retains_route_and_dhcp_option_without_emitting_them() {
        // Arrange
        let profile = parse_profile(REAL_WORLD).unwrap();

        // Act
        let body = profile.to_canonical_config();

        // Assert
        assert_eq!(profile.routes().len(), 1);
        assert_eq!(profile.redirect_gateway().len(), 1);
        assert_eq!(profile.dhcp_dns_servers(), vec!["10.20.0.1"]);
        assert!(!body.contains("route "));
        assert!(!body.contains("redirect-gateway"));
        assert!(!body.contains("dhcp-option"));
    }

    #[test]
    fn canonical_config_keeps_inline_material_and_clamped_verb() {
        // Arrange
        let profile = parse_profile(REAL_WORLD).unwrap();

        // Act
        let body = profile.to_canonical_config();

        // Assert
        assert!(body.contains("<ca>\n-----BEGIN CERTIFICATE-----"));
        assert!(body.contains("</tls-auth>\n"));
        assert!(body.contains("\nverb 4\n"));
        assert!(!body.contains("verb 5"));
        assert!(body.contains("key-direction 1"));
        assert!(body.contains("<connection>\nremote vpn2.example.com 443 tcp\n"));
    }

    #[test]
    fn canonical_config_emits_nothing_that_contradicts_daemon_flags() {
        // Arrange
        let profile = parse_profile(REAL_WORLD).unwrap();

        // Act
        let body = profile.to_canonical_config();

        // Assert
        for forbidden in [
            "management",
            "script-security",
            "dns-updown",
            "auth-retry",
            "pull-filter",
            "route-noexec",
        ] {
            assert!(
                !body.contains(forbidden),
                "canonical config leaked {forbidden}"
            );
        }
    }

    #[test]
    fn rejects_inline_auth_user_pass_block_bypass() {
        // Arrange / Act
        let err = parse_profile(HOSTILE).unwrap_err();

        // Assert
        assert_eq!(
            err,
            ValidationError::ForbiddenInlineTag {
                line: 5,
                tag: "auth-user-pass".into()
            }
        );
    }

    #[test]
    fn rejects_every_known_inline_tag_bypass() {
        // Arrange
        let tags = [
            "auth-user-pass",
            "http-proxy-user-pass",
            "auth-token-secret-file",
            "plugin",
            "up",
        ];

        // Act / Assert
        for tag in tags {
            let input = format!("{MINIMAL}<{tag}>\npayload\n</{tag}>\n");
            let err = parse_profile(&input).unwrap_err();
            assert!(
                matches!(err, ValidationError::ForbiddenInlineTag { .. }),
                "<{tag}> was not rejected"
            );
        }
    }

    #[test]
    fn rejects_duplicate_inline_material() {
        // Arrange
        let input = format!("{MINIMAL}<ca>\nA\n</ca>\n<ca>\nB\n</ca>\n");

        // Act
        let err = parse_profile(&input).unwrap_err();

        // Assert
        assert!(matches!(err, ValidationError::DuplicateInlineTag { .. }));
    }

    #[test]
    fn rejects_profile_without_a_remote() {
        // Arrange / Act
        let err = parse_profile("client\ndev tun\n").unwrap_err();

        // Assert
        assert_eq!(err, ValidationError::MissingRemote);
    }

    #[test]
    fn rejects_empty_profile() {
        // Arrange / Act / Assert
        assert_eq!(
            parse_profile("# nothing\n").unwrap_err(),
            ValidationError::EmptyProfile
        );
    }

    #[test]
    fn rejects_file_over_the_size_cap() {
        // Arrange
        let input = "#".repeat(MAX_FILE_BYTES + 1);

        // Act / Assert
        assert!(matches!(
            parse_profile(&input).unwrap_err(),
            ValidationError::FileTooLarge { .. }
        ));
    }

    #[test]
    fn rejects_profile_over_the_directive_cap() {
        // Arrange
        let input = format!("{}{}", MINIMAL, "nobind\n".repeat(MAX_DIRECTIVES));

        // Act / Assert
        assert!(matches!(
            parse_profile(&input).unwrap_err(),
            ValidationError::TooManyDirectives { .. }
        ));
    }

    #[test]
    fn rejects_argument_injection_attempts() {
        // Arrange
        let attempts = [
            "remote vpn.example.com$(id) 1194",
            "remote `hostname` 1194",
            "verify-x509-name ../../../etc/shadow",
            "auth \"SHA256;reboot\"",
            "auth SHA256&&id",
            "dev tun|nc",
        ];

        // Act / Assert
        for attempt in attempts {
            let err = parse_minimal_plus(attempt).unwrap_err();
            assert!(
                matches!(
                    err,
                    ValidationError::UnsafeArgument { .. }
                        | ValidationError::InvalidArgument { .. }
                ),
                "`{attempt}` was not rejected"
            );
        }
    }

    #[test]
    fn reports_the_offending_line_number() {
        // Arrange
        let input = format!("{MINIMAL}nobind\nplugin /tmp/evil.so\n");

        // Act
        let err = parse_profile(&input).unwrap_err();

        // Assert
        assert_eq!(err.line(), Some(5));
        assert_eq!(err.directive(), Some("plugin"));
    }

    #[test]
    fn rejects_inline_block_inside_a_connection_block() {
        // Arrange
        let input = format!("{MINIMAL}<connection>\n<ca>\nX\n</ca>\n</connection>\n");

        // Act
        let err = parse_profile(&input).unwrap_err();

        // Assert
        assert!(matches!(err, ValidationError::NestedInlineBlock { .. }));
    }

    #[test]
    fn accepts_a_connection_only_profile() {
        // Arrange
        let input = "client\ndev tun\n<connection>\nremote a.example.com 443 tcp\n</connection>\n";

        // Act
        let profile = parse_profile(input).unwrap();

        // Assert
        assert!(profile.remotes().is_empty());
        assert_eq!(profile.connections()[0].remotes.len(), 1);
    }

    #[test]
    fn rejects_unknown_directive_from_a_newer_openvpn() {
        // Arrange / Act
        let err = parse_minimal_plus("some-future-directive on").unwrap_err();

        // Assert
        assert!(matches!(err, ValidationError::UnknownDirective { .. }));
    }
}
