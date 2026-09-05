// SPDX-License-Identifier: GPL-3.0-or-later

//! The typed profile and its canonical config emission.
//!
//! Emission is deliberately not a round-trip of the input: it is a re-serialisation of what the
//! validator understood. Anything the validator did not understand never reaches openvpn.

use std::fmt;
use std::net::IpAddr;

use zeroize::Zeroizing;

/// One validated directive, ready to be written out verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedDirective {
    pub name: String,
    pub args: Vec<String>,
}

impl EmittedDirective {
    pub fn new(name: &str, args: Vec<String>) -> Self {
        Self {
            name: name.to_owned(),
            args,
        }
    }

    pub fn bare(name: &str) -> Self {
        Self::new(name, Vec::new())
    }
}

impl fmt::Display for EmittedDirective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        for arg in &self.args {
            // Arguments passed validation, so they contain no quote or backslash to escape.
            if arg.is_empty() || arg.contains(' ') {
                write!(f, " \"{arg}\"")?;
            } else {
                write!(f, " {arg}")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProto {
    Udp,
    Tcp,
}

impl fmt::Display for TransportProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteHost {
    Name(String),
    Ip(IpAddr),
}

impl fmt::Display for RemoteHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(n) => f.write_str(n),
            Self::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub host: RemoteHost,
    pub port: u16,
    pub proto: Option<TransportProto>,
}

impl Remote {
    pub fn to_directive(&self) -> EmittedDirective {
        let mut args = vec![self.host.to_string(), self.port.to_string()];
        if let Some(proto) = self.proto {
            args.push(proto.to_string());
        }
        EmittedDirective::new("remote", args)
    }
}

/// A pushed-route-equivalent from the profile. Retained for the proxy's egress logic and
/// deliberately never emitted: the daemon installs routing policy itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDirective {
    pub network: String,
    pub netmask: Option<String>,
    pub gateway: Option<String>,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectGateway {
    pub flags: Vec<String>,
}

/// `dhcp-option DNS 10.8.0.1` and friends. Retained because the proxy's resolver needs it;
/// never emitted, because emitting it feeds openvpn's root dns-updown path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpOption {
    pub kind: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticChallenge {
    pub prompt: String,
    pub echo: bool,
    pub format_flags: Option<u8>,
}

impl StaticChallenge {
    pub fn to_directive(&self) -> EmittedDirective {
        let mut args = vec![
            self.prompt.clone(),
            if self.echo { "1".into() } else { "0".into() },
        ];
        if let Some(flags) = self.format_flags {
            args.push(flags.to_string());
        }
        EmittedDirective::new("static-challenge", args)
    }
}

/// A `<connection>` block: an alternate server entry with its own transport settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionBlock {
    pub directives: Vec<EmittedDirective>,
    pub remotes: Vec<Remote>,
}

/// Inline crypto material. The body is secret in the `key`/`tls-crypt` cases, so it is zeroized
/// on drop and never rendered by `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct InlineMaterial {
    pub tag: String,
    pub body: Zeroizing<String>,
}

impl fmt::Debug for InlineMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InlineMaterial")
            .field("tag", &self.tag)
            .field("body", &"<redacted>")
            .finish()
    }
}

/// A validated profile. Fields are read-only by construction: build a new `Profile` rather than
/// mutating one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Profile {
    directives: Vec<EmittedDirective>,
    connections: Vec<ConnectionBlock>,
    inline: Vec<InlineMaterial>,
    remotes: Vec<Remote>,
    routes: Vec<RouteDirective>,
    redirect_gateway: Vec<RedirectGateway>,
    dhcp_options: Vec<DhcpOption>,
    needs_auth_user_pass: bool,
    static_challenge: Option<StaticChallenge>,
}

/// Everything the parser collected, moved into a `Profile` in one step.
pub struct ProfileParts {
    pub directives: Vec<EmittedDirective>,
    pub connections: Vec<ConnectionBlock>,
    pub inline: Vec<InlineMaterial>,
    pub remotes: Vec<Remote>,
    pub routes: Vec<RouteDirective>,
    pub redirect_gateway: Vec<RedirectGateway>,
    pub dhcp_options: Vec<DhcpOption>,
    pub needs_auth_user_pass: bool,
    pub static_challenge: Option<StaticChallenge>,
}

impl Profile {
    pub fn from_parts(parts: ProfileParts) -> Self {
        Self {
            directives: parts.directives,
            connections: parts.connections,
            inline: parts.inline,
            remotes: parts.remotes,
            routes: parts.routes,
            redirect_gateway: parts.redirect_gateway,
            dhcp_options: parts.dhcp_options,
            needs_auth_user_pass: parts.needs_auth_user_pass,
            static_challenge: parts.static_challenge,
        }
    }

    pub fn directives(&self) -> &[EmittedDirective] {
        &self.directives
    }
    pub fn connections(&self) -> &[ConnectionBlock] {
        &self.connections
    }
    pub fn inline(&self) -> &[InlineMaterial] {
        &self.inline
    }
    pub fn remotes(&self) -> &[Remote] {
        &self.remotes
    }
    pub fn routes(&self) -> &[RouteDirective] {
        &self.routes
    }
    pub fn redirect_gateway(&self) -> &[RedirectGateway] {
        &self.redirect_gateway
    }
    pub fn dhcp_options(&self) -> &[DhcpOption] {
        &self.dhcp_options
    }
    pub fn needs_auth_user_pass(&self) -> bool {
        self.needs_auth_user_pass
    }
    pub fn static_challenge(&self) -> Option<&StaticChallenge> {
        self.static_challenge.as_ref()
    }

    /// Every DNS server named by a retained `dhcp-option DNS`/`DNS6`, for the tunnel-pinned
    /// resolver's bootstrap set.
    pub fn dhcp_dns_servers(&self) -> Vec<&str> {
        self.dhcp_options
            .iter()
            .filter(|o| o.kind == "DNS" || o.kind == "DNS6")
            .filter_map(|o| o.values.first().map(String::as_str))
            .collect()
    }

    /// The canonical config body. Daemon-injected flags are command-line arguments and are not
    /// part of this body; nothing emitted here may contradict them.
    pub fn to_canonical_config(&self) -> Zeroizing<String> {
        let mut out = String::new();
        for directive in &self.directives {
            out.push_str(&directive.to_string());
            out.push('\n');
        }
        for connection in &self.connections {
            out.push_str("<connection>\n");
            for directive in &connection.directives {
                out.push_str(&directive.to_string());
                out.push('\n');
            }
            out.push_str("</connection>\n");
        }
        for material in &self.inline {
            out.push_str(&format!("<{}>\n", material.tag));
            out.push_str(&material.body);
            if !material.body.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&format!("</{}>\n", material.tag));
        }
        Zeroizing::new(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn quotes_only_arguments_containing_spaces() {
        // Arrange
        let plain = EmittedDirective::new("verb", vec!["3".into()]);
        let spaced = EmittedDirective::new("static-challenge", vec!["Enter OTP".into()]);

        // Act / Assert
        assert_eq!(plain.to_string(), "verb 3");
        assert_eq!(spaced.to_string(), "static-challenge \"Enter OTP\"");
    }

    #[test]
    fn emits_bare_directive_without_trailing_space() {
        // Arrange / Act / Assert
        assert_eq!(EmittedDirective::bare("client").to_string(), "client");
    }

    #[test]
    fn renders_remote_with_optional_protocol() {
        // Arrange
        let remote = Remote {
            host: RemoteHost::Name("vpn.example.com".into()),
            port: 1194,
            proto: Some(TransportProto::Udp),
        };

        // Act / Assert
        assert_eq!(
            remote.to_directive().to_string(),
            "remote vpn.example.com 1194 udp"
        );
    }

    #[test]
    fn canonical_config_emits_connection_and_inline_blocks() {
        // Arrange
        let profile = Profile::from_parts(ProfileParts {
            directives: vec![EmittedDirective::bare("client")],
            connections: vec![ConnectionBlock {
                directives: vec![EmittedDirective::new(
                    "remote",
                    vec!["a.example.com".into(), "443".into()],
                )],
                remotes: Vec::new(),
            }],
            inline: vec![InlineMaterial {
                tag: "ca".into(),
                body: Zeroizing::new("PEM\n".into()),
            }],
            remotes: Vec::new(),
            routes: Vec::new(),
            redirect_gateway: Vec::new(),
            dhcp_options: Vec::new(),
            needs_auth_user_pass: false,
            static_challenge: None,
        });

        // Act
        let body = profile.to_canonical_config();

        // Assert
        assert_eq!(
            body.as_str(),
            "client\n<connection>\nremote a.example.com 443\n</connection>\n<ca>\nPEM\n</ca>\n"
        );
    }

    #[test]
    fn debug_of_inline_material_does_not_render_body() {
        // Arrange
        let material = InlineMaterial {
            tag: "key".into(),
            body: Zeroizing::new("PRIVATE-KEY-BYTES".into()),
        };

        // Act / Assert
        assert!(!format!("{material:?}").contains("PRIVATE-KEY-BYTES"));
    }

    #[test]
    fn collects_dns_servers_from_retained_dhcp_options() {
        // Arrange
        let profile = Profile::from_parts(ProfileParts {
            directives: Vec::new(),
            connections: Vec::new(),
            inline: Vec::new(),
            remotes: Vec::new(),
            routes: Vec::new(),
            redirect_gateway: Vec::new(),
            dhcp_options: vec![
                DhcpOption {
                    kind: "DNS".into(),
                    values: vec!["10.8.0.1".into()],
                },
                DhcpOption {
                    kind: "DOMAIN".into(),
                    values: vec!["corp.example".into()],
                },
            ],
            needs_auth_user_pass: false,
            static_challenge: None,
        });

        // Act / Assert
        assert_eq!(profile.dhcp_dns_servers(), vec!["10.8.0.1"]);
    }
}
