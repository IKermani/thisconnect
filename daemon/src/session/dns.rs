// SPDX-License-Identifier: GPL-3.0-or-later

//! Tunnel DNS capture from openvpn's `PUSH_REPLY` (SPEC.md §5.4 D1).
//!
//! The server's resolver is never handed to us over the management protocol as a
//! typed event; it arrives only inside the `>LOG:` line openvpn prints when it
//! accepts the push. This module turns that line into values. It is pure: no I/O,
//! no globals, one `&str` in.
//!
//! Two things make this module possible and one makes it dangerous:
//!
//! * `--route-nopull` is banned (SPEC.md §4.2). That flag suppresses pushed
//!   *DNS* as well as pushed routes, so with it there is nothing to capture and
//!   leak-free proxy DNS cannot exist at all. Anyone "optimising" the flag back
//!   in deletes this feature. `--pull-filter ignore route` plus `--route-noexec`
//!   is the substitute, and it leaves `dhcp-option DNS` intact.
//! * openvpn's `sanitize_control_message()` scrubs auth tokens from the logged
//!   control message but does *not* touch dhcp-options, so the resolver really
//!   does arrive here intact. The same line may still carry other server-chosen
//!   material, so the raw text must never be logged or persisted — extract, then
//!   drop it.
//! * The wording of that log line is not a stability contract. So a push that
//!   yields no usable nameserver is a first-class, fail-closed value
//!   ([`DnsCapture::Missing`]), never an empty `Vec` that a caller can mistake
//!   for success, and the parser is pinned against a corpus of real push lines
//!   in this file's tests.

use std::net::{IpAddr, Ipv4Addr};

/// The management reader already refuses inbound lines longer than this; a
/// "control message" bigger than that is not something we walk looking for
/// addresses.
const MAX_PUSH_REPLY_BYTES: usize = 8192;

const CONTROL_MESSAGE_MARKER: &str = "Received control message:";
const PUSH_REPLY_KIND: &str = "PUSH_REPLY";

const MAX_DOMAIN_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;

/// The tunnel's `ifconfig` line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ifconfig {
    pub local: Ipv4Addr,
    /// Under `topology subnet` — the common modern case — the server sends a
    /// *netmask* in this position rather than a peer address. Callers must not
    /// treat it as something reachable.
    pub peer_or_netmask: Ipv4Addr,
}

/// Everything §5.4 and §5.5 need out of one accepted push.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PushReply {
    nameservers: Vec<IpAddr>,
    search_domains: Vec<String>,
    ifconfig: Option<Ifconfig>,
    has_ipv6: bool,
    dropped_addresses: usize,
    dropped_domains: usize,
}

impl PushReply {
    /// Parses the text of a `>LOG:` event. Returns `None` when the line is not an
    /// accepted `PUSH_REPLY`, which is the overwhelmingly common case: the caller
    /// feeds every log event through here.
    pub fn from_log_text(text: &str) -> Option<Self> {
        let payload = push_reply_payload(text)?;
        let parsed = payload
            .split(',')
            .map(str::trim)
            .fold(Accumulator::default(), Accumulator::absorb);
        Some(parsed.finish())
    }

    pub fn nameservers(&self) -> &[IpAddr] {
        &self.nameservers
    }

    pub fn search_domains(&self) -> &[String] {
        &self.search_domains
    }

    pub fn ifconfig(&self) -> Option<Ifconfig> {
        self.ifconfig
    }

    /// SPEC.md §5.5: a v4-only tunnel must reject AAAA and `ATYP=0x04`.
    pub fn tunnel_has_v6(&self) -> bool {
        self.has_ipv6
    }

    /// Addresses that were present but did not parse. Non-zero means the server,
    /// or our parse of it, is off — worth surfacing even when a usable server
    /// also arrived.
    pub fn dropped_addresses(&self) -> usize {
        self.dropped_addresses
    }

    pub fn dropped_domains(&self) -> usize {
        self.dropped_domains
    }

    /// The fail-closed verdict. Nameservers of a family the tunnel cannot carry
    /// are excluded here rather than handed to a resolver that would fail every
    /// query against them.
    pub fn capture(&self) -> DnsCapture {
        let usable: Vec<IpAddr> = self
            .nameservers
            .iter()
            .copied()
            .filter(|server| self.has_ipv6 || server.is_ipv4())
            .collect();

        if usable.is_empty() {
            return DnsCapture::Missing(self.missing_reason());
        }

        DnsCapture::Captured(TunnelDns {
            nameservers: usable,
            search_domains: self.search_domains.clone(),
            tunnel_has_v6: self.has_ipv6,
        })
    }

    fn missing_reason(&self) -> MissingDns {
        match (self.nameservers.is_empty(), self.dropped_addresses) {
            (false, _) => MissingDns::UnreachableFamily {
                discarded: self.nameservers.len(),
            },
            (true, 0) => MissingDns::NoDnsOptions,
            (true, dropped) => MissingDns::AllAddressesMalformed { dropped },
        }
    }
}

/// What the tunnel's own resolver turned out to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelDns {
    pub nameservers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub tunnel_has_v6: bool,
}

/// Deliberately not `Vec<IpAddr>`: "no DNS captured" must be impossible to read
/// as success. A `Missing` obliges the caller to use the configured
/// `tunnel_fallback_dns` *through the tun* and to say so in the UI
/// (SPEC.md §5.4 D4). It never licenses the system resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsCapture {
    Captured(TunnelDns),
    Missing(MissingDns),
}

impl DnsCapture {
    /// The tunnel came up and no `PUSH_REPLY` was ever seen.
    pub fn none_received() -> Self {
        DnsCapture::Missing(MissingDns::NoPushReply)
    }

    pub fn captured(&self) -> Option<&TunnelDns> {
        match self {
            DnsCapture::Captured(dns) => Some(dns),
            DnsCapture::Missing(_) => None,
        }
    }
}

/// User-facing, and safe to log: none of these variants can contain server text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MissingDns {
    #[error("the server never sent a PUSH_REPLY")]
    NoPushReply,

    #[error("the tunnel pushed no DNS server")]
    NoDnsOptions,

    #[error("all {dropped} pushed DNS addresses were malformed")]
    AllAddressesMalformed { dropped: usize },

    #[error("the tunnel pushed only {discarded} DNS servers of a family it cannot carry")]
    UnreachableFamily { discarded: usize },
}

fn push_reply_payload(text: &str) -> Option<&str> {
    if text.len() > MAX_PUSH_REPLY_BYTES {
        return None;
    }
    let after_marker = text.split_once(CONTROL_MESSAGE_MARKER)?.1;
    let after_kind = after_marker.split_once(PUSH_REPLY_KIND)?.1;
    let body = after_kind.strip_prefix(',').unwrap_or(after_kind);
    Some(body.trim().trim_end_matches(['\'', '"']))
}

/// Fold state. `in_dns_address_list` exists because the pushed option list is
/// comma separated *and* openvpn 2.6's `dns server N address a,b` separates its
/// own addresses with commas, so one logical option can arrive as several
/// fragments.
#[derive(Clone, Debug, Default)]
struct Accumulator {
    reply: PushReply,
    in_dns_address_list: bool,
}

impl Accumulator {
    fn finish(self) -> PushReply {
        self.reply
    }

    fn absorb(self, option: &str) -> Self {
        let mut tokens = option.split_whitespace();
        let Some(keyword) = tokens.next() else {
            return self.without_continuation();
        };
        match keyword.to_ascii_lowercase().as_str() {
            "dhcp-option" => self.without_continuation().absorb_dhcp_option(tokens),
            "dns" => self.without_continuation().absorb_dns(tokens),
            "ifconfig" => self.without_continuation().absorb_ifconfig(tokens),
            // SPEC.md §5.5: either of these proves the tunnel carries v6.
            "ifconfig-ipv6" | "route-ipv6" | "tun-ipv6" => self.without_continuation().with_ipv6(),
            _ => self.absorb_address_continuation(option),
        }
    }

    fn absorb_dhcp_option<'a>(self, mut tokens: impl Iterator<Item = &'a str>) -> Self {
        let kind = tokens.next().unwrap_or_default().to_ascii_uppercase();
        match kind.as_str() {
            "DNS" | "DNS6" => match tokens.next() {
                Some(value) => self.with_address(value),
                None => self.with_dropped_address(),
            },
            "DOMAIN" | "ADOMAIN" | "DOMAIN-SEARCH" => match tokens.next() {
                Some(value) => self.with_domain(value),
                None => self.with_dropped_domain(),
            },
            // WINS, NBDD, NTP and friends are not ours to interpret.
            _ => self,
        }
    }

    /// The openvpn 2.6+ form: `dns server <priority> address <ip> [<ip>…]` and
    /// `dns search-domains <domain> […]`.
    fn absorb_dns<'a>(self, mut tokens: impl Iterator<Item = &'a str>) -> Self {
        match tokens
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "server" => {
                let _priority = tokens.next();
                match tokens
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "address" => tokens
                        .fold(self, Accumulator::with_address)
                        .expecting_more_addresses(),
                    // resolve-domains, dnssec, transport: not a resolver address.
                    _ => self,
                }
            }
            "search-domains" => tokens.fold(self, Accumulator::with_domain),
            _ => self,
        }
    }

    fn absorb_ifconfig<'a>(self, mut tokens: impl Iterator<Item = &'a str>) -> Self {
        let local = tokens
            .next()
            .and_then(|value| value.parse::<Ipv4Addr>().ok());
        let peer = tokens
            .next()
            .and_then(|value| value.parse::<Ipv4Addr>().ok());
        match (local, peer) {
            (Some(local), Some(peer_or_netmask)) => self.with_ifconfig(Ifconfig {
                local,
                peer_or_netmask,
            }),
            _ => self.with_dropped_address(),
        }
    }

    /// A fragment of a comma-separated `dns server … address` list. Anything that
    /// is not wholly addresses ends the list rather than being counted as junk:
    /// it is simply the next pushed option.
    fn absorb_address_continuation(self, option: &str) -> Self {
        if !self.in_dns_address_list {
            return self.without_continuation();
        }
        let addresses: Option<Vec<IpAddr>> = option.split_whitespace().map(parse_address).collect();
        match addresses {
            Some(addresses) if !addresses.is_empty() => addresses
                .into_iter()
                .fold(self, Accumulator::with_parsed_address),
            _ => self.without_continuation(),
        }
    }

    fn with_address(self, value: &str) -> Self {
        match parse_address(value) {
            Some(address) => self.with_parsed_address(address),
            None => self.with_dropped_address(),
        }
    }

    fn with_parsed_address(self, address: IpAddr) -> Self {
        if self.reply.nameservers.contains(&address) {
            return self;
        }
        let nameservers = [self.reply.nameservers.clone(), vec![address]].concat();
        Self {
            reply: PushReply {
                nameservers,
                ..self.reply
            },
            ..self
        }
    }

    fn with_domain(self, value: &str) -> Self {
        let Some(domain) = normalise_domain(value) else {
            return self.with_dropped_domain();
        };
        if self.reply.search_domains.contains(&domain) {
            return self;
        }
        let search_domains = [self.reply.search_domains.clone(), vec![domain]].concat();
        Self {
            reply: PushReply {
                search_domains,
                ..self.reply
            },
            ..self
        }
    }

    fn with_ifconfig(self, ifconfig: Ifconfig) -> Self {
        Self {
            reply: PushReply {
                ifconfig: Some(ifconfig),
                ..self.reply
            },
            ..self
        }
    }

    fn with_ipv6(self) -> Self {
        Self {
            reply: PushReply {
                has_ipv6: true,
                ..self.reply
            },
            ..self
        }
    }

    fn with_dropped_address(self) -> Self {
        let dropped_addresses = self.reply.dropped_addresses.saturating_add(1);
        Self {
            reply: PushReply {
                dropped_addresses,
                ..self.reply
            },
            ..self
        }
    }

    fn with_dropped_domain(self) -> Self {
        let dropped_domains = self.reply.dropped_domains.saturating_add(1);
        Self {
            reply: PushReply {
                dropped_domains,
                ..self.reply
            },
            ..self
        }
    }

    fn expecting_more_addresses(self) -> Self {
        Self {
            in_dns_address_list: true,
            ..self
        }
    }

    fn without_continuation(self) -> Self {
        Self {
            in_dns_address_list: false,
            ..self
        }
    }
}

/// A bare literal, or openvpn 2.6's `addr[:port]` / `[v6]:port` server form.
/// Anything else is dropped; a hostname here would be a name we cannot resolve
/// without the very resolver we are trying to find.
fn parse_address(token: &str) -> Option<IpAddr> {
    if let Ok(address) = token.parse::<IpAddr>() {
        return Some(address);
    }
    let head = match token.strip_prefix('[') {
        Some(rest) => rest.split_once(']')?.0,
        None => token.rsplit_once(':')?.0,
    };
    head.parse::<IpAddr>().ok()
}

fn normalise_domain(value: &str) -> Option<String> {
    let trimmed = value.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > MAX_DOMAIN_BYTES {
        return None;
    }
    let labels_are_sane = trimmed.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_BYTES
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    });
    labels_are_sane.then(|| trimmed.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::net::Ipv6Addr;

    /// Real shapes seen from openvpn 2.6/2.7 servers. The parse is a string
    /// dependency on wording that is not a contract, so these are the pins.
    const PLAIN_V4: &str = "PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1 bypass-dhcp,dhcp-option DNS 10.8.0.1,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 120,ifconfig 10.8.0.6 255.255.255.0,peer-id 3,cipher AES-256-GCM'";

    const DUAL_STACK: &str = "PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DNS6 fd00:abcd::1,tun-ipv6,route-ipv6 ::/0,ifconfig-ipv6 fd00:abcd::1002/64 fd00:abcd::1,ifconfig 10.8.0.6 10.8.0.5'";

    const DNS_SERVER_FORM: &str = "PUSH: Received control message: 'PUSH_REPLY,dns server 1 address 192.168.10.1 fd00:10::1,dns server 1 resolve-domains corp.example,ifconfig-ipv6 fd00:27::6/64 fd00:27::1,ifconfig 172.27.232.6 172.27.232.5'";

    const DNS_SERVER_COMMA_LIST: &str = "PUSH: Received control message: 'PUSH_REPLY,dns server 1 address 9.9.9.9,149.112.112.112,dns search-domains corp.example lab.example,ifconfig 10.9.0.4 10.9.0.3'";

    const NO_DNS: &str = "PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 60,ifconfig 10.8.0.6 255.255.255.0,peer-id 0'";

    const SEARCH_DOMAINS: &str = "PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.10.0.1,dhcp-option DOMAIN example.com,dhcp-option ADOMAIN sub.example.com,dhcp-option DOMAIN-SEARCH corp.example.com,dhcp-option WINS 10.10.0.2,ifconfig 10.10.0.6 10.10.0.5'";

    const TRUNCATED: &str = "PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.8.0.";

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn captures_a_single_pushed_v4_resolver() {
        // Arrange / Act
        let reply = PushReply::from_log_text(PLAIN_V4).expect("a PUSH_REPLY line");

        // Assert
        assert_eq!(reply.nameservers(), [v4(10, 8, 0, 1)]);
        assert!(!reply.tunnel_has_v6());
        assert_eq!(
            reply.ifconfig(),
            Some(Ifconfig {
                local: Ipv4Addr::new(10, 8, 0, 6),
                peer_or_netmask: Ipv4Addr::new(255, 255, 255, 0),
            })
        );
        assert_eq!(reply.dropped_addresses(), 0);
    }

    #[test]
    fn captures_dns6_only_when_the_tunnel_carries_v6() {
        // Arrange / Act
        let reply = PushReply::from_log_text(DUAL_STACK).expect("a PUSH_REPLY line");

        // Assert
        assert!(reply.tunnel_has_v6());
        let dns = reply.capture();
        let captured = dns.captured().expect("both families are usable");
        assert_eq!(
            captured.nameservers,
            [
                v4(10, 8, 0, 1),
                IpAddr::V6("fd00:abcd::1".parse::<Ipv6Addr>().expect("literal"))
            ]
        );
    }

    #[test]
    fn parses_the_openvpn_26_dns_server_address_form() {
        // Arrange / Act
        let reply = PushReply::from_log_text(DNS_SERVER_FORM).expect("a PUSH_REPLY line");

        // Assert
        assert_eq!(
            reply.nameservers(),
            [
                v4(192, 168, 10, 1),
                IpAddr::V6("fd00:10::1".parse::<Ipv6Addr>().expect("literal"))
            ]
        );
        assert!(reply.tunnel_has_v6());
    }

    #[test]
    fn rejoins_a_dns_server_address_list_split_on_commas() {
        // The option separator and the address separator are the same character,
        // so the second address arrives as its own fragment.
        let reply = PushReply::from_log_text(DNS_SERVER_COMMA_LIST).expect("a PUSH_REPLY line");

        assert_eq!(
            reply.nameservers(),
            [v4(9, 9, 9, 9), v4(149, 112, 112, 112)]
        );
        assert_eq!(
            reply.search_domains(),
            ["corp.example".to_owned(), "lab.example".to_owned()]
        );
    }

    #[test]
    fn a_following_option_ends_the_address_list_without_counting_a_drop() {
        let line = "PUSH: Received control message: 'PUSH_REPLY,dns server 1 address 9.9.9.9,peer-id 7,cipher AES-256-GCM'";

        let reply = PushReply::from_log_text(line).expect("a PUSH_REPLY line");

        assert_eq!(reply.nameservers(), [v4(9, 9, 9, 9)]);
        assert_eq!(reply.dropped_addresses(), 0);
    }

    #[test]
    fn a_push_with_no_dns_is_missing_not_empty() {
        // Arrange / Act
        let reply = PushReply::from_log_text(NO_DNS).expect("a PUSH_REPLY line");

        // Assert
        assert_eq!(
            reply.capture(),
            DnsCapture::Missing(MissingDns::NoDnsOptions)
        );
        assert!(reply.capture().captured().is_none());
    }

    #[test]
    fn collects_every_search_domain_form_and_ignores_unrelated_dhcp_options() {
        let reply = PushReply::from_log_text(SEARCH_DOMAINS).expect("a PUSH_REPLY line");

        assert_eq!(
            reply.search_domains(),
            [
                "example.com".to_owned(),
                "sub.example.com".to_owned(),
                "corp.example.com".to_owned()
            ]
        );
        assert_eq!(reply.dropped_domains(), 0);
    }

    #[test]
    fn a_truncated_line_drops_the_partial_address_and_fails_closed() {
        // Arrange / Act
        let reply = PushReply::from_log_text(TRUNCATED).expect("the marker is still present");

        // Assert
        assert!(reply.nameservers().is_empty());
        assert_eq!(reply.dropped_addresses(), 1);
        assert_eq!(
            reply.capture(),
            DnsCapture::Missing(MissingDns::AllAddressesMalformed { dropped: 1 })
        );
    }

    #[test]
    fn a_malformed_address_is_dropped_and_counted_never_passed_through() {
        let line = "PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.0.0.999,dhcp-option DNS dns.evil.example,dhcp-option DNS 10.0.0.1'";

        let reply = PushReply::from_log_text(line).expect("a PUSH_REPLY line");

        assert_eq!(reply.nameservers(), [v4(10, 0, 0, 1)]);
        assert_eq!(reply.dropped_addresses(), 2);
    }

    #[test]
    fn v6_resolvers_on_a_v4_only_tunnel_are_unusable() {
        let line = "PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS6 fd00::1,ifconfig 10.8.0.6 10.8.0.5'";

        let reply = PushReply::from_log_text(line).expect("a PUSH_REPLY line");

        assert!(!reply.tunnel_has_v6());
        assert_eq!(
            reply.capture(),
            DnsCapture::Missing(MissingDns::UnreachableFamily { discarded: 1 })
        );
    }

    #[test]
    fn route_ipv6_alone_proves_v6_capability() {
        let line = "PUSH: Received control message: 'PUSH_REPLY,route-ipv6 2000::/3,dhcp-option DNS 10.8.0.1'";

        let reply = PushReply::from_log_text(line).expect("a PUSH_REPLY line");

        assert!(reply.tunnel_has_v6());
    }

    #[test]
    fn duplicate_servers_and_domains_are_collapsed() {
        let line = "PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN Example.COM,dhcp-option DOMAIN example.com'";

        let reply = PushReply::from_log_text(line).expect("a PUSH_REPLY line");

        assert_eq!(reply.nameservers(), [v4(10, 8, 0, 1)]);
        assert_eq!(reply.search_domains(), ["example.com".to_owned()]);
    }

    #[test]
    fn accepts_an_address_with_a_port_in_the_26_form() {
        let line = "PUSH: Received control message: 'PUSH_REPLY,dns server 1 address 10.0.0.1:5353 [fd00::2]:53,route-ipv6 ::/0'";

        let reply = PushReply::from_log_text(line).expect("a PUSH_REPLY line");

        assert_eq!(
            reply.nameservers(),
            [
                v4(10, 0, 0, 1),
                IpAddr::V6("fd00::2".parse::<Ipv6Addr>().expect("literal"))
            ]
        );
    }

    #[test]
    fn rejects_domains_that_are_not_domains() {
        let line = "PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN corp..example,dhcp-option DOMAIN exämple.com,dhcp-option DOMAIN-SEARCH ok.example'";

        let reply = PushReply::from_log_text(line).expect("a PUSH_REPLY line");

        assert_eq!(reply.search_domains(), ["ok.example".to_owned()]);
        assert_eq!(reply.dropped_domains(), 2);
    }

    #[test]
    fn a_dhcp_option_with_no_value_counts_as_a_drop() {
        let line =
            "PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS,dhcp-option DOMAIN'";

        let reply = PushReply::from_log_text(line).expect("a PUSH_REPLY line");

        assert_eq!(reply.dropped_addresses(), 1);
        assert_eq!(reply.dropped_domains(), 1);
        assert_eq!(
            reply.capture(),
            DnsCapture::Missing(MissingDns::AllAddressesMalformed { dropped: 1 })
        );
    }

    #[test]
    fn ignores_log_lines_that_are_not_a_push_reply() {
        // Arrange
        let unrelated = [
            "PUSH: Received control message: 'AUTH_FAILED,session expired'",
            "PUSH: Received control message: 'RESTART'",
            "OPTIONS IMPORT: dhcp-option DNS 10.8.0.1 imported",
            "",
        ];

        // Act / Assert
        for line in unrelated {
            assert_eq!(PushReply::from_log_text(line), None, "line: {line}");
        }
    }

    #[test]
    fn refuses_an_oversized_control_message() {
        let line = format!(
            "PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.8.0.1{}'",
            ",x".repeat(MAX_PUSH_REPLY_BYTES)
        );

        assert_eq!(PushReply::from_log_text(&line), None);
    }

    #[test]
    fn a_push_reply_with_no_options_yields_no_dns() {
        let line = "PUSH: Received control message: 'PUSH_REPLY'";

        let reply = PushReply::from_log_text(line).expect("a PUSH_REPLY line");

        assert_eq!(
            reply.capture(),
            DnsCapture::Missing(MissingDns::NoDnsOptions)
        );
        assert_eq!(reply.ifconfig(), None);
    }

    #[test]
    fn a_tunnel_that_never_pushed_is_a_missing_capture() {
        assert_eq!(
            DnsCapture::none_received(),
            DnsCapture::Missing(MissingDns::NoPushReply)
        );
        assert!(DnsCapture::none_received().captured().is_none());
    }

    #[test]
    fn a_dhcp_option_type_is_matched_case_insensitively() {
        let line = "PUSH: Received control message: 'PUSH_REPLY,dhcp-option dns 10.8.0.1,dhcp-option Domain example.com'";

        let reply = PushReply::from_log_text(line).expect("a PUSH_REPLY line");

        assert_eq!(reply.nameservers(), [v4(10, 8, 0, 1)]);
        assert_eq!(reply.search_domains(), ["example.com".to_owned()]);
    }
}
