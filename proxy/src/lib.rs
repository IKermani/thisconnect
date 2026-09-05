// SPDX-License-Identifier: GPL-3.0-or-later

//! Unprivileged proxy worker: the SOCKS5 and HTTP CONNECT front ends, the mixed
//! listener that dispatches between them, the tunnel-pinned resolver, and the
//! egress dialer they all dial through. This crate must never require a
//! capability or root.
//!
//! No name resolution may escape the tunnel: `getaddrinfo`, `ToSocketAddrs`,
//! `tokio::net::lookup_host` and every socket constructor that accepts a
//! `&str` address are banned here, and `clippy.toml` enforces it in CI
//! (SPEC.md §5.4 D3). The socket constructors are on that list because tokio's
//! own sealed `ToSocketAddrs` resolves a string host through `getaddrinfo`
//! from inside tokio, out of reach of the ban on the standard-library trait.
//! Pass a `SocketAddr` obtained from the tunnel-pinned resolver instead.

pub mod credentials;
pub mod egress;
pub mod http;
pub mod listener;
pub mod resolver;
pub mod socks5;
pub mod stats;
