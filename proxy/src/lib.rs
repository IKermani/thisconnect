// SPDX-License-Identifier: GPL-3.0-or-later

//! Unprivileged proxy worker: the SOCKS5 and HTTP CONNECT front ends, and the tunnel-pinned
//! egress dialer they both dial through. This crate must never require a capability or root.

pub mod egress;
pub mod http;
pub mod socks5;
