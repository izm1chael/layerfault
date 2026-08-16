//! Shared SSRF-defense primitives for outbound HTTP clients: reject
//! resolution to private/loopback/link-local/cloud-metadata addresses
//! before connecting.
//!
//! Extracted from `crate::hub::client`, which had its own private copy of
//! this exact logic; `crate::agent_security::discovery::remote` reuses it
//! for MCP remote discovery. This is security-critical code duplicated in
//! two places is exactly the kind of duplication that is dangerous (one
//! copy gets hardened, the other quietly does not), so it now lives in one
//! place both callers depend on.

use anyhow::{bail, Context, Result};
use std::net::{IpAddr, ToSocketAddrs};

/// True for an address that must never be connected to: private,
/// loopback, link-local, multicast/reserved, unspecified, or the
/// well-known cloud instance-metadata address (`169.254.169.254`).
pub fn blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_unspecified()
                || v.octets()[0] == 0
                || v.octets()[0] >= 224
                || v.octets() == [169, 254, 169, 254]
        }
        IpAddr::V6(v) => {
            v.is_loopback()
                || v.is_unspecified()
                || v.is_unique_local()
                || v.is_unicast_link_local()
        }
    }
}

/// Resolve `host` and reject the connection if it is, or resolves to, a
/// blocked address. Resolving fresh on every call (rather than caching) is
/// deliberate: it is what defends against DNS-rebinding, where a host
/// resolves safely once and then to a blocked address on a later lookup.
pub fn reject_private_resolution(host: &str, port: u16) -> Result<()> {
    resolve_public_addresses(host, port).map(|_| ())
}

/// Resolve `host` once and return the exact validated addresses. Callers
/// that pin a connection must select from this returned set instead of
/// performing a second DNS lookup after validation.
pub fn resolve_public_addresses(host: &str, port: u16) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if blocked_ip(ip) {
            bail!("host resolves directly to blocked address {ip}");
        }
        return Ok(vec![ip]);
    }
    let mut addresses: Vec<_> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("unable to resolve host '{host}'"))?
        .map(|address| address.ip())
        .collect();
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        bail!("host '{host}' resolved to no addresses");
    }
    if addresses.iter().copied().any(blocked_ip) {
        bail!("host '{host}' resolved to a private/loopback/link-local address");
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_and_private_v4_are_blocked() {
        assert!(blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(blocked_ip("10.0.0.5".parse().unwrap()));
        assert!(blocked_ip("192.168.1.1".parse().unwrap()));
        assert!(blocked_ip("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn ordinary_public_v4_is_not_blocked() {
        assert!(!blocked_ip("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn loopback_v6_is_blocked() {
        assert!(blocked_ip("::1".parse().unwrap()));
    }

    #[test]
    fn direct_ip_literal_to_blocked_address_is_rejected() {
        let error = reject_private_resolution("127.0.0.1", 443)
            .expect_err("loopback literal must be rejected");
        assert!(error.to_string().contains("blocked address"));
    }
}
