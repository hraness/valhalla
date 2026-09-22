//! Canonical public route hints. Parsing never authorizes a dial.
use alloc::{format, string::String, string::ToString};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Error;

/// Fixed public protocol API base. No arbitrary path or suffix is advertised.
pub const API_BASE: &str = "/vhalla/v1";
/// Maximum complete canonical endpoint length, checked before allocation.
pub const MAX_ENDPOINT_BYTES: usize = 288;

/// The only endpoint schemes admitted by version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scheme {
    /// HTTP over authenticated TLS.
    Https,
    /// WebSocket over authenticated TLS.
    Wss,
}

/// A structurally checked host. DNS names still require guarded resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Host {
    /// Lowercase ASCII DNS name with at least two labels.
    Dns(String),
    /// A conservative public-unicast literal, not proof of reachability.
    Ip(IpAddr),
}

/// A canonical route hint, never permission to contact the named host.
///
/// A dialer must enforce DNS/address policy at every connection, disallow
/// redirects or revalidate them, authenticate TLS, and prove the advertised
/// application identity over a fresh session. The advertisement signer need
/// not control this endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    url: String,
    scheme: Scheme,
    host: Host,
    port: u16,
}

impl Endpoint {
    /// Parse an exact lowercase HTTPS/WSS URL with an explicit nonzero port.
    ///
    /// Version 1 requires the exact API_BASE path. Credentials, queries,
    /// fragments, escapes, trailing dots, zone IDs and alternative IP spellings
    /// are rejected rather than normalized.
    pub fn parse(url: &str) -> Result<Self, Error> {
        if url.len() > MAX_ENDPOINT_BYTES {
            return Err(Error::Bounds);
        }
        if !url.is_ascii() {
            return Err(Error::Endpoint);
        }
        let (scheme, authority) = if let Some(rest) = url.strip_prefix("https://") {
            (Scheme::Https, rest)
        } else if let Some(rest) = url.strip_prefix("wss://") {
            (Scheme::Wss, rest)
        } else {
            return Err(Error::Endpoint);
        };
        let authority = authority.strip_suffix(API_BASE).ok_or(Error::Endpoint)?;
        let (host, port) = authority.rsplit_once(':').ok_or(Error::Endpoint)?;
        if port.is_empty() || port.starts_with('0') || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::Endpoint);
        }
        let port: u16 = port.parse().map_err(|_| Error::Endpoint)?;
        let host = if let Some(raw) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let ip: Ipv6Addr = raw.parse().map_err(|_| Error::Endpoint)?;
            if format!("[{ip}]") != host || !public_ipv6(ip) {
                return Err(Error::Endpoint);
            }
            Host::Ip(IpAddr::V6(ip))
        } else if let Ok(ip) = host.parse::<Ipv4Addr>() {
            if ip.to_string() != host || !public_ipv4(ip) {
                return Err(Error::Endpoint);
            }
            Host::Ip(IpAddr::V4(ip))
        } else {
            check_dns(host)?;
            Host::Dns(host.to_string())
        };
        Ok(Self {
            url: url.to_string(),
            scheme,
            host,
            port,
        })
    }

    /// Borrow the exact canonical URL.
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// Borrow the parsed host; this does not perform DNS resolution.
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// Authenticated transport scheme requested by the hint.
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Explicit nonzero destination port.
    pub const fn port(&self) -> u16 {
        self.port
    }
}

fn check_dns(host: &str) -> Result<(), Error> {
    if host.len() > 253 || !host.contains('.') {
        return Err(Error::Endpoint);
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Error::Endpoint);
        }
    }
    // Alphabetic final labels also exclude WHATWG legacy numeric/hex IP
    // spellings that another URL parser could otherwise reinterpret.
    let tld = host.rsplit('.').next().ok_or(Error::Endpoint)?;
    if tld.len() < 2 || !tld.bytes().all(|b| b.is_ascii_lowercase()) {
        return Err(Error::Endpoint);
    }
    // Public DNS syntax is not evidence of a public resolution. These common
    // special/local namespaces are refused early; the dialer remains the guard.
    const RESERVED: &[&str] = &[
        "alt",
        "arpa",
        "example",
        "example.com",
        "example.net",
        "example.org",
        "home",
        "internal",
        "invalid",
        "lan",
        "local",
        "localdomain",
        "localhost",
        "onion",
        "test",
    ];
    if RESERVED.iter().any(|suffix| {
        host == *suffix
            || host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    }) {
        return Err(Error::Endpoint);
    }
    Ok(())
}

fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && ((b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99) || b == 168))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}

fn public_ipv6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // Conservatively admit 2000::/3, excluding protocol assignments,
    // transition mechanisms and documentation. No mapped/NAT64/local forms.
    s[0] & 0xe000 == 0x2000
        && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
        && s[0] != 0x2002
        && !(s[0] == 0x3fff && s[1] < 0x1000)
}
