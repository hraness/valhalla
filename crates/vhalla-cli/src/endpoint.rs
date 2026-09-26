//! Dialable relay endpoints: an explicit `IP:PORT` or a DNS `NAME:PORT`.
//! A name resolves at each use; TLS keeps pinning identity through the
//! selected CA and server name, never the resolved name. Listeners and
//! invite-advertised addresses remain numeric-only.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// One dialable endpoint as written on a flag or in a configuration file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Endpoint {
    Numeric(SocketAddr),
    Named(String, u16),
}

impl Endpoint {
    /// Parse `IP:PORT` canonically, else a strict `NAME:PORT`. A token
    /// shaped like an address literal but malformed (bad port, stray
    /// colons, out-of-range octets) is refused rather than sent to DNS.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        if let Ok(addr) = text.parse::<SocketAddr>() {
            return Ok(Self::Numeric(addr));
        }
        let (host, port) = text
            .rsplit_once(':')
            .ok_or("endpoint must be IP:PORT or NAME:PORT")?;
        let port: u16 = match port.parse::<u16>() {
            Ok(parsed) if parsed.to_string() == port => parsed,
            _ => return Err("endpoint port must be a canonical 0..65535".into()),
        };
        if host.parse::<IpAddr>().is_ok() || host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            return Err("endpoint address literal is malformed".into());
        }
        if host.is_empty()
            || host.len() > 253
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            || host
                .split('.')
                .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
        {
            return Err("endpoint host must be a canonical DNS name".into());
        }
        Ok(Self::Named(host.to_owned(), port))
    }

    /// Resolve to a concrete address at each call, so a redeployed service
    /// behind a stable name is picked up without rewriting custody.
    /// The first resolved address is used; an explicit IP:PORT remains
    /// the escape hatch when ordering matters.
    pub(crate) fn resolve(&self) -> Result<SocketAddr, String> {
        match self {
            Self::Numeric(addr) => Ok(*addr),
            Self::Named(host, port) => (host.as_str(), *port)
                .to_socket_addrs()
                .ok()
                .and_then(|mut resolved| resolved.next())
                .ok_or_else(|| "endpoint name did not resolve".to_owned()),
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Numeric(addr) => write!(f, "{addr}"),
            Self::Named(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

impl Serialize for Endpoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}
impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::Endpoint;
    use std::net::SocketAddr;

    fn named(text: &str) -> (String, u16) {
        match Endpoint::parse(text).unwrap() {
            Endpoint::Named(host, port) => (host, port),
            Endpoint::Numeric(addr) => panic!("{text} parsed as numeric {addr}"),
        }
    }

    #[test]
    fn numeric_endpoints_parse_without_dns() {
        assert_eq!(
            Endpoint::parse("127.0.0.1:9473").unwrap(),
            Endpoint::Numeric("127.0.0.1:9473".parse().unwrap())
        );
        assert_eq!(
            Endpoint::parse("[::1]:443").unwrap(),
            Endpoint::Numeric("[::1]:443".parse().unwrap())
        );
    }

    #[test]
    fn named_endpoints_parse_and_resolve() {
        assert_eq!(
            named("hayabusa.proxy.rlwy.net:45737"),
            ("hayabusa.proxy.rlwy.net".to_owned(), 45737)
        );
        assert_eq!(named("localhost:9473"), ("localhost".to_owned(), 9473));
        let resolved = Endpoint::parse("localhost:9473")
            .unwrap()
            .resolve()
            .unwrap();
        assert!(resolved.ip().is_loopback() && resolved.port() == 9473);
        assert!(Endpoint::parse("127.0.0.1:9473").unwrap().resolve().is_ok());
    }

    #[test]
    fn malformed_endpoints_refuse() {
        for text in [
            "host",
            "host:",
            ":443",
            "host:080",
            "host:70000",
            "host:1x",
            "999.1.2.3:443",
            "1.2.3.4:99999",
            "::1:8080",
            "-bad.example:443",
            "bad-.example:443",
            "a..b:443",
            "bad_name.example:443",
            "x:443:extra",
        ] {
            assert!(Endpoint::parse(text).is_err(), "accepted {text}");
        }
        assert!(Endpoint::parse(&format!("{}.com:443", "a".repeat(254))).is_err());
    }

    #[test]
    fn endpoint_serializes_canonical_text() {
        let named = Endpoint::parse("relay.example:8443").unwrap();
        assert_eq!(
            serde_json::to_string(&named).unwrap(),
            "\"relay.example:8443\""
        );
        let numeric = Endpoint::parse("10.0.0.2:9").unwrap();
        let round: Endpoint =
            serde_json::from_str(&serde_json::to_string(&numeric).unwrap()).unwrap();
        assert_eq!(round, numeric);
        assert_eq!(
            round.resolve().unwrap(),
            SocketAddr::from(([10, 0, 0, 2], 9))
        );
    }
}
