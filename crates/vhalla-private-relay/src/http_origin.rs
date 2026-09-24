//! A deliberately narrow HTTPS origin grammar; never a URL normalizer.
use crate::{Error, Result};

/// Canonical HTTPS with an ASCII DNS host and an optional nondefault port.
/// No URL path, credentials, fragment, IP literal or local-host alias is allowed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsOrigin {
    value: String,
    host_end: usize,
    port: u16,
}

impl HttpsOrigin {
    /// Refuse ambiguous spelling rather than silently selecting another origin.
    pub fn parse(value: &str) -> Result<Self> {
        if value.len() > 267 {
            return Err(Error::Bounds);
        }
        let authority = value.strip_prefix("https://").ok_or(Error::Bounds)?;
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => {
                let parsed = port.parse::<u16>().map_err(|_| Error::Bounds)?;
                if parsed == 0 || parsed == 443 || parsed.to_string() != port {
                    return Err(Error::Bounds);
                }
                (host, parsed)
            }
            None => (authority, 443),
        };
        if host.len() > 253 || !host.contains('.') || host.ends_with(".localhost") {
            return Err(Error::Bounds);
        }
        for label in host.split('.') {
            if label.is_empty()
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(Error::Bounds);
            }
        }
        // Browser URL parsers interpret a final decimal or hexadecimal number
        // as an IPv4 candidate, including shortened and octal IPv4 spellings.
        let last = host.rsplit('.').next().ok_or(Error::Bounds)?;
        if last.bytes().all(|byte| byte.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .is_some_and(|hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(Error::Bounds);
        }
        Ok(Self {
            value: value.to_owned(),
            host_end: 8 + host.len(),
            port,
        })
    }

    /// Exact serialized origin, without a trailing slash.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Exact HTTP Host authority, with the port only when nondefault.
    pub fn authority(&self) -> &str {
        &self.value[8..]
    }

    /// Canonical DNS name, without a port.
    pub fn host(&self) -> &str {
        &self.value[8..self.host_end]
    }

    /// Effective TLS port; omitted default ports return 443.
    pub fn port(&self) -> u16 {
        self.port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_exact_canonical_origin_authority_and_dns_name() {
        for (raw, host, authority, port) in [
            (
                "https://rooms.example.com",
                "rooms.example.com",
                "rooms.example.com",
                443,
            ),
            (
                "https://a-b.example:8443",
                "a-b.example",
                "a-b.example:8443",
                8443,
            ),
            (
                "https://1.example:65535",
                "1.example",
                "1.example:65535",
                65535,
            ),
            (
                "https://xn--caf-dma.example",
                "xn--caf-dma.example",
                "xn--caf-dma.example",
                443,
            ),
        ] {
            let origin = HttpsOrigin::parse(raw).unwrap();
            assert_eq!(origin.as_str(), raw);
            assert_eq!(origin.host(), host);
            assert_eq!(origin.authority(), authority);
            assert_eq!(origin.port(), port);
        }
    }

    #[test]
    fn rejects_ambiguous_urls_ip_spellings_and_noncanonical_ports() {
        for raw in [
            "http://rooms.example",
            "HTTPS://rooms.example",
            "https://Rooms.example",
            "https://rooms.example/",
            "https://rooms.example/path",
            "https://rooms.example?x=1",
            "https://rooms.example#x",
            "https://user@rooms.example",
            "https://rooms.example.",
            "https://rooms..example",
            "https://-rooms.example",
            "https://rooms-.example",
            "https://rooms.exa_mple",
            "https://café.example",
            "https://rooms%2eexample",
            "https://localhost",
            "https://a.localhost",
            "https://singlelabel",
            "https://127.0.0.1",
            "https://127.1",
            "https://0177.0.0.1",
            "https://0x7f.0.0.0x1",
            "https://0x7f.0x",
            "https://[::1]",
            "https://rooms.example:443",
            "https://rooms.example:0443",
            "https://rooms.example:08443",
            "https://rooms.example:0",
            "https://rooms.example:65536",
            "https://rooms.example:+8443",
            "https://rooms.example:",
            "https://rooms.example:8443:1",
            "https://rooms.example\n",
        ] {
            assert_eq!(HttpsOrigin::parse(raw), Err(Error::Bounds), "{raw}");
        }
    }

    #[test]
    fn enforces_dns_label_and_total_host_bounds() {
        let label = "a".repeat(63);
        let longest = format!("{label}.{label}.{label}.{}", "a".repeat(61));
        assert_eq!(longest.len(), 253);
        assert!(HttpsOrigin::parse(&format!("https://{longest}:65535")).is_ok());
        assert!(HttpsOrigin::parse(&format!("https://{longest}a")).is_err());
        assert!(HttpsOrigin::parse(&format!("https://{}.example", "a".repeat(64))).is_err());
    }
}
