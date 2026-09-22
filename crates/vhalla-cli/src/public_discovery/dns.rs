//! Each blocking system lookup has a killable process owner, never a detached thread.
use super::*;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::atomic::AtomicUsize,
};
use vhalla_public_protocol::{Host, Scheme};

const MAX_ANSWERS: usize = 16;
const MAX_ANSWER_BYTES: usize = MAX_ANSWERS * 40;
const RESOLVE_TIME: Duration = Duration::from_secs(5);
static NEXT_ADDRESS: AtomicUsize = AtomicUsize::new(0);

/// Canonical child entry point: no caller-selected program, flags, port, or path.
/// It performs DNS only, never connects to the returned addresses.
pub(super) fn child(args: &[OsString]) -> Result<(), String> {
    if args.len() != 3 {
        return Err("internal resolver requires one canonical HTTPS endpoint".into());
    }
    let endpoint = Endpoint::parse(args[2].to_str().ok_or("invalid resolver endpoint")?)
        .map_err(|_| "invalid resolver endpoint")?;
    if endpoint.scheme() != Scheme::Https {
        return Err("resolver requires HTTPS".into());
    }
    let Host::Dns(host) = endpoint.host() else {
        return Err("resolver requires a DNS name".into());
    };
    // The final dot makes the validated DNS name absolute: no search suffixes.
    // ToSocketAddrs may block inside libc; only this supervised child does so.
    let absolute = format!("{host}.");
    let answers = (absolute.as_str(), endpoint.port())
        .to_socket_addrs()
        .map_err(|_| "system DNS resolution failed")?;
    let mut ips = BTreeSet::new();
    for (index, answer) in answers.enumerate() {
        if index >= MAX_ANSWERS {
            return Err("system DNS answer count exceeds limit".into());
        }
        if matches!(answer, SocketAddr::V6(v6) if v6.scope_id() != 0) {
            return Err("scoped DNS answer refused".into());
        }
        check_ip(answer.ip())?;
        ips.insert(answer.ip());
    }
    if ips.is_empty() {
        return Err("system DNS returned no addresses".into());
    }
    // Emit only after the entire bounded answer set passed, never a safe prefix
    // followed by an unsafe answer. Parent independently checks the same frame.
    let raw: String = ips.iter().map(|ip| format!("{ip}\n")).collect();
    std::io::stdout()
        .write_all(raw.as_bytes())
        .map_err(|e| format!("resolver output: {e}"))
}

fn check_ip(ip: IpAddr) -> Result<(), String> {
    // Reuse the canonical endpoint policy: conservative public unicast only.
    // This excludes mapped/NAT64, local/link-local, multicast, transition,
    // benchmark, documentation and reserved address ranges. It is not proof of
    // reachability or protection against a host's own unusual routing table.
    let host = match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    Endpoint::parse(&format!("https://{host}:443/vhalla/v1"))
        .map(|_| ())
        .map_err(|_| "non-public DNS address refused".into())
}

fn parse_answers(raw: &[u8]) -> Result<Vec<IpAddr>, String> {
    if raw.is_empty() || raw.len() > MAX_ANSWER_BYTES || raw.last() != Some(&b'\n') {
        return Err("invalid bounded resolver frame".into());
    }
    let text = std::str::from_utf8(raw).map_err(|_| "non-ASCII resolver frame")?;
    let mut answers = Vec::new();
    for line in text[..text.len() - 1].split('\n') {
        if answers.len() >= MAX_ANSWERS {
            return Err("resolver answer count exceeds limit".into());
        }
        let ip: IpAddr = line.parse().map_err(|_| "invalid resolver address")?;
        if ip.to_string() != line || answers.last().is_some_and(|last| *last >= ip) {
            return Err("noncanonical resolver addresses".into());
        }
        check_ip(ip)?;
        answers.push(ip);
    }
    Ok(answers)
}

pub(super) fn resolve(
    endpoint: &Endpoint,
    cancel: &AtomicBool,
    remaining: Duration,
) -> Result<Vec<IpAddr>, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("curl request cancelled".into());
    }
    if endpoint.scheme() != Scheme::Https {
        return Err("selected seed requires HTTPS".into());
    }
    if let Host::Ip(ip) = endpoint.host() {
        check_ip(*ip)?;
        return Ok(vec![*ip]);
    }
    let executable = std::env::current_exe().map_err(|e| format!("resolver executable: {e}"))?;
    let mut command = Command::new(executable);
    command
        .env_clear()
        .args(["public", "discovery-resolve", endpoint.as_str()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let raw = run(
        command,
        None,
        MAX_ANSWER_BYTES,
        remaining.min(RESOLVE_TIME),
        cancel,
        "DNS resolver",
    )?;
    parse_answers(&raw)
}

/// Install a non-expiring exact cache entry. No wildcard, plus-prefix, or DNS
/// fallback; the original URL still controls SNI and certificate validation.
pub(super) fn pin(
    command: &mut Command,
    endpoint: &Endpoint,
    addresses: &[IpAddr],
) -> Result<(), String> {
    pin_at(
        command,
        endpoint,
        addresses,
        NEXT_ADDRESS.fetch_add(1, Ordering::Relaxed),
    )
}

fn pin_at(
    command: &mut Command,
    endpoint: &Endpoint,
    addresses: &[IpAddr],
    cursor: usize,
) -> Result<(), String> {
    if endpoint.scheme() != Scheme::Https {
        return Err("selected seed requires HTTPS".into());
    }
    if addresses.is_empty() || addresses.len() > MAX_ANSWERS {
        return Err("invalid dial address count".into());
    }
    let mut unique = BTreeSet::new();
    for ip in addresses {
        check_ip(*ip)?;
        if !unique.insert(*ip) {
            return Err("duplicate dial address".into());
        }
    }
    match endpoint.host() {
        Host::Dns(host) => {
            let mut addresses = addresses.to_vec();
            // Retry priority changes without any unguarded re-resolution. Curl
            // can try the full checked set within this one transfer deadline.
            let start = cursor % addresses.len();
            addresses.rotate_left(start);
            let addresses = addresses
                .iter()
                .map(|ip| match ip {
                    IpAddr::V4(ip) => ip.to_string(),
                    IpAddr::V6(ip) => format!("[{ip}]"),
                })
                .collect::<Vec<_>>()
                .join(",");
            command
                .arg("--resolve")
                .arg(format!("{host}:{}:{addresses}", endpoint.port()));
        }
        Host::Ip(ip) if addresses == [*ip] => {
            // The URL is already a canonical checked IP. Avoid --resolve's
            // IPv6-host syntax, which older system curl versions do not support.
        }
        Host::Ip(_) => return Err("literal endpoint address changed".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_dns_refuses_special_mapped_mixed_and_oversized_answers() {
        for ip in [
            "0.0.0.0",
            "10.1.2.3",
            "127.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.1.1",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "::ffff:127.0.0.1",
            "64:ff9b::808:808",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "2002:808:808::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(check_ip(ip.parse().unwrap()).is_err(), "{ip}");
            let mut ips = ["8.8.8.8".parse::<IpAddr>().unwrap(), ip.parse().unwrap()];
            ips.sort();
            let raw = format!("{}\n{}\n", ips[0], ips[1]);
            assert!(parse_answers(raw.as_bytes()).is_err(), "mixed {ip}");
        }
        for raw in [
            "",
            "8.8.8.8",
            "8.8.8.8\n\n",
            "8.8.8.8\r\n",
            "8.8.8.8\n8.8.8.8\n",
            "08.8.8.8\n",
            "2001:4860:4860::8888%1\n",
        ] {
            assert!(parse_answers(raw.as_bytes()).is_err(), "{raw:?}");
        }
        let raw: String = (1..=17).map(|n| format!("8.8.8.{n}\n")).collect();
        assert!(parse_answers(raw.as_bytes()).is_err());
        assert_eq!(
            parse_answers(b"8.8.8.8\n2001:4860:4860::8888\n")
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn discovery_dns_pins_exact_host_port_and_rotates_only_verified_addresses() {
        let endpoint = Endpoint::parse("https://seed.vhalla.dev:8443/vhalla/v1").unwrap();
        let addresses = [
            "8.8.8.8".parse().unwrap(),
            "2001:4860:4860::8888".parse().unwrap(),
        ];
        let mut observed = BTreeSet::new();
        for cursor in 0..2 {
            let mut command = command();
            pin_at(&mut command, &endpoint, &addresses, cursor).unwrap();
            let args: Vec<_> = command.get_args().map(|s| s.to_str().unwrap()).collect();
            assert_eq!(&args[..2], ["--disable", "--resolve"]);
            assert!(args[2].starts_with("seed.vhalla.dev:8443:"));
            assert!(args[2].contains("8.8.8.8"));
            assert!(args[2].contains("[2001:4860:4860::8888]"));
            observed.insert(args[2].to_owned());
        }
        assert_eq!(observed.len(), 2);
        let literal = Endpoint::parse("https://[2001:4860:4860::8888]:443/vhalla/v1").unwrap();
        let mut command = command();
        pin(&mut command, &literal, &addresses[1..]).unwrap();
        assert_eq!(command.get_args().count(), 1);
        assert!(pin(&mut command, &literal, &addresses[..1]).is_err());
        assert!(pin(&mut command, &endpoint, &["127.0.0.1".parse().unwrap()]).is_err());
        assert!(pin(&mut command, &endpoint, &[addresses[0]; 17]).is_err());
    }

    #[test]
    fn discovery_dns_child_validates_exact_arguments_before_any_resolution() {
        for args in [
            vec!["public", "discovery-resolve"],
            vec![
                "public",
                "discovery-resolve",
                "https://localhost:443/vhalla/v1",
            ],
            vec![
                "public",
                "discovery-resolve",
                "https://127.0.0.1:443/vhalla/v1",
            ],
            vec![
                "public",
                "discovery-resolve",
                "https://seed.vhalla.dev:443/vhalla/v1",
                "extra",
            ],
            vec![
                "public",
                "discovery-resolve",
                "wss://seed.vhalla.dev:443/vhalla/v1",
            ],
        ] {
            let args: Vec<_> = args.into_iter().map(OsString::from).collect();
            assert!(child(&args).is_err());
        }
    }
}
