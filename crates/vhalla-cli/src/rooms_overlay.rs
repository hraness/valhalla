#![cfg(all(unix, feature = "experimental-rooms-node"))]

use std::{collections::BTreeSet, ffi::OsString, net::Ipv4Addr};

use vhalla_rooms_node::PublicKey;

struct Member {
    name: String,
    key: String,
    port: u16,
    address: Ipv4Addr,
}

pub fn run(args: Vec<OsString>) -> Result<(), String> {
    let mut subcommand = None;
    let mut profile = None;
    let mut member_specs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let value = args[i].to_str().ok_or("overlay arguments must be UTF-8")?;
        match value {
            "plan" if subcommand.is_none() => subcommand = Some(value.to_owned()),
            "--profile" => {
                i += 1;
                profile = Some(
                    args.get(i)
                        .ok_or("--profile needs a value")?
                        .to_str()
                        .ok_or("--profile must be UTF-8")?
                        .to_owned(),
                );
            }
            "--members" => {
                i += 1;
                while i < args.len() && !args[i].to_str().unwrap_or("").starts_with("--") {
                    member_specs.push(
                        args[i]
                            .to_str()
                            .ok_or("--members values must be UTF-8")?
                            .to_owned(),
                    );
                    i += 1;
                }
                continue;
            }
            _ => return Err(HELP.into()),
        }
        i += 1;
    }
    if subcommand.as_deref() != Some("plan") {
        return Err(HELP.into());
    }
    let (control_plane, path) = match profile.as_deref() {
        Some("tailscale") => ("tailscale", "direct-or-derp-relay"),
        Some("cloudflare-mesh") => ("cloudflare-one", "cloudflare-edge-relay"),
        _ => return Err("--profile must be tailscale or cloudflare-mesh".into()),
    };
    if member_specs.len() < 2 {
        return Err("overlay plan needs at least two public --members specs".into());
    }
    let mut names = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut members = Vec::with_capacity(member_specs.len());
    for spec in member_specs {
        let member = parse_member(&spec)?;
        if !names.insert(member.name.clone()) {
            return Err(format!("duplicate overlay member name {:?}", member.name));
        }
        if !keys.insert(member.key.clone()) {
            return Err(format!(
                "duplicate overlay member key for {:?}",
                member.name
            ));
        }
        if !addresses.insert((member.address, member.port)) {
            return Err(format!(
                "duplicate overlay endpoint {}:{}",
                member.address, member.port
            ));
        }
        members.push(member);
    }
    emit_plan(profile.as_deref().unwrap(), control_plane, path, &members)
}

const HELP: &str = "vhalla rooms overlay plan --profile tailscale|cloudflare-mesh --members NAME=KEY64@IP:PORT NAME=KEY64@IP:PORT ...";

fn parse_member(spec: &str) -> Result<Member, String> {
    let (name, endpoint) = spec
        .split_once('=')
        .ok_or_else(|| format!("overlay member {spec:?} must be NAME=KEY64@IP:PORT"))?;
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("overlay member name {name:?} is invalid"));
    }
    let (key, endpoint) = endpoint
        .split_once('@')
        .ok_or_else(|| format!("overlay member {spec:?} must be NAME=KEY64@IP:PORT"))?;
    let public = PublicKey::from_bytes(
        crate::rooms::hex32(key)
            .map_err(|_| format!("overlay member {name:?} key must be 64 hex"))?,
    )
    .map_err(|_| format!("overlay member {name:?} key is not an Ed25519 public key"))?;
    let (address, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| format!("overlay member {name:?} endpoint must be IP:PORT"))?;
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("overlay member {name:?} address must be IPv4"))?;
    if !is_private_overlay(address) {
        return Err(format!(
            "overlay address {address} must be RFC1918 or shared 100.64.0.0/10 space"
        ));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("overlay member {name:?} port must be 1..65535"))?;
    if port == 0 {
        return Err(format!("overlay member {name:?} port must be 1..65535"));
    }
    Ok(Member {
        name: name.to_owned(),
        key: crate::json::hex(public.as_bytes()),
        port,
        address,
    })
}

fn is_private_overlay(address: Ipv4Addr) -> bool {
    let [a, b, _, _] = address.octets();
    a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 100 && (64..=127).contains(&b))
}

fn emit_plan(
    profile: &str,
    control_plane: &str,
    path: &str,
    members: &[Member],
) -> Result<(), String> {
    use crate::json;
    let plans: Vec<String> = members
        .iter()
        .enumerate()
        .map(|(i, member)| {
            let peers = members
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, peer)| format!("{}@{}:{}", peer.key, peer.address, peer.port))
                .collect::<Vec<_>>()
                .join(",");
            json::object(vec![
                ("index", i.to_string()),
                ("name", json::string(&member.name)),
                ("public_key", json::string(&member.key)),
                ("address", json::string(&member.address.to_string())),
                ("listen", json::string(&member.address.to_string())),
                ("port", member.port.to_string()),
                ("peers", json::string(&peers)),
                ("peers_only", "true".into()),
            ])
        })
        .collect();
    crate::rooms::emit(json::object(vec![
        ("profile", json::string(profile)),
        ("control_plane", json::string(control_plane)),
        ("path", json::string(path)),
        ("supports_tcp", "true".into()),
        ("supports_udp", "true".into()),
        ("live_qualified", "false".into()),
        ("members", json::array(plans)),
    ]))
}
