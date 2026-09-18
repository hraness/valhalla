#![cfg(all(unix, feature = "experimental-rooms-node"))]
//! Tailcat overlay planner and launcher for room-consensus meshes.
//!
//! Tailcat (`tailscale/tailcat`) provides account-less, userspace TCP
//! tunnels that are useful for carrying the libp2p mesh traffic across
//! different networks. This module is a pure planner for `plan`, a live
//! launcher for `up`, and a health checker for `status`. It reads the
//! per-member `node.json` files produced by `rooms node-init`, allocates
//! the local forward-port namespace, and emits an executable plan or
//! starts the processes and the matching `peers` CSV for each member.

use std::{
    ffi::OsString,
    fs::File,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;

#[derive(Deserialize)]
struct NodeForTailcat {
    /// libp2p TCP listen port.
    port: u16,
    /// libp2p TCP listen host.
    #[serde(default = "default_listen")]
    listen: String,
    /// Peers line in the node file - ignored, the planner rewrites it.
    #[allow(dead_code)]
    #[serde(default)]
    peers: Option<String>,
}

fn default_listen() -> String {
    "127.0.0.1".into()
}

struct Member {
    name: String,
    node_json: String,
    port: u16,
    listen: String,
}

/// Dispatch `tailcat` subcommands.
///
/// Supported:
/// - `plan` emits the mesh commands and peers CSV.
/// - `up` starts the serves and forwards on this host.
pub fn run(args: Vec<OsString>) -> Result<(), String> {
    let mut subcommand = String::new();
    let mut nodes: Vec<String> = Vec::new();
    let mut base_port = 17_000u16;
    let mut output = "json".to_string();
    let mut tailcat_bin = "tailcat".to_string();
    let mut i = 0;
    while i < args.len() {
        let value = args[i]
            .to_str()
            .ok_or("tailcat arguments must be UTF-8")?
            .to_owned();
        match value.as_str() {
            "plan" | "status" | "up" => subcommand = value,
            "--nodes" => {
                i += 1;
                while i < args.len() && !args[i].to_str().unwrap_or("").starts_with("--") {
                    nodes.push(
                        args[i]
                            .to_str()
                            .ok_or("--nodes paths must be UTF-8")?
                            .to_owned(),
                    );
                    i += 1;
                }
                continue;
            }
            "--base-port" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or("--base-port needs a value")?
                    .to_str()
                    .ok_or("--base-port must be UTF-8")?;
                base_port = v
                    .parse::<u16>()
                    .map_err(|_| "--base-port must be a valid u16")?;
            }
            "--output" => {
                i += 1;
                output = args
                    .get(i)
                    .ok_or("--output needs a value")?
                    .to_str()
                    .ok_or("--output must be UTF-8")?
                    .to_owned();
            }
            "--tailcat" => {
                i += 1;
                tailcat_bin = args
                    .get(i)
                    .ok_or("--tailcat needs a value")?
                    .to_str()
                    .ok_or("--tailcat must be UTF-8")?
                    .to_owned();
            }
            _ => return Err(HELP.into()),
        }
        i += 1;
    }
    if nodes.len() < 2 {
        return Err("tailcat needs at least two --nodes node.json files".into());
    }
    let mut members = Vec::with_capacity(nodes.len());
    for path in nodes {
        let raw = std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?;
        if raw.len() > 64 * 1024 {
            return Err(format!("{path} exceeds 64KiB"));
        }
        let node: NodeForTailcat =
            serde_json::from_slice(&raw).map_err(|e| format!("{path} JSON: {e}"))?;
        let name = Path::new(&path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&path)
            .to_owned();
        members.push(Member {
            name,
            node_json: path,
            port: node.port,
            listen: node.listen,
        });
    }
    match subcommand.as_str() {
        "plan" => {
            if output != "json" && output != "shell" {
                return Err("--output must be json or shell".into());
            }
            if output == "json" {
                emit_json(&members, base_port)
            } else {
                emit_shell(&members, base_port)
            }
        }
        "status" => emit_status(&members, base_port),
        "up" => emit_up(&members, base_port, &tailcat_bin),
        _ => Err(HELP.into()),
    }
}

const HELP: &str = "vhalla rooms tailcat {plan|status|up} --nodes A/node.json B/node.json ... [--base-port N]\n  plan [--output json|shell]\n  status\n  up [--tailcat PATH]";

fn emit_json(members: &[Member], base: u16) -> Result<(), String> {
    use crate::json;
    let serves: Vec<String> = members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            json::object(vec![
                ("index", i.to_string()),
                ("name", json::string(&m.name)),
                ("port", m.port.to_string()),
                ("listen", json::string(&m.listen)),
                (
                    "addr_file",
                    json::string(&format!("/tmp/tailcat-addr-{i}.txt")),
                ),
            ])
        })
        .collect();
    let forwards: Vec<String> = members
        .iter()
        .enumerate()
        .flat_map(|(i, _from)| {
            members.iter().enumerate().filter_map(move |(j, to)| {
                if i == j {
                    return None;
                }
                let fwd = base + (i as u16) * 100 + j as u16;
                Some(json::object(vec![
                    ("from", i.to_string()),
                    ("to", j.to_string()),
                    ("local_port", fwd.to_string()),
                    (
                        "remote_addr",
                        json::string(&format!("{}:{}", to.listen, to.port)),
                    ),
                    (
                        "addr_file",
                        json::string(&format!("/tmp/tailcat-addr-{j}.txt")),
                    ),
                ]))
            })
        })
        .collect();
    let peers: Vec<String> = members
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let list: Vec<String> = members
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(j, _)| format!("127.0.0.1:{}", base + (i as u16) * 100 + j as u16))
                .collect();
            json::object(vec![
                ("index", i.to_string()),
                ("name", json::string(&members[i].name)),
                ("node_json", json::string(&members[i].node_json)),
                ("peers", json::string(&list.join(","))),
            ])
        })
        .collect();
    crate::rooms::emit(json::object(vec![
        ("serves", json::array(serves)),
        ("forwards", json::array(forwards)),
        ("peers", json::array(peers)),
    ]))
}

fn emit_shell(members: &[Member], base: u16) -> Result<(), String> {
    use crate::json;
    let mut lines = vec![
        "#!/bin/sh".into(),
        "set -e".into(),
        "# Start tailcat serves and wait for addresses".into(),
    ];
    for (i, m) in members.iter().enumerate() {
        lines.push(format!(
            "TAILCAT_ADDR_FILE=/tmp/tailcat-addr-{i}.txt tailcat --key=new serve {} > /tmp/tailcat-serve-{i}.log 2>&1 &",
            m.port
        ));
    }
    lines.push(format!(
        "for i in {}; do while [ ! -f /tmp/tailcat-addr-$i.txt ]; do sleep 0.1; done; done",
        (0..members.len())
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    ));
    lines.push("# Start tailcat forwards".into());
    for (i, _) in members.iter().enumerate() {
        for (j, to) in members.iter().enumerate() {
            if i == j {
                continue;
            }
            let fwd = base + (i as u16) * 100 + j as u16;
            lines.push(format!(
                "tailcat --key=new forward $(cat /tmp/tailcat-addr-{j}.txt) {fwd}:{}:{} > /tmp/tailcat-fwd-{i}-{j}.log 2>&1 &",
                to.listen, to.port
            ));
        }
    }
    lines.push("# Suggested peers for each node.json".into());
    for (i, m) in members.iter().enumerate() {
        let list: Vec<String> = members
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(j, _)| format!("127.0.0.1:{}", base + (i as u16) * 100 + j as u16))
            .collect();
        lines.push(format!(
            "# {name} (node: {json}): --peers {peers}",
            name = m.name,
            json = m.node_json,
            peers = list.join(",")
        ));
    }
    crate::rooms::emit(json::string(&lines.join("\n")))
}

/// Check whether the planned tailcat serves and forwards appear to be running.
fn emit_status(members: &[Member], base: u16) -> Result<(), String> {
    use crate::json;
    let timeout = Duration::from_millis(100);
    let serves: Vec<String> = members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let path = format!("/tmp/tailcat-addr-{i}.txt");
            let (ready, addr) = match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let trimmed = text.trim();
                    if trimmed.is_empty() {
                        (false, None)
                    } else {
                        (true, Some(trimmed.to_string()))
                    }
                }
                Err(_) => (false, None),
            };
            json::object(vec![
                ("index", i.to_string()),
                ("name", json::string(&m.name)),
                ("addr_file", json::string(&path)),
                ("ready", ready.to_string()),
                ("addr", json::optional(addr.as_deref(), json::string)),
            ])
        })
        .collect();
    let forwards: Vec<String> = members
        .iter()
        .enumerate()
        .flat_map(|(i, _)| {
            members.iter().enumerate().filter_map(move |(j, _)| {
                if i == j {
                    return None;
                }
                let local_port = base + (i as u16) * 100 + j as u16;
                let addr = format!("127.0.0.1:{local_port}");
                let (connected, error) = match addr
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| e.to_string())
                    .and_then(|a| {
                        std::net::TcpStream::connect_timeout(&a, timeout).map_err(|e| e.to_string())
                    }) {
                    Ok(_) => (true, None),
                    Err(e) => (false, Some(e)),
                };
                Some(json::object(vec![
                    ("from", i.to_string()),
                    ("to", j.to_string()),
                    ("local_port", local_port.to_string()),
                    ("connected", connected.to_string()),
                    ("error", json::optional(error.as_deref(), json::string)),
                ]))
            })
        })
        .collect();
    crate::rooms::emit(json::object(vec![
        ("serves", json::array(serves)),
        ("forwards", json::array(forwards)),
    ]))
}

fn emit_up(members: &[Member], base: u16, tailcat_bin: &str) -> Result<(), String> {
    use crate::json;

    let mut serve_children: Vec<std::process::Child> = Vec::new();
    let mut serve_objects: Vec<String> = Vec::new();

    for (i, m) in members.iter().enumerate() {
        let addr_file = format!("/tmp/tailcat-addr-{i}.txt");
        let log_file = format!("/tmp/tailcat-serve-{i}.log");
        let log = File::create(&log_file).map_err(|e| format!("{log_file}: {e}"))?;
        let mut cmd = Command::new(tailcat_bin);
        cmd.arg("--key=new")
            .arg("serve")
            .arg(m.port.to_string())
            .env("TAILCAT_ADDR_FILE", &addr_file)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(
                File::create(format!("/tmp/tailcat-serve-{i}.err"))
                    .map_err(|e| format!("stderr log {i}: {e}"))?,
            ));
        let child = cmd.spawn().map_err(|e| format!("{tailcat_bin}: {e}"))?;
        serve_children.push(child);
        serve_objects.push(json::object(vec![
            ("index", i.to_string()),
            ("name", json::string(&m.name)),
            ("port", m.port.to_string()),
            ("pid", serve_children[i].id().to_string()),
            ("addr_file", json::string(&addr_file)),
            ("log", json::string(&log_file)),
        ]));
    }

    let addrs = wait_for_tailcat_addresses(members.len())?;

    let mut forward_children: Vec<std::process::Child> = Vec::new();
    let mut forward_objects: Vec<String> = Vec::new();

    for (i, _) in members.iter().enumerate() {
        for (j, to) in members.iter().enumerate() {
            if i == j {
                continue;
            }
            let fwd = base + (i as u16) * 100 + j as u16;
            let log_file = format!("/tmp/tailcat-fwd-{i}-{j}.log");
            let log = File::create(&log_file).map_err(|e| format!("{log_file}: {e}"))?;
            let mut cmd = Command::new(tailcat_bin);
            cmd.arg("--key=new")
                .arg("forward")
                .arg(&addrs[j])
                .arg(format!("{fwd}:{}:{}", to.listen, to.port))
                .stdout(Stdio::from(log))
                .stderr(Stdio::from(
                    File::create(format!("/tmp/tailcat-fwd-{i}-{j}.err"))
                        .map_err(|e| format!("stderr log {i}-{j}: {e}"))?,
                ));
            let child = cmd.spawn().map_err(|e| format!("{tailcat_bin}: {e}"))?;
            forward_children.push(child);
            forward_objects.push(json::object(vec![
                ("from", i.to_string()),
                ("to", j.to_string()),
                ("local_port", fwd.to_string()),
                (
                    "pid",
                    forward_children[forward_children.len() - 1]
                        .id()
                        .to_string(),
                ),
                ("remote_addr", json::string(&addrs[j])),
                ("remote_host", json::string(&to.listen)),
                ("remote_port", to.port.to_string()),
                ("log", json::string(&log_file)),
            ]));
        }
    }

    let _children = (serve_children, forward_children);
    crate::rooms::emit(json::object(vec![
        ("serves", json::array(serve_objects)),
        ("forwards", json::array(forward_objects)),
    ]))
}

fn wait_for_tailcat_addresses(count: usize) -> Result<Vec<String>, String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut addrs: Vec<Option<String>> = vec![None; count];
    while Instant::now() < deadline {
        for (i, slot) in addrs.iter_mut().enumerate() {
            if slot.is_some() {
                continue;
            }
            let path = format!("/tmp/tailcat-addr-{i}.txt");
            if let Ok(text) = std::fs::read_to_string(&path) {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    *slot = Some(trimmed.to_owned());
                }
            }
        }
        if addrs.iter().all(|a| a.is_some()) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let missing: Vec<usize> = addrs
        .iter()
        .enumerate()
        .filter(|(_, a)| a.is_none())
        .map(|(i, _)| i)
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "tailcat serve(s) never wrote an address: {missing:?}. Check /tmp/tailcat-serve-*.log"
        ));
    }
    Ok(addrs.into_iter().flatten().collect())
}
