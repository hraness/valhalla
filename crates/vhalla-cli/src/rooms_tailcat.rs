#![cfg(all(unix, feature = "experimental-rooms-node"))]
//! Tailcat overlay planner for room-consensus meshes.
//!
//! Tailcat (`tailscale/tailcat`) provides account-less, userspace TCP
//! tunnels that are useful for carrying the libp2p mesh traffic across
//! different networks. This module is a pure planner: it reads the
//! per-member `node.json` files produced by `rooms node-init`, allocates
//! the local forward-port namespace, and emits an executable plan so an
//! operator (or a supervisor script) can spawn the `tailcat serve` and
//! `tailcat forward` processes and the matching `peers` CSV for each
//! member.

use std::{ffi::OsString, path::Path};

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

/// Plan a tailcat mesh from a list of `node.json` files.
///
/// Usage: `vhalla rooms tailcat plan --nodes NODE.json... --base-port N`
///
/// For N members the plan needs N `tailcat serve` processes and
/// N*(N-1) `tailcat forward` processes. Each member `i` dials its peers
/// at `127.0.0.1:<base + i*100 + j>` where `j != i`. The emitted JSON
/// contains the commands and the resulting `peers` CSV for each
/// `node-init --peers` call.
pub fn run(args: Vec<OsString>) -> Result<(), String> {
    let mut nodes: Vec<String> = Vec::new();
    let mut base_port = 17_000u16;
    let mut output = "json".to_string();
    let mut i = 0;
    while i < args.len() {
        let value = args[i]
            .to_str()
            .ok_or("tailcat arguments must be UTF-8")?
            .to_owned();
        match value.as_str() {
            "plan" => {}
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
            _ => return Err(HELP.into()),
        }
        i += 1;
    }
    if nodes.len() < 2 {
        return Err("tailcat plan needs at least two --nodes node.json files".into());
    }
    if output != "json" && output != "shell" {
        return Err("--output must be json or shell".into());
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
    if output == "json" {
        emit_json(&members, base_port)
    } else {
        emit_shell(&members, base_port)
    }
}

const HELP: &str = "vhalla rooms tailcat plan --nodes A/node.json B/node.json ... [--base-port N] [--output json|shell]";

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
