#![cfg(all(unix, feature = "experimental-rooms-node"))]
#![allow(missing_docs)]

use std::process::Command;

use vhalla_rooms_node::PrivateKey;

fn key(seed: u8) -> String {
    PrivateKey::from([seed; 32])
        .public_key()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn member(name: &str, seed: u8, address: &str, port: u16) -> String {
    format!("{name}={}@{address}:{port}", key(seed))
}

fn plan(profile: &str, members: &[String]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vhalla"));
    command.env("HRANESS_SUPPORT", "off").args([
        "rooms",
        "overlay",
        "plan",
        "--profile",
        profile,
        "--members",
    ]);
    for member in members {
        command.arg(member);
    }
    command.output().unwrap()
}

#[test]
fn tailscale_plan_emits_closed_pinned_members() {
    let output = plan(
        "tailscale",
        &[
            member("alice", 1, "100.64.0.1", 17001),
            member("bob", 2, "100.64.0.2", 17002),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["profile"], "tailscale");
    assert_eq!(value["path"], "direct-or-derp-relay");
    assert_eq!(value["supports_udp"], true);
    assert_eq!(value["live_qualified"], false);
    assert_eq!(value["members"][0]["name"], "alice");
    assert_eq!(value["members"][0]["public_key"], key(1));
    assert_eq!(value["members"][0]["listen"], "100.64.0.1");
    assert_eq!(value["members"][0]["peers_only"], true);
    assert_eq!(
        value["members"][0]["peers"],
        format!("{}@100.64.0.2:17002", key(2))
    );
    assert_eq!(
        value["members"][1]["peers"],
        format!("{}@100.64.0.1:17001", key(1))
    );
}

#[test]
fn cloudflare_mesh_plan_names_relayed_control_plane() {
    let output = plan(
        "cloudflare-mesh",
        &[
            member("alice", 3, "100.96.0.1", 17001),
            member("bob", 4, "100.96.0.2", 17002),
        ],
    );
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["control_plane"], "cloudflare-one");
    assert_eq!(value["path"], "cloudflare-edge-relay");
    assert_eq!(value["supports_tcp"], true);
    assert_eq!(value["supports_udp"], true);
}

#[test]
fn overlay_plan_rejects_public_duplicate_or_malformed_members() {
    let public = plan(
        "tailscale",
        &[
            member("alice", 5, "8.8.8.8", 17001),
            member("bob", 6, "100.64.0.2", 17002),
        ],
    );
    assert!(!public.status.success());
    assert!(String::from_utf8_lossy(&public.stderr).contains("must be RFC1918 or shared"));
    let duplicate = plan(
        "cloudflare-mesh",
        &[
            member("alice", 5, "100.96.0.1", 17001),
            member("alice", 6, "100.96.0.2", 17002),
        ],
    );
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("duplicate overlay member name"));
    let malformed = format!("alice={}@100.96.0.1:17001", "05".repeat(31));
    let malformed = plan(
        "cloudflare-mesh",
        &[malformed, member("bob", 6, "100.96.0.2", 17002)],
    );
    assert!(!malformed.status.success());
    assert!(String::from_utf8_lossy(&malformed.stderr).contains("key must be 64 hex"));
}
