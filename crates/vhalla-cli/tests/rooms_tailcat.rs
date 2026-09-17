#![cfg(all(unix, feature = "experimental-rooms-node"))]
//! Planner output for tailcat overlay meshes.

use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf, process::Command};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-cli-tailcat-{:032x}",
            u128::from_be_bytes(nonce)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn child(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn tailcat_plan_emits_peers_for_each_member() {
    let tmp = Temp::new();
    let a = tmp.child("a.json");
    let b = tmp.child("b.json");
    fs::write(&a, r#"{"port":17001,"listen":"0.0.0.0","peers":""}"#).unwrap();
    fs::write(&b, r#"{"port":17002,"listen":"0.0.0.0","peers":""}"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .args([
            "rooms",
            "tailcat",
            "plan",
            "--nodes",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--base-port",
            "18000",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("planner output is JSON");
    let peers = value["peers"].as_array().expect("peers array");
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0]["peers"].as_str().unwrap(), "127.0.0.1:18001");
    assert_eq!(peers[1]["peers"].as_str().unwrap(), "127.0.0.1:18100");
    let forwards = value["forwards"].as_array().expect("forwards array");
    assert_eq!(forwards.len(), 2);
}
