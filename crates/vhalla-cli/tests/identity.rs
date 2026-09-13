#![cfg(unix)]
//! Real CLI identity lifecycle.
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf, process::Command};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path =
            std::env::temp_dir().join(format!("vhalla-cli-{:032x}", u128::from_be_bytes(nonce)));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn child(&self) -> PathBuf {
        self.0.join("identity")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn cli_initializes_once_and_shows_only_the_same_public_key() {
    let dir = Temp::new();
    let run = |operation: &str| {
        Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .args(["identity", operation])
            .arg(dir.child())
            .output()
            .unwrap()
    };
    let created = run("init");
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let shown = run("show");
    assert!(shown.status.success());
    assert_eq!(created.stdout, shown.stdout);
    let public = String::from_utf8(created.stdout).unwrap();
    let hex = public.trim().strip_prefix("application-key ").unwrap();
    assert_eq!(hex.len(), 64);
    assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(!run("init").status.success());
    assert_eq!(run("show").stdout, shown.stdout);
}

#[cfg(not(feature = "experimental-network"))]
#[test]
fn network_commands_are_absent_from_default_build() {
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .args(["experimental", "listen", "unused", "unused"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("require an explicit build"));
}
