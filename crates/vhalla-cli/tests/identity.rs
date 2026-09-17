#![cfg(unix)]
//! Real CLI identity lifecycle.
use std::{
    fs,
    io::Write,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Command, Stdio},
};
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
            .env("HRANESS_SUPPORT", "off")
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

#[test]
fn cli_backup_and_restore_round_trips_the_same_public_key() {
    let src = Temp::new();
    let dst = Temp::new();
    let run = |operation: &str, args: &[&str], input: Option<&str>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vhalla"));
        cmd.env("HRANESS_SUPPORT", "off")
            .args(["identity", operation]);
        for a in args {
            cmd.arg(a);
        }
        if let Some(s) = input {
            cmd.stdin(Stdio::piped());
            let mut child = cmd.spawn().unwrap();
            child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
            child.wait_with_output().unwrap()
        } else {
            cmd.output().unwrap()
        }
    };
    let created = run("init", &[src.child().to_str().unwrap()], None);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let backed = run("backup", &[src.child().to_str().unwrap()], None);
    assert!(
        backed.status.success(),
        "{}",
        String::from_utf8_lossy(&backed.stderr)
    );
    let text = String::from_utf8(backed.stdout).unwrap();
    let (phrase_line, public_line) = text
        .lines()
        .next()
        .and_then(|first| text.lines().nth(1).map(|second| (first, second)))
        .unwrap();
    let phrase = phrase_line
        .strip_prefix("mnemonic ")
        .expect("backup prints a mnemonic line");
    let public = public_line
        .strip_prefix("application-key ")
        .expect("backup prints the application key");
    let restored = run(
        "restore",
        &[dst.child().to_str().unwrap()],
        Some(phrase),
    );
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    let shown = run("show", &[dst.child().to_str().unwrap()], None);
    assert!(shown.status.success());
    let shown_public = String::from_utf8(shown.stdout)
        .unwrap()
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("application-key "))
        .unwrap()
        .to_owned();
    assert_eq!(public, shown_public, "restore must reproduce the same key");
}

#[cfg(not(feature = "experimental-network"))]
#[test]
fn network_commands_are_absent_from_default_build() {
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .args(["experimental", "listen", "unused", "unused"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("require an explicit build"));
}
