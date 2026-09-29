#![cfg(windows)]
//! The Windows release binary: help, version, identity custody and a clear
//! refusal for the commands that run only on macOS and Linux.
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path =
            std::env::temp_dir().join(format!("vhalla-win-{:032x}", u128::from_be_bytes(nonce)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn vhalla(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .env("HRANESS_SUPPORT_AUDIENCE", "off")
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap()
}

fn text(args: &[&str]) -> Output {
    let args: Vec<&std::ffi::OsStr> = args.iter().map(std::ffi::OsStr::new).collect();
    vhalla(&args)
}

#[test]
fn help_and_version_answer() {
    let help = text(&["--help"]);
    assert!(help.status.success());
    let page = String::from_utf8(help.stdout).unwrap();
    assert!(page.contains("Usage: vhalla <command>"), "{page}");
    assert!(page.contains("identity"), "{page}");

    let version = text(&["--version"]);
    assert!(version.status.success());
    let line = String::from_utf8(version.stdout).unwrap();
    assert!(
        line.starts_with(&format!("vhalla {} features=[", env!("CARGO_PKG_VERSION"))),
        "{line}"
    );
}

#[test]
fn identity_initializes_once_and_shows_the_same_key() {
    let temp = Temp::new();
    let dir = temp.0.join("identity");
    let run = |operation: &str| {
        vhalla(&[
            std::ffi::OsStr::new("identity"),
            std::ffi::OsStr::new(operation),
            dir.as_os_str(),
        ])
    };
    let created = run("init");
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let shown = run("show");
    assert!(
        shown.status.success(),
        "{}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let key = String::from_utf8(shown.stdout).unwrap();
    assert!(!key.trim().is_empty());
    assert!(
        String::from_utf8_lossy(&created.stdout).contains(key.trim()),
        "init output should name the key that show reports"
    );
    let again = run("init");
    assert!(
        !again.status.success(),
        "an existing identity is never replaced"
    );
}

#[test]
fn unix_only_commands_name_the_linux_build() {
    for command in ["rooms", "status", "demo", "private-host", "public"] {
        let output = text(&[command]);
        assert_eq!(output.status.code(), Some(1), "{command}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("runs only on macOS and Linux"),
            "{command}: {error}"
        );
        assert!(error.contains("WSL"), "{command}: {error}");
    }
}
