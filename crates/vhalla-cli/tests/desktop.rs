#![cfg(unix)]
//! This computer: the outputs folder, saved room status and the retired
//! menu bar command.
use std::process::Command;

#[test]
fn outputs_creates_and_prints_the_directory() {
    let home = std::env::temp_dir().join(format!("vhalla-desktop-test-{}", std::process::id()));
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .arg("outputs")
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed = String::from_utf8(output.stdout).unwrap();
    let dir = printed.trim();
    assert!(dir.ends_with("outputs"), "{dir}");
    assert!(std::path::Path::new(dir).is_dir());
    let _ = std::fs::remove_dir_all(&home);
}

/// Every form of the retired `menubar` command names its replacement,
/// exits non-zero and changes nothing on disk.
#[test]
fn menubar_is_retired_and_changes_nothing() {
    let home = std::env::temp_dir().join(format!("vhalla-menubar-retired-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    for args in [
        &["menubar"][..],
        &["menubar", "install"],
        &["menubar", "status"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .env("HOME", &home)
            .env("XDG_DATA_HOME", home.join("data"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        let text = String::from_utf8_lossy(&output.stderr);
        assert!(text.contains("The menu bar is retired."), "{args:?} {text}");
        assert!(text.contains("vhalla status"), "{args:?} {text}");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .env("HOME", &home)
        .args(["menubar", "--json"])
        .output()
        .unwrap();
    let line = String::from_utf8(output.stdout).unwrap();
    assert!(line.starts_with("{\"ok\":false,"), "{line}");
    assert!(line.contains("\"code\":\"valhalla.retired\""), "{line}");
    assert_eq!(std::fs::read_dir(&home).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn outputs_rejects_extra_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .args(["outputs", "extra"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unknown outputs command extra."));
}

/// `menubar refresh` was a released verb: it still refreshes, as
/// `status refresh` with the same arguments, and names the new spelling.
#[test]
fn menubar_refresh_still_refreshes_as_status_refresh() {
    let home = std::env::temp_dir().join(format!("vhalla-menubar-refresh-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .args([
            "menubar",
            "refresh",
            "/missing/social",
            "/missing/replica",
            "realm",
            "/missing/node",
            "--config",
            "/missing/node.toml",
            "--json",
        ])
        .env("HOME", &home)
        .env("XDG_DATA_HOME", home.join("data"))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(
        text.contains("vhalla menubar refresh is now vhalla status refresh"),
        "{text}"
    );
    let line = String::from_utf8(output.stdout).unwrap();
    assert!(!line.contains("valhalla.retired"), "{line}");
    let root = if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Valhalla")
    } else {
        home.join("data/valhalla")
    };
    assert!(root.join("room-status.json").is_file());
    // Too few arguments is the same usage error `status refresh` gives.
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .env("HOME", &home)
        .env("XDG_DATA_HOME", home.join("data"))
        .args(["menubar", "refresh", "a"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("status refresh needs"));
    let _ = std::fs::remove_dir_all(&home);
}

/// `status refresh` always leaves `status` an answer: counts, or a fixed
/// code when room status can't be read. It writes only `room-status.json`:
/// no file for the retired menu bar, nothing in the outputs folder.
#[test]
fn status_refresh_saves_only_room_status() {
    let home = std::env::temp_dir().join(format!("vhalla-refresh-test-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .args([
            "status",
            "refresh",
            "/missing/social",
            "/missing/replica",
            "realm",
            "/missing/node",
            "--config",
            "/missing/node.toml",
        ])
        .env("HOME", &home)
        .env("XDG_DATA_HOME", home.join("data"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let root = if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Valhalla")
    } else {
        home.join("data/valhalla")
    };
    let saved = std::fs::read_to_string(root.join("room-status.json")).unwrap();
    assert!(
        saved.starts_with("{\"schemaVersion\":1,\"refreshedAt\":"),
        "{saved}"
    );
    assert!(saved.contains("\"error\":\""), "{saved}");
    assert!(!root.join("menubar-status.json").exists());
    assert!(!root.join("outputs").exists());
    let _ = std::fs::remove_dir_all(&home);
}
