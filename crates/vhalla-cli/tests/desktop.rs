#![cfg(unix)]
//! Desktop companion command surface.
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

#[test]
fn menubar_reports_a_missing_binary() {
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .arg("menubar")
        .env("VHALLA_MENUBAR_PATH", "/definitely/missing/vhalla-menubar")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("doesn't name a usable menu bar"));
}

#[test]
fn menubar_without_a_binary_points_to_the_installer() {
    let home = std::env::temp_dir().join(format!("vhalla-menubar-none-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .env("HRANESS_AUDIENCE", "human")
        .env("LANG", "en_US.UTF-8")
        .env_remove("VHALLA_MENUBAR_PATH")
        .arg("menubar")
        .env("HOME", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stderr);
    // A checkout with a release build finds it; otherwise the installer is next.
    if !output.status.success() {
        assert!(
            text.starts_with("✗ The Valhalla menu bar isn't on this Mac yet."),
            "{text}"
        );
        assert!(
            text.contains("install.sh | sh -s -- --with-menubar"),
            "{text}"
        );
        assert!(text.contains("→ vhalla menubar install"), "{text}");
        assert!(!text.contains("cargo build"), "{text}");
    }
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn menubar_and_outputs_reject_extra_arguments() {
    for command in ["menubar", "outputs"] {
        let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args([command, "extra"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("usage:"),
            "{command}"
        );
    }
}

#[test]
fn menubar_status_reports_an_uninstalled_companion() {
    let home = std::env::temp_dir().join(format!("vhalla-menubar-test-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .args(["menubar", "status"])
        .env("HOME", &home)
        .env("VHALLA_MENUBAR_PATH", "/definitely/missing/vhalla-menubar")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.starts_with("Valhalla's menu bar isn't installed."),
        "{text}"
    );
    assert!(text.contains("vhalla menubar install"), "{text}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn menubar_rejects_an_unknown_subcommand() {
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .args(["menubar", "bogus"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
}

/// `install` with an unqualified override fails before touching launchd or
/// the state directory — the failure path must be side-effect free.
#[test]
fn menubar_install_requires_a_qualified_binary() {
    let home = std::env::temp_dir().join(format!("vhalla-install-test-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .args(["menubar", "install"])
        .env("HOME", &home)
        .env("VHALLA_MENUBAR_PATH", "/definitely/missing/vhalla-menubar")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!home.join("Library").exists());
    let _ = std::fs::remove_dir_all(&home);
}

/// `refresh` always leaves the menu an answer: counts, or a fixed code
/// when room status can't be read. It never writes into the outputs folder.
#[test]
fn menubar_refresh_saves_a_status_the_menu_can_read() {
    let home = std::env::temp_dir().join(format!("vhalla-refresh-test-{}", std::process::id()));
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
    let saved = std::fs::read_to_string(root.join("menubar-status.json")).unwrap();
    assert!(
        saved.starts_with("{\"schemaVersion\":1,\"refreshedAt\":"),
        "{saved}"
    );
    assert!(saved.contains("\"error\":\""), "{saved}");
    assert!(!saved.contains("/missing"), "{saved}");
    assert!(!root.join("outputs/rooms-status.json").exists());
    let _ = std::fs::remove_dir_all(&home);
}
