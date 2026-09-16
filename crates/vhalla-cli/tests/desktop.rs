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
    assert!(String::from_utf8_lossy(&output.stderr).contains("not built"));
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
    assert!(text.contains("installed: none"), "{text}");
    if cfg!(target_os = "macos") {
        assert!(text.contains("launch agent: none"), "{text}");
    }
    assert!(text.contains("nothing qualified"), "{text}");
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
    let _ = std::fs::remove_dir_all(&home);
}
