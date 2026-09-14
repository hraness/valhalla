#![cfg(unix)]
//! Desktop companion command surface.
use std::process::Command;

#[test]
fn outputs_creates_and_prints_the_directory() {
    let home = std::env::temp_dir().join(format!("vhalla-desktop-test-{}", std::process::id()));
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
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
