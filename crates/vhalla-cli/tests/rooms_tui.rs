#![cfg(unix)]
//! The `rooms tui` command surface: feature gating and argument checks.
//! The interactive loop needs a real terminal, so coverage here stops at
//! the CLI boundary; the model itself is fully tested inside
//! `vhalla-rooms-tui` on ratatui's `TestBackend`.

#[cfg(all(
    feature = "experimental-rooms-node",
    not(feature = "experimental-rooms-tui")
))]
#[test]
fn tui_command_reports_missing_feature() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .args([
            "rooms",
            "tui",
            "unused",
            "unused",
            "00000000000000000000000000000047",
            "unused",
            "--config",
            "unused",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("experimental-rooms-tui"));
}

#[cfg(feature = "experimental-rooms-tui")]
mod enabled {
    use std::process::Command;

    #[test]
    fn tui_requires_config() {
        let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .args([
                "rooms",
                "tui",
                "unused",
                "unused",
                "00000000000000000000000000000047",
                "unused",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("--config"));
    }

    #[test]
    fn tui_rejects_missing_node_home() {
        let dir = std::env::temp_dir().join(format!("vhalla-tui-args-{}", std::process::id()));
        let config = dir.join("config.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&config, "{}").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .args([
                "rooms",
                "tui",
                "unused",
                "unused",
                "00000000000000000000000000000047",
                "--config",
                config.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("NODE_HOME"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
