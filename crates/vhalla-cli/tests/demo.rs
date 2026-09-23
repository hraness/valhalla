#![cfg(unix)]
#![allow(missing_docs)]
//! Real CLI subprocess runs of the narrated local demo.

#[cfg(not(feature = "experimental-social"))]
#[test]
fn demo_is_absent_from_the_default_build() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .args(["demo"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("experimental-social"));
}

#[cfg(feature = "experimental-social")]
mod enabled {
    use std::process::{Command, Output};

    fn demo(args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args(args)
            .output()
            .unwrap()
    }

    #[test]
    fn demo_completes_the_full_local_exchange() {
        let output = demo(&["demo"]);
        assert!(output.status.success(), "{:?}", output);
        let stdout = String::from_utf8(output.stdout).unwrap();
        for marker in [
            "Two owners appear",
            "Alice enrolls an agent",
            "The agent writes",
            "The owner seals the chain",
            "Alice exports her history",
            "Bob imports it and replies",
            "The exchange comes back",
            "Where it all lives",
            "State from this run:",
        ] {
            assert!(stdout.contains(marker), "missing '{marker}' in:\n{stdout}");
        }
        // Every narrated command actually ran and returned JSON.
        assert_eq!(stdout.matches("$ vhalla social ").count(), 12);
        assert_eq!(stdout.matches("\"durable\":true").count(), 11);
        // The readback shows both members' posts committed in one thread.
        assert!(stdout.contains("First signed post from the demo agent."));
        assert!(stdout.contains("Signed and received. Who else is in here?"));
        assert!(stdout.contains("\"state\":\"committed\""));
        // The scratch directory exists, is owner-only, and is printed.
        let state = stdout
            .lines()
            .find(|line| line.starts_with("State from this run: "))
            .unwrap()
            .trim_start_matches("State from this run: ");
        let metadata = std::fs::metadata(state).unwrap();
        assert!(metadata.is_dir());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        std::fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn demo_rejects_extra_arguments_and_prints_help() {
        let output = demo(&["demo", "extra"]);
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("usage: vhalla demo"));
        let help = demo(&["demo", "--help"]);
        assert!(help.status.success());
        let stdout = String::from_utf8(help.stdout).unwrap();
        assert!(stdout.contains("vhalla demo"));
        assert!(stdout.contains("nothing touches the network"));
    }
}
