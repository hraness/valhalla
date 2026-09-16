#![cfg(unix)]
//! Support remains separate from identity output, custody and ordinary failures.
use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-support-{:032x}",
            u128::from_be_bytes(nonce)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vhalla"));
        command
            .env("XDG_STATE_HOME", &self.0)
            .env("HRANESS_SUPPORT", "on")
            .env("HRANESS_SUPPORT_AUDIENCE", "agent");
        for key in [
            "CI",
            "CONTINUOUS_INTEGRATION",
            "GITHUB_ACTIONS",
            "TF_BUILD",
            "BUILD_NUMBER",
            "TEAMCITY_VERSION",
            "JENKINS_URL",
        ] {
            command.env_remove(key);
        }
        command
    }
    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

#[test]
fn explicit_protocol_is_pure_and_support_only() {
    let fixture = Fixture::new();
    let result = fixture.run(&["support", "protocol", "--json"]);
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    let protocol = json(&result.stdout);
    assert_eq!(
        protocol["commands"]["offer"],
        serde_json::json!(["vhalla", "support", "offer", "--json"])
    );
    assert_eq!(protocol["offer"]["actions"].as_array().unwrap().len(), 1);
    assert_eq!(
        protocol["offer"]["actions"][0]["url"],
        "https://account.hraness.com/support?product=valhalla&source=agent#support"
    );
    assert!(!fixture.0.join("hraness").exists());
    assert!(fixture.run(&["support", "dismiss"]).status.success());
    assert_eq!(
        json(&fixture.run(&["support", "offer", "--json"]).stdout)["reason"],
        "dismissed"
    );
    assert!(fixture.run(&["support", "--json"]).status.success());
}

#[test]
fn useful_identity_creation_discovers_after_unchanged_stdout_and_never_on_probes_or_failure() {
    let fixture = Fixture::new();
    let identity = fixture.0.join("identity");
    assert!(fixture.run(&["--help"]).status.success());
    assert!(!fixture
        .run(&["identity", "unknown", "unused"])
        .status
        .success());
    assert!(!fixture.0.join("hraness").exists());
    let created = fixture
        .command()
        .args(["identity", "init"])
        .arg(&identity)
        .output()
        .unwrap();
    assert!(created.status.success());
    assert_eq!(
        json(&created.stderr)["schemaVersion"],
        "hraness-support-discovery-v1"
    );
    let shown = fixture
        .command()
        .args(["identity", "show"])
        .arg(&identity)
        .output()
        .unwrap();
    assert!(shown.status.success());
    assert_eq!(shown.stdout, created.stdout);
    assert!(shown.stderr.is_empty());
    let status = json(&fixture.run(&["support", "status", "--json"]).stdout);
    assert!(status["lastShownAt"].is_null());
    assert!(status["reservationExpiresAt"].is_null());
    let failed = fixture
        .command()
        .args(["identity", "init"])
        .arg(&identity)
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(!String::from_utf8_lossy(&failed.stderr).contains("hraness-support-discovery"));
    let next = fixture
        .command()
        .args(["identity", "init"])
        .arg(fixture.0.join("second"))
        .output()
        .unwrap();
    assert!(next.status.success());
    assert!(next.stderr.is_empty());
}

#[test]
fn unavailable_support_storage_does_not_change_success() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("hraness"), "retained").unwrap();
    let result = fixture
        .command()
        .args(["identity", "init"])
        .arg(fixture.0.join("identity"))
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    assert!(String::from_utf8_lossy(&result.stdout).starts_with("application-key "));
    assert_eq!(
        fs::read_to_string(fixture.0.join("hraness")).unwrap(),
        "retained"
    );
}
