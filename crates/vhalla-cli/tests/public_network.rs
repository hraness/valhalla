//! Native pinned-bootstrap publication and refusal regressions.
#![cfg(all(unix, feature = "experimental-public"))]
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_core::RealmId;
use vhalla_social::archive::Limits;
struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "vhalla-public-bootstrap-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .args(args)
        .output()
        .unwrap()
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn bootstrap_export_binds_frozen_genesis_checks_pin_and_never_overwrites() {
    let home = Home::new();
    let social = home.0.join("genesis-social");
    drop(vhalla_social_store::Store::create(&social, RealmId(1), Limits::default()).unwrap());
    let key = vhalla_rooms_node::PrivateKey::from([7; 32]);
    let config = serde_json::json!({"realm":format!("{:032x}",1),"directory":hex(&[2;32]),"policy":{"base_cost":8,"window_seconds":86400,"max_in_window":1,"support_epoch_seconds":86400,"max_lifetime_rooms":8},"eligible":[],"limits":{"records":1024,"control_reserve":128,"data_per_owner":128,"data_per_writer":64,"control_per_owner":32,"pending":128,"pending_per_signer":8},"validators":[{"from":1,"key":hex(key.public_key().as_bytes()),"power":1}]});
    let config_path = home.0.join("network.json");
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let out = home.0.join("network.vhbootstrap");
    let result = run(&[
        "public".as_ref(),
        "bootstrap-export".as_ref(),
        config_path.as_os_str(),
        social.as_os_str(),
        out.as_os_str(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    let pin = stdout
        .lines()
        .find_map(|l| l.strip_prefix("bootstrap-pin "))
        .unwrap();
    assert_eq!(pin.len(), 64);
    assert!(stdout.contains("network-id "));
    let bytes = fs::read(&out).unwrap();
    let result = run(&[
        "public".as_ref(),
        "bootstrap-check".as_ref(),
        out.as_os_str(),
        pin.as_ref(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(stdout, String::from_utf8(result.stdout).unwrap());
    let repeated = run(&[
        "public".as_ref(),
        "bootstrap-export".as_ref(),
        config_path.as_os_str(),
        social.as_os_str(),
        out.as_os_str(),
    ]);
    assert!(!repeated.status.success());
    assert_eq!(fs::read(&out).unwrap(), bytes);
    let wrong = hex(&[0; 32]);
    assert!(!run(&[
        "public".as_ref(),
        "bootstrap-check".as_ref(),
        out.as_os_str(),
        wrong.as_ref()
    ])
    .status
    .success());
    let alias = home.0.join("symlink");
    std::os::unix::fs::symlink(&out, &alias).unwrap();
    assert!(!run(&[
        "public".as_ref(),
        "bootstrap-check".as_ref(),
        alias.as_os_str(),
        pin.as_ref()
    ])
    .status
    .success());
    let mut tampered = bytes;
    *tampered.last_mut().unwrap() ^= 1;
    fs::write(&out, tampered).unwrap();
    assert!(!run(&[
        "public".as_ref(),
        "bootstrap-check".as_ref(),
        out.as_os_str(),
        pin.as_ref()
    ])
    .status
    .success());
}
