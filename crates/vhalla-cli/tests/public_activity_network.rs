//! Real CLI local peer selection; never dials or signs authored room content.
#![cfg(all(unix, feature = "experimental-public"))]
use ed25519_dalek::SigningKey;
use std::{
    ffi::OsString,
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_public_client::{Bootstrap, Validator, ValidatorActivation};
use vhalla_public_protocol::{
    AdvertisementClaims, Capabilities, Endpoint, UnsignedAdvertisement, PROTOCOL_VERSION,
};
use vhalla_rooms_consensus::fixture;
static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Home {
    path: PathBuf,
    pin: [u8; 32],
    peer: [u8; 32],
    raw: Vec<u8>,
}
impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vhalla-native-peer-cli-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let scenario = fixture::scenario(1, 1);
        let validators = (101..=104)
            .map(|s| SigningKey::from_bytes(&[s; 32]))
            .collect::<Vec<_>>();
        let bootstrap = Bootstrap::from_genesis(
            scenario.genesis,
            vec![ValidatorActivation {
                from: 1,
                validators: validators
                    .iter()
                    .map(|k| Validator {
                        public_key: k.verifying_key().to_bytes(),
                        power: 1,
                    })
                    .collect(),
            }],
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[56; 32]);
        let peer = key.verifying_key().to_bytes();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let raw = UnsignedAdvertisement::new(AdvertisementClaims {
            network: bootstrap.network_id(),
            application_key: peer,
            sequence: 1,
            issued_at: now,
            expires_at: now + 3600,
            protocol: PROTOCOL_VERSION,
            capabilities: Capabilities::READ,
            endpoints: vec![Endpoint::parse("https://explicit.vhalla.dev:443/vhalla/v1").unwrap()],
        })
        .unwrap()
        .sign_with_key(&key)
        .unwrap()
        .encode();
        fs::write(path.join("bootstrap"), bootstrap.encode()).unwrap();
        fs::write(path.join("ad"), &raw).unwrap();
        Self {
            path,
            pin: bootstrap.pin(),
            peer,
            raw,
        }
    }
    fn args(&self, state: &str) -> Vec<OsString> {
        vec![
            "public".into(),
            "activity".into(),
            "peer-add".into(),
            self.path.join("bootstrap").into(),
            hex(&self.pin).into(),
            self.path.join(state).into(),
            hex(&self.peer).into(),
            "https://explicit.vhalla.dev:443/vhalla/v1".into(),
            self.path.join("ad").into(),
        ]
    }
    fn run(&self, args: &[OsString]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .args(args)
            .output()
            .unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn peer_add_cli_pins_exact_bootstrap_key_and_https_route_without_a_dial() {
    let home = Home::new();
    for change in 0..5 {
        let name = format!("refused-{change}");
        let mut args = home.args(&name);
        match change {
            0 => args[4] = hex(&[99; 32]).into(),
            1 => {
                args[6] = hex(&SigningKey::from_bytes(&[57; 32]).verifying_key().to_bytes()).into()
            }
            2 => args[7] = "https://other.vhalla.dev:443/vhalla/v1".into(),
            3 => args[7] = "http://127.0.0.1:80/vhalla/v1".into(),
            _ => {
                let ad = vhalla_public_protocol::PeerAdvertisement::decode(&home.raw).unwrap();
                let mut claims = ad.unverified_claims().clone();
                claims.issued_at = 1000;
                claims.expires_at = 1100;
                fs::write(
                    home.path.join("expired"),
                    UnsignedAdvertisement::new(claims)
                        .unwrap()
                        .sign_with_key(&SigningKey::from_bytes(&[56; 32]))
                        .unwrap()
                        .encode(),
                )
                .unwrap();
                args[8] = home.path.join("expired").into();
            }
        }
        let output = home.run(&args);
        assert!(!output.status.success(), "{change}");
        assert!(!home.path.join(name).exists());
        assert_eq!(fs::read(home.path.join("ad")).unwrap(), home.raw);
    }
    let args = home.args("selected");
    let output = home.run(&args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "selected-and-retained-no-dial");
    assert_eq!(report["peer"], hex(&home.peer));
    let retained = fs::read(home.path.join("selected/STATE")).unwrap();
    assert!(!home.run(&args).status.success());
    assert_eq!(
        fs::read(home.path.join("selected/STATE")).unwrap(),
        retained
    );
}
