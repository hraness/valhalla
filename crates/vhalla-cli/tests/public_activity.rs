//! Maintained CLI authoring under real certificates and durable restart state.
#![cfg(all(unix, feature = "experimental-public"))]
use ed25519_dalek::{Signer, SigningKey};
use std::{
    ffi::OsString,
    fs,
    path::PathBuf,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_journal::{Bundle, BundleParts, FsStore, Journal};
use vhalla_public_client::{Bootstrap, CertifiedClient, Validator, ValidatorActivation};
use vhalla_room_activity::{
    puzzle_share::{self, CollectStatus, Collector, Kind},
    RoomScope, SignedEvent,
};
use vhalla_rooms::{RoomGenesisId, RoomUpdate, Slug, UpdateAction};
use vhalla_rooms_consensus::fixture;

struct Home {
    path: PathBuf,
    scenario: fixture::Scenario,
    validators: Vec<SigningKey>,
    pin: [u8; 32],
    network: [u8; 32],
    genesis: [u8; 32],
    room: RoomGenesisId,
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vhalla-native-author-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        let scenario = fixture::scenario(1, 1);
        let validators = (101..=104)
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .collect::<Vec<_>>();
        let bootstrap = Bootstrap::from_genesis(
            scenario.genesis.clone(),
            vec![ValidatorActivation {
                from: 1,
                validators: validators
                    .iter()
                    .map(|key| Validator {
                        public_key: key.verifying_key().to_bytes(),
                        power: 1,
                    })
                    .collect(),
            }],
        )
        .unwrap();
        let pin = bootstrap.pin();
        let network = bootstrap.network_id();
        fs::write(path.join("bootstrap"), bootstrap.encode()).unwrap();
        let genesis = CertifiedClient::new(bootstrap, pin)
            .unwrap()
            .frontier()
            .commitment();
        let mut home = Self {
            path,
            scenario,
            validators,
            pin,
            network,
            genesis,
            room: RoomGenesisId::from_bytes([0; 32]),
        };
        let mut cursor = 0;
        let (evidence, records, _) = fixture::first_create(
            &home.scenario.app,
            &home.scenario.owners[0],
            &mut home.scenario.sources,
            &mut cursor,
            "author-lobby",
            1,
        );
        home.commit(100, evidence, records, false);
        home.room = home
            .scenario
            .app
            .registry()
            .room(&Slug::new("author-lobby").unwrap())
            .unwrap()
            .genesis();
        home.policy(true);
        home
    }
    fn commit(&mut self, at: u64, evidence: Vec<Vec<u8>>, records: Vec<Vec<u8>>, corrupt: bool) {
        let checked = self
            .scenario
            .app
            .prepare(at, evidence, records, None)
            .unwrap();
        let next = checked.next();
        let batch = checked.batch();
        let value = batch.value_id();
        let mut certificate = b"VC2".to_vec();
        certificate.extend_from_slice(&next.height.to_be_bytes());
        certificate.extend_from_slice(&0u32.to_be_bytes());
        certificate.extend_from_slice(&value);
        certificate.extend_from_slice(&3u16.to_be_bytes());
        for key in &self.validators[..3] {
            let public =
                vhalla_rooms_node::PublicKey::from_bytes(key.verifying_key().to_bytes()).unwrap();
            let address = vhalla_rooms_node::Address::from_public_key(&public).into_inner();
            let mut vote = b"RV1".to_vec();
            vote.push(1);
            vote.extend_from_slice(&next.height.to_be_bytes());
            vote.extend_from_slice(&0u32.to_be_bytes());
            vote.push(1);
            vote.extend_from_slice(&value);
            vote.extend_from_slice(&address);
            certificate.extend_from_slice(&address);
            certificate.extend_from_slice(&key.sign(&vote).to_bytes());
        }
        if corrupt {
            *certificate.last_mut().unwrap() ^= 1;
        }
        let bundle = Bundle::new(BundleParts {
            certificate,
            predecessor: batch.parent.commitment(),
            next: next.commitment(),
            batch: batch.encode(),
            value: value.to_vec(),
            configuration: self.scenario.genesis.policy.id().as_bytes().to_vec(),
            control_record: next.control.to_vec(),
            debit_marker: next.value.to_vec(),
            height: next.height,
        })
        .unwrap();
        Journal::with_genesis(self.path.join("journal"), FsStore, self.genesis)
            .commit(&bundle)
            .unwrap();
        self.scenario.app.apply_locally(checked);
    }
    fn policy(&mut self, enabled: bool) {
        let room = self
            .scenario
            .app
            .registry()
            .room_by_genesis(self.room)
            .unwrap();
        let owner = &self.scenario.owners[0];
        let height = self.scenario.app.frontier().height + 1;
        let update = RoomUpdate {
            directory: self.scenario.genesis.directory,
            realm: self.scenario.genesis.realm,
            genesis: self.room,
            previous: room.head(),
            owner: owner.id,
            social_control: owner.head,
            controller_key: owner.key.verifying_key().to_bytes(),
            expires_at: 1_000_000,
            nonce: [height as u8; 32],
            action: UpdateAction::SetPublicActivityPolicy {
                network: self.network,
                enabled,
            },
        }
        .sign_with_key(&owner.key)
        .unwrap();
        self.commit(height * 100, vec![], vec![update.encode()], false);
    }
    fn args(&self, command: &str) -> Vec<OsString> {
        vec![
            "public".into(),
            "activity".into(),
            command.into(),
            self.path.join("bootstrap").into(),
            hex(&self.pin).into(),
            self.path.join("journal").into(),
            self.path.join("key").into(),
            self.path.join("outbox").into(),
            hex(self.room.as_bytes()).into(),
        ]
    }
    fn run(&self, command: &str, extras: &[OsString]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .args(self.args(command))
            .args(extras)
            .output()
            .unwrap()
    }
    fn text(&self, text: &str) -> OsString {
        let p = self.path.join("text");
        fs::write(&p, text).unwrap();
        p.into()
    }
    fn export(&self, name: &str) -> Vec<vhalla_room_activity::VerifiedEvent> {
        success(self.run("outbox", &["0".into(), self.path.join(name).into()]));
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(self.path.join(name).join("manifest.json")).unwrap())
                .unwrap();
        manifest["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| {
                SignedEvent::decode(
                    &fs::read(self.path.join(name).join(record["file"].as_str().unwrap())).unwrap(),
                )
                .unwrap()
                .verify()
                .unwrap()
            })
            .collect()
    }
    fn scope(&self) -> RoomScope {
        RoomScope {
            network: self.network,
            realm: self.scenario.genesis.realm,
            directory: self.scenario.genesis.directory,
            room: self.room,
        }
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn new_author_signed_restart_history_and_puzzle_export_roundtrip() {
    let home = Home::new();
    success(home.run("init", &[]));
    assert!(!home.run("init", &[]).status.success());
    let author = vhalla_identity::Identity::open(home.path.join("key"))
        .unwrap()
        .public_key();
    let raw = br#"{"att_native":"12"}"#;
    let parts = puzzle_share::pack(Kind::Responses, raw).unwrap();
    let part = puzzle_share::Part::decode(parts[0].as_str()).unwrap();
    let out = success(home.run("queue", &[home.text(parts[0].as_str())]));
    assert!(out.contains("author-sequence 1"));
    success(home.run("queue", &[home.text("A separate ordinary post")]));
    let events = home.export("export");
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].claims().previous, events[0].id());
    assert_eq!(events[1].claims().sequence, 2);
    let mut collector =
        Collector::new(home.scope(), author, Kind::Responses, *part.digest()).unwrap();
    assert_eq!(collector.push(&events[0]).unwrap(), CollectStatus::Complete);
    assert_eq!(collector.bytes().unwrap(), raw);
    assert!(!home
        .run("outbox", &["0".into(), home.path.join("export").into()])
        .status
        .success());
}

#[test]
fn exact_reservation_survives_restart_and_compatible_policy_head_advance() {
    let mut home = Home::new();
    success(home.run("init", &[]));
    let reserved = success(home.run("reserve", &[home.text("Retain this exact draft")]));
    let id = reserved
        .lines()
        .find_map(|line| line.strip_prefix("reserved-event "))
        .unwrap()
        .to_owned();
    assert!(home.export("before").is_empty());
    assert!(!home
        .run("queue", &[home.text("Must not replace pending content")])
        .status
        .success());
    home.commit(300, vec![], vec![], false);
    let resumed = success(home.run("resume", &[]));
    assert!(resumed.contains(&format!("event-id {id}")));
    assert!(!home.run("resume", &[]).status.success());
    let events = home.export("after");
    assert_eq!(events.len(), 1);
    assert_eq!(hex(events[0].id().as_bytes()), id);
}

#[test]
fn revoked_policy_preserves_reservation_and_absent_state_never_resets_author() {
    let mut home = Home::new();
    success(home.run("init", &[]));
    success(home.run("reserve", &[home.text("Retain through revocation")]));
    home.policy(false);
    let result = home.run("resume", &[]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("does not allow"));
    assert!(home.export("revoked-export").is_empty());
    fs::rename(home.path.join("outbox"), home.path.join("preserved-outbox")).unwrap();
    assert!(!home.run("queue", &[home.text("No reset")]).status.success());
    assert!(!home.path.join("outbox").exists());
    assert!(!home.run("init", &[]).status.success());
}

#[test]
fn wrong_bootstrap_and_invalid_certificate_never_create_author_paths() {
    let mut home = Home::new();
    let mut args = home.args("init");
    args[4] = hex(&[0; 32]).into();
    assert!(!Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .args(args)
        .output()
        .unwrap()
        .status
        .success());
    assert!(!home.path.join("key").exists());
    home.commit(300, vec![], vec![], true);
    assert!(!home.run("init", &[]).status.success());
    assert!(!home.path.join("key").exists());
    assert!(!home.path.join("outbox").exists());
}
