//! Maintained CLI authoring under real certificates and durable restart state.
#![cfg(all(unix, feature = "experimental-public"))]
use ed25519_dalek::{Signer, SigningKey};
use std::{
    ffi::OsString,
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
        static NEXT_HOME: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vhalla-native-author-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_HOME.fetch_add(1, Ordering::Relaxed)
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
        let journal = Journal::with_genesis(self.path.join("journal"), FsStore, self.genesis);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match journal.commit(&bundle) {
                Ok(_) => break,
                // A sibling test can fork while this process holds the lock;
                // close-on-exec closes the child's inherited handle at exec,
                // but contention can briefly outlive our local handle. Retry
                // only contention, always using this exact certified bundle.
                Err(vhalla_journal::JournalError::Busy) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("fixture journal {}: {error}", self.path.display()),
            }
        }
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

fn replay_profile(home: &Home, command: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .args([
            OsString::from("public"),
            "activity".into(),
            command.into(),
            home.path.join("bootstrap").into(),
            hex(&home.pin).into(),
            home.path.join("journal").into(),
            home.path.join("replay").into(),
        ])
        .output()
        .unwrap()
}
fn with_profile(home: &Home, mut extras: Vec<OsString>) -> Vec<OsString> {
    extras.push("--replay-profile".into());
    extras.push(home.path.join("replay").into());
    extras
}
fn report_number(report: &str, name: &str) -> u64 {
    report
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name} ")))
        .unwrap()
        .parse()
        .unwrap()
}
fn retained_draft(home: &Home) -> Option<vhalla_browser_storage::outbox::ReservedDraft> {
    let identity = vhalla_identity::Identity::open(home.path.join("key")).unwrap();
    let store = vhalla_browser_storage::native::NativeOutbox::open(
        home.path.join("outbox"),
        vhalla_browser_storage::outbox::AuthorScope::new(home.scope(), identity.public_key()),
        vhalla_browser_storage::history::HistoryScope::new(home.network, home.pin),
    )
    .unwrap();
    store.load_pending().unwrap()
}

#[test]
fn replay_profile_crosses_4096_with_real_certificates_and_no_early_author() {
    let mut home = Home::new();
    for _ in 0..4099 {
        home.commit(home.scenario.app.frontier().time + 1, vec![], vec![], false);
    }
    let target = home.scenario.app.frontier().height;
    assert!(target > 4096);
    let created = success(replay_profile(&home, "replay-init"));
    assert!(created.contains("status replay-profile-created"));
    assert_eq!(report_number(&created, "durable-height"), 0);
    let first = success(replay_profile(&home, "replay-step"));
    assert!(first.contains("status more"), "{first}");
    assert_eq!(report_number(&first, "replayed-from"), 0);
    let mut at = report_number(&first, "durable-height");
    assert!(at > 0 && at <= 4096);
    assert!(!home.path.join("key").exists());
    assert!(!home.path.join("outbox").exists());
    for _ in 0..8 {
        let next = success(replay_profile(&home, "replay-step"));
        assert_eq!(report_number(&next, "replayed-from"), at);
        let end = report_number(&next, "durable-height");
        assert!(end > at && end - at <= 4096);
        at = end;
        if next.contains("status caught-up-local-journal") {
            break;
        }
    }
    assert_eq!(at, target);
    let initialized = success(home.run("init", &with_profile(&home, vec![])));
    assert!(initialized.contains("status new-local-author-ready"));
    let queued = success(home.run(
        "queue",
        &with_profile(&home, vec![home.text("after bounded verified catch-up")]),
    ));
    assert!(queued.contains("author-sequence 1"));
    let frames = home.export("checkpoint-export");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].claims().scope, home.scope());
}

#[test]
fn replay_profile_handoff_old_or_new_outbox_head_preserves_exact_pending_bytes() {
    let mut home = Home::new();
    success(replay_profile(&home, "replay-init"));
    success(home.run("init", &with_profile(&home, vec![])));
    success(home.run(
        "reserve",
        &with_profile(&home, vec![home.text("retained exact pending request")]),
    ));
    let draft = retained_draft(&home).unwrap();
    let old_outbox = fs::read(home.path.join("outbox/STATE")).unwrap();
    let old_profile = fs::read(home.path.join("replay/STATE")).unwrap();
    let bare = replay_profile(&home, "replay-step");
    assert!(!bare.status.success());
    assert!(String::from_utf8_lossy(&bare.stderr).contains("author anchor"));
    assert_eq!(
        fs::read(home.path.join("replay/STATE")).unwrap(),
        old_profile
    );

    home.commit(300, vec![], vec![], false);
    success(home.run("catch-up", &with_profile(&home, vec![])));
    assert_eq!(retained_draft(&home), Some(draft.clone()));
    // Model the crash just before the outbox advance: the new cache is durable
    // while the exact prior author STATE/pending remains. No signed bytes change.
    fs::write(home.path.join("outbox/STATE"), &old_outbox).unwrap();
    success(home.run("catch-up", &with_profile(&home, vec![])));
    assert_eq!(retained_draft(&home), Some(draft.clone()));
    // The other crash outcome has the advanced author head equal to the cache
    // frontier. A subsequent extension must rebind it before advancing again.
    home.commit(400, vec![], vec![], false);
    success(home.run("catch-up", &with_profile(&home, vec![])));
    assert_eq!(retained_draft(&home), Some(draft.clone()));
    let resumed = success(home.run("resume", &with_profile(&home, vec![])));
    assert!(resumed.contains("author-sequence 1"));
    let frames = home.export("resumed-checkpoint-export");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].id(), draft.request().id());
}

#[test]
fn replay_profile_tamper_refuses_before_signing_or_reservation_replacement() {
    let home = Home::new();
    success(replay_profile(&home, "replay-init"));
    success(home.run("init", &with_profile(&home, vec![])));
    success(home.run(
        "reserve",
        &with_profile(&home, vec![home.text("never replace this reservation")]),
    ));
    let old_outbox = fs::read(home.path.join("outbox/STATE")).unwrap();
    let draft = retained_draft(&home).unwrap();
    let mut damaged = fs::read(home.path.join("replay/STATE")).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(home.path.join("replay/STATE"), &damaged).unwrap();
    assert!(!home
        .run("resume", &with_profile(&home, vec![]))
        .status
        .success());
    assert_eq!(fs::read(home.path.join("replay/STATE")).unwrap(), damaged);
    assert_eq!(
        fs::read(home.path.join("outbox/STATE")).unwrap(),
        old_outbox
    );
    assert_eq!(retained_draft(&home), Some(draft));
    assert!(home.export("no-signed-checkpoint-export").is_empty());
}

#[test]
fn replay_profile_detects_lost_checkpoint_height_before_authoring() {
    let home = Home::new();
    success(replay_profile(&home, "replay-init"));
    success(home.run("init", &with_profile(&home, vec![])));
    let old_profile = fs::read(home.path.join("replay/STATE")).unwrap();
    let old_outbox = fs::read(home.path.join("outbox/STATE")).unwrap();
    let marker = home.path.join("journal/heights/0000000000000002");
    let original = fs::read(&marker).unwrap();
    fs::write(&marker, [0; 32]).unwrap();
    assert!(!home
        .run(
            "queue",
            &with_profile(
                &home,
                vec![home.text("must not sign against missing evidence")]
            )
        )
        .status
        .success());
    assert_eq!(
        fs::read(home.path.join("replay/STATE")).unwrap(),
        old_profile
    );
    assert_eq!(
        fs::read(home.path.join("outbox/STATE")).unwrap(),
        old_outbox
    );
    assert_eq!(fs::read(&marker).unwrap(), [0; 32]);
    fs::write(&marker, original).unwrap();
    success(home.run(
        "queue",
        &with_profile(&home, vec![home.text("healthy exact evidence restored")]),
    ));
}

#[test]
fn replay_profile_new_author_init_cannot_advance_or_replace_retained_anchor() {
    let mut home = Home::new();
    success(replay_profile(&home, "replay-init"));
    success(home.run("init", &with_profile(&home, vec![])));
    home.commit(300, vec![], vec![], false);
    for after_handoff in [false, true] {
        if after_handoff {
            success(home.run("catch-up", &with_profile(&home, vec![])));
        }
        let old = fs::read(home.path.join("replay/STATE")).unwrap();
        let mut args = home.args("init");
        args[6] = home.path.join("other-key").into();
        args[7] = home.path.join("other-outbox").into();
        args.extend(with_profile(&home, vec![]));
        let result = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .args(args)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("anchored replay profile"));
        assert_eq!(fs::read(home.path.join("replay/STATE")).unwrap(), old);
        assert!(!home.path.join("other-key").exists());
        assert!(!home.path.join("other-outbox").exists());
    }
}

#[test]
fn replay_profile_fresh_cache_rebuild_binds_existing_outbox_before_any_replay() {
    let mut home = Home::new();
    success(home.run("init", &[]));
    success(home.run(
        "reserve",
        &[home.text("preserve this author across cache loss")],
    ));
    let draft = retained_draft(&home).unwrap();
    success(replay_profile(&home, "replay-init"));
    success(home.run("catch-up", &with_profile(&home, vec![])));
    let mut old_cache = fs::read(home.path.join("replay/STATE")).unwrap();
    *old_cache.last_mut().unwrap() ^= 1;
    fs::write(home.path.join("replay/STATE"), &old_cache).unwrap();
    assert!(!home
        .run("catch-up", &with_profile(&home, vec![]))
        .status
        .success());
    // Preserve the entire unusable test profile. The application exposes no
    // reset/import command; recovery uses an explicitly different new path.
    fs::rename(home.path.join("replay"), home.path.join("old-replay")).unwrap();
    home.commit(300, vec![], vec![], false);
    let old_outbox = fs::read(home.path.join("outbox/STATE")).unwrap();
    let created = success(replay_profile(&home, "replay-init"));
    assert!(created.contains("status replay-profile-created"));
    assert_eq!(report_number(&created, "durable-height"), 0);
    assert_eq!(
        fs::read(home.path.join("outbox/STATE")).unwrap(),
        old_outbox
    );
    success(home.run("catch-up", &with_profile(&home, vec![])));
    assert_eq!(retained_draft(&home), Some(draft.clone()));
    assert_eq!(
        fs::read(home.path.join("old-replay/STATE")).unwrap(),
        old_cache
    );
    let anchored = fs::read(home.path.join("replay/STATE")).unwrap();
    assert!(!replay_profile(&home, "replay-step").status.success());
    assert_eq!(fs::read(home.path.join("replay/STATE")).unwrap(), anchored);
    success(home.run("resume", &with_profile(&home, vec![])));
    let frames = home.export("rebuilt-cache-export");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].id(), draft.request().id());
    assert_eq!(
        fs::read(home.path.join("old-replay/STATE")).unwrap(),
        old_cache
    );
}
