#![cfg(unix)]
//! Real social CLI subprocesses cross signing, admission, durable storage, and escaped presentation.

#[cfg(not(feature = "experimental-social"))]
#[test]
fn social_commands_are_absent_from_the_default_build() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .args([
            "social",
            "records",
            "unused",
            "00000000000000000000000000000047",
        ])
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
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::{Read, Write},
        os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt},
        path::{Path, PathBuf},
        process::{Command, Output, Stdio},
        thread,
        time::{Duration, Instant},
    };
    use vhalla_core::RealmId;
    use vhalla_social::{
        archive::{Archive, Limits, MAX_SNAPSHOT_BYTES},
        control::ControlView,
        view::{Content, Eligibility, Measured, RecordState, Register, View},
        AgentId, OwnerId, PostRef, RecordId,
    };
    use vhalla_social_store::Pin;

    const REALM: &str = "00000000000000000000000000000047";
    const OTHER_REALM: &str = "00000000000000000000000000000048";
    const CAPTURE: u64 = 262_144;

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).unwrap();
            let path = std::env::temp_dir().join(format!(
                "vhalla-cli-social-{:032x}",
                u128::from_be_bytes(nonce)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    struct Account {
        store: PathBuf,
        key: PathBuf,
        owner: String,
    }
    impl Account {
        fn init(temp: &Temp, label: &str, realm: &str) -> Self {
            let store = temp.path(&format!("{label}-store"));
            let key = temp.path(&format!("{label}-key"));
            let output = ok(&store, realm, "init", &[path(&key)]);
            assert_eq!(output["durable"], true);
            Self {
                store,
                key,
                owner: field(&output, "owner"),
            }
        }
        fn actor(&self) -> String {
            format!("owner:{}", self.owner)
        }
    }
    fn path(path: &Path) -> &str {
        path.to_str().unwrap()
    }
    fn field(value: &Value, name: &str) -> String {
        value
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing string field {name}: {value}"))
            .to_owned()
    }
    fn digest(text: &str) -> [u8; 32] {
        assert_eq!(text.len(), 64);
        let mut out = [0; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
    fn record(text: &str) -> RecordId {
        RecordId::from_bytes(digest(text))
    }
    fn owner(text: &str) -> OwnerId {
        OwnerId::from_bytes(digest(text))
    }
    fn safe(bytes: &[u8]) {
        assert!(
            bytes
                .iter()
                .all(|byte| *byte == b'\n' || (0x20..=0x7e).contains(byte)),
            "output contains terminal controls or unescaped Unicode"
        );
    }
    fn run(store: &Path, realm: &str, command: &str, args: &[&str]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args(["social", command])
            .arg(store)
            .arg(realm)
            .args(args)
            .args(["--now", "10"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let read = |pipe: Box<dyn Read + Send>| {
            thread::spawn(move || {
                let mut raw = Vec::new();
                pipe.take(CAPTURE + 1).read_to_end(&mut raw).unwrap();
                raw
            })
        };
        let out = read(Box::new(stdout));
        let err = read(Box::new(stderr));
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() > Duration::from_secs(15) {
                child.kill().unwrap();
                child.wait().unwrap();
                let _ = out.join();
                let _ = err.join();
                panic!("social {command} exceeded bounded process deadline");
            }
            thread::sleep(Duration::from_millis(5));
        };
        let stdout = out.join().unwrap();
        let stderr = err.join().unwrap();
        assert!(stdout.len() <= CAPTURE as usize && stderr.len() <= CAPTURE as usize);
        safe(&stdout);
        safe(&stderr);
        Output {
            status,
            stdout,
            stderr,
        }
    }
    fn ok(store: &Path, realm: &str, command: &str, args: &[&str]) -> Value {
        let output = run(store, realm, command, args);
        assert!(
            output.status.success(),
            "social {command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(value.is_object());
        value
    }
    fn fails(store: &Path, realm: &str, command: &str, args: &[&str]) {
        let output = run(store, realm, command, args);
        assert!(
            !output.status.success(),
            "social {command} unexpectedly succeeded"
        );
        assert!(
            output.stdout.is_empty(),
            "failed operation must not emit a durable-success object"
        );
    }
    fn contains_text(value: &Value, expected: &str) -> bool {
        match value {
            Value::String(text) => text == expected,
            Value::Array(values) => values.iter().any(|v| contains_text(v, expected)),
            Value::Object(values) => values.values().any(|v| contains_text(v, expected)),
            _ => false,
        }
    }
    fn export(account: &Account, file: &Path) -> Archive {
        ok(&account.store, REALM, "export", &[path(file)]);
        let bytes = fs::read(file).unwrap();
        Archive::from_snapshot(RealmId(71), Limits::default(), &bytes).unwrap()
    }
    fn repost_discoverable(store: &Path, timeline_owner: &str, post: &str, source_owner: &str) {
        // The query needs only the profile owner, so a reader can discover reposts
        // without already knowing the post or revision they point to.
        let timeline = ok(store, REALM, "timeline", &[timeline_owner]);
        let items = timeline["timeline"]["items"].as_array().unwrap();
        let entry = items
            .iter()
            .find(|entry| entry["kind"] == "repost" && entry["post"] == post)
            .expect("owner timeline must expose its retained repost");
        assert_eq!(entry["owner"], timeline_owner);
        assert_eq!(entry["source_incomplete"], false);
        assert_eq!(entry["attribution"]["owner"], source_owner);
        assert!(contains_text(&entry["preference"]["committed"], post));
    }

    #[test]
    fn agent_lifecycle_persists_committed_history_and_escapes_hostile_text() {
        let temp = Temp::new();
        let account = Account::init(&temp, "owner", REALM);
        let agent_key = temp.path("agent-key");
        let enrollment = ok(
            &account.store,
            REALM,
            "enroll",
            &[
                path(&account.key),
                &account.owner,
                path(&agent_key),
                "all",
                "1000",
            ],
        );
        let agent = field(&enrollment, "agent");
        let grant = field(&enrollment, "grant");
        let actor = format!("agent:{agent}:{grant}");
        let text =
            "line one\n\"quoted\" \\ <script>alert(1)</script> \u{1b}[31m \u{202e}agent\u{2066} 🦀";
        let post = ok(
            &account.store,
            REALM,
            "post",
            &[path(&agent_key), &actor, "profile", text],
        );
        assert_eq!(post["durable"], true);
        let event = field(&post, "event");
        let shown = ok(&account.store, REALM, "post-show", &[&event]);
        assert!(
            contains_text(&shown, text),
            "escaped JSON must decode to original inert text"
        );
        let initial = export(&account, &temp.path("provisional.snapshot"));
        let eligibility = Eligibility::new(vec![]).unwrap();
        assert_eq!(
            View::new(&initial, 10, &eligibility).state(record(&event)),
            Some(RecordState::Provisional)
        );
        let bio_text = "bounded agent biography";
        let bio = ok(
            &account.store,
            REALM,
            "bio",
            &[path(&agent_key), &actor, bio_text],
        );
        let bio_id = field(&bio, "event");
        let mut heads = [event.clone(), bio_id];
        heads.sort();
        ok(
            &account.store,
            REALM,
            "seal",
            &[path(&account.key), &account.owner, &heads.join(",")],
        );
        ok(
            &account.store,
            REALM,
            "retire",
            &[path(&account.key), &account.owner, &agent, "-"],
        );
        fails(
            &account.store,
            REALM,
            "post",
            &[path(&agent_key), &actor, "profile", "after retirement"],
        );
        let archive = export(&account, &temp.path("retired.snapshot"));
        let control = ControlView::new(&archive, 10);
        assert!(!control
            .agent(AgentId::from_bytes(digest(&agent)))
            .unwrap()
            .active());
        assert!(control.accepted_ids().any(|id| id == record(&event)));
        assert_eq!(
            View::new(&archive, 10, &eligibility).state(record(&event)),
            Some(RecordState::Committed)
        );
        assert!(contains_text(
            &ok(&account.store, REALM, "post-show", &[&event]),
            text
        ));
        let fresh = Account::init(&temp, "replica", REALM);
        ok(
            &fresh.store,
            REALM,
            "import",
            &[path(&temp.path("retired.snapshot"))],
        );
        let replicated = export(&fresh, &temp.path("replicated.snapshot"));
        assert!(replicated.is_extension_of(&archive));
        assert!(!ControlView::new(&replicated, 10)
            .agent(AgentId::from_bytes(digest(&agent)))
            .unwrap()
            .active());
        assert!(contains_text(
            &ok(&fresh.store, REALM, "post-show", &[&event]),
            text
        ));
    }

    #[test]
    fn replies_votes_follows_and_retractions_survive_file_exchange_and_restarts() {
        let temp = Temp::new();
        let alice = Account::init(&temp, "alice", REALM);
        let bob = Account::init(&temp, "bob", REALM);
        let post = ok(
            &alice.store,
            REALM,
            "post",
            &[path(&alice.key), &alice.actor(), "profile", "original"],
        );
        let post_id = field(&post, "event");
        let reply = ok(
            &alice.store,
            REALM,
            "reply",
            &[
                path(&alice.key),
                &alice.actor(),
                &post_id,
                &post_id,
                "reply",
            ],
        );
        let reply_id = field(&reply, "event");
        export(&alice, &temp.path("alice.snapshot"));
        ok(
            &bob.store,
            REALM,
            "import",
            &[path(&temp.path("alice.snapshot"))],
        );
        ok(
            &bob.store,
            REALM,
            "react",
            &[path(&bob.key), &bob.actor(), &post_id, "up", &post_id],
        );
        ok(
            &bob.store,
            REALM,
            "follow",
            &[path(&bob.key), &bob.actor(), &alice.owner, "on"],
        );
        ok(
            &bob.store,
            REALM,
            "repost",
            &[path(&bob.key), &bob.actor(), &post_id, &post_id],
        );
        repost_discoverable(&bob.store, &bob.owner, &post_id, &alice.owner);
        export(&bob, &temp.path("bob.snapshot"));
        ok(
            &alice.store,
            REALM,
            "import",
            &[path(&temp.path("bob.snapshot"))],
        );
        repost_discoverable(&alice.store, &bob.owner, &post_id, &alice.owner);
        ok(&alice.store, REALM, "thread", &[&post_id]);
        ok(
            &alice.store,
            REALM,
            "stats",
            &[&alice.owner, "--eligible", &bob.owner],
        );
        let before = export(&alice, &temp.path("before-retract.snapshot"));
        let eligibility = Eligibility::new(vec![owner(&bob.owner)]).unwrap();
        let view = View::new(&before, 10, &eligibility);
        assert_eq!(view.thread(record(&post_id)).unwrap().len(), 2);
        assert!(view
            .thread(record(&post_id))
            .unwrap()
            .iter()
            .any(|post| post.id == record(&reply_id)));
        assert!(matches!(
            view.follow(owner(&bob.owner), owner(&alice.owner))
                .unwrap()
                .committed,
            Register::Resolved { value: true, .. }
        ));
        let votes = view
            .votes(PostRef {
                post: record(&post_id),
                revision: record(&post_id),
            })
            .unwrap();
        assert!(
            matches!(votes.committed, Measured::Known(tally) if tally.up == 1 && tally.down == 0)
        );
        let before_stats = view.stats(owner(&alice.owner)).unwrap();
        assert_eq!(before_stats.eligible_appreciation, Measured::Known(1));
        drop(view);
        ok(
            &alice.store,
            REALM,
            "retract",
            &[path(&alice.key), &alice.actor(), &post_id],
        );
        let after = export(&alice, &temp.path("after-retract.snapshot"));
        assert!(after.is_extension_of(&before));
        let view = View::new(&after, 10, &eligibility);
        assert!(matches!(
            view.post(record(&post_id)).unwrap().observed,
            Content::Retracted { .. }
        ));
        assert_eq!(
            view.stats(owner(&alice.owner))
                .unwrap()
                .eligible_appreciation,
            Measured::Known(1)
        );
        ok(
            &bob.store,
            REALM,
            "import",
            &[path(&temp.path("after-retract.snapshot"))],
        );
        let bob_after = export(&bob, &temp.path("bob-after.snapshot"));
        assert_eq!(bob_after.root(), after.root());
        assert!(matches!(
            View::new(&bob_after, 10, &eligibility)
                .post(record(&post_id))
                .unwrap()
                .observed,
            Content::Retracted { .. }
        ));
    }

    #[test]
    fn malformed_missing_and_wrong_realm_inputs_preserve_pinned_history() {
        let temp = Temp::new();
        let account = Account::init(&temp, "valid", REALM);
        let post = ok(
            &account.store,
            REALM,
            "post",
            &[path(&account.key), &account.actor(), "profile", "keep"],
        );
        let event = field(&post, "event");
        let before = fs::read(account.store.join("pin")).unwrap();
        let missing = temp.path("missing-store");
        fails(&missing, REALM, "records", &[]);
        assert!(!missing.exists());
        fails(&account.store, OTHER_REALM, "records", &[]);
        for (name, rights, expiry) in [
            ("invalid-rights-agent", "not-a-right", "1000"),
            ("expired-agent", "all", "10"),
        ] {
            let key = temp.path(name);
            fails(
                &account.store,
                REALM,
                "enroll",
                &[
                    path(&account.key),
                    &account.owner,
                    path(&key),
                    rights,
                    expiry,
                ],
            );
            assert!(!key.exists(), "invalid enrollment created an identity");
        }
        fails(
            &account.store,
            REALM,
            "reply",
            &[
                path(&account.key),
                &account.actor(),
                &"ab".repeat(32),
                &"ab".repeat(32),
                "unknown parent",
            ],
        );
        let hostile = temp.path("hostile.snapshot");
        fs::write(&hostile, b"not a signed archive").unwrap();
        fails(&account.store, REALM, "import", &[path(&hostile)]);
        let sparse = temp.path("oversize.snapshot");
        fs::File::create(&sparse)
            .unwrap()
            .set_len(MAX_SNAPSHOT_BYTES as u64 + 1)
            .unwrap();
        fails(&account.store, REALM, "import", &[path(&sparse)]);
        export(&account, &temp.path("valid.snapshot"));
        let linked = temp.path("linked.snapshot");
        symlink(temp.path("valid.snapshot"), &linked).unwrap();
        fails(&account.store, REALM, "import", &[path(&linked)]);
        let fifo = temp.path("snapshot.fifo");
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        // No writer is connected: a blocking read-open would exceed run()'s deadline.
        fails(&account.store, REALM, "import", &[path(&fifo)]);
        let mut corrupt = fs::read(temp.path("valid.snapshot")).unwrap();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        fs::write(&hostile, corrupt).unwrap();
        fails(&account.store, REALM, "import", &[path(&hostile)]);
        let foreign = Account::init(&temp, "foreign", OTHER_REALM);
        ok(
            &foreign.store,
            OTHER_REALM,
            "export",
            &[path(&temp.path("wrong-realm.snapshot"))],
        );
        fails(
            &account.store,
            REALM,
            "import",
            &[path(&temp.path("wrong-realm.snapshot"))],
        );
        let existing = temp.path("existing-output");
        fs::write(&existing, b"preserve user bytes").unwrap();
        fails(&account.store, REALM, "export", &[path(&existing)]);
        assert_eq!(fs::read(&existing).unwrap(), b"preserve user bytes");
        assert_eq!(ok(&account.store, REALM, "recover", &[])["durable"], true);
        assert_eq!(fs::read(account.store.join("pin")).unwrap(), before);
        assert!(contains_text(
            &ok(&account.store, REALM, "post-show", &[&event]),
            "keep"
        ));
    }

    #[test]
    fn pending_intent_blocks_reads_and_writes_until_exact_recovery_then_extends_history() {
        let temp = Temp::new();
        let account = Account::init(&temp, "recovering", REALM);
        let before = fs::read(account.store.join("pin")).unwrap();
        let expected = Pin::decode(&before).unwrap();

        // Produce the candidate with the real signer and CLI from an exact independent
        // copy. The original then models interruption after a complete durable intent.
        let copy = temp.path("candidate-store");
        fs::DirBuilder::new().mode(0o700).create(&copy).unwrap();
        for entry in fs::read_dir(&account.store).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let text = name.to_str().unwrap();
            assert!(text == "lock" || text == "pin" || text.starts_with("bundle-"));
            assert!(entry.file_type().unwrap().is_file());
            fs::copy(entry.path(), copy.join(name)).unwrap();
        }
        let prepared = ok(
            &copy,
            REALM,
            "post",
            &[
                path(&account.key),
                &account.actor(),
                "profile",
                "prepared before interruption",
            ],
        );
        let prepared_id = field(&prepared, "event");
        let next = fs::read(copy.join("pin")).unwrap();
        let next_pin = Pin::decode(&next).unwrap();
        assert_eq!(next_pin.generation(), expected.generation() + 1);
        let candidate_file = temp.path("candidate.snapshot");
        ok(&copy, REALM, "export", &[path(&candidate_file)]);
        let snapshot = fs::read(&candidate_file).unwrap();
        let candidate = Archive::from_snapshot(RealmId(71), Limits::default(), &snapshot).unwrap();
        assert_eq!(candidate.root(), next_pin.logical());
        assert_eq!(candidate.physical_digest(), next_pin.physical());

        // Independently encode the documented native intent; no internal fault hook or
        // test constructor bypasses verification on the application recovery path.
        let mut intent = b"VHSI\0\0\0\x01".to_vec();
        intent.extend_from_slice(&before);
        intent.extend_from_slice(&next);
        intent.extend_from_slice(&u32::try_from(snapshot.len()).unwrap().to_be_bytes());
        intent.extend_from_slice(&snapshot);
        let mut checksum = Sha256::new();
        checksum.update(b"vhalla/social/store/intent/v1\0");
        checksum.update(&intent);
        intent.extend_from_slice(&checksum.finalize());
        let intent_path = account.store.join("intent");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&intent_path)
            .unwrap();
        file.write_all(&intent).unwrap();
        file.sync_all().unwrap();
        drop(file);
        fs::File::open(&account.store).unwrap().sync_all().unwrap();

        fails(&account.store, REALM, "records", &[]);
        fails(
            &account.store,
            REALM,
            "post",
            &[
                path(&account.key),
                &account.actor(),
                "profile",
                "must not sign different history",
            ],
        );
        let blocked_export = temp.path("blocked.snapshot");
        fails(&account.store, REALM, "export", &[path(&blocked_export)]);
        assert!(!blocked_export.exists());
        assert_eq!(fs::read(account.store.join("pin")).unwrap(), before);
        assert_eq!(fs::read(&intent_path).unwrap(), intent);

        let recovered = ok(&account.store, REALM, "recover", &[]);
        assert_eq!(recovered["durable"], true);
        assert_eq!(recovered["generation"], next_pin.generation());
        assert_eq!(fs::read(account.store.join("pin")).unwrap(), next);
        assert!(!intent_path.exists());
        let recovered_archive = export(&account, &temp.path("recovered.snapshot"));
        assert_eq!(recovered_archive.snapshot(), snapshot);
        let after = ok(
            &account.store,
            REALM,
            "post",
            &[
                path(&account.key),
                &account.actor(),
                "profile",
                "after exact recovery",
            ],
        );
        let after_id = field(&after, "event");
        assert_ne!(prepared_id, after_id);
        assert_eq!(after["generation"], next_pin.generation() + 1);
        let final_archive = export(&account, &temp.path("after-recovery.snapshot"));
        assert!(final_archive.is_extension_of(&candidate));
        let eligibility = Eligibility::new(vec![]).unwrap();
        let view = View::new(&final_archive, 10, &eligibility);
        for id in [&prepared_id, &after_id] {
            assert_eq!(view.state(record(id)), Some(RecordState::Committed));
        }
        assert!(contains_text(
            &ok(&account.store, REALM, "post-show", &[&prepared_id]),
            "prepared before interruption"
        ));
    }

    #[test]
    fn planned_rotation_preserves_owner_and_rejects_the_previous_controller() {
        let temp = Temp::new();
        let account = Account::init(&temp, "rotating", REALM);
        let next = temp.path("next-controller");
        ok(
            &account.store,
            REALM,
            "rotate",
            &[path(&account.key), &account.owner, path(&next)],
        );
        let pin = fs::read(account.store.join("pin")).unwrap();
        fails(
            &account.store,
            REALM,
            "post",
            &[path(&account.key), &account.actor(), "profile", "old key"],
        );
        assert_eq!(fs::read(account.store.join("pin")).unwrap(), pin);
        let post = ok(
            &account.store,
            REALM,
            "post",
            &[path(&next), &account.actor(), "profile", "current key"],
        );
        let event = field(&post, "event");
        let archive = export(&account, &temp.path("rotated.snapshot"));
        let eligibility = Eligibility::new(vec![]).unwrap();
        assert_eq!(
            View::new(&archive, 10, &eligibility)
                .post(record(&event))
                .unwrap()
                .attribution
                .owner,
            owner(&account.owner)
        );
        ok(&account.store, REALM, "profile", &[&account.owner]);
    }

    #[test]
    fn exact_signed_facets_survive_export_and_legacy_revision_removes_them() {
        let temp = Temp::new();
        let account = Account::init(&temp, "facets", REALM);
        let mention = format!("0:4:owner:{}", account.owner);
        let posted = ok(
            &account.store,
            REALM,
            "post",
            &[
                path(&account.key),
                &account.actor(),
                "profile",
                "@you #Rust 🧠",
                "--mention",
                &mention,
                "--tag",
                "5:10:Rust",
            ],
        );
        let post = field(&posted, "event");
        let shown = ok(&account.store, REALM, "post-show", &[&post]);
        assert!(contains_text(&shown, "mention-owner"));
        assert!(contains_text(&shown, "rust"));
        let archive = export(&account, &temp.path("facets.snapshot"));
        let eligibility = Eligibility::default();
        let view = View::new(&archive, 10, &eligibility);
        let Content::Present(Register::Resolved { value, .. }) =
            view.post(record(&post)).unwrap().committed
        else {
            panic!("committed faceted post");
        };
        assert_eq!(value.facets.len(), 2);

        let pin = fs::read(account.store.join("pin")).unwrap();
        // Offsets inside an emoji and an explicit legacy/facet conflict must not publish.
        fails(
            &account.store,
            REALM,
            "revise",
            &[
                path(&account.key),
                &account.actor(),
                &post,
                "🧠 @you",
                "--mention",
                &format!("1:4:owner:{}", account.owner),
            ],
        );
        fails(
            &account.store,
            REALM,
            "revise",
            &[
                path(&account.key),
                &account.actor(),
                &post,
                "@you",
                "--mention",
                &mention,
                "--format",
                "legacy",
            ],
        );
        assert_eq!(fs::read(account.store.join("pin")).unwrap(), pin);
        ok(
            &account.store,
            REALM,
            "revise",
            &[
                path(&account.key),
                &account.actor(),
                &post,
                "@you #Rust",
                "--format",
                "legacy",
            ],
        );
        let updated = export(&account, &temp.path("legacy-revision.snapshot"));
        assert!(updated.is_extension_of(&archive));
        let view = View::new(&updated, 10, &eligibility);
        let Content::Present(Register::Resolved { value, .. }) =
            view.post(record(&post)).unwrap().committed
        else {
            panic!("committed legacy revision");
        };
        assert!(value.facets.is_empty());
    }

    #[test]
    fn discovery_offline_mentions_private_readers_and_exact_acknowledgements() {
        let temp = Temp::new();
        let alice = Account::init(&temp, "discovery-alice", REALM);
        let bob = Account::init(&temp, "discovery-bob", REALM);
        let mut agents = Vec::new();
        for name in ["reader-one", "reader-two"] {
            let key = temp.path(name);
            let enrolled = ok(
                &bob.store,
                REALM,
                "enroll",
                &[path(&bob.key), &bob.owner, path(&key), "all", "1000"],
            );
            agents.push(field(&enrolled, "agent"));
        }
        let bob_export = temp.path("bob-initial.snapshot");
        export(&bob, &bob_export);
        ok(&alice.store, REALM, "import", &[path(&bob_export)]);
        let mention = format!("0:4:agent:{}", agents[0]);
        let posted = ok(
            &alice.store,
            REALM,
            "post",
            &[
                path(&alice.key),
                &alice.actor(),
                "channel:00000000000000000000000000000001",
                "@bee #Rust WASM",
                "--mention",
                &mention,
                "--tag",
                "5:10:Rust",
            ],
        );
        let post = field(&posted, "event");
        let source_export = temp.path("alice-post.snapshot");
        export(&alice, &source_export);
        ok(&bob.store, REALM, "import", &[path(&source_export)]);
        ok(
            &bob.store,
            REALM,
            "follow",
            &[path(&bob.key), &bob.actor(), &alice.owner, "on"],
        );

        let private_one = temp.path("private-one");
        let private_two = temp.path("private-two");
        let reader_one = format!("agent:{}", agents[0]);
        let reader_two = format!("agent:{}", agents[1]);
        let local = |command: &str, values: &[&str], private: &Path, reader: &str| {
            let mut args = values.to_vec();
            args.extend(["--private", path(private), "--reader", reader]);
            ok(&bob.store, REALM, command, &args)
        };
        for (private, reader) in [(&private_one, &reader_one), (&private_two, &reader_two)] {
            local("reader-init", &[], private, reader);
            local("reader-observe", &[], private, reader);
        }
        let before = export(&bob, &temp.path("before-private.snapshot")).snapshot();
        let initial = local("notifications", &[], &private_one, &reader_one);
        let item = initial["notifications"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["reason"] == "mention")
            .unwrap();
        assert_eq!(item["read"], "unread");
        assert_eq!(item["lane"], "selected");
        assert_eq!(item["recipient_agents"][0], agents[0]);
        let exact = field(item, "id");
        let same = local("notifications", &[], &private_one, &reader_one);
        assert_eq!(initial, same, "query must not mutate read state");
        local("notifications-ack", &[&exact], &private_one, &reader_one);
        let acknowledged = local("notifications", &[], &private_one, &reader_one);
        assert_eq!(acknowledged["notifications"][0]["read"], "read");
        let sibling = local("notifications", &[], &private_two, &reader_two);
        assert_eq!(sibling["notifications"][0]["read"], "unread");

        local("reader-set", &["more", "rust"], &private_one, &reader_one);
        local(
            "reader-set",
            &["save-search", "wasm", "WASM"],
            &private_one,
            &reader_one,
        );
        let results = local(
            "search-saved",
            &["wasm", "--tag", "rust"],
            &private_one,
            &reader_one,
        );
        assert_eq!(results["items"][0]["post"], post);
        assert_eq!(results["items"][0]["owner"], alice.owner);
        assert_eq!(results["coverage"]["network_complete"], false);
        assert!(
            local("feed", &["discover"], &private_one, &reader_one)["items"][0]["why"]["topic"]
                .as_i64()
                .unwrap()
                > 0
        );
        assert_eq!(
            local("feed", &["discover"], &private_two, &reader_two)["items"][0]["why"]["topic"],
            0
        );
        local(
            "reader-set",
            &["clear-interests"],
            &private_one,
            &reader_one,
        );
        let down = local(
            "reader-feedback",
            &[&post, &post, "down"],
            &private_one,
            &reader_one,
        );
        let repeated = local(
            "reader-feedback",
            &[&post, &post, "down"],
            &private_one,
            &reader_one,
        );
        assert_eq!(
            down, repeated,
            "repeated feedback must not accumulate or publish"
        );
        assert!(
            local("feed", &["discover"], &private_one, &reader_one)["items"][0]["why"]["topic"]
                .as_i64()
                .unwrap()
                < 0
        );
        assert_eq!(
            local("feed", &["discover"], &private_two, &reader_two)["items"][0]["why"]["topic"],
            0
        );
        local(
            "reader-feedback",
            &[&post, &post, "clear"],
            &private_one,
            &reader_one,
        );
        assert_eq!(
            local("feed", &["discover"], &private_one, &reader_one)["items"][0]["why"]["topic"],
            0
        );
        local("reader-seen", &[&post, &post], &private_one, &reader_one);
        assert_eq!(
            export(&bob, &temp.path("after-private.snapshot")).snapshot(),
            before,
            "private queries, feedback and acknowledgements must not enter public export"
        );

        let revised = ok(
            &alice.store,
            REALM,
            "revise",
            &[
                path(&alice.key),
                &alice.actor(),
                &post,
                "@bee #Rust revised WASM",
                "--mention",
                &mention,
                "--tag",
                "5:10:Rust",
            ],
        );
        let revision = field(&revised, "event");
        let updated_export = temp.path("alice-revised.snapshot");
        export(&alice, &updated_export);
        ok(&bob.store, REALM, "import", &[path(&updated_export)]);
        let edited = local("notifications", &[], &private_one, &reader_one);
        let edited_item = edited["notifications"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["reason"] == "mention")
            .unwrap();
        assert_ne!(edited_item["id"], exact);
        assert_eq!(edited_item["event"], revision);
        assert_eq!(edited_item["priority"], "read");
        assert_eq!(edited_item["read"], "unread");
        let private_before = local("reader-show", &[], &private_one, &reader_one);
        fails(
            &bob.store,
            REALM,
            "notifications-ack",
            &[
                &exact,
                "--private",
                path(&private_one),
                "--reader",
                &reader_one,
            ],
        );
        assert_eq!(
            local("reader-show", &[], &private_one, &reader_one),
            private_before
        );
        let unread = local(
            "notifications",
            &["--unread", "on"],
            &private_one,
            &reader_one,
        );
        assert_eq!(unread["notifications"][0]["event"], revision);
        local(
            "reader-set",
            &["mute", &alice.owner],
            &private_one,
            &reader_one,
        );
        assert!(
            local("search", &["WASM"], &private_one, &reader_one)["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            local("notifications", &[], &private_one, &reader_one)["notifications"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            !local("search", &["WASM"], &private_two, &reader_two)["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        ok(
            &bob.store,
            REALM,
            "repost",
            &[path(&bob.key), &bob.actor(), &post, &post],
        );
        let repost = local(
            "search",
            &["WASM", "--kind", "repost"],
            &private_two,
            &reader_two,
        );
        assert_eq!(repost["items"][0]["revision"], post);
        assert_eq!(repost["items"][0]["owner"], alice.owner);
        assert_eq!(repost["items"][0]["reposted_by"][0], bob.owner);
        ok(
            &bob.store,
            REALM,
            "reply",
            &[
                path(&bob.key),
                &bob.actor(),
                &post,
                &revision,
                "thread reply",
            ],
        );
        let boards = local("boards", &[], &private_two, &reader_two);
        assert_eq!(boards["boards"][0]["roots"], 1);
        assert_eq!(boards["boards"][0]["replies"], 1);
        assert_eq!(
            local("directory", &[], &private_two, &reader_two)["owners"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        // A late control record must remove provisional candidates at every new query.
        let author_key = temp.path("author-agent");
        let enrolled = ok(
            &alice.store,
            REALM,
            "enroll",
            &[
                path(&alice.key),
                &alice.owner,
                path(&author_key),
                "all",
                "1000",
            ],
        );
        let author_agent = field(&enrolled, "agent");
        let grant = field(&enrolled, "grant");
        let author = format!("agent:{author_agent}:{grant}");
        let provisional = ok(
            &alice.store,
            REALM,
            "post",
            &[
                path(&author_key),
                &author,
                "profile",
                "@bee provisional-only",
                "--mention",
                &mention,
            ],
        );
        let provisional_id = field(&provisional, "event");
        let provisional_export = temp.path("provisional.snapshot");
        export(&alice, &provisional_export);
        ok(&bob.store, REALM, "import", &[path(&provisional_export)]);
        assert!(
            local("search", &["provisional-only"], &private_two, &reader_two)["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let live = local(
            "search",
            &["provisional-only", "--live", "on", "--state", "provisional"],
            &private_two,
            &reader_two,
        );
        assert_eq!(live["items"][0]["post"], provisional_id);
        ok(
            &alice.store,
            REALM,
            "revoke",
            &[path(&alice.key), &alice.owner, &grant, "-"],
        );
        let revoked_export = temp.path("revoked.snapshot");
        export(&alice, &revoked_export);
        ok(&bob.store, REALM, "import", &[path(&revoked_export)]);
        assert!(local(
            "search",
            &["provisional-only", "--live", "on"],
            &private_two,
            &reader_two
        )["items"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(!contains_text(
            &local(
                "notifications",
                &["--live", "on"],
                &private_two,
                &reader_two
            ),
            &provisional_id
        ));
    }
}
