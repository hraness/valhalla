//! Real-application replay through the durable boundary: `Registry` +
//! `Archive` behind the journal and both snapshot stores.
use super::*;
use crate::fixture;
use std::sync::atomic::{AtomicUsize, Ordering};

fn dir(tag: &str) -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "room-live-ack-{tag}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SEQ.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cert(batch: &Batch, height: u64, tag: &str) -> CommitCertificate {
    CommitCertificate {
        bytes: format!("cert-{tag}-{height}").into_bytes(),
        value_commitment: batch.value_id(),
        height,
    }
}

#[test]
fn decided_batch_publishes_both_stores_then_acks() {
    let plan = fixture::plan(2, 4, 12);
    let home = dir("decide");
    let mut adapter = Adapter::open(&home, &plan.genesis).unwrap();
    let mut sink = EngineSink::default();

    for (height, batch) in &plan.batches {
        adapter.hold(batch.clone());
        assert_eq!(
            adapter.on_decided(&mut sink, &cert(batch, *height, "d")),
            DecidedOutcome::Acked
        );
    }
    assert_eq!(
        sink.sent,
        vec![
            EngineMsg::CommitAck { height: 1 },
            EngineMsg::CommitAck { height: 2 }
        ]
    );
    // The real registry really advanced: two finalized rooms exist.
    let registry = adapter.application().registry();
    assert_eq!(registry.search("room", 8, 64).unwrap().rooms.len(), 2);
    assert_eq!(adapter.frontier().height, 2);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn restart_rebuilds_from_journal_and_pinned_snapshots() {
    let plan = fixture::plan(3, 4, 12);
    let home = dir("restart");
    let mut sink = EngineSink::default();
    let before = {
        let mut adapter = Adapter::open(&home, &plan.genesis).unwrap();
        for (height, batch) in &plan.batches {
            adapter.hold(batch.clone());
            adapter.on_decided(&mut sink, &cert(batch, *height, "r"));
        }
        adapter.frontier().commitment()
        // drop: store locks release with the adapter
    };
    let reopened = Adapter::open(&home, &plan.genesis).unwrap();
    assert_eq!(reopened.frontier().commitment(), before);
    assert_eq!(reopened.frontier().height, 3);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn exact_redelivery_reconciles_without_double_apply() {
    let plan = fixture::plan(1, 4, 8);
    let home = dir("redeliver");
    let mut adapter = Adapter::open(&home, &plan.genesis).unwrap();
    let mut sink = EngineSink::default();
    let batch = plan.batches.values().next().unwrap().clone();
    adapter.hold(batch.clone());
    let certificate = cert(&batch, 1, "x");
    assert_eq!(
        adapter.on_decided(&mut sink, &certificate),
        DecidedOutcome::Acked
    );
    let revision = adapter.application().registry().revision();
    assert_eq!(
        adapter.on_finalized(&mut sink, &certificate),
        DecidedOutcome::Acked
    );
    assert_eq!(adapter.application().registry().revision(), revision);
    assert_eq!(
        sink.sent,
        vec![
            EngineMsg::CommitAck { height: 1 },
            EngineMsg::NextHeightReply { height: 2 }
        ]
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn unknown_value_and_equivocation_are_rejected() {
    let plan = fixture::plan(2, 4, 12);
    let home = dir("reject");
    let mut adapter = Adapter::open(&home, &plan.genesis).unwrap();
    let mut sink = EngineSink::default();

    // A certificate naming a value nobody holds.
    let foreign = CommitCertificate {
        bytes: b"cert-foreign".to_vec(),
        value_commitment: [9; 32],
        height: 1,
    };
    assert_eq!(
        adapter.on_decided(&mut sink, &foreign),
        DecidedOutcome::Rejected
    );

    // Commit height 1, then a certificate at the same height naming a
    // different value — the durable marker rejects the equivocation.
    let first = plan.batches.get(&1).unwrap().clone();
    adapter.hold(first.clone());
    assert_eq!(
        adapter.on_decided(&mut sink, &cert(&first, 1, "a")),
        DecidedOutcome::Acked
    );
    let second = plan.batches.get(&2).unwrap().clone();
    assert_eq!(
        adapter.on_decided(
            &mut sink,
            &CommitCertificate {
                bytes: b"cert-equivocated".to_vec(),
                value_commitment: second.value_id(),
                height: 1,
            },
        ),
        DecidedOutcome::Rejected
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn forged_result_claim_is_rejected_before_any_durable_write() {
    let plan = fixture::plan(1, 4, 8);
    let home = dir("forged");
    let mut adapter = Adapter::open(&home, &plan.genesis).unwrap();
    let mut sink = EngineSink::default();
    let mut forged = plan.batches.values().next().unwrap().clone();
    forged.result_registry = [0xEE; 32];
    // value_id covers the forged claim, so the certificate must name the
    // forged value — and validate must still reject on the result compare.
    adapter.hold(forged.clone());
    let certificate = CommitCertificate {
        bytes: b"cert-forged".to_vec(),
        value_commitment: forged.value_id(),
        height: 1,
    };
    assert_eq!(
        adapter.on_decided(&mut sink, &certificate),
        DecidedOutcome::Rejected
    );
    assert_eq!(adapter.frontier().height, 0);
    assert_eq!(adapter.recover().unwrap().pin.height, 0);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn corrupt_retained_batch_fails_rebuild_closed() {
    let plan = fixture::plan(1, 4, 8);
    let home = dir("corrupt");
    {
        let mut adapter = Adapter::open(&home, &plan.genesis).unwrap();
        let mut sink = EngineSink::default();
        let batch = plan.batches.values().next().unwrap().clone();
        adapter.hold(batch.clone());
        adapter.on_decided(&mut sink, &cert(&batch, 1, "c"));
    }
    // Truncate the retained bundle file — rebuild must fail closed.
    let bundle = std::fs::read_dir(home.join("journal").join("bundles"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .next()
        .expect("bundle file");
    let bytes = std::fs::read(&bundle).unwrap();
    std::fs::write(&bundle, &bytes[..bytes.len() / 2]).unwrap();
    match Adapter::open(&home, &plan.genesis) {
        Err(_) => {}
        Ok(_) => panic!("corrupt retained batch must fail the rebuild"),
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// The data plane: a replica with no engine and no proposal stream reads
/// committed bundles from a peer's journal, verifies each certificate
/// through the caller's hook, and replays them through the same durable
/// decide path — converging byte-identically without ever voting.
#[test]
fn replica_absorbs_committed_bundles_and_converges() {
    let plan = fixture::plan(3, 4, 12);
    let source_home = dir("source");
    let commitment = {
        let mut adapter = Adapter::open(&source_home, &plan.genesis).unwrap();
        let mut sink = EngineSink::default();
        for (height, batch) in &plan.batches {
            adapter.hold(batch.clone());
            adapter.on_decided(&mut sink, &cert(batch, *height, "s"));
        }
        adapter.frontier().commitment()
        // drop: the replica then opens the source's journal read-side
    };

    let replica_home = dir("replica");
    let mut replica = Adapter::open(&replica_home, &plan.genesis).unwrap();
    let source_journal = Journal::new(source_home.join("journal"), FsStore);

    // The stand-in verifier checks what a real engine verifier would:
    // the certificate's claimed height and the value it decides.
    let verify = |bytes: &[u8], height: u64, value: &[u8; 32]| {
        bytes == format!("cert-s-{height}").as_bytes()
            && plan
                .batches
                .get(&height)
                .is_some_and(|b| b.value_id() == *value)
    };

    // Out-of-order absorption is rejected: the h=2 batch's parent is not
    // yet applied — the replica must fetch earlier bundles first.
    let h2 = source_journal
        .bundle(source_journal.at_height(2).unwrap().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(replica.absorb(&h2, verify), DecidedOutcome::Rejected);
    assert_eq!(replica.frontier().height, 0);

    for height in 1..=3u64 {
        let bundle = source_journal
            .bundle(source_journal.at_height(height).unwrap().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(replica.absorb(&bundle, verify), DecidedOutcome::Acked);
    }
    assert_eq!(replica.frontier().commitment(), commitment);
    assert_eq!(replica.frontier().height, 3);
    // The replica's journal binds byte-identical bundles — the absorbed
    // evidence is the same object the deciding quorum committed.
    for height in 1..=3u64 {
        let replica_journal = Journal::new(replica_home.join("journal"), FsStore);
        let replica_id = replica_journal.at_height(height).unwrap().unwrap();
        let source_id = source_journal.at_height(height).unwrap().unwrap();
        assert_eq!(replica_id, source_id);
    }
    // Re-absorbing a committed bundle reconciles without double-applying.
    let h1 = source_journal
        .bundle(source_journal.at_height(1).unwrap().unwrap())
        .unwrap()
        .unwrap();
    let revision = replica.application().registry().revision();
    assert_eq!(replica.absorb(&h1, verify), DecidedOutcome::Acked);
    assert_eq!(replica.application().registry().revision(), revision);
    let _ = std::fs::remove_dir_all(&source_home);
    let _ = std::fs::remove_dir_all(&replica_home);
}

/// A bundle whose certificate fails the caller's verification, or whose
/// bound value does not match its batch, is rejected before any write —
/// a peer cannot push an unverified decision into a replica's journal.
#[test]
fn replica_rejects_unverified_and_misbound_bundles() {
    let plan = fixture::plan(1, 4, 8);
    let source_home = dir("src-forge");
    {
        let mut adapter = Adapter::open(&source_home, &plan.genesis).unwrap();
        let mut sink = EngineSink::default();
        let batch = plan.batches.values().next().unwrap().clone();
        adapter.hold(batch.clone());
        adapter.on_decided(&mut sink, &cert(&batch, 1, "s"));
    }
    let source_journal = Journal::new(source_home.join("journal"), FsStore);
    let bundle = source_journal
        .bundle(source_journal.at_height(1).unwrap().unwrap())
        .unwrap()
        .unwrap();

    let replica_home = dir("replica-forge");
    let mut replica = Adapter::open(&replica_home, &plan.genesis).unwrap();
    // Verification refuses: nothing is held, replayed or journaled.
    assert_eq!(
        replica.absorb(&bundle, |_, _, _| false),
        DecidedOutcome::Rejected
    );
    // A well-formed bundle lying about its decided value is rejected on
    // the binding check before verification is even consulted.
    let batch = plan.batches.values().next().unwrap().clone();
    let misbound = Bundle::new(BundleParts {
        certificate: b"cert-s-1".to_vec(),
        predecessor: [0xAA; 32],
        next: [0xBB; 32],
        batch: batch.encode(),
        value: [0xCC; 32].to_vec(),
        configuration: Vec::new(),
        control_record: Vec::new(),
        debit_marker: Vec::new(),
        height: 1,
    })
    .unwrap();
    assert_eq!(
        replica.absorb(&misbound, |_, _, _| panic!("verify must not run")),
        DecidedOutcome::Rejected
    );
    assert_eq!(replica.frontier().height, 0);
    assert_eq!(replica.recover().unwrap().pin.height, 0);
    let _ = std::fs::remove_dir_all(&source_home);
    let _ = std::fs::remove_dir_all(&replica_home);
}

/// Identical post-genesis evidence is guaranteed by the committed value
/// itself, so the residual deployment precondition is a shared genesis
/// archive and config. A replica seeded with a divergent genesis
/// produces a different genesis frontier commitment and must reject the
/// first committed bundle on the parent — divergence fails closed
/// rather than silently forking the registry.
#[test]
fn divergent_genesis_rejects_the_first_bundle_on_parent() {
    let plan = fixture::plan(1, 4, 8);
    let source_home = dir("src-diverge");
    {
        let mut adapter = Adapter::open(&source_home, &plan.genesis).unwrap();
        let mut sink = EngineSink::default();
        let batch = plan.batches.values().next().unwrap().clone();
        adapter.hold(batch.clone());
        adapter.on_decided(&mut sink, &cert(&batch, 1, "s"));
    }
    let source_journal = Journal::new(source_home.join("journal"), FsStore);
    let bundle = source_journal
        .bundle(source_journal.at_height(1).unwrap().unwrap())
        .unwrap()
        .unwrap();
    let verify = |bytes: &[u8], height: u64, value: &[u8; 32]| {
        bytes == format!("cert-s-{height}").as_bytes()
            && plan
                .batches
                .get(&height)
                .is_some_and(|b| b.value_id() == *value)
    };

    // Same everything except the admitted policy — a real divergence
    // surface, since policy is committed into every registry digest.
    let mut genesis = plan.genesis.clone();
    genesis.policy.base_cost += 1;
    let replica_home = dir("replica-diverge");
    let mut replica = Adapter::open(&replica_home, &genesis).unwrap();
    assert_eq!(
        replica.absorb(&bundle, verify),
        DecidedOutcome::Rejected,
        "a divergent genesis must reject the first committed bundle"
    );
    assert_eq!(replica.frontier().height, 0);
    assert_eq!(replica.recover().unwrap().pin.height, 0);
    let _ = std::fs::remove_dir_all(&source_home);
    let _ = std::fs::remove_dir_all(&replica_home);
}

#[test]
fn batch_clock_is_monotonic_and_step_bounded() {
    let mut scenario = fixture::scenario(2, 4);
    // The first committed batch anchors the clock at whatever it carries.
    let anchored = scenario
        .app
        .prepare(1_000_000, vec![], vec![], None)
        .unwrap();
    scenario.app.apply_locally(anchored);
    assert_eq!(scenario.app.frontier().time, 1_000_000);

    // A batch must not regress the committed clock — including an
    // evidence-free batch whose replay would otherwise succeed.
    let mut regressed = scenario
        .app
        .prepare(1_000_000, vec![], vec![], None)
        .unwrap()
        .batch()
        .clone();
    regressed.time = 999_999;
    assert!(matches!(
        scenario.app.validate(&regressed),
        Err(ApplyError::Clock)
    ));

    // Nor advance it more than MAX_TIME_DRIFT per height.
    let mut jumped = regressed.clone();
    jumped.time = 1_000_000 + MAX_TIME_DRIFT + 1;
    assert!(matches!(
        scenario.app.validate(&jumped),
        Err(ApplyError::Clock)
    ));

    // The boundary itself is admitted.
    let edge = scenario
        .app
        .prepare(1_000_000 + MAX_TIME_DRIFT, vec![], vec![], None)
        .unwrap();
    assert!(scenario.app.validate(edge.batch()).is_ok());

    // Producers clamp into the window: an over-shot clock lands on the
    // bound, an under-shot on the frontier — the assembled batch always
    // validates, so a stalled clock ratchets back rather than freezing.
    let clamped = scenario
        .app
        .prepare(u64::MAX, vec![], vec![], None)
        .unwrap();
    assert_eq!(clamped.batch().time, 1_000_000 + MAX_TIME_DRIFT);
    assert!(scenario.app.validate(clamped.batch()).is_ok());
    let floored = scenario.app.prepare(7, vec![], vec![], None).unwrap();
    assert_eq!(floored.batch().time, 1_000_000);
}

#[test]
fn eligible_transition_commits_in_band_and_governs_next_height() {
    // A committed-but-ineligible source stands beside the admitted pair.
    let mut archive = Archive::new(fixture::REALM, fixture::limits()).unwrap();
    let owners: Vec<_> = (0..2)
        .map(|i| fixture::beneficiary(&mut archive, 1 + i))
        .collect();
    let sources: Vec<_> = (60..62).map(|s| fixture::owner(&mut archive, s)).collect();
    let mut newcomer = fixture::owner(&mut archive, 62);
    let mut admitted: Vec<OwnerId> = sources.iter().map(|s| s.id).collect();
    let genesis = Genesis {
        directory: fixture::DIRECTORY,
        realm: fixture::REALM,
        policy: fixture::policy(),
        eligible: admitted.clone(),
        limits: fixture::limits(),
        archive: archive.clone(),
    };
    let mut app = Application::genesis(archive, genesis.registry().unwrap());
    let beneficiary = owners[0].id;

    // The transition batch carries evidence from the not-yet-admitted source
    // plus the update admitting it. The update applies last, so this batch's
    // award is still denied — the new set governs subsequent heights.
    let mut cursor = 0usize;
    admitted.push(newcomer.id);
    let first = app
        .prepare(
            1,
            fixture::evidence_for(
                app.social(),
                beneficiary,
                std::slice::from_mut(&mut newcomer),
                &mut cursor,
                1,
            ),
            vec![],
            Some(admitted.clone()),
        )
        .unwrap();
    let batch = first.batch().clone();
    assert_eq!(batch.eligible, Some(admitted.clone()));
    assert!(app.validate(&batch).is_ok());
    app.apply_locally(first);
    assert_eq!(
        app.registry().account(beneficiary).earned,
        0,
        "the carrying batch's award still sees the old eligible set"
    );
    assert!(app.registry().eligible().contains(&newcomer.id));

    // Next height: evidence from the now-admitted source credits.
    let second = app
        .prepare(
            2,
            fixture::evidence_for(
                app.social(),
                beneficiary,
                std::slice::from_mut(&mut newcomer),
                &mut cursor,
                1,
            ),
            vec![],
            None,
        )
        .unwrap();
    app.apply_locally(second);
    assert_eq!(app.registry().account(beneficiary).earned, 1);

    // An over-bound update can never commit: replay rejects it on every
    // validator identically.
    let oversized: Vec<OwnerId> = (0..=vhalla_rooms::registry::MAX_OWNERS)
        .map(|i| OwnerId::from_bytes([i as u8; 32]))
        .collect();
    assert!(matches!(
        app.prepare(3, vec![], vec![], Some(oversized)),
        Err(ApplyError::Registry(RegistryError::Capacity))
    ));
}

#[test]
fn vrb1_batches_and_bodies_decode_without_transitions() {
    // A transition-free batch canonically encodes as `VRB1` — retained V1
    // journals decode and re-encode to identical bytes, so committed value
    // ids survive the upgrade.
    let scenario = fixture::scenario(2, 4);
    let checked = scenario.app.prepare(1, vec![], vec![], None).unwrap();
    let batch = checked.batch().clone();
    let encoded = batch.encode();
    assert_eq!(&encoded[..4], b"VRB1");
    let decoded = Batch::decode(&encoded).unwrap();
    assert!(decoded.eligible.is_none());
    assert_eq!(decoded.encode(), encoded);
    assert_eq!(decoded.value_id(), batch.value_id());

    // `VRB2` carrying an empty transition is noncanonical — `None` is `VRB1`.
    let mut flag0 = encoded.clone();
    flag0[..4].copy_from_slice(b"VRB2");
    let flag_at = 4 + FRONTIER_BYTES + 8 + 4 + 4;
    flag0.insert(flag_at, 0);
    assert!(matches!(Batch::decode(&flag0), Err(ApplyError::Decode)));

    // A transition batch encodes `VRB2` and round-trips. The wire rejects
    // noncanonical sets — unsorted or duplicate ids have no byte form.
    let mut transition = batch.clone();
    transition.eligible = Some(vec![
        OwnerId::from_bytes([9; 32]),
        OwnerId::from_bytes([7; 32]),
    ]);
    let raw = transition.encode();
    assert_eq!(&raw[..4], b"VRB2");
    let decoded = Batch::decode(&raw).unwrap();
    assert_eq!(
        decoded.eligible,
        Some(vec![
            OwnerId::from_bytes([7; 32]),
            OwnerId::from_bytes([9; 32]),
        ]),
        "encode normalizes to the canonical sorted-unique form"
    );
    assert_eq!(decoded.encode(), raw);
    assert_eq!(decoded.value_id(), transition.value_id());

    let mut unsorted = raw.clone();
    let id_at = flag_at + 1 + 4;
    unsorted[id_at..id_at + 32].copy_from_slice(&[9; 32]);
    unsorted[id_at + 32..id_at + 64].copy_from_slice(&[7; 32]);
    assert!(matches!(Batch::decode(&unsorted), Err(ApplyError::Decode)));
    let mut dup = unsorted.clone();
    dup[id_at + 32..id_at + 64].copy_from_slice(&[9; 32]);
    assert!(matches!(Batch::decode(&dup), Err(ApplyError::Decode)));

    // Bodies follow the same convention: `VBB1` iff no transition.
    let body = BatchBody {
        time: 9,
        evidence: vec![],
        records: vec![],
        eligible: Some(vec![OwnerId::from_bytes([7; 32])]),
    };
    let raw = body.encode();
    assert_eq!(&raw[..4], b"VBB2");
    let decoded = BatchBody::decode(&raw).unwrap();
    assert_eq!(decoded.eligible, body.eligible);
    assert_eq!(decoded.encode(), raw);

    let plain = BatchBody {
        time: 9,
        evidence: vec![],
        records: vec![],
        eligible: None,
    };
    let raw = plain.encode();
    assert_eq!(&raw[..4], b"VBB1");
    let decoded = BatchBody::decode(&raw).unwrap();
    assert!(decoded.eligible.is_none());
    assert_eq!(decoded.encode(), raw);

    let mut flag0 = raw.clone();
    flag0[..4].copy_from_slice(b"VBB2");
    flag0.insert(4 + 8 + 4 + 4, 0);
    assert!(matches!(BatchBody::decode(&flag0), Err(ApplyError::Decode)));
}
