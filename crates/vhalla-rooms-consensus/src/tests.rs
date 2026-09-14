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
