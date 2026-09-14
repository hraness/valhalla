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
