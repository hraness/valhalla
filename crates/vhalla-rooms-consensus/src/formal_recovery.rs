//! Production correspondence for the rooms durable-frontier model.
//!
//! Each cut publishes real canonical journal bytes and zero, one or both real
//! snapshot stores, while leaving the application frontier unapplied. These
//! tests cover the adapter's already-verified-certificate boundary; they do not
//! substitute for the node's quorum/signature checks or physical power-loss tests.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
            "vhalla-formal-recovery-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy, Debug)]
enum Cut {
    Journal,
    Social,
    BothSnapshots,
}

const CUTS: [Cut; 3] = [Cut::Journal, Cut::Social, Cut::BothSnapshots];

fn publish_through(
    adapter: &mut Adapter<FsStore>,
    checked: &Checked,
    cut: Cut,
) -> (CommitCertificate, Bundle) {
    let before = adapter.frontier();
    let next = checked.next();
    let certificate = CommitCertificate {
        bytes: format!("already-verified-formal-certificate-{}", next.height).into_bytes(),
        value_commitment: checked.batch().value_id(),
        height: next.height,
    };
    let bundle = Bundle::new(BundleParts {
        certificate: certificate.bytes.clone(),
        predecessor: before.commitment(),
        next: next.commitment(),
        batch: checked.batch().encode(),
        value: certificate.value_commitment.to_vec(),
        configuration: adapter
            .application()
            .registry()
            .policy()
            .id()
            .as_bytes()
            .to_vec(),
        control_record: next.control.to_vec(),
        debit_marker: next.value.to_vec(),
        height: next.height,
    })
    .unwrap();
    assert_eq!(adapter.journal.commit(&bundle).unwrap(), Outcome::Committed);
    if matches!(cut, Cut::Social | Cut::BothSnapshots) {
        adapter
            .social
            .commit(checked.social.clone(), adapter.social.pin())
            .unwrap();
    }
    if matches!(cut, Cut::BothSnapshots) {
        adapter
            .rooms
            .commit(checked.registry.clone(), adapter.rooms.pin())
            .unwrap();
    }
    assert_eq!(adapter.frontier(), before, "the cut is before memory apply");
    assert_eq!(adapter.recover().unwrap().pin.next, next.commitment());
    (certificate, bundle)
}

fn assert_applied(adapter: &Adapter<FsStore>, checked: &Checked, bundle: &Bundle) {
    assert_eq!(
        adapter.frontier(),
        checked.next(),
        "the complete frontier advances"
    );
    assert_eq!(
        adapter.application().social().snapshot(),
        checked.social.snapshot()
    );
    assert_eq!(
        adapter.application().registry().snapshot(),
        checked.registry.snapshot()
    );
    assert_eq!(
        adapter.social.archive().snapshot(),
        checked.social.snapshot()
    );
    assert_eq!(
        adapter.rooms.registry().snapshot(),
        checked.registry.snapshot()
    );
    assert_eq!(
        adapter
            .committed_at_height(checked.next().height)
            .unwrap()
            .bytes(),
        bundle.bytes(),
        "reconciliation preserves exact committed evidence"
    );
}

fn redeliver(adapter: &mut Adapter<FsStore>, checked: &Checked, cut: Cut) {
    let (certificate, bundle) = publish_through(adapter, checked, cut);
    let mut sink = EngineSink::default();
    assert_eq!(
        adapter.on_decided(&mut sink, &certificate),
        DecidedOutcome::Acked
    );
    assert_applied(adapter, checked, &bundle);
    assert_eq!(
        sink.sent,
        vec![EngineMsg::CommitAck {
            height: certificate.height
        }]
    );
    let revision = adapter.application().registry().revision();
    let social_pin = adapter.social.pin();
    let rooms_pin = adapter.rooms.pin();
    assert_eq!(
        adapter.on_finalized(&mut sink, &certificate),
        DecidedOutcome::Acked
    );
    assert_applied(adapter, checked, &bundle);
    assert_eq!(adapter.application().registry().revision(), revision);
    assert_eq!(adapter.social.pin(), social_pin);
    assert_eq!(adapter.rooms.pin(), rooms_pin);
    assert_eq!(
        sink.sent.last(),
        Some(&EngineMsg::NextHeightReply {
            height: certificate.height + 1
        })
    );
    let foreign = CommitCertificate {
        value_commitment: [0xEE; 32],
        ..certificate
    };
    assert_eq!(
        adapter.on_decided(&mut sink, &foreign),
        DecidedOutcome::Rejected
    );
    assert_eq!(
        sink.sent.len(),
        2,
        "conflicting identity emits no acknowledgement"
    );
    assert_applied(adapter, checked, &bundle);
}

#[test]
fn formal_recovery_empty_clock_batch_redelivery_applies_full_frontier() {
    for cut in CUTS {
        let home = Home::new();
        let scenario = fixture::scenario(1, 1);
        let mut adapter = Adapter::open(&home.0, &scenario.genesis).unwrap();
        let before = adapter.frontier();
        let checked = adapter
            .application()
            .prepare(1_000_000, vec![], vec![], None)
            .unwrap();
        assert_eq!(before.registry, checked.next().registry);
        assert_eq!(before.social, checked.next().social);
        assert_ne!(
            before.control,
            checked.next().control,
            "the clock expires an existing grant"
        );
        assert_ne!(before.value, checked.next().value);
        redeliver(&mut adapter, &checked, cut);
    }
}

#[test]
fn formal_recovery_game_batch_redelivery_preserves_order_and_identity() {
    for cut in CUTS {
        let home = Home::new();
        let scenario = fixture::scenario(1, 1);
        let mut adapter = Adapter::open(&home.0, &scenario.genesis).unwrap();
        let checked = adapter
            .application()
            .prepare_with_games(
                1,
                vec![],
                vec![],
                vec![GameCommitment {
                    realm: scenario.genesis.realm,
                    room: RoomId(2),
                    session: [3; 32],
                    epoch: 4,
                    kind: GameCommitmentKind::Event,
                    object: [5; 32],
                }],
                None,
                None,
            )
            .unwrap();
        redeliver(&mut adapter, &checked, cut);
    }
}

#[test]
fn formal_recovery_changed_snapshots_redeliver_from_each_publication_cut() {
    for cut in CUTS {
        let home = Home::new();
        let plan = fixture::plan(1, 2, 2);
        let mut adapter = Adapter::open(&home.0, &plan.genesis).unwrap();
        let checked = adapter.validate(&plan.batches[&1]).unwrap();
        assert_ne!(adapter.frontier().registry, checked.next().registry);
        assert_ne!(adapter.frontier().social, checked.next().social);
        redeliver(&mut adapter, &checked, cut);
    }
}

#[test]
fn formal_recovery_reopen_accepts_social_only_publication_cuts() {
    for cut in CUTS {
        let home = Home::new();
        let mut scenario = fixture::scenario(1, 1);
        let mut adapter = Adapter::open(&home.0, &scenario.genesis).unwrap();
        let evidence = fixture::seal_record(&mut scenario.sources[0], &[]).encode();
        let checked = adapter
            .application()
            .prepare(1, vec![evidence], vec![], None)
            .unwrap();
        assert_eq!(adapter.frontier().registry, checked.next().registry);
        assert_ne!(adapter.frontier().social, checked.next().social);
        let (certificate, bundle) = publish_through(&mut adapter, &checked, cut);
        drop(adapter);
        let mut reopened = Adapter::open(&home.0, &scenario.genesis)
            .unwrap_or_else(|error| panic!("honest {cut:?} cut must reopen: {error}"));
        assert_applied(&reopened, &checked, &bundle);
        assert_eq!(reopened.decide(&certificate), DecidedOutcome::Acked);
        assert_applied(&reopened, &checked, &bundle);
    }
}

#[test]
fn formal_recovery_reopen_accepts_changed_and_root_preserving_history() {
    for cut in CUTS {
        let home = Home::new();
        let plan = fixture::plan(1, 2, 2);
        let mut adapter = Adapter::open(&home.0, &plan.genesis).unwrap();
        let first = adapter.validate(&plan.batches[&1]).unwrap();
        let (_, first_bundle) = publish_through(&mut adapter, &first, cut);
        drop(adapter);
        let mut adapter = Adapter::open(&home.0, &plan.genesis).unwrap();
        assert_applied(&adapter, &first, &first_bundle);
        for time in [first.next().time + 1, first.next().time + 2] {
            let checked = adapter
                .application()
                .prepare(time, vec![], vec![], None)
                .unwrap();
            assert_eq!(adapter.frontier().registry, checked.next().registry);
            assert_eq!(adapter.frontier().social, checked.next().social);
            let (certificate, bundle) = publish_through(&mut adapter, &checked, cut);
            drop(adapter);
            adapter = Adapter::open(&home.0, &plan.genesis).unwrap();
            assert_applied(&adapter, &checked, &bundle);
            assert_eq!(adapter.decide(&certificate), DecidedOutcome::Acked);
        }
        assert_eq!(adapter.frontier().height, 3);
    }
}

#[test]
fn formal_recovery_reopen_refuses_snapshots_ahead_of_empty_journal() {
    for (social, rooms) in [(true, false), (false, true), (true, true)] {
        let home = Home::new();
        let plan = fixture::plan(1, 2, 2);
        let mut adapter = Adapter::open(&home.0, &plan.genesis).unwrap();
        let checked = adapter.validate(&plan.batches[&1]).unwrap();
        // These deliberately impossible states must remain refusals: no journal
        // record authorizes either changed snapshot, even at the genesis frontier.
        if social {
            adapter
                .social
                .commit(checked.social.clone(), adapter.social.pin())
                .unwrap();
        }
        if rooms {
            adapter
                .rooms
                .commit(checked.registry.clone(), adapter.rooms.pin())
                .unwrap();
        }
        assert_eq!(adapter.recover().unwrap().pin.height, 0);
        drop(adapter);
        match Adapter::open(&home.0, &plan.genesis) {
            Err(AdapterError::Corrupt) => {}
            Err(other) => panic!("expected divergence refusal, got {other}"),
            Ok(_) => panic!("an empty journal cannot authorize changed snapshots"),
        }
    }
}

#[test]
fn formal_recovery_reopen_refuses_rooms_ahead_of_social() {
    let home = Home::new();
    let plan = fixture::plan(1, 2, 2);
    let mut adapter = Adapter::open(&home.0, &plan.genesis).unwrap();
    let checked = adapter.validate(&plan.batches[&1]).unwrap();
    let (_, bundle) = publish_through(&mut adapter, &checked, Cut::Journal);
    // Reversing snapshot publication is not a recoverable protocol cut: the
    // rooms state now depends on social evidence absent from the durable store.
    adapter
        .rooms
        .commit(checked.registry.clone(), adapter.rooms.pin())
        .unwrap();
    drop(adapter);
    match Adapter::open(&home.0, &plan.genesis) {
        Err(AdapterError::Corrupt) => {}
        Err(other) => panic!("expected publication-order refusal, got {other}"),
        Ok(_) => panic!("rooms cannot publish before their social evidence"),
    }
    let journal = Journal::new(home.0.join("journal"), FsStore);
    assert_eq!(
        journal.bundle(bundle.id()).unwrap().unwrap().bytes(),
        bundle.bytes()
    );
    assert_eq!(journal.at_height(1).unwrap(), Some(bundle.id()));
}
