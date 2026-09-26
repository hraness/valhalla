//! Real-application replay through the durable boundary: `Registry` +
//! `Archive` behind the journal and both snapshot stores.
use super::*;
use crate::fixture;
use hegel::{generators as gs, HealthCheck, TestCase};
use std::collections::BTreeSet;
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
fn committed_game_only_batch_reconciles_an_unadvanced_frontier() {
    let plan = fixture::plan(0, 4, 8);
    let home = dir("game-reconcile");
    let mut adapter = Adapter::open(&home, &plan.genesis).unwrap();
    let checked = adapter
        .application()
        .prepare_with_games(
            1,
            vec![],
            vec![],
            vec![GameCommitment {
                realm: plan.genesis.realm,
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
    let batch = checked.batch().clone();
    let certificate = cert(&batch, 1, "game");
    adapter.hold(batch);
    assert_eq!(adapter.decide(&certificate), DecidedOutcome::Acked);
    let committed = adapter.frontier();
    adapter.app = Application::genesis(
        plan.genesis.archive.clone(),
        plan.genesis.registry().unwrap(),
    );
    assert_eq!(adapter.frontier().height, 0);
    assert_eq!(adapter.decide(&certificate), DecidedOutcome::Acked);
    assert_eq!(adapter.frontier(), committed);
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

/// The committed-sequence oracle a replica is checked against: the source's
/// own frontier commitment, applied-transition count and clock after every
/// committed height, plus the committed bundle each height binds.
struct CommittedSequence {
    commitment: Vec<[u8; 32]>,
    revision: Vec<u64>,
    time: Vec<u64>,
    last_time: Vec<u64>,
    bundles: BTreeMap<u64, Bundle>,
}

/// Runs `plan` through a fresh source adapter on `home`, records the oracle
/// per committed height (index 0 is genesis), then drops the adapter so the
/// journal reads back exactly as a peer would fetch it.
fn commit_plan(home: &PathBuf, plan: &fixture::Plan, tag: &str) -> CommittedSequence {
    let mut commitment = Vec::new();
    let mut revision = Vec::new();
    let mut time = Vec::new();
    let mut last_time = Vec::new();
    {
        let mut adapter = Adapter::open(home, &plan.genesis).unwrap();
        let mut sink = EngineSink::default();
        commitment.push(adapter.frontier().commitment());
        revision.push(adapter.application().registry().revision());
        time.push(adapter.frontier().time);
        last_time.push(adapter.application().registry().last_time());
        for (height, batch) in &plan.batches {
            adapter.hold(batch.clone());
            assert_eq!(
                adapter.on_decided(&mut sink, &cert(batch, *height, tag)),
                DecidedOutcome::Acked
            );
            commitment.push(adapter.frontier().commitment());
            revision.push(adapter.application().registry().revision());
            time.push(adapter.frontier().time);
            last_time.push(adapter.application().registry().last_time());
        }
        // drop: the replica then opens the source's journal read-side
    }
    let journal = Journal::new(home.join("journal"), FsStore);
    let mut bundles = BTreeMap::new();
    for height in plan.batches.keys() {
        let id = journal.at_height(*height).unwrap().unwrap();
        bundles.insert(*height, journal.bundle(id).unwrap().unwrap());
    }
    CommittedSequence {
        commitment,
        revision,
        time,
        last_time,
        bundles,
    }
}

/// The in-memory state must equal the committed prefix exactly: height,
/// frontier commitment, agreed clock and applied-transition count.
fn assert_converged(replica: &Adapter<FsStore>, source: &CommittedSequence, committed: u64) {
    let frontier = replica.frontier();
    assert_eq!(frontier.height, committed);
    assert_eq!(frontier.commitment(), source.commitment[committed as usize]);
    assert_eq!(frontier.time, source.time[committed as usize]);
    let registry = replica.application().registry();
    assert_eq!(registry.revision(), source.revision[committed as usize]);
    assert_eq!(registry.last_time(), source.last_time[committed as usize]);
}

/// The durable pin — the authority on committed state — must record exactly
/// the committed prefix, and the retained bundles on disk must be exactly
/// that prefix: the pin references only the tip, so earlier committed
/// bundles report as "orphans" of the pin — and a rejected or replayed
/// input must never add to either set.
fn assert_pin(replica: &Adapter<FsStore>, source: &CommittedSequence, committed: u64) {
    let recovered = replica.recover().unwrap();
    assert_eq!(recovered.pin.height, committed);
    assert_eq!(recovered.pin.next, source.commitment[committed as usize]);
    assert_eq!(
        recovered.pin.predecessor,
        if committed == 0 {
            [0; 32]
        } else {
            source.commitment[committed as usize - 1]
        }
    );
    assert_eq!(
        recovered.pin.bundle,
        if committed == 0 {
            [0; 32]
        } else {
            source.bundles[&committed].id()
        }
    );
    let retained: BTreeSet<[u8; 32]> = recovered.orphans.iter().copied().collect();
    let expected: BTreeSet<[u8; 32]> = (1..committed).map(|h| source.bundles[&h].id()).collect();
    assert_eq!(
        retained, expected,
        "retained bundles must be exactly the committed prefix"
    );
    assert!(
        !recovered.dropped_tmp && recovered.dropped_heights.is_empty(),
        "rejected input must leave no unpublished residue"
    );
}

/// Generative companion to `replica_absorbs_committed_bundles_and_converges`,
/// `replica_rejects_unverified_and_misbound_bundles`,
/// `exact_redelivery_reconciles_without_double_apply` and
/// `restart_rebuilds_from_journal_and_pinned_snapshots`.
///
/// Two replicas sit behind one committed source. Each drawn step picks a
/// replica and an operation: absorb a bundle at a drawn height (in-order,
/// redelivery or out-of-order), restart, absorb a forged or misbound bundle,
/// or take an engine-path certificate (honest or equivocating). The oracle
/// throughout is the committed sequence itself: a replica's frontier,
/// applied revision, clock and durable pin must always equal the source's
/// record of its committed prefix — never more (rejected input never
/// lands), never twice (no double-apply), never less (exact convergence
/// with byte-identical evidence).
///
/// `held` models `pending`: absorb holds every bundle that passes binding +
/// verification even when the decide then rejects it, `prune_pending` keeps
/// only the batch parented on a newly advanced frontier, and a restart
/// drops the map — that is what makes an engine-path decide at the next
/// height ack exactly when the batch was previously delivered.
#[hegel::test(test_cases = 32, suppress_health_check = [HealthCheck::TooSlow])]
fn replicas_converge_under_drawn_delivery_interleavings(tc: TestCase) {
    let heights = 4u64;
    let plan = fixture::plan(heights, 4, 12);
    let source_home = dir("gen-source");
    let source = commit_plan(&source_home, &plan, "g");
    // The stand-in verifier binds the (height, value) pair a real engine
    // verifier would: the certificate's claimed height and decided value.
    let verify = |bytes: &[u8], height: u64, value: &[u8; 32]| {
        bytes == format!("cert-g-{height}").as_bytes()
            && plan
                .batches
                .get(&height)
                .is_some_and(|b| b.value_id() == *value)
    };
    let homes = [dir("gen-r0"), dir("gen-r1")];
    let mut replicas = [
        Some(Adapter::open(&homes[0], &plan.genesis).unwrap()),
        Some(Adapter::open(&homes[1], &plan.genesis).unwrap()),
    ];
    let mut committed = [0u64; 2];
    let mut held: [BTreeSet<u64>; 2] = [BTreeSet::new(), BTreeSet::new()];

    for _ in 0..tc.draw(gs::integers::<usize>().min_value(1).max_value(12)) {
        let which = usize::from(tc.draw(gs::booleans()));
        let slot = &mut replicas[which];
        match tc.draw(gs::integers::<u8>().max_value(9)) {
            // A committed bundle arrives. Near-frontier draws mix in-order
            // delivery, redelivery and gaps; uniform draws roam farther.
            0..=4 => {
                let replica = slot.as_mut().unwrap();
                let h = if tc.draw(gs::booleans()) {
                    (committed[which] + tc.draw(gs::integers::<u64>().max_value(3)))
                        .saturating_sub(1)
                        .clamp(1, heights)
                } else {
                    tc.draw(gs::integers::<u64>().min_value(1).max_value(heights))
                };
                let revision_before = replica.application().registry().revision();
                let outcome = replica.absorb(&source.bundles[&h], verify);
                // Binding and verification passed, so the batch is now held
                // whether or not the decide below it committed.
                held[which].insert(h);
                if h <= committed[which] {
                    assert_eq!(
                        outcome,
                        DecidedOutcome::Acked,
                        "an already-committed bundle must reconcile"
                    );
                    assert_eq!(
                        replica.application().registry().revision(),
                        revision_before,
                        "a committed batch must never double-apply"
                    );
                } else if h == committed[which] + 1 {
                    assert_eq!(outcome, DecidedOutcome::Acked);
                    committed[which] = h;
                    held[which].retain(|&x| x == h + 1);
                } else {
                    assert_eq!(
                        outcome,
                        DecidedOutcome::Rejected,
                        "a gap delivery must be rejected, not skipped ahead"
                    );
                }
            }
            // Restart: rebuild from the journal and pinned snapshots.
            5..=6 => {
                drop(slot.take()); // store locks release with the adapter
                let replica = slot.insert(Adapter::open(&homes[which], &plan.genesis).unwrap());
                held[which].clear();
                assert_converged(replica, &source, committed[which]);
            }
            // A forged or misbound bundle arrives — every variant must be
            // rejected before durable state moves.
            7..=8 => {
                let replica = slot.as_mut().unwrap();
                let h = tc.draw(gs::integers::<u64>().min_value(1).max_value(heights));
                let genuine = &source.bundles[&h];
                let mut parts = BundleParts {
                    certificate: genuine.field(0).unwrap().to_vec(),
                    predecessor: genuine.field(1).unwrap().try_into().unwrap(),
                    next: genuine.field(2).unwrap().try_into().unwrap(),
                    batch: genuine.field(3).unwrap().to_vec(),
                    value: genuine.field(4).unwrap().to_vec(),
                    configuration: genuine.field(5).unwrap().to_vec(),
                    control_record: genuine.field(6).unwrap().to_vec(),
                    debit_marker: genuine.field(7).unwrap().to_vec(),
                    height: h,
                };
                match tc.draw(gs::integers::<u8>().max_value(3)) {
                    // Misbound: a real batch under a different committed
                    // value — the binding check rejects before verify runs.
                    0 => {
                        parts.value = plan.batches[&(h % heights + 1)].value_id().to_vec();
                        let forged = Bundle::new(parts).unwrap();
                        assert_eq!(
                            replica.absorb(&forged, |_, _, _| panic!("verify must not run")),
                            DecidedOutcome::Rejected
                        );
                    }
                    // Certificate bytes nobody can verify.
                    1 => {
                        parts.certificate = tc.draw(gs::vecs(gs::integers::<u8>()).max_size(48));
                        if parts.certificate == genuine.field(0).unwrap() {
                            parts.certificate.push(0);
                        }
                        let forged = Bundle::new(parts).unwrap();
                        assert_eq!(replica.absorb(&forged, verify), DecidedOutcome::Rejected);
                    }
                    // The bundle lies about which height it commits.
                    2 => {
                        let mut claimed =
                            tc.draw(gs::integers::<u64>().min_value(1).max_value(heights + 2));
                        if claimed == h {
                            claimed += 1;
                        }
                        parts.height = claimed;
                        let forged = Bundle::new(parts).unwrap();
                        assert_eq!(replica.absorb(&forged, verify), DecidedOutcome::Rejected);
                    }
                    // A real certificate shape over a batch with a forged
                    // claim — the committed (height, value) pair rejects it.
                    _ => {
                        let mut batch = Batch::decode(genuine.field(3).unwrap()).unwrap();
                        match tc.draw(gs::integers::<u8>().max_value(3)) {
                            0 => batch.result_registry = [0xEE; 32],
                            1 => batch.result_social = [0xEE; 32],
                            2 => batch.result_control = [0xEE; 32],
                            _ => {
                                batch.time =
                                    batch.time.wrapping_add(tc.draw(gs::integers::<u64>()) | 1)
                            }
                        }
                        parts.batch = batch.encode();
                        parts.value = batch.value_id().to_vec();
                        let forged = Bundle::new(parts).unwrap();
                        assert_eq!(replica.absorb(&forged, verify), DecidedOutcome::Rejected);
                    }
                }
            }
            // An engine-path certificate arrives: honest pairs reconcile or
            // commit a held batch; equivocating values are always rejected.
            _ => {
                let replica = slot.as_mut().unwrap();
                let h = tc.draw(gs::integers::<u64>().min_value(1).max_value(heights));
                let honest = tc.draw(gs::booleans());
                let value = if honest {
                    plan.batches[&h].value_id()
                } else {
                    plan.batches[&(h % heights + 1)].value_id()
                };
                if tc.draw(gs::booleans()) {
                    replica.hold(plan.batches[&h].clone());
                    held[which].insert(h);
                }
                let mut sink = EngineSink::default();
                let outcome = replica.on_decided(
                    &mut sink,
                    &CommitCertificate {
                        bytes: format!("cert-g-{h}").into_bytes(),
                        value_commitment: value,
                        height: h,
                    },
                );
                let expected_ack = honest
                    && (h <= committed[which]
                        || (h == committed[which] + 1 && held[which].contains(&h)));
                if expected_ack {
                    assert_eq!(outcome, DecidedOutcome::Acked);
                    assert_eq!(sink.sent, vec![EngineMsg::CommitAck { height: h }]);
                    if h == committed[which] + 1 {
                        committed[which] = h;
                        held[which].retain(|&x| x == h + 1);
                    }
                } else {
                    assert_eq!(outcome, DecidedOutcome::Rejected);
                    assert!(
                        sink.sent.is_empty(),
                        "a rejected certificate must emit nothing"
                    );
                }
            }
        }
        let replica = replicas[which].as_ref().unwrap();
        assert_converged(replica, &source, committed[which]);
        assert_pin(replica, &source, committed[which]);
    }

    // Whatever the delivery schedule, each replica's journal holds exactly
    // its committed prefix — the same bundles the deciding quorum committed.
    for (which, slot) in replicas.iter().enumerate() {
        let replica = slot.as_ref().unwrap();
        assert_converged(replica, &source, committed[which]);
        assert_pin(replica, &source, committed[which]);
        for h in 1..=committed[which] {
            assert_eq!(
                replica.committed_at_height(h).unwrap().id(),
                source.bundles[&h].id(),
                "committed evidence must be the byte-identical committed bundle"
            );
        }
        assert!(
            replica.committed_at_height(committed[which] + 1).is_none(),
            "no evidence may exist beyond the committed sequence"
        );
        let _ = std::fs::remove_dir_all(&homes[which]);
    }
    let _ = std::fs::remove_dir_all(&source_home);
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

/// Generative companion to `batch_clock_is_monotonic_and_step_bounded`:
/// over a drawn sequence of raw clock inputs interleaved with commits, the
/// producer always clamps into the committed window, the committed clock
/// never regresses and never advances more than `MAX_TIME_DRIFT` per
/// height, and a batch claiming a time outside the window fails with
/// exactly `ApplyError::Clock` — the drawn step count stands in for the
/// hand-written boundary cases.
#[hegel::test(test_cases = 64)]
fn committed_clock_holds_across_drawn_steps(tc: TestCase) {
    let mut scenario = fixture::scenario(2, 4);
    let mut committed_time = 0u64;
    for _ in 0..tc.draw(gs::integers::<usize>().max_value(15)) {
        let raw = tc.draw(gs::integers::<u64>());
        let checked = scenario.app.prepare(raw, vec![], vec![], None).unwrap();
        let window_top = committed_time.saturating_add(MAX_TIME_DRIFT);
        let expected = if committed_time == 0 {
            raw
        } else {
            raw.clamp(committed_time, window_top)
        };
        assert_eq!(
            checked.batch().time,
            expected,
            "the producer must clamp the clock into the committed window"
        );
        // A drawn out-of-window claim must fail with `Clock` — and only
        // those claims: in-window claims proceed to the result compare.
        let mut probe = checked.batch().clone();
        probe.time = tc.draw(gs::integers::<u64>());
        let in_window = committed_time == 0 || (committed_time..=window_top).contains(&probe.time);
        assert_eq!(
            matches!(scenario.app.validate(&probe), Err(ApplyError::Clock)),
            !in_window,
            "Clock rejection must be exactly the out-of-window set"
        );
        if tc.draw(gs::booleans()) {
            let time = checked.batch().time;
            scenario.app.apply_locally(checked);
            assert!(
                time >= committed_time,
                "the committed clock never regresses"
            );
            assert!(
                committed_time == 0 || time <= window_top,
                "nor advances more than MAX_TIME_DRIFT per height"
            );
            committed_time = time;
            assert_eq!(scenario.app.frontier().time, committed_time);
        }
    }
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
        games: vec![],
        eligible: Some(vec![OwnerId::from_bytes([7; 32])]),
        rotation: None,
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
        games: vec![],
        eligible: None,
        rotation: None,
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

#[test]
fn vrb3_orders_bounded_game_commitments_without_mutating_application_state() {
    let scenario = fixture::scenario(2, 4);
    let commitment = GameCommitment {
        realm: RealmId(11),
        room: RoomId(12),
        session: [13; 32],
        epoch: 14,
        kind: GameCommitmentKind::Settlement,
        object: [15; 32],
    };
    let checked = scenario
        .app
        .prepare_with_games(1, vec![], vec![], vec![commitment], None, None)
        .unwrap();
    let batch = checked.batch();
    let raw = batch.encode();
    assert_eq!(&raw[..4], b"VRB3");
    assert_eq!(batch.result_registry, scenario.app.registry().digest());
    assert_eq!(
        batch.result_social,
        *scenario.app.social().root().as_bytes()
    );
    let decoded = Batch::decode(&raw).unwrap();
    assert_eq!(decoded.games, vec![commitment]);
    assert_eq!(decoded.encode(), raw);
    assert!(scenario.app.validate(&decoded).is_ok());
    let mut with_transition = decoded.clone();
    with_transition.eligible = Some(vec![
        OwnerId::from_bytes([9; 32]),
        OwnerId::from_bytes([7; 32]),
    ]);
    let transition_raw = with_transition.encode();
    assert_eq!(&transition_raw[..4], b"VRB3");
    assert_eq!(
        Batch::decode(&transition_raw).unwrap().eligible,
        Some(vec![
            OwnerId::from_bytes([7; 32]),
            OwnerId::from_bytes([9; 32]),
        ])
    );

    let another = GameCommitment {
        kind: GameCommitmentKind::Event,
        object: [16; 32],
        ..commitment
    };
    let forward = scenario
        .app
        .prepare_with_games(1, vec![], vec![], vec![commitment, another], None, None)
        .unwrap();
    let reverse = scenario
        .app
        .prepare_with_games(1, vec![], vec![], vec![another, commitment], None, None)
        .unwrap();
    assert_ne!(forward.batch().value_id(), reverse.batch().value_id());

    let body = BatchBody {
        time: 1,
        evidence: vec![],
        records: vec![],
        games: vec![commitment],
        eligible: Some(vec![OwnerId::from_bytes([7; 32])]),
        rotation: None,
    };
    let raw = body.encode();
    assert_eq!(&raw[..4], b"VBB3");
    let decoded = BatchBody::decode(&raw).unwrap();
    assert_eq!(decoded.games, body.games);
    assert_eq!(decoded.eligible, body.eligible);
    assert_eq!(decoded.encode(), raw);

    assert!(matches!(
        scenario.app.prepare_with_games(
            1,
            vec![],
            vec![],
            vec![commitment; MAX_GAME_COMMITMENTS + 1],
            None,
            None,
        ),
        Err(ApplyError::Bounds)
    ));

    let mut bad_kind = batch.encode();
    let game_at = 4 + FRONTIER_BYTES + 8 + 4 + 4 + 1 + 4;
    let kind_at = game_at + 16 + 16 + 32 + 8;
    assert_eq!(bad_kind[kind_at], GameCommitmentKind::Settlement as u8);
    bad_kind[kind_at] = 1;
    assert!(matches!(Batch::decode(&bad_kind), Err(ApplyError::Decode)));
    let mut zero_count = batch.encode();
    zero_count[game_at - 4..game_at].copy_from_slice(&0_u32.to_be_bytes());
    assert!(matches!(
        Batch::decode(&zero_count),
        Err(ApplyError::Decode)
    ));
}

#[test]
fn decoders_accept_only_canonical_bytes() {
    // Canonical-form invariant: any input a decoder accepts must re-encode
    // to the identical bytes. Exercising every truncation, a trailing byte,
    // and byte mutations of valid encodings therefore covers the whole
    // noncanonical-input space without a fuzzer — a panic, hang or
    // decode-then-encode difference is a decoder bug.
    fn check(mut raws: Vec<Vec<u8>>, decode: impl Fn(&[u8]) -> Option<Vec<u8>>) {
        for raw in raws.drain(..) {
            for cut in 0..=raw.len() {
                if let Some(re) = decode(&raw[..cut]) {
                    assert_eq!(re, raw[..cut], "accepted prefix {cut} noncanonical");
                }
            }
            for extra in [0u8, 1, 0xFF] {
                let mut trailing = raw.clone();
                trailing.push(extra);
                assert!(decode(&trailing).is_none(), "trailing byte accepted");
            }
            for i in 0..raw.len() {
                for delta in [0x01u8, 0x80, 0xFF] {
                    let mut mutated = raw.clone();
                    mutated[i] ^= delta;
                    if let Some(re) = decode(&mutated) {
                        assert_eq!(re, mutated, "mutation at {i} accepted noncanonically");
                    }
                }
            }
        }
    }

    let scenario = fixture::scenario(2, 4);
    let checked = scenario.app.prepare(1, vec![], vec![], None).unwrap();
    let mut transition = checked.batch().clone();
    transition.eligible = Some(vec![
        OwnerId::from_bytes([9; 32]),
        OwnerId::from_bytes([7; 32]),
    ]);
    let game = scenario
        .app
        .prepare_with_games(
            1,
            vec![],
            vec![],
            vec![GameCommitment {
                realm: RealmId(1),
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
    check(
        vec![
            checked.batch().encode(),
            transition.encode(),
            game.batch().encode(),
        ],
        |raw| Batch::decode(raw).ok().map(|batch| batch.encode()),
    );

    let body = BatchBody {
        time: 9,
        evidence: vec![],
        records: vec![],
        games: vec![],
        eligible: Some(vec![OwnerId::from_bytes([7; 32])]),
        rotation: None,
    };
    let game_body = BatchBody {
        time: 9,
        evidence: vec![],
        records: vec![],
        games: vec![GameCommitment {
            realm: RealmId(1),
            room: RoomId(2),
            session: [3; 32],
            epoch: 4,
            kind: GameCommitmentKind::Settlement,
            object: [5; 32],
        }],
        eligible: None,
        rotation: None,
    };
    check(
        vec![
            body.encode(),
            game_body.encode(),
            BatchBody {
                time: 9,
                evidence: vec![],
                records: vec![],
                games: vec![],
                eligible: None,
                rotation: None,
            }
            .encode(),
        ],
        |raw| BatchBody::decode(raw).ok().map(|body| body.encode()),
    );

    check(
        vec![encode_eligible_update(&[
            OwnerId::from_bytes([9; 32]),
            OwnerId::from_bytes([7; 32]),
            OwnerId::from_bytes([9; 32]),
        ])],
        |raw| {
            decode_eligible_update(raw)
                .ok()
                .map(|set| encode_eligible_update(&set))
        },
    );
}

/// Diagnostic: validate the real on-disk batch against the real app state.
/// Manual tool — needs `DIAG_APP=<adapter dir>` and `DIAG_BATCH=<file>`.
#[test]
#[ignore = "requires DIAG_APP and DIAG_BATCH against a live node home"]
fn diag_validate_live_batch() {
    let app_dir = std::env::var("DIAG_APP").expect("DIAG_APP");
    let batch_path = std::env::var("DIAG_BATCH").expect("DIAG_BATCH");
    let realm = RealmId(0x47);
    let directory = DirectoryId::from_bytes(hex_literal(
        "9ba57514cf3136a4572dadce837da2262d84bb67a7a9fbcaf8bf3934f3c53498",
    ));
    let eligible = vec![OwnerId::from_bytes(hex_literal(
        "12a4240e36c6407cf2d6563628869c1c4032e4252c0aa64bdd3b978103048b2b",
    ))];
    let limits = Limits {
        records: 1024,
        control_reserve: 128,
        data_per_owner: 128,
        data_per_writer: 64,
        control_per_owner: 32,
        pending: 128,
        pending_per_signer: 8,
    };
    let policy = DirectoryPolicy {
        base_cost: 1,
        window_seconds: 60,
        max_in_window: 4,
        support_epoch_seconds: 60,
        max_lifetime_rooms: 8,
    };
    let genesis = Genesis {
        directory,
        realm,
        policy,
        eligible,
        limits,
        archive: {
            // The app's own committed archive is the undrifted genesis input.
            let app_dir2 = std::path::PathBuf::from(&app_dir);
            let store =
                vhalla_social_store::Store::open(app_dir2.join("social"), realm, limits, None)
                    .unwrap();
            store.archive().clone()
        },
    };
    let adapter = Adapter::open(app_dir, &genesis).expect("adapter open");
    eprintln!("frontier: {:?}", adapter.application().frontier());
    let bytes = std::fs::read(batch_path).unwrap();
    let batch = Batch::decode(&bytes).expect("batch decode");
    eprintln!(
        "batch: parent={:?} time={} evidence={} records={} eligible={:?}",
        batch.parent,
        batch.time,
        batch.evidence.len(),
        batch.records.len(),
        batch.eligible.as_ref().map(|e| e.len())
    );
    for (i, raw) in batch.records.iter().enumerate() {
        if let Ok(record) = vhalla_rooms::SignedRecord::decode(raw).and_then(|r| r.verify()) {
            eprintln!("  record[{i}]: {:?}", record.body());
        }
    }
    match adapter.validate(&batch) {
        Ok(_) => eprintln!("VERDICT: VALID"),
        Err(e) => eprintln!("VERDICT: INVALID — {e:?}"),
    }
    panic!("show output");
}

fn hex_literal(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    out
}

#[test]
fn restart_replays_published_journal_after_unpublished_snapshot_preparation() {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    for (store_name, prefix) in [
        ("social", b"".as_slice()),
        ("social", b"VHSI".as_slice()),
        ("rooms", b"".as_slice()),
        ("rooms", b"VHRI".as_slice()),
    ] {
        let plan = fixture::plan(1, 4, 8);
        let home = dir("snapshot-prepare-restart");
        let mut adapter = Adapter::open(&home, &plan.genesis).unwrap();
        let batch = plan.batches.get(&1).unwrap();
        let checked = adapter.application().validate(batch).unwrap();
        let next = checked.next();
        let certificate = cert(batch, 1, "interrupted-materialization");
        let bundle = Bundle::new(BundleParts {
            certificate: certificate.bytes,
            predecessor: adapter.frontier().commitment(),
            next: next.commitment(),
            batch: batch.encode(),
            value: batch.value_id().to_vec(),
            configuration: adapter
                .application()
                .registry()
                .policy()
                .id()
                .as_bytes()
                .to_vec(),
            control_record: next.control.to_vec(),
            debit_marker: next.value.to_vec(),
            height: 1,
        })
        .unwrap();
        assert_eq!(adapter.journal.commit(&bundle).unwrap(), Outcome::Committed);
        // The journal marker is published before either snapshot. Interruption
        // of rooms preparation comes after the social snapshot has committed.
        if store_name == "rooms" {
            adapter
                .social
                .commit(checked.social.clone(), adapter.social.pin())
                .unwrap();
        }
        assert_eq!(adapter.recover().unwrap().pin.height, 1);
        assert_eq!(adapter.frontier().height, 0);
        drop(adapter);
        let scratch = home.join(store_name).join("intent.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&scratch)
            .unwrap();
        file.write_all(prefix).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let reopened = Adapter::open(&home, &plan.genesis).unwrap();
        assert_eq!(reopened.frontier(), next);
        assert_eq!(
            reopened.application().social().snapshot(),
            checked.social.snapshot()
        );
        assert_eq!(
            reopened.application().registry().snapshot(),
            checked.registry.snapshot()
        );
        assert_eq!(
            reopened.committed_at_height(1).unwrap().bytes(),
            bundle.bytes()
        );
        assert!(!scratch.exists());
        drop(reopened);
        assert_eq!(
            Adapter::open(&home, &plan.genesis).unwrap().frontier(),
            next
        );
        let _ = std::fs::remove_dir_all(home);
    }
}

/// A deterministic Ed25519 public key for validator members — committed
/// sets require canonical points, not raw digest bytes.
fn member_key(seed: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    ed25519_dalek::SigningKey::from_bytes(&bytes)
        .verifying_key()
        .to_bytes()
}

fn member(seed: u8, power: u64) -> ValidatorMember {
    ValidatorMember {
        key: member_key(seed),
        power,
    }
}

#[test]
fn rotation_intake_file_round_trips_and_rejects_malformed() {
    let rotation = CommittedRotation {
        from: 30,
        validators: vec![member(2, 7), member(1, 3)],
    };
    let raw = encode_rotation_update(&rotation);
    assert_eq!(&raw[..4], b"VRT1");
    let decoded = decode_rotation_update(&raw).unwrap();
    // Decode returns the canonical key-sorted set.
    assert_eq!(decoded.from, 30);
    assert!(decoded
        .validators
        .windows(2)
        .all(|pair| pair[0].key < pair[1].key));
    assert_eq!(decoded.validators.len(), 2);
    // Re-encoding the canonical decode is byte-stable.
    assert_eq!(
        encode_rotation_update(&decoded),
        raw
    );

    // Bad magic, trailing bytes, zero count, unsorted keys, zero power.
    let mut bad_magic = raw.clone();
    bad_magic[3] = b'2';
    assert!(decode_rotation_update(&bad_magic).is_err());
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(decode_rotation_update(&trailing).is_err());
    let mut zero_count = raw.clone();
    zero_count[8..12].copy_from_slice(&0u32.to_be_bytes());
    zero_count.truncate(16);
    assert!(decode_rotation_update(&zero_count).is_err());
    // Swap the two members — the wire is strictly key-ascending.
    let mut unsorted = raw.clone();
    let (a, b) = (16usize, 56usize);
    for i in 0..40 {
        unsorted.swap(a + i, b + i);
    }
    assert!(decode_rotation_update(&unsorted).is_err());
    // Zero the first member's power.
    let mut zeroed = raw.clone();
    zeroed[16 + 32..16 + 40].copy_from_slice(&0u64.to_be_bytes());
    assert!(decode_rotation_update(&zeroed).is_err());
}

#[test]
fn vrb4_batches_and_bodies_carry_the_rotation() {
    let scenario = fixture::scenario(2, 4);
    let plain = scenario.app.prepare(1, vec![], vec![], None).unwrap().batch;
    // A rotation-bearing batch encodes `VRB4` and carries the set.
    let mut rotated = plain.clone();
    rotated.rotation = Some(CommittedRotation {
        from: 30,
        validators: vec![member(2, 7), member(1, 3)],
    });
    let raw = rotated.encode();
    assert_eq!(&raw[..4], b"VRB4");
    let decoded = Batch::decode(&raw).unwrap();
    assert_eq!(
        decoded.rotation.as_ref().unwrap().validators.len(),
        2
    );
    assert_eq!(decoded.encode(), raw);
    assert_eq!(decoded.value_id(), rotated.value_id());
    // The rotation binds the value id: same batch sans rotation differs.
    assert_ne!(rotated.value_id(), plain.value_id());
    // `VRB4` requires the rotation — a tag-0 tail is noncanonical.
    let mut flag0 = raw.clone();
    let tag_at = flag0.len() - (8 + 4 + 2 * 40) - 1;
    flag0[tag_at] = 0;
    flag0.truncate(tag_at + 1);
    assert!(matches!(Batch::decode(&flag0), Err(ApplyError::Decode)));
    // Trailing garbage past the rotation tail is rejected.
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(matches!(Batch::decode(&trailing), Err(ApplyError::Decode)));

    let body = BatchBody {
        time: 9,
        evidence: vec![],
        records: vec![],
        games: vec![],
        eligible: None,
        rotation: Some(CommittedRotation {
            from: 12,
            validators: vec![member(3, 1)],
        }),
    };
    let raw = body.encode();
    assert_eq!(&raw[..4], b"VBB4");
    let decoded = BatchBody::decode(&raw).unwrap();
    assert_eq!(decoded.rotation, body.rotation);
    assert_eq!(decoded.encode(), raw);
}

#[test]
fn replay_commits_rotation_into_registry_schedule() {
    let scenario = fixture::scenario(2, 4);
    // The notice bound on a fresh frontier: `from` must clear
    // `frontier.height + MIN_ROTATION_NOTICE`, so at genesis `from` 2 is
    // refused and 3 is the earliest valid activation.
    let near = CommittedRotation {
        from: 2,
        validators: vec![member(3, 1)],
    };
    assert!(matches!(
        scenario
            .app
            .prepare_with_games(1, vec![], vec![], vec![], None, Some(near)),
        Err(ApplyError::Rotation)
    ));
    let rotation = CommittedRotation {
        from: 30,
        validators: vec![member(1, 5), member(2, 3)],
    };
    let checked = scenario
        .app
        .prepare_with_games(1, vec![], vec![], vec![], None, Some(rotation.clone()))
        .unwrap();
    let batch = checked.batch().clone();
    // The scheduled set is inside the claimed registry digest.
    let mut app = Application::genesis(
        scenario.app.social().clone(),
        scenario.app.registry().clone(),
    );
    let checked = app.validate(&batch).unwrap();
    app.apply_locally(checked);
    let schedule = app.registry().validator_schedule();
    assert_eq!(schedule.len(), 1);
    assert_eq!(schedule[&30].len(), 2);
    // A next activation past the committed one commits in order.
    let ok = CommittedRotation {
        from: 31,
        validators: vec![member(3, 1)],
    };
    assert!(app
        .prepare_with_games(2, vec![], vec![], vec![], None, Some(ok))
        .is_ok());
    // An activation at or below the committed schedule's latest entry is
    // append-only-closed through the registry bound — 25 clears the
    // notice bound (frontier 1 + 2) so the rejection is the order rule.
    let backfill = CommittedRotation {
        from: 25,
        validators: vec![member(4, 1)],
    };
    assert!(matches!(
        app.prepare_with_games(
            2,
            vec![],
            vec![],
            vec![],
            None,
            Some(backfill)
        ),
        Err(ApplyError::Registry(RegistryError::Bounds))
    ));
}

#[test]
fn replay_rejects_invalid_rotation_members() {
    let scenario = fixture::scenario(2, 4);
    // Zero-power member passes struct construction (decode would reject
    // it) and fails at the registry bound during replay.
    let zero = CommittedRotation {
        from: 30,
        validators: vec![ValidatorMember {
            key: member_key(1),
            power: 0,
        }],
    };
    assert!(matches!(
        scenario
            .app
            .prepare_with_games(1, vec![], vec![], vec![], None, Some(zero)),
        Err(ApplyError::Registry(RegistryError::Bounds))
    ));
    // A key that is not a canonical Ed25519 point.
    let mut bad_member = member(2, 1);
    bad_member.key = [0x02; 32];
    let bad = CommittedRotation {
        from: 30,
        validators: vec![bad_member],
    };
    assert!(matches!(
        scenario
            .app
            .prepare_with_games(1, vec![], vec![], vec![], None, Some(bad)),
        Err(ApplyError::Registry(RegistryError::Bounds))
    ));
}
