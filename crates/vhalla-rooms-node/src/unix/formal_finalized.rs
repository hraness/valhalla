//! Production correspondence for the rooms-frontier host response boundary.
//!
//! These schedules drive the real host loop with authenticated certificates.
//! They inspect the commands sent to the pinned engine, not a simulated WAL:
//! its `Next::Restart` path resets the current-height WAL instead of replaying it.
use super::*;
use arc_malachitebft_core_consensus::MisbehaviorEvidence;
use arc_malachitebft_core_types::{CommitCertificate, CommitSignature, NilOrVal, VoteType};
use tokio::sync::{mpsc, oneshot};

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
enum Failure {
    JournalRead,
    MissingCandidate,
}

fn certificate(key: &PrivateKey, batch: &Batch) -> CommitCertificate<RoomContext> {
    let height = Height::new(batch.parent.height + 1);
    let address = Address::from_public_key(&key.public_key());
    let id = RoomValueId(batch.value_id());
    let round = Round::new(0);
    let vote = RoomVote::new(
        VoteType::Precommit,
        height,
        round,
        NilOrVal::Val(id),
        address,
    );
    CommitCertificate {
        height,
        round,
        value_id: id,
        commit_signatures: vec![CommitSignature::new(
            address,
            RoomSigner::new(key.clone()).sign(&crate::vote_sign_bytes(&vote)),
        )],
    }
}

fn finalized(
    certificate: CommitCertificate<RoomContext>,
    reply: oneshot::Sender<Next<RoomContext>>,
) -> AppMsg<RoomContext> {
    AppMsg::Finalized {
        certificate,
        extensions: Default::default(),
        evidence: MisbehaviorEvidence {
            proposals: Default::default(),
            votes: Default::default(),
        },
        reply,
    }
}

fn assert_next_height(next: Next<RoomContext>, next_set: &RoomValidatorSet) {
    match next {
        Next::Start(height, params) => {
            assert_eq!(height, Height::new(2));
            assert_eq!(params, height_params(next_set));
        }
        Next::Restart(height, _) => panic!("must not reset the WAL at {height}"),
    }
}

async fn exercise(failure: Failure) {
    let (keys, set) = validators(1);
    let mut app = test_app("formal-finalized", &keys[0], &set);
    let home = app.store.parent().unwrap().to_path_buf();
    let cleanup = Cleanup(home.parent().unwrap().to_path_buf());
    let next_key = PrivateKey::from([63; 32]);
    let next_set = RoomValidatorSet::new(vec![RoomValidator::new(next_key.public_key(), 1)]);
    assert_ne!(set, next_set);
    app.validator_sets.insert(2, next_set.clone());

    let batch = batch_plan(1).remove(&1).unwrap();
    let id = RoomValueId(batch.value_id());
    let certificate = certificate(&keys[0], &batch);
    let canonical = verify_commit_certificate(&certificate, &set).unwrap().bytes;
    let before = app.adapter.lock().unwrap().frontier();
    let expected = app.adapter.lock().unwrap().validate(&batch).unwrap().next();
    // Retained bytes exist even when the adapter has not admitted the candidate.
    // The missing-candidate schedule repairs only that local availability gap.
    app.persist_batch(&id, &batch);
    if matches!(failure, Failure::JournalRead) {
        app.register_batch(batch.clone());
    }
    let retained = app.store.join("batches").join(hex(&id.0));
    let exact_batch = std::fs::read(&retained).unwrap();
    assert_eq!(exact_batch, batch.encode());
    let journal = app.adapter.lock().unwrap().dir().to_path_buf();
    let obstruction = journal.join("HEAD.tmp");
    if matches!(failure, Failure::JournalRead) {
        // A directory at an unused temporary-file name makes journal recovery
        // fail with real I/O. Existing journal and candidate bytes are untouched.
        // This covers Withheld, not a claim about physical power-loss behavior.
        assert!(!obstruction.exists());
        std::fs::create_dir_all(&obstruction).unwrap();
    }

    let adapter = Arc::clone(&app.adapter);
    let sink = Arc::clone(&app.sink);
    let (messages, consensus) = mpsc::channel(2);
    let (network, _network_rx) = mpsc::channel(1);
    let (requests, _requests_rx) = mpsc::channel(1);
    let (net_requests, _net_requests_rx) = mpsc::channel(1);
    let mut channels = Channels {
        consensus,
        network,
        requests,
        net_requests,
        events: Default::default(),
    };
    let (_submissions, mut submission_rx) = mpsc::channel(1);
    let driver = async move {
        let (decided_reply, decided) = oneshot::channel();
        let (finalized_reply, finalization) = oneshot::channel();
        messages
            .send(AppMsg::Decided {
                certificate: certificate.clone(),
                extensions: Default::default(),
                reply: decided_reply,
            })
            .await
            .unwrap();
        // The pinned connector spawns independent reply waiters for these
        // messages: Finalized does not wait for a successful Decided reply.
        messages
            .send(finalized(certificate.clone(), finalized_reply))
            .await
            .unwrap();
        assert!(
            decided.await.is_err(),
            "failed decision must not acknowledge"
        );
        assert!(
            finalization.await.is_err(),
            "failed finalization must send neither Start nor a WAL-reset Restart"
        );
        assert_eq!(adapter.lock().unwrap().frontier(), before);
        assert!(sink.lock().unwrap().sent.is_empty());
        assert_eq!(std::fs::read(&retained).unwrap(), exact_batch);
        assert!(!journal.join("HEAD").exists());

        match failure {
            Failure::JournalRead => std::fs::remove_dir(&obstruction).unwrap(),
            Failure::MissingCandidate => adapter.lock().unwrap().hold(batch),
        }
        assert_eq!(adapter.lock().unwrap().recover().unwrap().pin.height, 0);
        let (reply, retried) = oneshot::channel();
        messages
            .send(finalized(certificate.clone(), reply))
            .await
            .unwrap();
        assert_next_height(retried.await.unwrap(), &next_set);
        assert_eq!(adapter.lock().unwrap().frontier(), expected);
        let committed = adapter.lock().unwrap().committed_at_height(1).unwrap();
        assert_eq!(committed.field(0).unwrap(), canonical);
        assert_eq!(committed.field(3).unwrap(), exact_batch);
        let exact_bundle = committed.bytes().to_vec();
        assert_eq!(std::fs::read(&retained).unwrap(), exact_batch);

        // Exact finalized redelivery must acknowledge the same durable frontier
        // and roster without rewriting the committed bundle or retained batch.
        let (reply, repeated) = oneshot::channel();
        messages.send(finalized(certificate, reply)).await.unwrap();
        assert_next_height(repeated.await.unwrap(), &next_set);
        assert_eq!(adapter.lock().unwrap().frontier(), expected);
        assert_eq!(
            adapter
                .lock()
                .unwrap()
                .committed_at_height(1)
                .unwrap()
                .bytes(),
            exact_bundle
        );
        assert_eq!(std::fs::read(&retained).unwrap(), exact_batch);
        assert_eq!(
            sink.lock().unwrap().sent,
            vec![
                vhalla_rooms_consensus::EngineMsg::NextHeightReply { height: 2 },
                vhalla_rooms_consensus::EngineMsg::NextHeightReply { height: 2 },
            ]
        );
        drop(messages);
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(run(&mut app, &mut channels, &mut submission_rx), driver);
    })
    .await
    .expect("host responses and exact retries must finish");
    assert_eq!(app.adapter.lock().unwrap().frontier(), expected);
    drop(app);
    let reopened = Adapter::open(home.join("app"), &genesis()).unwrap();
    assert_eq!(reopened.frontier(), expected);
    drop(reopened);
    drop(cleanup);
}

#[tokio::test]
async fn withheld_finalization_preserves_frontier_and_retries_with_next_roster() {
    exercise(Failure::JournalRead).await;
}

#[tokio::test]
async fn rejected_finalization_preserves_frontier_and_retries_with_next_roster() {
    exercise(Failure::MissingCandidate).await;
}

#[tokio::test]
async fn local_proposal_restores_exact_candidate_after_earlier_frontier_pruning() {
    let (keys, set) = validators(1);
    let mut app = test_app("formal-local-candidate", &keys[0], &set);
    let home = app.store.parent().unwrap().to_path_buf();
    let cleanup = Cleanup(home.parent().unwrap().to_path_buf());
    let plan = batch_plan(3);
    // Match startup's preplanned proposal ownership: all three canonical
    // batches are durable, held and assigned before the first height commits.
    for (&height, batch) in &plan {
        let id = app.register_batch(batch.clone());
        app.proposals.insert(height, id);
    }
    for height in 1..=2 {
        assert_eq!(
            app.decide(&certificate(&keys[0], &plan[&height])),
            DecidedOutcome::Acked
        );
        app.sweep_decided(height);
    }
    let batch = &plan[&3];
    let id = RoomValueId(batch.value_id());
    let cert = certificate(&keys[0], batch);
    let expected = app.adapter.lock().unwrap().validate(batch).unwrap().next();
    let retained = app.store.join("batches").join(hex(&id.0));
    let exact_batch = std::fs::read(&retained).unwrap();
    let adapter = Arc::clone(&app.adapter);
    let sink = Arc::clone(&app.sink);

    let (messages, consensus) = mpsc::channel(2);
    let (network, mut network_rx) = mpsc::channel(1);
    let (requests, _requests_rx) = mpsc::channel(1);
    let (net_requests, _net_requests_rx) = mpsc::channel(1);
    let mut channels = Channels {
        consensus,
        network,
        requests,
        net_requests,
        events: Default::default(),
    };
    let (_submissions, mut submission_rx) = mpsc::channel(1);
    let driver = async move {
        let (reply, proposed) = oneshot::channel::<LocallyProposedValue<RoomContext>>();
        messages
            .send(AppMsg::GetValue {
                height: Height::new(3),
                round: Round::new(0),
                timeout: Duration::from_secs(1),
                reply,
            })
            .await
            .unwrap();
        let proposed = proposed.await.unwrap();
        assert_eq!(proposed.value.id, id);
        assert_eq!(&proposed.value.bytes[..], exact_batch);
        // The local proposer never receives its own gossip. Drain the actual
        // emitted stream without feeding it back through wire admission.
        loop {
            let NetworkMsg::PublishProposalPart(part) = network_rx.recv().await.unwrap();
            if matches!(part.content, StreamContent::Fin) {
                break;
            }
        }
        let (reply, decided) = oneshot::channel();
        messages
            .send(AppMsg::Decided {
                certificate: cert.clone(),
                extensions: Default::default(),
                reply,
            })
            .await
            .unwrap();
        decided
            .await
            .expect("the exact locally proposed retained candidate must remain committable");
        let (reply, finalization) = oneshot::channel();
        messages.send(finalized(cert, reply)).await.unwrap();
        match finalization.await.unwrap() {
            Next::Start(height, params) => {
                assert_eq!(height, Height::new(4));
                assert_eq!(params, height_params(&set));
            }
            Next::Restart(_, _) => panic!("local custody must not require resetting the WAL"),
        }
        assert_eq!(adapter.lock().unwrap().frontier(), expected);
        assert_eq!(std::fs::read(&retained).unwrap(), exact_batch);
        assert_eq!(
            adapter
                .lock()
                .unwrap()
                .committed_at_height(3)
                .unwrap()
                .field(3)
                .unwrap(),
            exact_batch
        );
        assert_eq!(
            sink.lock().unwrap().sent,
            vec![
                vhalla_rooms_consensus::EngineMsg::CommitAck { height: 3 },
                vhalla_rooms_consensus::EngineMsg::NextHeightReply { height: 4 },
            ]
        );
        drop(messages);
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(run(&mut app, &mut channels, &mut submission_rx), driver);
    })
    .await
    .expect("local proposal, decision and finalization must finish");
    drop(app);
    let reopened = Adapter::open(home.join("app"), &genesis()).unwrap();
    assert_eq!(reopened.frontier(), expected);
    drop(reopened);
    drop(cleanup);
}

#[test]
fn refused_local_metadata_does_not_readmit_a_pruned_candidate() {
    let (keys, set) = validators(1);
    let mut app = test_app("formal-local-capacity", &keys[0], &set);
    let home = app.store.parent().unwrap().to_path_buf();
    let cleanup = Cleanup(home.parent().unwrap().to_path_buf());
    let plan = batch_plan(3);
    for (&height, batch) in &plan {
        let id = app.register_batch(batch.clone());
        app.proposals.insert(height, id);
    }
    for height in 1..=2 {
        assert_eq!(
            app.decide(&certificate(&keys[0], &plan[&height])),
            DecidedOutcome::Acked
        );
        app.sweep_decided(height);
    }
    let batch = &plan[&3];
    let id = RoomValueId(batch.value_id());
    app.seen.insert(
        3,
        (0..MAX_SEEN_RECORDS_PER_HEIGHT)
            .map(|round| SeenProposal {
                round: Round::new(round as u32),
                pol_round: Round::Nil,
                proposer: app.address,
                value_id: id,
            })
            .collect(),
    );
    let proposed = LocallyProposedValue::new(
        Height::new(3),
        Round::new(MAX_SEEN_RECORDS_PER_HEIGHT as u32),
        RoomValue::new(id.0, batch.encode().into()),
    );
    assert!(prepare_local_parts(&mut app, &proposed).is_none());
    // This candidate was pruned after height 1. A refused new metadata slot
    // must not restore it as a side effect or grow the adapter's pending set.
    assert_eq!(
        app.decide(&certificate(&keys[0], batch)),
        DecidedOutcome::Rejected
    );
    assert_eq!(app.adapter.lock().unwrap().frontier().height, 2);
    assert_eq!(app.seen[&3].len(), MAX_SEEN_RECORDS_PER_HEIGHT);
    drop(app);
    drop(cleanup);
}
