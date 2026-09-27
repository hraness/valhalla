//! Durable equivocation evidence and migration across the legacy seen format.
use super::*;
use arc_malachitebft_core_types::{CommitCertificate, CommitSignature, NilOrVal, VoteType};
use std::os::unix::fs::MetadataExt;
use vhalla_rooms_consensus::fixture;

struct Home(PathBuf);
impl Home {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "room-seen-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(path.join("store/batches")).unwrap();
        std::fs::create_dir_all(path.join("store/seen")).unwrap();
        Self(path)
    }
    fn open(&self) -> App {
        let store = self.0.join("store");
        let adapter = Arc::new(Mutex::new(
            Adapter::open(self.0.join("app"), &fixture::plan(0, 8, 16).genesis).unwrap(),
        ));
        let (mut held_by_id, seen) = load_store(&store);
        let live = seen
            .values()
            .flat_map(|records| records.iter().map(|record| record.value_id))
            .collect();
        retain_recoverable_batches(&mut held_by_id, &live, adapter.lock().unwrap().frontier());
        for batch in held_by_id.values() {
            adapter.lock().unwrap().hold(batch.clone());
        }
        let private_key = PrivateKey::from([9; 32]);
        let address = Address::from_public_key(&private_key.public_key());
        let set = RoomValidatorSet::new(vec![RoomValidator::new(private_key.public_key(), 1)]);
        App {
            ctx: RoomContext,
            adapter,
            sink: Arc::new(Mutex::new(EngineSink::default())),
            validator_sets: BTreeMap::from([(1, set)]),
            address,
            private_key,
            proposals: BTreeMap::new(),
            pending_proposals: VecDeque::new(),
            assigned_bodies: BTreeMap::new(),
            held_by_id,
            streams: BTreeMap::new(),
            parts_cache: BTreeMap::new(),
            stream_seq: 0,
            boundary_latency: Arc::new(Mutex::new(Vec::new())),
            store,
            seen,
            resupplied: Arc::new(Mutex::new(0)),
            held_replies: Vec::new(),
        }
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn batch(slug: &str) -> Batch {
    let mut scenario = fixture::scenario(8, 16);
    let mut cursor = 0;
    let (evidence, records, _) = fixture::first_create(
        &scenario.app,
        &scenario.owners[0],
        &mut scenario.sources,
        &mut cursor,
        slug,
        1,
    );
    scenario
        .app
        .prepare(1, evidence, records, None)
        .unwrap()
        .batch()
        .clone()
}
fn proposed(batch: &Batch, round: u32) -> LocallyProposedValue<RoomContext> {
    LocallyProposedValue::new(
        Height::new(1),
        Round::new(round),
        RoomValue::new(batch.value_id(), batch.encode().into()),
    )
}
fn feed(app: &mut App, parts: &[RoomPart], id: u64) -> Option<ProposedValue<RoomContext>> {
    let peer = PeerId::random();
    let stream = StreamId::new(id.to_be_bytes().to_vec().into());
    for (sequence, part) in parts.iter().enumerate() {
        assert!(app
            .handle_part(
                peer,
                StreamMessage::new(
                    stream.clone(),
                    sequence as u64,
                    StreamContent::Data(part.clone())
                )
            )
            .is_none());
    }
    app.handle_part(
        peer,
        StreamMessage::new(stream, parts.len() as u64, StreamContent::Fin),
    )
}
fn seen_body(id: RoomValueId, pol: Round) -> [u8; 40] {
    let mut bytes = [0; 40];
    bytes[..32].copy_from_slice(&id.0);
    bytes[32..].copy_from_slice(&pol.as_i64().to_be_bytes());
    bytes
}
fn certificate(app: &App, id: RoomValueId) -> CommitCertificate<RoomContext> {
    let height = Height::new(app.held_by_id[&id].parent.height + 1);
    let vote = RoomVote::new(
        VoteType::Precommit,
        height,
        Round::new(2),
        NilOrVal::Val(id),
        app.address,
    );
    CommitCertificate {
        height,
        round: Round::new(2),
        value_id: id,
        commit_signatures: vec![CommitSignature::new(
            app.address,
            RoomSigner::new(app.private_key.clone()).sign(&vote_sign_bytes(&vote)),
        )],
    }
}

#[test]
fn seen_equivocations_same_slot_survive_restart_and_resupply() {
    let home = Home::new("equivocation");
    let mut app = home.open();
    let a = batch("alpha");
    let b = batch("beta");
    let parts_a = app.build_parts(&proposed(&a, 2));
    let parts_b = app.build_parts(&proposed(&b, 2));
    for (i, parts) in [&parts_a, &parts_b, &parts_a, &parts_b]
        .into_iter()
        .enumerate()
    {
        assert!(feed(&mut app, parts, i as u64).unwrap().validity.is_valid());
    }
    assert_eq!(app.seen[&1].len(), 2);
    let files: Vec<_> = std::fs::read_dir(app.store.join("seen"))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(files.len(), 2);
    for file in files {
        assert_eq!(file.file_name().to_string_lossy().split('_').count(), 4);
    }
    drop(app);
    let mut reopened = home.open();
    let supplied = reopened.resupply_for(Height::new(1));
    assert_eq!(supplied.len(), 2);
    assert!(supplied
        .iter()
        .all(|value| value.validity.is_valid() && value.round == Round::new(2)));
    assert_eq!(
        supplied
            .iter()
            .map(|value| value.value.id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([RoomValueId(a.value_id()), RoomValueId(b.value_id())])
    );
}

#[test]
fn seen_immutable_retries_validate_exact_bytes_and_preserve_conflicts() {
    let home = Home::new("immutable");
    let dir = home.0.join("store/seen");
    let body = seen_body(RoomValueId([7; 32]), Round::Nil);
    persist_seen(&dir, "record", &body).unwrap();
    let inode = std::fs::metadata(dir.join("record")).unwrap().ino();
    persist_seen(&dir, "record", &body).unwrap();
    assert_eq!(std::fs::metadata(dir.join("record")).unwrap().ino(), inode);
    let other = seen_body(RoomValueId([8; 32]), Round::Nil);
    assert!(persist_seen(&dir, "record", &other).is_err());
    assert_eq!(read_seen_body(&dir.join("record")).unwrap(), body);
    std::fs::write(dir.join("partial"), b"partial").unwrap();
    assert!(persist_seen(&dir, "partial", &body).is_err());
    assert_eq!(std::fs::read(dir.join("partial")).unwrap(), b"partial");
    std::os::unix::fs::symlink(dir.join("record"), dir.join("link")).unwrap();
    assert!(persist_seen(&dir, "link", &body).is_err());
}

#[test]
fn seen_legacy_names_deduplicate_and_new_names_bind_the_body() {
    let home = Home::new("legacy");
    let mut app = home.open();
    let value = batch("legacy");
    let id = app.register_batch(value);
    let legacy = format!("1_2_{}", hex(&app.address.into_inner()));
    let body = seen_body(id, Round::Nil);
    store_write(&app.store.join("seen"), &legacy, &body).unwrap();
    let new_name = format!("{legacy}_{}", hex(&id.0));
    persist_seen(&app.store.join("seen"), &new_name, &body).unwrap();
    assert_eq!(load_store(&app.store).1[&1].len(), 1);
    let mismatched = format!("{legacy}_{}", hex(&[8; 32]));
    store_write(&app.store.join("seen"), &mismatched, &body).unwrap();
    assert!(decode_seen(&mismatched, &body).is_none());
    assert!(decode_seen(&format!("{new_name}_extra"), &body).is_none());
    assert!(decode_seen(
        &format!("1_4294967296_{}", hex(&app.address.into_inner())),
        &body
    )
    .is_none());
    assert!(decode_seen(&format!("1_-2_{}", hex(&app.address.into_inner())), &body).is_none());
    assert_eq!(load_store(&app.store).1[&1].len(), 1);
    // Contradictory legacy/new metadata for the same identity stops recovery.
    store_write(
        &app.store.join("seen"),
        &legacy,
        &seen_body(id, Round::new(1)),
    )
    .unwrap();
    assert!(std::panic::catch_unwind(|| load_store(&app.store)).is_err());
    assert_eq!(
        read_seen_body(&app.store.join("seen").join(&new_name)).unwrap(),
        body
    );
}

#[test]
fn seen_conflicting_duplicate_header_never_reaches_engine() {
    let home = Home::new("header-conflict");
    let mut app = home.open();
    let parts = app.build_parts(&proposed(&batch("same-value"), 2));
    assert!(feed(&mut app, &parts, 0).unwrap().validity.is_valid());
    let RoomPart::Init(mut init) = parts[0].clone() else {
        unreachable!()
    };
    init.pol_round = Round::new(1);
    // A genuinely equivocating proposer can sign contradictory metadata;
    // preserve the first admitted record instead of replacing it.
    let conflict = app.sign_parts(init, &batch("same-value").encode());
    assert!(feed(&mut app, &conflict, 1).is_none());
    assert_eq!(app.seen[&1].len(), 1);
    assert_eq!(app.seen[&1][0].pol_round, Round::Nil);
    assert_eq!(load_store(&app.store).1[&1][0].pol_round, Round::Nil);
}

#[test]
fn seen_legacy_overwrite_keeps_unreferenced_value_decidable_after_restart() {
    let home = Home::new("legacy-overwrite");
    let mut app = home.open();
    let a = batch("lost-reference");
    let b = batch("surviving-reference");
    let id_a = app.register_batch(a);
    let id_b = app.register_batch(b);
    // Exactly the old on-disk result: both batches, only the last slot's
    // metadata, and no spec-held proposal or pending Value marker for A.
    let legacy = format!("1_2_{}", hex(&app.address.into_inner()));
    store_write(
        &app.store.join("seen"),
        &legacy,
        &seen_body(id_b, Round::Nil),
    )
    .unwrap();
    drop(app);
    let mut reopened = home.open();
    assert!(reopened.proposals.is_empty() && reopened.pending_proposals.is_empty());
    assert!(reopened.parts_cache.is_empty());
    assert_eq!(reopened.resupply_for(Height::new(1))[0].value.id, id_b);
    let cert_a = certificate(&reopened, id_a);
    assert_eq!(reopened.decide(&cert_a), DecidedOutcome::Acked);
    assert_eq!(reopened.adapter.lock().unwrap().frontier().value, id_a.0);
}

#[test]
fn seen_restart_restreams_our_locked_value_with_exact_new_round_identity() {
    let home = Home::new("restream");
    let mut app = home.open();
    let value = batch("locked");
    let id = app.register_batch(value.clone());
    let original = app.build_parts(&proposed(&value, 1));
    assert!(feed(&mut app, &original, 0).unwrap().validity.is_valid());
    drop(app);
    let mut reopened = home.open();
    assert!(reopened.parts_cache.is_empty());
    let address = reopened.address;
    assert!(reopened
        .restream_parts(Height::new(1), Round::new(3), Round::new(3), address, id)
        .is_none());
    assert!(reopened
        .restream_parts(Height::new(2), Round::new(3), Round::new(1), address, id)
        .is_none());
    let foreign = Address::from_public_key(&PrivateKey::from([77; 32]).public_key());
    assert!(reopened
        .restream_parts(Height::new(1), Round::new(3), Round::new(1), foreign, id)
        .is_none());
    let parts = reopened
        .restream_parts(Height::new(1), Round::new(3), Round::new(1), address, id)
        .unwrap();
    let (RoomPart::Init(init), RoomPart::Fin(fin)) =
        (parts.first().unwrap(), parts.last().unwrap())
    else {
        unreachable!()
    };
    assert_eq!(init.pol_round, Round::new(1));
    assert!(verify_fin(
        &reopened.private_key.public_key(),
        init,
        &value.encode(),
        &fin.signature
    ));
    let mut changed = init.clone();
    changed.pol_round = Round::Nil;
    assert!(!verify_fin(
        &reopened.private_key.public_key(),
        &changed,
        &value.encode(),
        &fin.signature
    ));
    let accepted = feed(&mut reopened, &parts, 1).unwrap();
    assert!(accepted.validity.is_valid());
    assert_eq!(accepted.round, Round::new(3));
    assert_eq!(accepted.valid_round, Round::new(1));
    // A value-only cache hit must not resend round 3 when asked for round 4.
    let next = reopened
        .restream_parts(Height::new(1), Round::new(4), Round::new(1), address, id)
        .unwrap();
    let accepted = feed(&mut reopened, &next, 2).unwrap();
    assert_eq!(accepted.round, Round::new(4));
    assert_eq!(accepted.valid_round, Round::new(1));
    assert_eq!(load_store(&reopened.store).1[&1].len(), 3);
}

async fn check_reply_ordering(held: bool, fail_write: bool) {
    let home = Home::new("reply-order");
    let mut app = home.open();
    let id = app.register_batch(batch("reply"));
    app.proposals.insert(1, id);
    if fail_write {
        std::fs::rename(app.store.join("seen"), app.store.join("seen-saved")).unwrap();
        std::fs::write(app.store.join("seen"), b"do not overwrite").unwrap();
    }
    let (reply, reply_rx) = tokio::sync::oneshot::channel();
    let (messages, consensus) = tokio::sync::mpsc::channel(1);
    if held {
        app.held_replies.push(HeldReply {
            height: 1,
            round: Round::new(2),
            deadline: std::time::Instant::now() + Duration::from_secs(30),
            reply,
        });
    } else {
        messages
            .send(AppMsg::GetValue {
                height: Height::new(1),
                round: Round::new(2),
                timeout: Duration::from_secs(30),
                reply,
            })
            .await
            .unwrap();
    }
    let (network, _network_rx) = tokio::sync::mpsc::channel(1);
    let (requests, _requests_rx) = tokio::sync::mpsc::channel(1);
    let (net_requests, _net_requests_rx) = tokio::sync::mpsc::channel(1);
    let mut channels = Channels {
        consensus,
        network,
        requests,
        net_requests,
        events: Default::default(),
    };
    let (_submissions, mut submission_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move { run(&mut app, &mut channels, &mut submission_rx).await });
    let result = tokio::time::timeout(Duration::from_secs(5), reply_rx)
        .await
        .unwrap();
    if fail_write {
        assert!(
            result.is_err(),
            "engine must not receive a proposal after persistence failed"
        );
        assert!(task.await.unwrap_err().is_panic());
        assert_eq!(
            std::fs::read(home.0.join("store/seen")).unwrap(),
            b"do not overwrite"
        );
    } else {
        assert_eq!(result.unwrap().value.id, id);
        let (batches, seen) = load_store(&home.0.join("store"));
        assert!(batches.contains_key(&id));
        assert_eq!(seen[&1].len(), 1);
        assert_eq!(seen[&1][0].round, Round::new(2));
        // The network is intentionally backpressured; durability and the
        // engine reply must not wait for all paced stream messages.
        task.abort();
        let _ = task.await;
    }
}

#[tokio::test]
async fn seen_direct_and_held_replies_follow_durable_preparation() {
    check_reply_ordering(false, false).await;
    check_reply_ordering(true, false).await;
}

#[tokio::test]
async fn seen_failed_preparation_cannot_release_direct_or_held_reply() {
    check_reply_ordering(false, true).await;
    check_reply_ordering(true, true).await;
}

#[test]
fn seen_committed_height_redelivery_retains_legacy_next_height_batch() {
    let home = Home::new("legacy-redelivery");
    let mut app = home.open();
    let plan = fixture::plan(2, 8, 16);
    let first = app.register_batch(plan.batches[&1].clone());
    let cert = certificate(&app, first);
    assert_eq!(app.decide(&cert), DecidedOutcome::Acked);
    let next = app.register_batch(plan.batches[&2].clone());
    drop(app);
    let mut reopened = home.open();
    assert!(reopened.seen.is_empty());
    reopened.sweep_decided(1);
    assert!(reopened.held_by_id.contains_key(&next));
    let cert = certificate(&reopened, next);
    assert_eq!(reopened.decide(&cert), DecidedOutcome::Acked);
    reopened.sweep_decided(2);
    assert!(!reopened.held_by_id.contains_key(&next));
}

#[test]
fn seen_first_arrival_pol_tamper_cannot_poison_authentic_retry() {
    let home = Home::new("pol-tamper");
    let mut app = home.open();
    let value = batch("authentic");
    let authentic = app.build_parts(&proposed(&value, 2));
    let mut tampered = authentic.clone();
    let RoomPart::Init(init) = &mut tampered[0] else {
        unreachable!()
    };
    init.pol_round = Round::new(1);
    assert!(!feed(&mut app, &tampered, 0).unwrap().validity.is_valid());
    assert!(app.seen.is_empty());
    assert!(app.held_by_id.is_empty());
    assert!(app.parts_cache.is_empty());
    for dir in ["seen", "batches"] {
        assert_eq!(std::fs::read_dir(app.store.join(dir)).unwrap().count(), 0);
    }
    let accepted = feed(&mut app, &authentic, 1).unwrap();
    assert!(accepted.validity.is_valid());
    assert_eq!(accepted.valid_round, Round::Nil);
    assert_eq!(load_store(&app.store).1[&1].len(), 1);
    assert_eq!(app.parts_cache[&accepted.value.id], authentic);
    assert!(app
        .restream_parts(
            Height::new(1),
            Round::new(2),
            Round::Nil,
            app.address,
            accepted.value.id
        )
        .is_some());
}

#[test]
fn stalled_height_budget_survives_restart_without_pruning_or_new_artifacts() {
    let home = Home::new("retention-budget");
    let mut app = home.open();
    let retained = batch("retained-budget");
    let id = app.register_batch(retained.clone());
    let proposer = hex(&app.address.into_inner());
    // Model an already durable store at the exact production boundary. The
    // loader must derive its admission budget from retained files after restart.
    for round in 0..MAX_SEEN_RECORDS_PER_HEIGHT {
        let name = format!("1_{round}_{proposer}_{}", hex(&id.0));
        std::fs::write(app.store.join("seen").join(name), seen_body(id, Round::Nil)).unwrap();
    }
    drop(app);
    let mut app = home.open();
    assert_eq!(app.seen[&1].len(), MAX_SEEN_RECORDS_PER_HEIGHT);
    let fresh = batch("refused-budget");
    let fresh_parts = app.build_parts(&proposed(&fresh, MAX_SEEN_RECORDS_PER_HEIGHT as u32));
    assert!(feed(&mut app, &fresh_parts, 0).is_none());
    assert!(!app.held_by_id.contains_key(&RoomValueId(fresh.value_id())));
    assert!(!app
        .store
        .join("batches")
        .join(hex(&fresh.value_id()))
        .exists());
    assert_eq!(
        std::fs::read_dir(app.store.join("seen")).unwrap().count(),
        MAX_SEEN_RECORDS_PER_HEIGHT
    );
    // Previously admitted exact headers remain usable at capacity.
    let repeated = app.build_parts(&proposed(&retained, 0));
    assert!(feed(&mut app, &repeated, 1).unwrap().validity.is_valid());
    assert!(app.held_by_id.contains_key(&id));
    // A new local round is refused without fabricating/publishing a signature
    // result or deleting the batch that may support a retained WAL lock.
    assert!(prepare_local_parts(
        &mut app,
        &proposed(&retained, MAX_SEEN_RECORDS_PER_HEIGHT as u32)
    )
    .is_none());
    assert_eq!(app.seen[&1].len(), MAX_SEEN_RECORDS_PER_HEIGHT);
    assert!(app.store.join("batches").join(hex(&id.0)).exists());
}

#[test]
fn stalled_parent_value_budget_refuses_disk_growth_but_keeps_exact_retries() {
    let home = Home::new("value-budget");
    let mut app = home.open();
    let kept = batch("retention-kept");
    let id = app.register_batch(kept.clone());
    // Fill the capacity accounting with other IDs at this exact parent. The
    // canonical incoming value still goes through the real verification path.
    for n in 1..MAX_RETAINED_VALUES_PER_PARENT {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&(n as u64).to_be_bytes());
        app.held_by_id.insert(RoomValueId(key), kept.clone());
    }
    let other = batch("retention-other");
    let parts = app.build_parts(&proposed(&other, 1));
    assert!(!feed(&mut app, &parts, 0).unwrap().validity.is_valid());
    assert!(!app
        .store
        .join("batches")
        .join(hex(&other.value_id()))
        .exists());
    assert!(app.seen.is_empty());
    let existing = RoomValue::new(id.0, kept.encode().into());
    assert!(app.verdict_for(&existing).is_valid());
    assert!(app.held_by_id.contains_key(&id));
}

#[test]
fn startup_scan_retains_live_evidence_without_materializing_old_history() {
    let home = Home::new("streaming-reopen");
    let app = home.open();
    let mut frontier = app.adapter.lock().unwrap().frontier();
    frontier.height = 1024;
    let store = &app.store;
    let proposer = hex(&app.address.into_inner());
    let template = batch("streaming-history");
    for height in 0..1024u64 {
        let mut historical = template.clone();
        historical.parent.height = height;
        let id = RoomValueId(historical.value_id());
        std::fs::write(store.join("batches").join(hex(&id.0)), historical.encode()).unwrap();
        let name = format!("{}_0_{}_{}", height + 1, proposer, hex(&id.0));
        std::fs::write(store.join("seen").join(name), seen_body(id, Round::Nil)).unwrap();
    }
    // Legacy overwrite can leave an unreferenced live-parent value. Preserve it.
    let mut live = template.clone();
    live.parent = frontier;
    let live_id = RoomValueId(live.value_id());
    std::fs::write(store.join("batches").join(hex(&live_id.0)), live.encode()).unwrap();
    // A retained undecided reference survives even when its parent differs.
    let referenced_id = RoomValueId(template.value_id());
    std::fs::write(
        store
            .join("seen")
            .join(format!("1025_1_{}_{}", proposer, hex(&referenced_id.0))),
        seen_body(referenced_id, Round::Nil),
    )
    .unwrap();
    // Sparse corrupt input is bounded before decoding and remains untouched.
    let oversized = store.join("batches/oversized");
    std::fs::File::create(&oversized)
        .unwrap()
        .set_len(1 << 30)
        .unwrap();
    let StoreScan {
        held,
        seen,
        scanned,
    } = load_store_at(store, Some(frontier));
    assert_eq!(scanned, (1025, 1025));
    assert_eq!(held.len(), 2);
    assert_eq!(held[&live_id], live);
    assert_eq!(held[&referenced_id], template);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[&1025].len(), 1);
    assert_eq!(
        std::fs::read_dir(store.join("batches")).unwrap().count(),
        1026
    );
    assert_eq!(std::fs::read_dir(store.join("seen")).unwrap().count(), 1025);
    assert_eq!(std::fs::metadata(oversized).unwrap().len(), 1 << 30);
}
