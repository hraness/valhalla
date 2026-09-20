//! Hostile proposal traffic stays bounded and cannot poison subsequent work.
use super::*;
use crate::{RoomValidator, RoomValidatorSet};
use vhalla_rooms_consensus::fixture;

struct Harness {
    app: App,
    base: PathBuf,
}

impl Harness {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "room-ingress-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = base.join("store");
        std::fs::create_dir_all(store.join("batches")).unwrap();
        std::fs::create_dir_all(store.join("seen")).unwrap();
        let private_key = PrivateKey::from([9; 32]);
        let address = Address::from_public_key(&private_key.public_key());
        let set = RoomValidatorSet::new(vec![RoomValidator::new(private_key.public_key(), 1)]);
        let app = App {
            ctx: RoomContext,
            adapter: Arc::new(Mutex::new(
                Adapter::open(base.join("app"), &fixture::plan(0, 8, 16).genesis).unwrap(),
            )),
            sink: Arc::new(Mutex::new(EngineSink::default())),
            validator_sets: BTreeMap::from([(1, set)]),
            address,
            private_key,
            proposals: BTreeMap::new(),
            pending_proposals: VecDeque::new(),
            assigned_bodies: BTreeMap::new(),
            held_by_id: BTreeMap::new(),
            streams: BTreeMap::new(),
            parts_cache: BTreeMap::new(),
            stream_seq: 0,
            boundary_latency: Arc::new(Mutex::new(Vec::new())),
            store,
            seen: BTreeMap::new(),
            resupplied: Arc::new(Mutex::new(0)),
            held_replies: Vec::new(),
        };
        Self { app, base }
    }

    fn healthy_parts(&mut self) -> Vec<RoomPart> {
        let batch = fixture::plan(1, 8, 16).batches.remove(&1).unwrap();
        self.app.build_parts(&LocallyProposedValue::new(
            Height::new(1),
            Round::new(0),
            RoomValue::new(batch.value_id(), batch.encode().into()),
        ))
    }

    fn healthy_after(&mut self, peer: PeerId, id: u64) {
        let parts = self.healthy_parts();
        let value = feed_parts(&mut self.app, peer, id, &parts, true)
            .expect("healthy proposal must still assemble after hostile traffic");
        assert!(value.validity.is_valid());
        assert_eq!(value.height, Height::new(1));
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn message(id: u64, seq: u64, content: StreamContent<RoomPart>) -> StreamMessage<RoomPart> {
    StreamMessage::new(
        StreamId::new(id.to_be_bytes().to_vec().into()),
        seq,
        content,
    )
}

fn feed_parts(
    app: &mut App,
    peer: PeerId,
    id: u64,
    parts: &[RoomPart],
    reverse: bool,
) -> Option<ProposedValue<RoomContext>> {
    let mut order: Vec<usize> = (0..parts.len()).collect();
    if reverse {
        order.reverse();
    }
    for i in order {
        assert!(app
            .handle_part(
                peer,
                message(id, i as u64, StreamContent::Data(parts[i].clone()))
            )
            .is_none());
    }
    app.handle_part(peer, message(id, parts.len() as u64, StreamContent::Fin))
}

#[test]
fn ingress_malformed_headers_release_buffers_and_healthy_proposals_survive() {
    let mut h = Harness::new("headers");
    let peer = PeerId::random();
    let parts = h.healthy_parts();
    let RoomPart::Init(good) = parts[0].clone() else {
        unreachable!()
    };
    let mut cases = Vec::new();
    let mut bad = good.clone();
    bad.round = Round::Nil;
    cases.push(bad);
    let mut bad = good.clone();
    bad.height = Height::new(0);
    cases.push(bad);
    let mut bad = good.clone();
    bad.height = Height::new(u64::MAX);
    bad.round = Round::new(1);
    cases.push(bad);
    let mut bad = good;
    bad.pol_round = bad.round;
    cases.push(bad);
    for (id, bad) in cases.into_iter().enumerate() {
        let id = id as u64;
        h.app.handle_part(
            peer,
            message(
                id,
                1,
                StreamContent::Data(RoomPart::Data(vec![7; 16].into())),
            ),
        );
        assert_eq!(h.app.streams.len(), 1);
        // No valid signature is required to reject the malformed header.
        h.app.handle_part(
            peer,
            message(id, 2, StreamContent::Data(parts.last().unwrap().clone())),
        );
        h.app.handle_part(peer, message(id, 3, StreamContent::Fin));
        assert!(h
            .app
            .handle_part(
                peer,
                message(id, 0, StreamContent::Data(RoomPart::Init(bad)))
            )
            .is_none());
        assert!(
            h.app.streams.is_empty(),
            "bad header releases earlier out-of-order data"
        );
        h.healthy_after(peer, 100 + id);
    }
}

#[test]
fn ingress_per_peer_flood_cannot_starve_another_peer() {
    let mut h = Harness::new("per-peer");
    let bad = PeerId::random();
    let good = PeerId::random();
    for id in 0..1_000 {
        h.app.handle_part(
            bad,
            message(
                id,
                1,
                StreamContent::Data(RoomPart::Data(vec![1; PROPOSAL_CHUNK_BYTES].into())),
            ),
        );
    }
    assert_eq!(h.app.streams.len(), MAX_PROPOSAL_STREAMS_PER_PEER);
    h.healthy_after(good, 0);
    assert_eq!(h.app.streams.len(), MAX_PROPOSAL_STREAMS_PER_PEER);
    for stream in h.app.streams.values_mut() {
        stream.first_seen = Some(std::time::Instant::now() - STREAM_STALE - Duration::from_secs(1));
    }
    h.app.expire_streams();
    assert!(h.app.streams.is_empty());
    h.healthy_after(bad, 10_000);
}

#[test]
fn ingress_global_flood_keeps_admitted_work_live_and_releases_capacity() {
    let mut h = Harness::new("global");
    let good = PeerId::random();
    let parts = h.healthy_parts();
    h.app
        .handle_part(good, message(0, 0, StreamContent::Data(parts[0].clone())));
    for _ in 0..MAX_PROPOSAL_STREAMS {
        h.app.handle_part(
            PeerId::random(),
            message(1, 1, StreamContent::Data(RoomPart::Data(vec![1].into()))),
        );
    }
    assert_eq!(h.app.streams.len(), MAX_PROPOSAL_STREAMS);
    let completed = feed_parts(&mut h.app, good, 0, &parts, false).unwrap();
    assert!(
        completed.validity.is_valid(),
        "already admitted stream must progress at the cap"
    );
    assert_eq!(h.app.streams.len(), MAX_PROPOSAL_STREAMS - 1);
    h.healthy_after(PeerId::random(), 2);
}

#[test]
fn ingress_empty_oversized_and_sparse_chunks_allocate_no_unbounded_metadata() {
    let mut h = Harness::new("chunks");
    let peer = PeerId::random();
    for id in 0..1_000 {
        h.app.handle_part(
            peer,
            message(id, 1, StreamContent::Data(RoomPart::Data(Bytes::new()))),
        );
    }
    assert!(h.app.streams.is_empty());
    for (seq, data) in [
        (1, vec![0; PROPOSAL_CHUNK_BYTES + 1]),
        (0, vec![0]),
        (u64::MAX, vec![0]),
    ] {
        h.app.handle_part(
            peer,
            message(1, seq, StreamContent::Data(RoomPart::Data(data.into()))),
        );
        assert!(h.app.streams.is_empty());
    }
    for seq in 1..=MAX_PROPOSAL_CHUNKS as u64 {
        h.app.handle_part(
            peer,
            message(2, seq, StreamContent::Data(RoomPart::Data(vec![0].into()))),
        );
    }
    assert_eq!(
        h.app.streams.values().next().unwrap().data.len(),
        MAX_PROPOSAL_CHUNKS
    );
    h.app.handle_part(
        peer,
        message(
            2,
            MAX_PROPOSAL_CHUNKS as u64 + 1,
            StreamContent::Data(RoomPart::Data(vec![0].into())),
        ),
    );
    assert!(
        h.app.streams.is_empty(),
        "out-of-range sequence releases all prior chunks"
    );
    h.healthy_after(peer, 3);
}

#[test]
fn ingress_duplicate_and_conflicting_parts_have_bounded_effects() {
    let mut h = Harness::new("duplicates");
    let peer = PeerId::random();
    let data = StreamContent::Data(RoomPart::Data(vec![1; 10].into()));
    for _ in 0..100 {
        h.app.handle_part(peer, message(1, 1, data.clone()));
    }
    let state = h.app.streams.values().next().unwrap();
    assert_eq!(state.data.len(), 1);
    assert_eq!(state.data_len, 10);
    h.app.handle_part(
        peer,
        message(
            1,
            1,
            StreamContent::Data(RoomPart::Data(vec![2; 10].into())),
        ),
    );
    assert!(h.app.streams.is_empty());
    let parts = h.healthy_parts();
    h.app
        .handle_part(peer, message(2, 0, StreamContent::Data(parts[0].clone())));
    let RoomPart::Init(mut conflicting) = parts[0].clone() else {
        unreachable!()
    };
    conflicting.round = Round::new(1);
    h.app.handle_part(
        peer,
        message(2, 0, StreamContent::Data(RoomPart::Init(conflicting))),
    );
    assert!(h.app.streams.is_empty());
    h.healthy_after(peer, 3);
}

#[test]
fn ingress_maximum_wire_payload_reorders_and_overflow_releases_it() {
    let mut h = Harness::new("maximum");
    let peer = PeerId::random();
    let data = vec![7; crate::MAX_VALUE_BYTES];
    let parts = h.app.build_parts(&LocallyProposedValue::new(
        Height::new(1),
        Round::new(0),
        RoomValue::new([0; 32], data.clone().into()),
    ));
    assert_eq!(parts.len(), MAX_PROPOSAL_CHUNKS + 2);
    let value = feed_parts(&mut h.app, peer, 1, &parts, true).unwrap();
    assert_eq!(value.value.bytes.as_ref(), data.as_slice());
    assert!(
        !value.validity.is_valid(),
        "transport capacity does not bypass batch validation"
    );
    assert!(h.app.streams.is_empty());
    // Maximum legal chunk count can still exceed the aggregate byte budget.
    for seq in 1..=MAX_PROPOSAL_CHUNKS as u64 {
        h.app.handle_part(
            peer,
            message(
                2,
                seq,
                StreamContent::Data(RoomPart::Data(vec![7; PROPOSAL_CHUNK_BYTES].into())),
            ),
        );
    }
    assert!(
        h.app.streams.is_empty(),
        "one oversized final chunk releases the full buffer"
    );
    h.healthy_after(peer, 3);
}

#[test]
fn ingress_missing_or_conflicting_sequence_slots_do_not_assemble() {
    let mut h = Harness::new("sequence");
    let peer = PeerId::random();
    let parts = h.healthy_parts();
    for (seq, part) in parts.iter().enumerate() {
        if seq != 1 {
            h.app.handle_part(
                peer,
                message(1, seq as u64, StreamContent::Data(part.clone())),
            );
        }
    }
    assert!(h
        .app
        .handle_part(peer, message(1, parts.len() as u64, StreamContent::Fin))
        .is_none());
    assert_eq!(
        h.app.streams.len(),
        1,
        "an early terminator cannot discard a delayed valid chunk"
    );
    let completed = h
        .app
        .handle_part(peer, message(1, 1, StreamContent::Data(parts[1].clone())))
        .unwrap();
    assert!(completed.validity.is_valid());
    assert!(h.app.streams.is_empty());
    h.app.handle_part(
        peer,
        message(2, 2, StreamContent::Data(parts.last().unwrap().clone())),
    );
    h.app.handle_part(
        peer,
        message(2, 2, StreamContent::Data(RoomPart::Data(vec![1].into()))),
    );
    assert!(
        h.app.streams.is_empty(),
        "Data must not reuse the Fin signature slot"
    );
    h.healthy_after(peer, 3);
}

#[test]
fn ingress_terminator_first_with_every_part_reversed_still_validates() {
    let mut h = Harness::new("terminator-first");
    let peer = PeerId::random();
    let parts = h.healthy_parts();
    assert!(h
        .app
        .handle_part(peer, message(1, parts.len() as u64, StreamContent::Fin))
        .is_none());
    for seq in (1..parts.len()).rev() {
        assert!(h
            .app
            .handle_part(
                peer,
                message(1, seq as u64, StreamContent::Data(parts[seq].clone()))
            )
            .is_none());
    }
    let complete = h
        .app
        .handle_part(peer, message(1, 0, StreamContent::Data(parts[0].clone())))
        .unwrap();
    assert!(complete.validity.is_valid());
    assert!(h.app.streams.is_empty());
}

#[test]
fn ingress_signed_wrong_height_cannot_write_future_proposal_state() {
    let mut h = Harness::new("signed-height");
    let peer = PeerId::random();
    let batch = fixture::plan(1, 8, 16).batches.remove(&1).unwrap();
    let parts = h.app.build_parts(&LocallyProposedValue::new(
        Height::new(2),
        Round::new(0),
        RoomValue::new(batch.value_id(), batch.encode().into()),
    ));
    let value = feed_parts(&mut h.app, peer, 1, &parts, true).unwrap();
    assert!(
        !value.validity.is_valid(),
        "valid signature cannot authorize a different batch height"
    );
    assert!(h.app.streams.is_empty());
    assert!(h.app.held_by_id.is_empty());
    assert!(h.app.seen.is_empty());
    assert!(h.app.parts_cache.is_empty());
    for dir in ["batches", "seen"] {
        assert_eq!(
            std::fs::read_dir(h.app.store.join(dir)).unwrap().count(),
            0,
            "height mismatch must fail before any durable admission"
        );
    }
    h.healthy_after(peer, 2);
}

#[tokio::test]
async fn startup_rejects_invalid_validator_schedules_before_creating_state() {
    let key = PrivateKey::from([27; 32]);
    let valid = RoomValidatorSet::new(vec![RoomValidator::new(key.public_key(), 1)]);
    let overflow = RoomValidatorSet::new(vec![RoomValidator::new(key.public_key(), u64::MAX)]);
    let schedules = [
        BTreeMap::new(),
        BTreeMap::from([(0, valid)]),
        BTreeMap::from([(1, RoomValidatorSet::new(Vec::new()))]),
        BTreeMap::from([(1, overflow)]),
    ];
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for (index, validator_sets) in schedules.into_iter().enumerate() {
        let home = std::env::temp_dir().join(format!(
            "room-invalid-start-{}-{stamp}-{index}",
            std::process::id()
        ));
        assert!(!home.exists());
        let spec = NodeSpec {
            home: home.clone(),
            config: node_config(1, 1, 0),
            node_key: key.clone(),
            validator_sets,
            held: BTreeMap::new(),
            genesis: fixture::plan(0, 8, 16).genesis,
            wal_faults: None,
            net_gate: None,
        };
        let result = tokio::spawn(async move { RoomNode::start(spec).await }).await;
        assert!(result.is_err_and(|error| error.is_panic()));
        assert!(
            !home.exists(),
            "invalid config must fail before side effects"
        );
    }
}
