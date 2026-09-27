//! Disk-backed complete consensus history; no lifetime cache is needed.
use super::*;
use arc_malachitebft_core_types::{NilOrVal, VoteType};
use arc_malachitebft_sync::{Response, ValueResponse};
use ed25519_dalek::{Signer as _, SigningKey};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use vhalla_journal::{Bundle, BundleParts, FsStore, Journal};
use vhalla_rooms_consensus::{fixture, Application, Frontier};

struct HistoryFixture {
    base: PathBuf,
    genesis: Genesis,
    key: PrivateKey,
    set: RoomValidatorSet,
}

impl HistoryFixture {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "vhalla-history-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let key = PrivateKey::from([9; 32]);
        let set = RoomValidatorSet::new(vec![RoomValidator::new(key.public_key(), 1)]);
        Self {
            base,
            genesis: fixture::scenario(1, 1).genesis,
            key,
            set,
        }
    }

    fn open(&self) -> Adapter<FsStore> {
        Adapter::open(self.base.join("app"), &self.genesis).unwrap()
    }

    fn certificate(&self, height: u64, id: [u8; 32]) -> Vec<u8> {
        let address = Address::from_public_key(&self.key.public_key());
        let vote = RoomVote::new(
            VoteType::Precommit,
            Height::new(height),
            Round::new(0),
            NilOrVal::Val(RoomValueId(id)),
            address,
        );
        let mut raw = b"VC2".to_vec();
        raw.extend_from_slice(&height.to_be_bytes());
        raw.extend_from_slice(&0u32.to_be_bytes());
        raw.extend_from_slice(&id);
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw.extend_from_slice(&address.into_inner());
        raw.extend_from_slice(
            &SigningKey::from_bytes(&[9; 32])
                .sign(&crate::vote_sign_bytes(&vote))
                .to_bytes(),
        );
        assert!(crate::cert::verify_canonical_certificate(
            &raw,
            height,
            &RoomValueId(id),
            &self.set
        ));
        raw
    }

    fn commit_empty(&self, adapter: &mut Adapter<FsStore>) -> Batch {
        let height = adapter.frontier().height + 1;
        let batch = adapter
            .application()
            .prepare(height, vec![], vec![], None)
            .unwrap()
            .batch()
            .clone();
        let certificate = self.certificate(height, batch.value_id());
        adapter.hold(batch.clone());
        assert_eq!(
            adapter.decide(&RoomCertificate {
                bytes: certificate,
                value_commitment: batch.value_id(),
                height
            }),
            DecidedOutcome::Acked
        );
        batch
    }

    fn bundle(&self, batch: &Batch, next: Frontier) -> Bundle {
        Bundle::new(BundleParts {
            certificate: self.certificate(next.height, batch.value_id()),
            predecessor: batch.parent.commitment(),
            next: next.commitment(),
            batch: batch.encode(),
            value: batch.value_id().to_vec(),
            configuration: self.genesis.policy.id().as_bytes().to_vec(),
            control_record: next.control.to_vec(),
            debit_marker: next.value.to_vec(),
            height: next.height,
        })
        .unwrap()
    }

    fn app(&self) -> App {
        let store = self.base.join("store");
        for child in ["batches", "seen", "pending"] {
            std::fs::create_dir_all(store.join(child)).unwrap();
        }
        App {
            ctx: RoomContext,
            adapter: Arc::new(Mutex::new(self.open())),
            sink: Arc::new(Mutex::new(EngineSink::default())),
            validator_sets: BTreeMap::from([(1, self.set.clone())]),
            address: Address::from_public_key(&self.key.public_key()),
            private_key: self.key.clone(),
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
        }
    }
}

impl Drop for HistoryFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[test]
fn history_pages_continue_past_1024_after_restart() {
    const HEIGHTS: u64 = 1025;
    let fixture = HistoryFixture::new("long");
    // Initialize actual stores, then publish real verified canonical bundles.
    // Going through Journal here avoids repeating writer-side orphan scans
    // once per setup height; the reader must never invoke those scans.
    drop(fixture.open());
    let mut app = Application::genesis(
        fixture.genesis.archive.clone(),
        fixture.genesis.registry().unwrap(),
    );
    let journal = Journal::with_genesis(
        fixture.base.join("app/journal"),
        FsStore,
        app.frontier().commitment(),
    );
    for height in 1..=HEIGHTS {
        let checked = app.prepare(height, vec![], vec![], None).unwrap();
        let bundle = fixture.bundle(checked.batch(), checked.next());
        journal.commit(&bundle).unwrap();
        app.apply_locally(checked);
    }
    let adapter = fixture.open();
    assert_eq!(adapter.frontier(), app.frontier());
    drop(adapter);
    let adapter = fixture.open();
    let mut start = 1;
    let mut pages = 0;
    while start <= HEIGHTS {
        let values = read_decided_range(&adapter, start, u64::MAX).unwrap();
        assert_eq!(values.len(), (HEIGHTS - start + 1).min(32) as usize);
        for (offset, raw) in values.iter().enumerate() {
            let height = start + offset as u64;
            assert_eq!(raw.certificate.height.as_u64(), height);
            assert!(raw
                .certificate
                .commit_signatures
                .iter()
                .all(|sig| sig.extension.is_none()));
            let value = RoomCodec::decode_value(raw.value_bytes.clone()).unwrap();
            let batch = Batch::decode(&value.bytes).unwrap();
            assert_eq!(batch.parent.height + 1, height);
            assert_eq!(value.id.0, batch.value_id());
            let stored = adapter.committed_at_height(height).unwrap();
            assert_eq!(&value.bytes[..], stored.field(3).unwrap());
            assert!(crate::cert::verify_canonical_certificate(
                stored.field(0).unwrap(),
                height,
                &value.id,
                &fixture.set
            ));
        }
        let count = values.len();
        let response = Response::ValueResponse(ValueResponse::new(Height::new(start), values));
        let encoded = RoomCodec.encode(&response).unwrap();
        assert!(encoded.len() <= MAX_HISTORY_RESPONSE_BYTES);
        let decoded: Response<RoomContext> = RoomCodec.decode(encoded).unwrap();
        assert_eq!(decoded, response);
        start += count as u64;
        pages += 1;
    }
    assert_eq!(pages, 33);
    assert!(read_decided_range(&adapter, start, u64::MAX)
        .unwrap()
        .is_empty());
    assert!(read_decided_range(&adapter, u64::MAX, u64::MAX)
        .unwrap()
        .is_empty());
    assert!(read_decided_range(&adapter, 0, 1).unwrap().is_empty());
    assert!(read_decided_range(&adapter, 5, 4).unwrap().is_empty());
}

#[tokio::test]
async fn committed_held_reply_uses_disk_and_corruption_keeps_deadline_contract() {
    let fixture = HistoryFixture::new("held");
    let mut app = fixture.app();
    let batch = fixture.commit_empty(&mut app.adapter.lock().unwrap());
    app.sweep_decided(1);
    assert!(app.held_by_id.is_empty());
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.held_replies.push(HeldReply {
        height: 1,
        round: Round::new(7),
        deadline: Instant::now() + Duration::from_secs(60),
        reply: tx,
    });
    let mut answered = app.drain_answerable_held();
    assert_eq!(answered.len(), 1);
    let answer = answered.pop().unwrap();
    assert!(answer.live);
    assert_eq!(&answer.value.bytes[..], batch.encode());
    answer
        .reply
        .send(LocallyProposedValue::new(
            Height::new(answer.height),
            answer.round,
            answer.value,
        ))
        .unwrap();
    assert_eq!(rx.await.unwrap().round, Round::new(7));

    let head = app.adapter.lock().unwrap().dir().join("HEAD");
    let good = std::fs::read(&head).unwrap();
    std::fs::write(&head, b"corrupt").unwrap();
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    app.held_replies.push(HeldReply {
        height: 1,
        round: Round::new(8),
        deadline: Instant::now() + Duration::from_secs(60),
        reply: tx,
    });
    assert!(app.drain_answerable_held().is_empty());
    assert_eq!(app.held_replies.len(), 1);
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    app.held_replies[0].deadline = Instant::now();
    let answer = app.drain_answerable_held().pop().unwrap();
    assert!(!answer.live);
    assert!(answer.value.bytes.is_empty());
    answer
        .reply
        .send(LocallyProposedValue::new(
            Height::new(answer.height),
            answer.round,
            answer.value,
        ))
        .unwrap();
    assert_eq!(rx.await.unwrap().round, Round::new(8));
    assert_eq!(
        std::fs::read(&head).unwrap(),
        b"corrupt",
        "a read never repairs storage"
    );
    std::fs::write(&head, good).unwrap();
    assert_eq!(
        read_decided_range(&app.adapter.lock().unwrap(), 1, 1)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn missing_height_and_tip_disagreement_fail_the_whole_page() {
    let fixture = HistoryFixture::new("corruption");
    let mut adapter = fixture.open();
    for _ in 0..3 {
        fixture.commit_empty(&mut adapter);
    }
    let marker = adapter.dir().join("heights/0000000000000002");
    let good = std::fs::read(&marker).unwrap();
    std::fs::remove_file(&marker).unwrap();
    assert!(read_decided_range(&adapter, 1, 3)
        .unwrap_err()
        .contains("missing published height 2"));
    assert!(!marker.exists(), "a reader cannot repair a gap");
    std::fs::write(&marker, good).unwrap();
    let tip = adapter.dir().join("heights/0000000000000003");
    let good = std::fs::read(&tip).unwrap();
    std::fs::write(&tip, [0; 32]).unwrap();
    assert!(
        read_decided_range(&adapter, 1, 1).is_err(),
        "HEAD is checked even for an older requested page"
    );
    assert_eq!(std::fs::read(&tip).unwrap(), [0; 32]);
    std::fs::write(&tip, good).unwrap();
    assert_eq!(read_decided_range(&adapter, 1, 3).unwrap().len(), 3);
}

#[test]
fn published_but_unapplied_height_is_not_served() {
    let fixture = HistoryFixture::new("applied");
    let mut adapter = fixture.open();
    fixture.commit_empty(&mut adapter);
    let checked = adapter
        .application()
        .prepare(2, vec![], vec![], None)
        .unwrap();
    let bundle = fixture.bundle(checked.batch(), checked.next());
    let journal = Journal::with_genesis(adapter.dir(), FsStore, [0; 32]);
    journal.commit(&bundle).unwrap();
    assert_eq!(adapter.frontier().height, 1);
    assert_eq!(read_decided_range(&adapter, 1, u64::MAX).unwrap().len(), 1);
    assert!(read_decided_range(&adapter, 2, 2).unwrap().is_empty());
    drop(adapter);
    let adapter = fixture.open();
    assert_eq!(adapter.frontier().height, 2);
    assert_eq!(read_decided_range(&adapter, 1, u64::MAX).unwrap().len(), 2);
}
