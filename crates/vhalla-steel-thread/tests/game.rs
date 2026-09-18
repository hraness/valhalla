//! Stage 5: a game session's records cross the transport replay window under
//! the host key into the game receiver, end in a settlement the receiver
//! reproduces, and never move a host effect.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use vhalla_core::{Epoch, EventId, PeerId, RealmId, RoomId, Sequence};
use vhalla_crypto::{
    peer_id_from_seed, sign, verifying_key_from_seed, SessionId, VerificationContext, VerifyError,
};
use vhalla_game_platonik::ids::CheckpointHash;
use vhalla_game_platonik::receiver::{ReceiverError, ReceiverPolicy};
use vhalla_game_platonik::record::{GameRecord, RecordKind};
use vhalla_game_platonik::session::{Session, State, Verdict};
use vhalla_game_platonik::settlement::SettleError;
use vhalla_game_platonik::wire::{
    decode_game_manifest, decode_session_open, encode_settlement, Settlement,
};
use vhalla_policy::Denied;
use vhalla_steel_thread::{
    GameEvidence, GameSession, MemorySession, SteelError, KIND_GAME_SETTLEMENT,
    KIND_READ_MEMORY_REQUEST,
};
use vhalla_transport::Frame;
use vhalla_wire::Envelope;
use vhalla_witness::platform::ClaimedReceipt;
use vhalla_witness::vectors::unhex;

/// The host the frozen live vector was signed by (`Signer::new(1)`).
const HOST_SEED: [u8; 32] = [1; 32];
const NOW: u64 = 1_000;

fn context() -> VerificationContext {
    VerificationContext {
        audience: PeerId(1),
        realm: RealmId(2),
        room: RoomId(3),
        epoch: Epoch(1),
        session: SessionId(4),
    }
}

fn frame(seed: [u8; 32], sequence: u64, kind: u8, body: &[u8]) -> Frame {
    let ctx = context();
    let envelope = Envelope::new(
        kind,
        peer_id_from_seed(seed),
        ctx.realm,
        ctx.room,
        EventId(sequence as u128),
        Sequence(sequence),
        body,
    )
    .unwrap();
    let signed = sign(
        envelope,
        ctx.audience,
        ctx.epoch,
        ctx.session,
        NOW + 100,
        seed,
    )
    .unwrap();
    Frame::new(&signed.encode().unwrap()).unwrap()
}

fn parse(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once(": "))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn bytes(fields: &BTreeMap<String, String>, key: &str) -> Vec<u8> {
    unhex(fields.get(key).unwrap_or_else(|| panic!("missing {key}"))).unwrap()
}

struct Vector {
    fields: BTreeMap<String, String>,
    records: Vec<Vec<u8>>,
}

fn vector() -> Vector {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vhalla-game-platonik/tests/vectors/game-v1-session-live.txt");
    let fields = parse(&fs::read_to_string(path).unwrap());
    let count: usize = fields["record_count"].parse().unwrap();
    let records = (0..count)
        .map(|i| bytes(&fields, &format!("record[{i}].record")))
        .collect();
    Vector { fields, records }
}

fn open(vector: &Vector) -> Session {
    let manifest = decode_game_manifest(&bytes(&vector.fields, "game_manifest")).unwrap();
    let open = decode_session_open(&bytes(&vector.fields, "session_open")).unwrap();
    let realm = open.realm;
    let session = Session::open(manifest, open, realm).unwrap();
    assert_eq!(
        session.host(),
        verifying_key_from_seed(HOST_SEED).to_bytes(),
        "the vector's host is the seed this test signs frames with"
    );
    session
}

fn policy() -> ReceiverPolicy {
    ReceiverPolicy {
        max_replays: 64,
        max_work: u64::MAX,
        max_steps: u64::MAX,
    }
}

/// Plays every record of the live vector through the steel thread and returns
/// the session and the final checkpoint hash.
fn play(session: &mut GameSession, vector: &Vector) -> CheckpointHash {
    let mut last = None;
    for (index, raw) in vector.records.iter().enumerate() {
        let sequence = index as u64 + 1;
        let evidence = session
            .receive_game(
                frame(HOST_SEED, sequence, KIND_GAME_SETTLEMENT, raw),
                NOW + sequence,
            )
            .unwrap();
        let is_seal = vector
            .fields
            .contains_key(&format!("record[{index}].checkpoint"));
        match evidence {
            GameEvidence::Pending => assert!(!is_seal, "record {index} is not a seal"),
            GameEvidence::Checkpoint(checkpoint) => {
                assert!(is_seal, "record {index} is a seal");
                let committed = bytes(&vector.fields, &format!("record[{index}].checkpoint_hash"));
                assert_eq!(checkpoint.hash().0.to_vec(), committed);
                last = Some(checkpoint.hash());
            }
            GameEvidence::Settlement(_) => panic!("record {index} is not a settlement"),
        }
    }
    last.expect("the vector seals at least once")
}

fn settlement_record(
    session_key: vhalla_game_platonik::ids::SessionKey,
    body: Settlement,
) -> Vec<u8> {
    GameRecord::sign(
        RecordKind::Settlement,
        session_key,
        encode_settlement(&body),
        &SigningKey::from_bytes(&HOST_SEED),
    )
    .unwrap()
    .encode()
}

#[test]
fn a_live_session_settles_through_the_transport_window() {
    let vector = vector();
    let session = open(&vector);
    let key = session.key();
    let mut steel = GameSession::new(context(), session, policy()).unwrap();
    let final_checkpoint = play(&mut steel, &vector);
    assert_eq!(steel.state(), State::Finished);
    let receipt = ClaimedReceipt::decode(&bytes(&vector.fields, "receipt")).unwrap();
    let next = vector.records.len() as u64 + 1;
    // The vector does not record the verdict; a wrong claim is refused
    // without a verdict, and the reproduced one settles.
    let mut settled = None;
    for (offset, passed) in [true, false].into_iter().enumerate() {
        let body = Settlement::Result {
            session: key,
            epoch: Epoch(0),
            checkpoint: final_checkpoint,
            receipt,
            passed,
        };
        let raw = settlement_record(key, body);
        match steel.receive_game(
            frame(HOST_SEED, next + offset as u64, KIND_GAME_SETTLEMENT, &raw),
            NOW + next,
        ) {
            Ok(GameEvidence::Settlement(verdict)) => {
                assert_eq!(verdict.passed(), passed);
                settled = Some(verdict);
                break;
            }
            Err(SteelError::Game(ReceiverError::Settle(SettleError::PassedMismatch))) => {}
            other => panic!("unexpected outcome {other:?}"),
        }
    }
    let verdict = settled.expect("one of the two claims is the reproduced verdict");
    assert_eq!(verdict.session(), key);
    assert!(matches!(verdict.verdict(), Verdict::Result { .. }));
    // The settlement is evidence the receiver can export as its own claim.
    let claim = verdict.export_claim(
        RealmId(2),
        SessionId(4),
        PeerId(1),
        Epoch(1),
        Sequence(1),
        NOW,
        NOW + 600,
        [55; 32],
    );
    assert_eq!(claim.issuer, peer_id_from_seed([55; 32]));
}

#[test]
fn only_the_host_and_only_the_game_kind_reach_the_receiver() {
    let vector = vector();
    let session = open(&vector);
    let mut steel = GameSession::new(context(), session, policy()).unwrap();
    let first = &vector.records[0];
    // A player's own transport signature is not the host's.
    assert_eq!(
        steel
            .receive_game(frame([2; 32], 1, KIND_GAME_SETTLEMENT, first), NOW + 1)
            .err(),
        Some(SteelError::Verify(VerifyError::AuthorMismatch))
    );
    // The host relabelling a game record as a read request never reaches the
    // receiver: the kind is inside the signed transcript.
    assert_eq!(
        steel
            .receive_game(
                frame(HOST_SEED, 1, KIND_READ_MEMORY_REQUEST, first),
                NOW + 1
            )
            .err(),
        Some(SteelError::Denied(Denied::Kind))
    );
    // A frame that is not a game record at all.
    assert_eq!(
        steel
            .receive_game(
                frame(HOST_SEED, 2, KIND_GAME_SETTLEMENT, b"not a record"),
                NOW + 1
            )
            .err(),
        Some(SteelError::Denied(Denied::Kind))
    );
    // The same frame twice: the transport window refuses the replay first.
    steel
        .receive_game(frame(HOST_SEED, 3, KIND_GAME_SETTLEMENT, first), NOW + 2)
        .unwrap();
    assert_eq!(
        steel
            .receive_game(frame(HOST_SEED, 3, KIND_GAME_SETTLEMENT, first), NOW + 3)
            .err(),
        Some(SteelError::Verify(VerifyError::Replay))
    );
    // A fresh envelope carrying the same record: the session refuses the
    // duplicate claim.
    assert!(matches!(
        steel
            .receive_game(frame(HOST_SEED, 4, KIND_GAME_SETTLEMENT, first), NOW + 4)
            .err(),
        Some(SteelError::Game(_))
    ));
    assert_eq!(steel.state(), State::Binding);
}

#[test]
fn a_game_frame_never_moves_a_host_effect() {
    let vector = vector();
    let mut memory = MemorySession::new(context(), verifying_key_from_seed(HOST_SEED), 7).unwrap();
    assert_eq!(
        memory
            .receive(
                frame(HOST_SEED, 1, KIND_GAME_SETTLEMENT, &vector.records[0]),
                NOW + 1
            )
            .err(),
        Some(SteelError::Denied(Denied::Kind))
    );
    assert_eq!(memory.reads(), 0);
}

/// The vector's player is `Signer::new(2)`, the same as the session tests.
const PLAYER_SEED: [u8; 32] = [2; 32];
const CARRIER_SEED: [u8; 32] = [9; 32];
const SCHEME: [u8; 32] = [0xA5; 32];

fn quorum_session(vector: &Vector) -> Session {
    use vhalla_game_platonik::quorum::{open as quorum_open, open_commitment};
    use vhalla_game_platonik::wire::Authority;
    use vhalla_rooms_consensus::{Batch, CommitCertificate, Frontier};
    let manifest = decode_game_manifest(&bytes(&vector.fields, "game_manifest")).unwrap();
    let mut open = decode_session_open(&bytes(&vector.fields, "session_open")).unwrap();
    let realm = open.realm;
    open.authority = Authority::Quorum { scheme: SCHEME };
    let batch = Batch {
        parent: Frontier {
            height: 41,
            value: [1; 32],
            registry: [2; 32],
            social: [3; 32],
            control: [4; 32],
            time: 100,
        },
        time: 101,
        evidence: Vec::new(),
        records: Vec::new(),
        games: vec![open_commitment(&open)],
        eligible: None,
        result_registry: [5; 32],
        result_social: [6; 32],
        result_control: [7; 32],
    };
    let certificate = CommitCertificate {
        bytes: vec![0xC3; 96],
        value_commitment: batch.value_id(),
        height: 42,
    };
    quorum_open(manifest, open, realm, &certificate, &batch, 0, |_, _, _| {
        true
    })
    .unwrap()
}

/// A record carrying a player-signed `BindCommit` this test's quorum
/// session expects: the player still signs its own events; only authority
/// events come from the unforgeable quorum actor.
fn player_bind_commit(
    session_key: vhalla_game_platonik::ids::SessionKey,
    slot: u16,
    sequence: u64,
    commit: [u8; 32],
) -> Vec<u8> {
    use vhalla_game_platonik::wire::{encode_game_event, EventBody, GameEvent};
    let event = GameEvent {
        session: session_key,
        epoch: Epoch(0),
        author: verifying_key_from_seed(PLAYER_SEED).to_bytes(),
        sequence: Sequence(sequence),
        parents: Vec::new(),
        body: EventBody::BindCommit { slot, commit },
    };
    GameRecord::sign(
        RecordKind::Event,
        session_key,
        encode_game_event(&event),
        &SigningKey::from_bytes(&PLAYER_SEED),
    )
    .unwrap()
    .encode()
}

#[test]
fn a_quorum_session_needs_proofs_and_a_carrier_not_a_host_signature() {
    use vhalla_game_platonik::quorum::{commitment, prove};
    use vhalla_game_platonik::session::{quorum_actor, Rejection};
    use vhalla_rooms_consensus::{Batch, CommitCertificate, Frontier};
    let vector = vector();
    // The host transport constructor refuses a quorum session outright: the
    // actor is a point, not a signing key.
    let quorum = quorum_session(&vector);
    assert_eq!(quorum.host(), quorum_actor(&SCHEME));
    assert_eq!(
        GameSession::new(context(), quorum_session(&vector), policy()).err(),
        Some(SteelError::Denied(Denied::Kind))
    );
    // And the quorum constructor refuses a host session.
    let carrier = verifying_key_from_seed(CARRIER_SEED);
    assert_eq!(
        GameSession::new_quorum(context(), open(&vector), &carrier, policy()).err(),
        Some(SteelError::Denied(Denied::Kind))
    );
    let mut steel = GameSession::new_quorum(context(), quorum, &carrier, policy()).unwrap();
    let slot = steel.session().opening().players[0].slots[0];
    assert_eq!(
        steel.session().opening().players[0].key,
        verifying_key_from_seed(PLAYER_SEED).to_bytes()
    );
    let raw = player_bind_commit(steel.session().key(), slot, 1, [7; 32]);
    // A carrier-signed frame without proof reaches the session and fails
    // closed: ordering authority is consensus, never the transport.
    assert_eq!(
        steel
            .receive_game(frame(CARRIER_SEED, 1, KIND_GAME_SETTLEMENT, &raw), NOW + 1)
            .err(),
        Some(SteelError::Game(ReceiverError::Session(
            Rejection::ProofRequired
        )))
    );
    // A frame not signed by the pinned carrier never reaches the session.
    assert_eq!(
        steel
            .receive_game(frame([8; 32], 2, KIND_GAME_SETTLEMENT, &raw), NOW + 2)
            .err(),
        Some(SteelError::Verify(VerifyError::AuthorMismatch))
    );
    // Mint the consumed proof: the record's own commitment decided in a
    // batch the certificate attests.
    let record = GameRecord::decode(&raw).unwrap();
    let named = commitment(steel.session(), &record).unwrap();
    let batch = Batch {
        parent: Frontier {
            height: 42,
            value: [1; 32],
            registry: [2; 32],
            social: [3; 32],
            control: [4; 32],
            time: 101,
        },
        time: 102,
        evidence: Vec::new(),
        records: Vec::new(),
        games: vec![named],
        eligible: None,
        result_registry: [5; 32],
        result_social: [6; 32],
        result_control: [7; 32],
    };
    let certificate = CommitCertificate {
        bytes: vec![0xC3; 96],
        value_commitment: batch.value_id(),
        height: 43,
    };
    let proof = prove(
        steel.session(),
        &record,
        &certificate,
        &batch,
        0,
        |_, _, _| true,
    )
    .unwrap();
    // The carrier delivers the record; the consumed proof is its authority.
    let evidence = steel
        .receive_game_quorum(
            frame(CARRIER_SEED, 3, KIND_GAME_SETTLEMENT, &raw),
            NOW + 3,
            proof,
        )
        .unwrap();
    assert!(matches!(evidence, GameEvidence::Pending));
    assert_eq!(steel.state(), State::Binding);
    // A proof bound to a different record is refused as a mismatch.
    let other_raw = player_bind_commit(steel.session().key(), slot, 2, [8; 32]);
    let other = GameRecord::decode(&other_raw).unwrap();
    let other_named = commitment(steel.session(), &other).unwrap();
    let batch2 = Batch {
        games: vec![other_named],
        ..batch
    };
    let certificate2 = CommitCertificate {
        bytes: vec![0xC3; 96],
        value_commitment: batch2.value_id(),
        height: 44,
    };
    let proof2 = prove(
        steel.session(),
        &other,
        &certificate2,
        &batch2,
        0,
        |_, _, _| true,
    )
    .unwrap();
    assert_eq!(
        steel
            .receive_game_quorum(
                frame(CARRIER_SEED, 4, KIND_GAME_SETTLEMENT, &raw),
                NOW + 4,
                proof2,
            )
            .err(),
        Some(SteelError::Game(ReceiverError::Session(
            Rejection::ProofMismatch
        )))
    );
}

#[test]
fn a_host_session_refuses_quorum_proofs_over_the_transport() {
    use vhalla_game_platonik::quorum::{commitment, prove};
    use vhalla_game_platonik::session::Rejection;
    use vhalla_rooms_consensus::{Batch, CommitCertificate, Frontier};
    let vector = vector();
    let mut steel = GameSession::new(context(), open(&vector), policy()).unwrap();
    let record = GameRecord::decode(&vector.records[0]).unwrap();
    let named = commitment(steel.session(), &record).unwrap();
    let batch = Batch {
        parent: Frontier {
            height: 41,
            value: [1; 32],
            registry: [2; 32],
            social: [3; 32],
            control: [4; 32],
            time: 100,
        },
        time: 101,
        evidence: Vec::new(),
        records: Vec::new(),
        games: vec![named],
        eligible: None,
        result_registry: [5; 32],
        result_social: [6; 32],
        result_control: [7; 32],
    };
    let certificate = CommitCertificate {
        bytes: vec![0xC3; 96],
        value_commitment: batch.value_id(),
        height: 42,
    };
    let proof = prove(
        steel.session(),
        &record,
        &certificate,
        &batch,
        0,
        |_, _, _| true,
    )
    .unwrap();
    assert_eq!(
        steel
            .receive_game_quorum(
                frame(HOST_SEED, 1, KIND_GAME_SETTLEMENT, &vector.records[0]),
                NOW + 1,
                proof,
            )
            .err(),
        Some(SteelError::Game(ReceiverError::Session(
            Rejection::ProofMismatch
        )))
    );
    // The host path itself is unchanged.
    assert!(steel
        .receive_game(
            frame(HOST_SEED, 2, KIND_GAME_SETTLEMENT, &vector.records[0]),
            NOW + 2
        )
        .is_ok());
}
