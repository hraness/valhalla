//! The signed carrier: sign, verify, tamper, wrong key, weak key, bounds.

use ed25519_dalek::SigningKey;
use vhalla_game_platonik::ids::SessionKey;
use vhalla_game_platonik::record::{GameRecord, RecordError, RecordKind, MAX_RECORD_BYTES};
use vhalla_game_platonik::wire::MAX_GAME_EVENT_BYTES;

#[test]
fn a_record_verifies_under_its_signer_and_nothing_else() {
    let key = SigningKey::from_bytes(&[5; 32]);
    let session = SessionKey([9; 32]);
    let record = GameRecord::sign(RecordKind::Event, session, vec![1, 2, 3], &key).unwrap();
    record.verify().unwrap();
    let raw = record.encode();
    assert!(raw.len() <= MAX_RECORD_BYTES);
    let back = GameRecord::decode(&raw).unwrap();
    assert_eq!(back, record);
    back.verify().unwrap();
    for index in 0..raw.len() {
        let mut bytes = raw.clone();
        bytes[index] ^= 1;
        let outcome = GameRecord::decode(&bytes).and_then(|r| r.verify());
        assert!(outcome.is_err(), "byte {index}");
    }
    let mut other_kind = record.clone();
    other_kind.kind = RecordKind::Checkpoint;
    assert_eq!(
        other_kind.verify(),
        Err(RecordError::Signature),
        "the kind is signed"
    );
    let mut other_session = record.clone();
    other_session.session = SessionKey([8; 32]);
    assert_eq!(
        other_session.verify(),
        Err(RecordError::Signature),
        "the session is signed"
    );
    let mut other_signer = record.clone();
    other_signer.signer = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
    assert_eq!(other_signer.verify(), Err(RecordError::Signature));
    let mut weak = record;
    weak.signer = [0; 32];
    assert_eq!(weak.verify(), Err(RecordError::WeakKey));
    let big = vec![0_u8; MAX_GAME_EVENT_BYTES + 1];
    assert_eq!(
        GameRecord::sign(RecordKind::Event, session, big, &key).err(),
        Some(RecordError::BodyTooLarge)
    );
    assert_eq!(
        GameRecord::sign(RecordKind::Checkpoint, session, vec![0; 1025], &key).err(),
        Some(RecordError::BodyTooLarge),
        "each kind has its own bound"
    );
}
