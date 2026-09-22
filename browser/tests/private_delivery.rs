//! Durable browser delivery model: finite retries, exact bytes and staged pages.
#![cfg(feature = "private-rooms")]
#[path = "../src/private/delivery_model.rs"]
mod model;
use model::State;
use vhalla_private_kernel::{OperationId, OutboxKind};
use vhalla_private_relay::{codec, PositionedItem, RelayItem, RelayNamespace, RelayPage};
fn item(sequence: u64) -> RelayItem {
    RelayItem::new(
        RelayNamespace::from_bytes([3; 32]).unwrap(),
        sequence,
        OperationId::from_bytes([4; 16]).unwrap(),
        OutboxKind::Application,
        b"opaque committed ciphertext",
    )
    .unwrap()
}
#[test]
fn interrupted_attempt_keeps_exact_pending_bytes_and_charged_backoff() {
    let mut s = State::new([1; 32], [2; 16], 17, 100);
    s.pending = item(1).encode().unwrap();
    assert!(s.reserve(100, 4096).unwrap());
    let raw = s.encode().unwrap();
    let mut reopened = State::decode(&raw).unwrap();
    assert_eq!(reopened.pending, s.pending);
    assert_eq!(reopened.attempts, 1);
    assert!(!reopened.reserve(101, 4096).unwrap());
    assert!(reopened.reserve(102, 4096).unwrap());
    assert_eq!(reopened.attempts, 2);
    assert!(reopened.reserve(99, 4096).is_err());
    for at in [200, 500, 1000, 2000, 3000, 4000, 5000, 6000] {
        assert!(reopened.reserve(at, 4096).unwrap());
    }
    assert!(!reopened.reserve(7000, 4096).unwrap());
    assert!(reopened.stopped);
    let mut again = State::decode(&reopened.encode().unwrap()).unwrap();
    assert!(!again.reserve(8000, 4096).unwrap());
    assert_eq!(again.attempts, 10);
    again.success();
    assert!(!again.reserve(9000, 4096).unwrap());
}
#[test]
fn staged_cursor_cannot_skip_or_regress_and_fresh_join_starts_at_trusted_cursor() {
    let page = RelayPage {
        head: 19,
        next: None,
        records: vec![
            PositionedItem {
                position: 18,
                item: item(1),
            },
            PositionedItem {
                position: 19,
                item: item(2),
            },
        ],
    };
    let mut s = State::new([1; 32], [2; 16], 17, 100);
    s.staged = codec::encode_page(&page).unwrap();
    assert!(s.check().is_ok());
    s.cursor = 18;
    s.applied = 1;
    assert!(s.check().is_ok());
    let raw = s.encode().unwrap();
    let resumed = State::decode(&raw).unwrap();
    assert_eq!(resumed.cursor, 18);
    assert_eq!(resumed.applied, 1);
    s.cursor = 19;
    assert!(s.check().is_err());
    s.cursor = 16;
    assert!(s.check().is_err());
    s.cursor = 18;
    s.applied = 3;
    assert!(s.check().is_err());
    s.cursor = 19;
    s.applied = 2;
    assert!(s.check().is_err()); // A finished page must have been cleared.
    s.applied = (1u64 << 32) + 1;
    assert!(s.check().is_err()); // Never truncate an index on a 32-bit worker.
}
#[test]
fn snapshots_refuse_every_truncation_trailing_bytes_and_oversized_progress() {
    let beyond_mailbox = vhalla_private_relay::MAX_RELAY_ITEMS as u64 + 1;
    assert!(State::new([1; 32], [2; 16], beyond_mailbox, 1)
        .encode()
        .is_err());
    let mut s = State::new([1; 32], [2; 16], 0, 1);
    let raw = s.encode().unwrap();
    for n in 0..raw.len() {
        assert!(State::decode(&raw[..n]).is_err());
    }
    let mut tail = raw.clone();
    tail.push(0);
    assert!(State::decode(&tail).is_err());
    s.attempts = model::ATTEMPTS + 1;
    assert!(s.encode().is_err());
    s.attempts = 0;
    s.wire_bytes = model::WIRE_BYTES + 1;
    assert!(s.encode().is_err());
    s.wire_bytes = 0;
    s.pending = item(2).encode().unwrap();
    assert!(s.encode().is_err());
    s.pending.clear();
    s.owner = [0; 16];
    assert!(s.encode().is_err());
}

#[test]
fn success_and_reopen_never_replenish_lifetime_attempt_or_byte_limits() {
    let mut attempts = State::new([1; 32], [2; 16], 0, 100);
    attempts.attempts = model::ATTEMPTS - 1;
    assert!(attempts.reserve(100, 4096).unwrap());
    attempts.success();
    let mut reopened = State::decode(&attempts.encode().unwrap()).unwrap();
    assert!(!reopened.reserve(101, 4096).unwrap());
    assert!(reopened.stopped);
    assert_eq!(reopened.attempts, model::ATTEMPTS);

    let mut bytes = State::new([1; 32], [2; 16], 0, 100);
    bytes.wire_bytes = model::WIRE_BYTES - 4096;
    assert!(bytes.reserve(100, 4096).unwrap());
    bytes.success();
    let mut reopened = State::decode(&bytes.encode().unwrap()).unwrap();
    assert!(!reopened.reserve(101, 1).unwrap());
    assert!(reopened.stopped);
    assert_eq!(reopened.wire_bytes, model::WIRE_BYTES);
    assert_eq!(reopened.attempts, 1);
}
