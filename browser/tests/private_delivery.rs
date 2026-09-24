//! Durable browser delivery model: finite retries, exact bytes and staged pages.
#![cfg(feature = "private-rooms")]
// The shared durable model also carries constants only the sync engine and
// worker use; this model-level test does not exercise every one.
#[allow(dead_code)]
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
fn browser_pause_receipt_matches_shared_native_golden_vector() {
    let vector = include_str!("../../vectors/private-controller-pause-v1.json");
    let selected = |field: &str| {
        vector
            .split(&format!("\"{field}\": \""))
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
    };
    let decode = |raw: &str| {
        raw.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };
    let raw = decode(selected("encoded_hex"));
    let receipt = model::generation::Receipt::decode(&raw).unwrap();
    assert_eq!(receipt.encode().unwrap(), raw);
    assert_eq!(
        receipt.commitment().unwrap().as_slice(),
        decode(selected("commitment"))
    );
    for at in 0..raw.len() {
        assert!(model::generation::Receipt::decode(&raw[..at]).is_err());
    }
    let mut corrupt = raw.clone();
    corrupt[425] = 0;
    assert!(model::generation::Receipt::decode(&corrupt).is_err());
    corrupt = raw.clone();
    corrupt[450] ^= 1;
    assert!(model::generation::Receipt::decode(&corrupt).is_err());
    corrupt = raw;
    corrupt.push(0);
    assert!(model::generation::Receipt::decode(&corrupt).is_err());
}

#[test]
fn v4_lineage_upgrade_preserves_real_shared_spend_and_finite_bounds() {
    let mut state = State::new([1; 32], [2; 16], 0, 100);
    assert!(state.reserve(100, 4096).unwrap());
    let mut v4 = state.encode().unwrap();
    v4.truncate(v4.len() - 91);
    v4[7] = 4;
    let upgraded = State::decode(&v4).unwrap();
    assert_eq!(upgraded.accounting(), state.accounting());
    assert_eq!(upgraded.lineage.generation, 0);
    assert_eq!(upgraded.lineage.original, state.binding);
    assert!(upgraded.lineage.audit.is_none());
    const {
        assert!(model::MAX_STATE < 5 * 1024 * 1024);
    }
    let mut audit = upgraded;
    audit.lineage.audit = Some(model::Audit {
        transition: [3; 32],
        head: 4096,
        digests: vec![[4; 32]; 4096],
    });
    assert!(State::decode(&audit.encode().unwrap()).is_ok());
    audit.lineage.audit.as_mut().unwrap().digests.push([4; 32]);
    assert!(audit.encode().is_err());
}

#[test]
fn complete_digest_list_and_largest_four_item_page_fit_the_existing_image_limit() {
    let namespace = RelayNamespace::from_bytes([3; 32]).unwrap();
    let payload = vec![42; vhalla_private_relay::MAX_RELAY_PAYLOAD];
    let largest = |sequence| {
        RelayItem::new(
            namespace,
            sequence,
            OperationId::from_bytes([4; 16]).unwrap(),
            OutboxKind::Application,
            &payload,
        )
        .unwrap()
    };
    let mut state = State::new([1; 32], [2; 16], 0, 100);
    state.lineage.audit = Some(model::Audit {
        transition: [3; 32],
        head: 4096,
        digests: vec![[4; 32]; 4096],
    });
    state.pending = largest(1).encode().unwrap();
    state.control_sent = Some(vhalla_private_kernel::protocol::ControlFloor::new(0, None).unwrap());
    state.pending_control = RelayItem::new(
        namespace,
        1,
        OperationId::from_bytes([5; 16]).unwrap(),
        vhalla_private_relay::RelayKind::Control,
        &payload,
    )
    .unwrap()
    .encode()
    .unwrap();
    state.staged = codec::encode_page(&RelayPage {
        head: 4096,
        next: Some(4),
        records: (1..=4)
            .map(|position| PositionedItem {
                position,
                item: largest(position),
            })
            .collect(),
    })
    .unwrap();
    let raw = state.encode().unwrap();
    assert!(raw.len() < model::MAX_STATE && model::MAX_STATE < 5 * 1024 * 1024);
    let restored = State::decode(&raw).unwrap();
    assert_eq!(restored.lineage.audit.unwrap().digests.len(), 4096);
    assert_eq!(restored.staged, state.staged);
    assert_eq!(restored.pending, state.pending);
    assert_eq!(restored.pending_control, state.pending_control);
    // Discovery may never create a second staged page alongside this one.
    state.discovery = Some(model::Discovery {
        staged: state.staged.clone(),
        ..Default::default()
    });
    assert!(state.encode().is_err());
}

#[test]
fn invitation_discovery_has_separate_checked_progress_and_one_bounded_candidate() {
    let invitation = RelayItem::new(
        RelayNamespace::from_bytes([3; 32]).unwrap(),
        1,
        OperationId::from_bytes([4; 16]).unwrap(),
        OutboxKind::ContactInvitation,
        b"authenticated encrypted invitation",
    )
    .unwrap();
    let page = RelayPage {
        head: 3,
        next: None,
        records: vec![
            PositionedItem {
                position: 1,
                item: item(1),
            },
            PositionedItem {
                position: 2,
                item: invitation.clone(),
            },
            PositionedItem {
                position: 3,
                item: item(2),
            },
        ],
    };
    let mut state = State::new([1; 32], [2; 16], 0, 100);
    state.start_discovery().unwrap();
    let d = state.discovery.as_mut().unwrap();
    d.cursor = 2;
    d.applied = 2;
    d.staged = codec::encode_page(&page).unwrap();
    d.response = Some(model::Admission {
        position: 2,
        kind: vhalla_private_relay::kind_byte(invitation.kind()),
        len: invitation.encode().unwrap().len() as u32,
        digest: invitation.digest(),
    });
    let raw = state.encode().unwrap();
    let decoded = State::decode(&raw).unwrap();
    assert_eq!(decoded.cursor, 0);
    assert_eq!(decoded.staged_after, 0);
    assert_eq!(decoded.applied, 0);
    assert!(decoded.admissions.is_empty());
    assert_eq!(decoded.discovery.as_ref().unwrap().cursor, 2);
    for n in 0..raw.len() {
        assert!(State::decode(&raw[..n]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(State::decode(&trailing).is_err());

    let mut invalid = decoded.clone();
    invalid.admissions.push(
        invalid
            .discovery
            .as_ref()
            .unwrap()
            .response
            .clone()
            .unwrap(),
    );
    assert!(
        invalid.encode().is_err(),
        "discovery never authorizes an ordinary admission ahead of cursor"
    );
    let mut invalid = decoded.clone();
    invalid
        .discovery
        .as_mut()
        .unwrap()
        .response
        .as_mut()
        .unwrap()
        .position = 3;
    assert!(invalid.encode().is_err());
    let mut invalid = decoded.clone();
    invalid.discovery.as_mut().unwrap().applied = 1;
    assert!(invalid.encode().is_err());
    let mut invalid = decoded.clone();
    invalid.discovery.as_mut().unwrap().complete = true;
    assert!(
        invalid.encode().is_err(),
        "completion requires a durable intent"
    );
    let d = state.discovery.as_mut().unwrap();
    d.intent = true;
    d.complete = true;
    assert!(
        state.encode().is_err(),
        "completed discovery cannot retain a second staged page"
    );
    let d = state.discovery.as_mut().unwrap();
    d.staged.clear();
    d.applied = 0;
    d.staged_after = d.cursor;
    assert!(state.encode().is_ok());
    state
        .admissions
        .push(state.discovery.as_ref().unwrap().response.clone().unwrap());
    assert!(
        state.encode().is_err(),
        "ordinary position invariant survives joining"
    );
}

#[test]
fn legacy_pending_conversion_preserves_charges_and_refuses_ambiguous_progress() {
    let mut state = State::new([1; 32], [2; 16], 0, 100);
    assert!(state.reserve(100, 4096).unwrap());
    let original = state;
    for version in 1..=3 {
        let mut raw = original.encode().unwrap();
        raw.truncate(raw.len() - 91); // v5 initial lineage, without scan/pause/intent.
        assert_eq!(raw.pop(), Some(0)); // v4's absent discovery discriminator.
        if version == 1 {
            raw.truncate(152); // Original twelve counters, then one stop flag.
            raw.push(0);
            raw.extend_from_slice(&[0; 8]); // Empty pending and staged blobs.
        } else if version == 2 {
            raw.drain(165..167); // No deferred index or control floor in v2.
            raw.truncate(raw.len() - 4); // No pending-control blob.
        }
        raw[7] = version;
        assert!(State::legacy(&raw));
        let mut legacy = State::decode(&raw).unwrap();
        legacy.start_discovery().unwrap();
        assert_eq!(legacy.attempts, original.attempts);
        assert_eq!(legacy.wire_bytes, original.wire_bytes);
        assert_eq!(legacy.failures, original.failures);
        assert_eq!(legacy.retry_at, original.retry_at);
        assert_eq!(legacy.wall, original.wall);
        assert!(legacy.start_discovery().is_err());
    }
    for field in 0..8 {
        let mut ambiguous = original.clone();
        match field {
            0 => {
                ambiguous.initial = 1;
                ambiguous.cursor = 1;
                ambiguous.staged_after = 1;
            }
            1 => {
                ambiguous.cursor = 1;
                ambiguous.staged_after = 1;
            }
            2 => ambiguous.sent = 1,
            3 => ambiguous.retained = 1,
            4 => ambiguous.pending = item(1).encode().unwrap(),
            5 => ambiguous.received = 1,
            6 => ambiguous.refused_total = 1,
            _ => ambiguous.blocked = model::blocked::TIME,
        }
        assert!(ambiguous.start_discovery().is_err());
        assert!(ambiguous.discovery.is_none());
    }
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
    // A bounded wall-clock step back keeps the retained clock; the attempt
    // only waits out its deferral instead of corrupting durable progress.
    assert!(!reopened.reserve(99, 4096).unwrap());
    for at in [200, 500, 1000, 2000, 3000, 4000, 5000, 6000] {
        assert!(reopened.reserve(at, 4096).unwrap());
    }
    assert!(!reopened.reserve(7000, 4096).unwrap());
    assert!(reopened.stopped());
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
    assert!(reopened.stopped());
    assert_eq!(reopened.attempts, model::ATTEMPTS);

    let mut bytes = State::new([1; 32], [2; 16], 0, 100);
    bytes.wire_bytes = model::WIRE_BYTES - 4096;
    assert!(bytes.reserve(100, 4096).unwrap());
    bytes.success();
    let mut reopened = State::decode(&bytes.encode().unwrap()).unwrap();
    assert!(!reopened.reserve(101, 1).unwrap());
    assert!(reopened.stopped());
    assert_eq!(reopened.wire_bytes, model::WIRE_BYTES);
    assert_eq!(reopened.attempts, 1);
}

#[test]
fn bounded_clock_regression_is_tolerated_but_a_bogus_clock_is_refused() {
    let mut s = State::new([1; 32], [2; 16], 0, 100_000);
    // Exactly one tolerated step back keeps the retained clock.
    assert!(s.observe(100_000 - model::CLOCK_REGRESSION).is_ok());
    assert_eq!(s.wall, 100_000);
    // One further second back is a bogus clock, not a new base.
    assert!(s.observe(100_000 - model::CLOCK_REGRESSION - 1).is_err());
    assert_eq!(s.wall, 100_000);
    // Forward observation still advances and reservations keep working off
    // the retained clock; a future step does not poison the budget.
    assert_eq!(s.observe(200_000).unwrap(), 200_000);
    assert!(s.reserve(300_000, 4096).unwrap());
    let mut reopened = State::decode(&s.encode().unwrap()).unwrap();
    assert_eq!(reopened.wall, 300_000);
    assert!(!reopened.reserve(300_001, 4096).unwrap());
    assert!(reopened.reserve(300_002, 4096).unwrap());
}

#[test]
fn three_hundred_completed_small_exchanges_settle_to_actual_bytes() {
    let mut s = State::new([1; 32], [2; 16], 0, 100);
    // The worst-case page reply reservation every PAGE attempt holds.
    let reserved = 14 + codec::MAX_RESPONSE + 4;
    for i in 0..300u64 {
        assert!(s.reserve(100 + i, reserved).unwrap());
        s.settle(reserved, 14 + 32);
        s.success();
    }
    assert_eq!(s.attempts, 300);
    // Charging the pessimistic reservation forever would exhaust the 1 GiB
    // budget around cycle 250; only the exact exchange bytes are retained.
    assert_eq!(s.wire_bytes, 300 * (14 + 32));
    assert!(!s.stopped());
}

#[test]
fn backoff_pauses_durably_and_only_explicit_resupply_resumes() {
    let mut s = State::new([1; 32], [2; 16], 0, 100);
    let mut at = 100;
    for _ in 0..10 {
        assert!(s.reserve(at, 4096).unwrap());
        at = s.retry_at;
    }
    // The eleventh attempt sees ten durable consecutive failures and pauses.
    assert!(!s.reserve(at, 4096).unwrap());
    assert_eq!(s.stop, model::Stop::Backoff);
    assert!(s.stopped());
    let mut reopened = State::decode(&s.encode().unwrap()).unwrap();
    assert_eq!(reopened.stop, model::Stop::Backoff);
    assert!(!reopened.reserve(u64::MAX / 2, 4096).unwrap());
    // An explicit profile resupply clears only the pause; spent attempt and
    // byte budgets are never replenished.
    assert!(reopened.resume());
    assert_eq!(reopened.stop, model::Stop::None);
    assert_eq!(reopened.attempts, 10);
    assert_eq!(reopened.wire_bytes, 10 * 4096);
    assert!(reopened.reserve(u64::MAX / 2, 4096).unwrap());
    // Terminal stops never resume.
    let mut exhausted = State::new([1; 32], [2; 16], 0, 100);
    exhausted.attempts = model::ATTEMPTS;
    assert!(!exhausted.reserve(100, 1).unwrap());
    assert_eq!(exhausted.stop, model::Stop::Exhausted);
    assert!(!exhausted.resume());
    let mut refused = State::new([1; 32], [2; 16], 0, 100);
    refused.halt(model::halt::FRAME);
    assert!(!refused.resume());
    assert!(refused.encode().is_ok());
}

#[test]
fn deferred_frontier_round_trips_and_capacity_never_evicts() {
    let mut state = State::new([1; 32], [2; 16], 0, 100);
    for position in 1..=model::MAX_DEFERRED as u64 {
        let item = item(position);
        state.cursor = position;
        state.staged_after = position;
        state
            .defer(
                model::Admission {
                    position,
                    kind: vhalla_private_relay::kind_byte(item.kind()),
                    len: item.encode().unwrap().len() as u32,
                    digest: item.digest(),
                },
                model::blocked::FUTURE_EPOCH,
            )
            .unwrap();
    }
    assert_eq!(state.resolved(), 0);
    let before = state.encode().unwrap();
    let ninth = item(9);
    assert!(state
        .defer(
            model::Admission {
                position: 9,
                kind: vhalla_private_relay::kind_byte(ninth.kind()),
                len: ninth.encode().unwrap().len() as u32,
                digest: ninth.digest(),
            },
            model::blocked::FUTURE_EPOCH
        )
        .is_err());
    assert_eq!(state.encode().unwrap(), before);
    let reopened = State::decode(&before).unwrap();
    assert_eq!(reopened.deferred, state.deferred);
    assert_eq!(reopened.resolved(), 0);
    let mut damaged = state.clone();
    damaged.deferred[1].item.position = damaged.deferred[0].item.position;
    assert!(damaged.encode().is_err());
    let mut damaged = state.clone();
    damaged.deferred[0].item.position = 0;
    assert!(damaged.encode().is_err());
    let mut damaged = state.clone();
    damaged.deferred[0].reason = model::blocked::ADMISSIONS_FULL;
    assert!(damaged.encode().is_err());
    state.deferred.remove(0);
    assert_eq!(
        state.resolved(),
        1,
        "later resolved records never conceal an earlier gap"
    );
}

#[test]
fn version_two_images_upgrade_without_resetting_exact_pending_or_budgets() {
    let mut state = State::new([1; 32], [2; 16], 17, 100);
    state.pending = item(1).encode().unwrap();
    assert!(state.reserve(100, 4096).unwrap());
    let mut old = state.encode().unwrap();
    old.truncate(old.len() - 91); // v5 initial lineage.
    old.pop(); // v4 absent discovery tag
               // v3 added an empty deferred index and absent control floor after v2's
               // empty admission index, plus an empty pending-control blob at the end.
    assert_eq!(&old[163..167], &[0, 0, 0, 0]);
    old.drain(165..167);
    old.truncate(old.len() - 4);
    old[7] = 2;
    let upgraded = State::decode(&old).unwrap();
    assert_eq!(upgraded.pending, state.pending);
    assert_eq!(upgraded.attempts, 1);
    assert_eq!(upgraded.wire_bytes, 4096);
    assert_eq!(upgraded.retry_at, state.retry_at);
    assert_eq!(upgraded.cursor, 17);
    assert!(upgraded.deferred.is_empty());
    assert_eq!(upgraded.encode().unwrap()[7], 5);
}

#[test]
fn version_one_stopped_image_remains_stopped_after_upgrade() {
    let state = State::new([1; 32], [2; 16], 0, 100);
    let current = state.encode().unwrap();
    let mut old = current[..152].to_vec(); // v1 contains the first twelve counters
    old[7] = 1;
    old.push(1); // Old stop flag has no recoverable reason.
    old.extend_from_slice(&[0; 8]); // Empty pending and staged blobs.
    let upgraded = State::decode(&old).unwrap();
    assert_eq!(upgraded.stop, model::Stop::Refused);
    assert_eq!(upgraded.detail, model::halt::LEGACY);
    assert!(upgraded.deferred.is_empty());
    assert_eq!(upgraded.encode().unwrap()[7], 5);
}
