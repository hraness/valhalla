use super::*;

fn sample() -> ControllerPauseReceipt {
    let context = Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes([1; 32]).unwrap(),
            anchor: AnchorId::from_bytes([2; 32]).unwrap(),
        },
        account: Key::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[3; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
        device: Key::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[4; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
    };
    let mut accounting = BrowserSharedAccounting {
        attempts: 9,
        wire_bytes: 1024,
        retained: 5,
        received: 3,
        refused_total: 1,
        total_byte_ceiling: MAX_TOTAL_BYTES,
        total_attempt_ceiling: 4096,
        commitment: [0; 32],
    };
    accounting.commitment = accounting.computed_commitment();
    ControllerPauseReceipt {
        context,
        controller_id: controller_id(context, [6; 32]),
        original_profile_binding: [6; 32],
        transition: [7; 32],
        generation: 0,
        namespace: [8; 32],
        endpoint: [9; 32],
        profile_binding: [6; 32],
        terminal_head: 3,
        items_commitment: [10; 32],
        outbox_head: 5,
        control_head: 2,
        image_commitment: [11; 32],
        accounting: Accounting::BrowserShared(accounting),
        prior_ledger_commitment: [0; 32],
    }
}

#[test]
fn browser_roundtrip_and_fixed_commitment() {
    let value = sample();
    let raw = value.encode().unwrap();
    assert_eq!(raw.len(), BROWSER_RECEIPT_BYTES);
    assert_eq!(ControllerPauseReceipt::decode(&raw).unwrap(), value);
    assert_eq!(
        value.commitment().unwrap(),
        [
            0x6e, 0xa1, 0x9c, 0xe5, 0xbb, 0x69, 0x50, 0x76, 0x33, 0x0f, 0x34, 0x57, 0x5b, 0xe8,
            0xdb, 0x3b, 0xa0, 0x7c, 0x0f, 0xb5, 0x84, 0xd4, 0x21, 0x5c, 0xca, 0x4b, 0xa5, 0xae,
            0x37, 0x25, 0x90, 0x72
        ]
    );
}

#[test]
fn browser_accounting_cannot_be_split_or_forged() {
    let raw = sample().encode().unwrap();
    for tag in [0, 2, 255] {
        let mut altered = raw.clone();
        altered[425] = tag;
        assert!(ControllerPauseReceipt::decode(&altered).is_err());
    }
    let mut altered = raw.clone();
    altered[426] ^= 1;
    assert!(ControllerPauseReceipt::decode(&altered).is_err());
    for len in 0..raw.len() {
        assert!(ControllerPauseReceipt::decode(&raw[..len]).is_err());
    }
    let mut extended = raw;
    extended.push(0);
    assert!(ControllerPauseReceipt::decode(&extended).is_err());
}

#[test]
fn native_boundaries_and_lineage_are_not_optional() {
    let mut value = sample();
    let normal = LedgerSnapshot {
        outgoing: 5,
        applied: 3,
        retained_jobs: 4,
        canonical_bytes: 100,
        charged_attempts: 6,
        outages: 2,
        resumes: 1,
        commitment: [12; 32],
    };
    let controls = LedgerSnapshot {
        outgoing: 2,
        applied: 0,
        retained_jobs: 2,
        canonical_bytes: 200,
        charged_attempts: 2,
        outages: 0,
        resumes: 0,
        commitment: [13; 32],
    };
    value.accounting = Accounting::NativeSplit {
        normal,
        controls,
        normal_total_byte_ceiling: 1000,
        control_total_byte_ceiling: 1000,
    };
    let raw = value.encode().unwrap();
    assert_eq!(raw.len(), NATIVE_RECEIPT_BYTES);
    assert_eq!(ControllerPauseReceipt::decode(&raw).unwrap(), value);
    for change in 0..4 {
        let mut altered = value.clone();
        match change {
            0 => altered.outbox_head += 1,
            1 => altered.terminal_head += 1,
            2 => altered.control_head += 1,
            _ => altered.generation = 1,
        }
        assert!(altered.encode().is_err());
    }
    value.generation = 1;
    value.prior_ledger_commitment = [14; 32];
    value.profile_binding = [15; 32];
    assert!(value.encode().is_ok());
    value.generation = MAX_GENERATIONS;
    assert!(value.encode().is_err());
}

#[test]
fn browser_limits_and_identity_are_checked_before_encoding() {
    let mut value = sample();
    value.controller_id[0] ^= 1;
    assert!(value.encode().is_err());
    value = sample();
    let Accounting::BrowserShared(mut counters) = value.accounting else {
        panic!()
    };
    counters.attempts = counters.total_attempt_ceiling + 1;
    counters.commitment = counters.computed_commitment();
    value.accounting = Accounting::BrowserShared(counters);
    assert!(value.encode().is_err());
}
