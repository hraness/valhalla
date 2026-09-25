use super::*;
use ed25519_dalek::SigningKey;
use vhalla_private_protocol::{AnchorId, Key, PrivateRoomScope, RoomId};

fn context() -> Context {
    Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes([1; 32]).unwrap(),
            anchor: AnchorId::from_bytes([2; 32]).unwrap(),
        },
        account: Key::from_bytes(SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes())
            .unwrap(),
        device: Key::from_bytes(SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes())
            .unwrap(),
    }
}
fn image(value: u8) -> Image {
    Image::from_bytes(&[value; 40]).unwrap()
}
fn record(position: u64, value: u8) -> StoredRecord {
    StoredRecord::from_bytes(RecordKey::Outbox(position), &[value; 80]).unwrap()
}

#[test]
fn generation_format_is_explicit_and_retains_exact_custody_limits() {
    let context = context();
    let limits = Limits::default();
    let legacy = format_frame(context, limits).unwrap();
    let guarded = guarded_format_frame(context, limits).unwrap();
    assert!(!guarded_format(&legacy));
    assert!(guarded_format(&guarded));
    assert_eq!(parse_format(context, &guarded), Ok(limits));
    assert_ne!(
        &guarded[..8],
        FORMAT,
        "an old writer rejects the new format"
    );
    assert_eq!(&legacy[8..152], &guarded[8..152]);
    assert!(delivery_selector_key(context).starts_with(&prefix(context)));
}

#[test]
fn delivery_selector_is_canonical_bounded_and_never_unpauses_generation_zero() {
    let selected = DeliveryGeneration {
        generation: 0,
        binding: [1; 32],
        namespace: [2; 32],
        paused: true,
        transition: [3; 32],
    };
    let raw = selected.encode().unwrap();
    assert_eq!(raw.len(), DeliveryGeneration::BYTES);
    assert_eq!(DeliveryGeneration::decode(&raw), Ok(selected));
    for at in 0..raw.len() {
        assert!(DeliveryGeneration::decode(&raw[..at]).is_err());
        let mut corrupt = raw.clone();
        corrupt[at] ^= 1;
        assert!(DeliveryGeneration::decode(&corrupt).is_err());
    }
    let mut extra = raw;
    extra.push(0);
    assert!(DeliveryGeneration::decode(&extra).is_err());
    assert!(DeliveryGeneration {
        paused: false,
        ..selected
    }
    .encode()
    .is_err());
    assert!(DeliveryGeneration {
        generation: 16,
        ..selected
    }
    .encode()
    .is_err());
    assert!(DeliveryGeneration {
        transition: [0; 32],
        ..selected
    }
    .encode()
    .is_err());
    assert!(DeliveryGeneration {
        generation: 1,
        paused: false,
        ..selected
    }
    .encode()
    .is_ok());
}

#[test]
fn full_context_format_limits_and_prefix_are_exact() {
    let ctx = context();
    let limits = Limits::default();
    let frame = format_frame(ctx, limits).unwrap();
    assert_eq!(frame.len(), FORMAT_BYTES);
    assert_eq!(parse_format(ctx, &frame), Ok(limits));
    let mut foreign = ctx;
    foreign.scope.room = RoomId::from_bytes([7; 32]).unwrap();
    assert_eq!(parse_format(foreign, &frame), Err(Error::Corrupt));
    assert_ne!(prefix(ctx), prefix(foreign));
    let mut bad = frame.clone();
    bad[150] ^= 1;
    assert_eq!(parse_format(ctx, &bad), Err(Error::Corrupt));
    for length in [0, 1, 135, 183] {
        assert!(parse_format(ctx, &frame[..length]).is_err());
    }
    let mut trailing = frame;
    trailing.push(0);
    assert!(parse_format(ctx, &trailing).is_err());
    assert!(format_frame(
        ctx,
        Limits {
            max_records: 0,
            max_record_bytes: 80
        }
    )
    .is_err());
}

#[test]
fn canonical_state_checks_counters_context_and_declared_length_before_image_copy() {
    let ctx = context();
    let limits = Limits::default();
    let next = image(2);
    let records = [record(1, 3)];
    let state = prepare(limits, None, None, &next, &records, &[None]).unwrap();
    let raw = state.encode(ctx);
    assert_eq!(raw.len(), STATE_OVERHEAD + 40);
    let loaded = State::decode(ctx, limits, &raw).unwrap();
    assert_eq!(loaded.image.as_bytes(), next.as_bytes());
    assert_eq!(loaded.records, 1);
    assert_eq!(loaded.bytes, 80);
    for (offset, replacement) in [
        (136, vec![0; 8]),
        (152, vec![0; 8]),
        (160, u32::MAX.to_be_bytes().to_vec()),
    ] {
        let mut bad = raw[..raw.len() - 32].to_vec();
        bad[offset..offset + replacement.len()].copy_from_slice(&replacement);
        append_checksum(b"vhalla/private-idb/state/v1\0", &mut bad);
        assert!(State::decode(ctx, limits, &bad).is_err());
    }
    let mut foreign = ctx;
    foreign.scope.anchor = AnchorId::from_bytes([8; 32]).unwrap();
    assert!(State::decode(foreign, limits, &raw).is_err());
    assert!(State::decode(ctx, limits, &vec![0; STATE_OVERHEAD + MAX_IMAGE_BYTES + 1]).is_err());
}

#[test]
fn independent_marker_makes_either_missing_published_half_corrupt() {
    let ctx = context();
    let data = record(1, 7);
    let proof = marker(ctx, &data);
    assert_eq!(proof.len(), 214);
    assert!(pair(ctx, data.key(), None, None).unwrap().is_none());
    let loaded = pair(
        ctx,
        data.key(),
        Some(data.as_bytes().to_vec()),
        Some(proof.clone()),
    )
    .unwrap()
    .unwrap();
    assert_eq!(loaded.as_bytes(), data.as_bytes());
    assert!(pair(ctx, data.key(), None, Some(proof.clone())).is_err());
    assert!(pair(ctx, data.key(), Some(data.as_bytes().to_vec()), None).is_err());
    assert!(pair(
        ctx,
        RecordKey::Outbox(2),
        Some(data.as_bytes().to_vec()),
        Some(proof.clone())
    )
    .is_err());
    let mut altered = data.as_bytes().to_vec();
    altered[0] ^= 1;
    assert!(pair(ctx, data.key(), Some(altered), Some(proof)).is_err());
    let operation = StoredRecord::from_bytes(RecordKey::Received([9; 32]), &[3; 40]).unwrap();
    assert_eq!(marker(ctx, &operation).len(), 238);
    // The longest RecordKey encoding, Acceptance{outbox, recipient}, produces
    // the largest marker; read-back bounds must cover it.
    let acceptance = StoredRecord::from_bytes(
        RecordKey::Acceptance {
            outbox: 1,
            recipient: ctx.account,
        },
        &[3; 40],
    )
    .unwrap();
    assert_eq!(marker(ctx, &acceptance).len(), MAX_MARKER_BYTES);
    let (data_key, proof_key) = record_keys(ctx, data.key()).unwrap();
    assert_ne!(data_key, proof_key);
    assert!(data_key.starts_with(&prefix(ctx)));
}

#[test]
fn whole_image_cas_all_collisions_and_capacity_preflight_do_not_mutate_prior_state() {
    let limits = Limits {
        max_records: 2,
        max_record_bytes: 160,
    };
    let original = image(1);
    let next = image(2);
    let first = record(1, 3);
    let state = prepare(
        limits,
        None,
        None,
        &original,
        std::slice::from_ref(&first),
        &[None],
    )
    .unwrap();
    assert!(matches!(
        prepare(limits, Some(&state), None, &next, &[], &[]),
        Err(Error::Stale)
    ));
    let altered = record(1, 4);
    let second = record(2, 5);
    assert!(matches!(
        prepare(
            limits,
            Some(&state),
            Some(&original),
            &next,
            &[second.clone(), altered],
            &[None, Some(first.clone())]
        ),
        Err(Error::Stale)
    ));
    assert_eq!(state.records, 1);
    assert_eq!(state.bytes, 80);
    assert_eq!(state.image.as_bytes(), original.as_bytes());
    let after = prepare(
        limits,
        Some(&state),
        Some(&original),
        &next,
        std::slice::from_ref(&second),
        &[None],
    )
    .unwrap();
    assert_eq!(after.records, 2);
    assert!(matches!(
        prepare(
            limits,
            Some(&after),
            Some(&next),
            &original,
            &[record(3, 7)],
            &[None]
        ),
        Err(Error::Bounds)
    ));
    assert!(matches!(
        prepare(
            limits,
            Some(&state),
            Some(&original),
            &next,
            &[second.clone(), second],
            &[None, None]
        ),
        Err(Error::Bounds)
    ));
}

#[test]
fn prefix_range_covers_unknown_metadata_including_high_unicode_suffixes() {
    let start = prefix(context());
    let end = format!("{}0", &start[..start.len() - 1]);
    for suffix in [
        "format",
        "state",
        "record/0101",
        "published/04",
        "unknown",
        "\u{ffff}",
        "\u{10ffff}",
    ] {
        let key = format!("{start}{suffix}");
        assert!(key >= start && key < end);
    }
}

#[test]
fn control_outbox_and_operation_are_one_bounded_transaction_with_all_position_duplicates_checked() {
    use vhalla_private_kernel::OperationId;
    let ctx = context();
    let limits = Limits {
        max_records: 3,
        max_record_bytes: 240,
    };
    let control = StoredRecord::from_bytes(RecordKey::Control(1), &[1; 80]).unwrap();
    let outbox = record(1, 2);
    let operation = StoredRecord::from_bytes(
        RecordKey::Operation(OperationId::from_bytes([3; 16]).unwrap()),
        &[3; 80],
    )
    .unwrap();
    assert!(RecordKey::Control(0).validate().is_err());
    assert_eq!(
        RecordKey::Control(1).encode(),
        [5u8, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    assert_eq!(marker(ctx, &control).len(), 214);
    let records = [control.clone(), outbox.clone(), operation.clone()];
    let state = prepare(limits, None, None, &image(4), &records, &[None, None, None]).unwrap();
    assert_eq!(state.records, 3);
    assert_eq!(state.bytes, 240);
    assert!(pair(
        ctx,
        control.key(),
        Some(control.as_bytes().to_vec()),
        Some(marker(ctx, &control))
    )
    .unwrap()
    .is_some());
    for bad in [
        [control.clone(), outbox.clone(), control.clone()],
        [control.clone(), outbox.clone(), outbox.clone()],
    ] {
        assert!(matches!(
            prepare(limits, None, None, &image(4), &bad, &[None, None, None]),
            Err(Error::Bounds)
        ));
    }
    let before = state.encode(ctx);
    let proposed = [
        StoredRecord::from_bytes(RecordKey::Control(2), &[1; 80]).unwrap(),
        record(2, 2),
        operation.clone(),
    ];
    assert!(matches!(
        prepare(
            limits,
            Some(&state),
            Some(&image(4)),
            &image(5),
            &proposed,
            &[None, None, Some(operation.clone())]
        ),
        Err(Error::Stale)
    ));
    assert_eq!(state.encode(ctx), before);
    assert!(matches!(
        prepare(
            limits,
            None,
            None,
            &image(4),
            &records,
            &[
                None,
                None,
                Some(StoredRecord::from_bytes(operation.key(), &[9; 80]).unwrap())
            ]
        ),
        Err(Error::Stale)
    ));
    assert!(matches!(
        prepare(
            limits,
            Some(&state),
            Some(&image(4)),
            &image(5),
            &[record(2, 9)],
            &[None]
        ),
        Err(Error::Bounds)
    ));
    assert!(matches!(
        validate_records(&[control, outbox, operation, record(2, 8)]),
        Err(Error::Bounds)
    ));
}
