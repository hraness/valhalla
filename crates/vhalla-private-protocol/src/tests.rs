use super::*;
use alloc::vec;

// Public deterministic fixture keys only; production has no seed constructor.
fn signer(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn signature(raw: &[u8]) -> [u8; 64] {
    raw[raw.len() - 64..].try_into().unwrap()
}
fn key(n: u8) -> Key {
    Key::from_bytes(signer(n).verifying_key().to_bytes()).unwrap()
}
fn anchor() -> SignedRoomAnchor {
    UnsignedRoomAnchor::new(RoomAnchorClaims {
        room: RoomId::from_bytes([1; 32]).unwrap(),
        owner_account: key(2),
        owner_device: key(3),
    })
    .unwrap()
    .sign(&signer(2))
    .unwrap()
}
fn enrollment() -> SignedDeviceEnrollment {
    UnsignedDeviceEnrollment::new(DeviceEnrollmentClaims {
        account: key(4),
        device: key(5),
        validity: Validity::new(10, 20).unwrap(),
    })
    .unwrap()
    .sign(&signer(4))
    .unwrap()
}
fn invitation() -> SignedInvitation {
    UnsignedInvitation::new(InvitationClaims {
        scope: anchor().verify().unwrap().scope(),
        owner_device: key(3),
        recipient_account: key(4),
        recipient_device: key(5),
        key_package: KeyPackageDigest::of_bytes(b"synthetic exact KeyPackage").unwrap(),
        nonce: Nonce::from_bytes([8; 32]).unwrap(),
        validity: Validity::new(10, 20).unwrap(),
        floor: ControlFloor::new(0, None).unwrap(),
    })
    .unwrap()
    .sign(&signer(3))
    .unwrap()
}
fn addition() -> Addition {
    let invite = invitation();
    Addition {
        invitation: invite.id(),
        account: invite.claims().recipient_account,
        device: invite.claims().recipient_device,
        key_package: invite.claims().key_package,
        welcome: WelcomeDigest::of_bytes(b"synthetic exact MLS-wrapped Welcome").unwrap(),
    }
}
fn control() -> SignedOwnerControl {
    UnsignedOwnerControl::new(OwnerControlClaims {
        scope: anchor().verify().unwrap().scope(),
        owner_device: key(3),
        parent: ControlFloor::new(0, None).unwrap(),
        prior_epoch: 0,
        next_epoch: 1,
        commit: CommitDigest::of_bytes(b"synthetic exact MLS-wrapped Commit").unwrap(),
        change: ControlChange::Membership {
            additions: vec![addition()],
            removals: vec![],
        },
    })
    .unwrap()
    .sign(&signer(3))
    .unwrap()
}

#[test]
fn exact_roundtrip_and_typed_signer_for_all_records() {
    macro_rules! roundtrip {
        ($value:expr, $signed:ident, $unsigned:ident) => {{
            let value = $value;
            let bytes = value.encode();
            let decoded = $signed::decode(&bytes).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(decoded.verify().unwrap().signed().encode(), bytes);
            assert_eq!(decoded.id(), value.id());
            assert_eq!(
                $unsigned::new(value.claims().clone())
                    .unwrap()
                    .sign(&signer(99)),
                Err(Error::Signer)
            );
        }};
    }
    roundtrip!(anchor(), SignedRoomAnchor, UnsignedRoomAnchor);
    roundtrip!(
        enrollment(),
        SignedDeviceEnrollment,
        UnsignedDeviceEnrollment
    );
    roundtrip!(invitation(), SignedInvitation, UnsignedInvitation);
    roundtrip!(control(), SignedOwnerControl, UnsignedOwnerControl);
}

#[test]
fn all_truncations_trailing_wrong_type_and_signature_mutations_refuse() {
    macro_rules! reject {
        ($value:expr, $signed:ident) => {{
            let value = $value;
            let bytes = value.encode();
            for len in 0..bytes.len() {
                assert!($signed::decode(&bytes[..len]).is_err(), "truncation {len}");
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!($signed::decode(&trailing).is_err());
            for index in 0..bytes.len() {
                let mut changed = bytes.clone();
                changed[index] ^= 1;
                assert!(
                    $signed::decode(&changed).and_then(|v| v.verify()).is_err(),
                    "byte mutation {index}"
                );
            }
            let mut version = bytes.clone();
            version[4] = 2;
            assert_eq!($signed::decode(&version), Err(Error::Protocol));
            assert_eq!(
                $signed::decode(&vec![0; MAX_RECORD_BYTES + 1]),
                Err(Error::Bounds)
            );
        }};
    }
    reject!(anchor(), SignedRoomAnchor);
    reject!(enrollment(), SignedDeviceEnrollment);
    reject!(invitation(), SignedInvitation);
    reject!(control(), SignedOwnerControl);
    assert!(SignedInvitation::decode(&enrollment().encode()).is_err());
    assert!(SignedRoomAnchor::decode(&control().encode()).is_err());
}

#[test]
fn all_invitation_context_fields_and_control_artifacts_are_signed() {
    let original = invitation();
    let mut variants = Vec::new();
    let mut c = original.claims().clone();
    c.scope.room = RoomId::from_bytes([42; 32]).unwrap();
    variants.push(c);
    let mut c = original.claims().clone();
    c.scope.anchor = AnchorId::from_bytes([42; 32]).unwrap();
    variants.push(c);
    let mut c = original.claims().clone();
    c.owner_device = key(42);
    variants.push(c);
    let mut c = original.claims().clone();
    c.recipient_account = key(42);
    variants.push(c);
    let mut c = original.claims().clone();
    c.recipient_device = key(42);
    variants.push(c);
    let mut c = original.claims().clone();
    c.key_package = KeyPackageDigest::of_bytes(b"other package").unwrap();
    variants.push(c);
    let mut c = original.claims().clone();
    c.nonce = Nonce::from_bytes([42; 32]).unwrap();
    variants.push(c);
    let mut c = original.claims().clone();
    c.validity = Validity::new(11, 20).unwrap();
    variants.push(c);
    let mut c = original.claims().clone();
    c.floor = ControlFloor::new(1, Some(ControlId::from_bytes([42; 32]).unwrap())).unwrap();
    variants.push(c);
    for claims in variants {
        assert_eq!(
            UnsignedInvitation::new(claims)
                .unwrap()
                .attach(signature(&original.encode())),
            Err(Error::Signature)
        );
    }
    let original = control();
    let mut c = original.claims().clone();
    c.commit = CommitDigest::of_bytes(b"different commit").unwrap();
    assert_eq!(
        UnsignedOwnerControl::new(c)
            .unwrap()
            .attach(signature(&original.encode())),
        Err(Error::Signature)
    );
    let mut c = original.claims().clone();
    if let ControlChange::Membership { additions, .. } = &mut c.change {
        additions[0].welcome = WelcomeDigest::of_bytes(b"different welcome").unwrap();
    }
    assert_eq!(
        UnsignedOwnerControl::new(c)
            .unwrap()
            .attach(signature(&original.encode())),
        Err(Error::Signature)
    );
}

#[test]
fn weak_keys_zero_identifiers_and_unsupported_policy_refuse() {
    assert_eq!(Key::from_bytes([0; 32]), Err(Error::Key));
    let mut identity = [0; 32];
    identity[0] = 1;
    assert_eq!(Key::from_bytes(identity), Err(Error::Key));
    assert_eq!(RoomId::from_bytes([0; 32]), Err(Error::Identifier));
    assert_eq!(AnchorId::from_bytes([0; 32]), Err(Error::Identifier));
    assert_eq!(Nonce::from_bytes([0; 32]), Err(Error::Identifier));
    assert_eq!(CommitDigest::from_bytes([0; 32]), Err(Error::Identifier));
    let bytes = anchor().encode();
    for offset in [102, 103, 104] {
        let mut changed = bytes.clone();
        changed[offset] = 99;
        assert_eq!(SignedRoomAnchor::decode(&changed), Err(Error::Protocol));
    }
    let mut weak = bytes;
    weak[38..70].fill(0);
    assert_eq!(SignedRoomAnchor::decode(&weak), Err(Error::Key));
}

#[test]
fn attribution_does_not_claim_current_owner_or_clock_or_membership() {
    let enrollment = enrollment().verify().unwrap();
    assert_eq!(enrollment.claims().validity.check_at(9), Err(Error::Time));
    assert_eq!(enrollment.claims().validity.check_at(10), Ok(()));
    assert_eq!(enrollment.claims().validity.check_at(19), Ok(()));
    assert_eq!(enrollment.claims().validity.check_at(20), Err(Error::Time));
    assert_eq!(Validity::new(20, 20), Err(Error::Time));
    assert_eq!(Validity::new(u64::MAX, 0), Err(Error::Time));
    // This other device can attribute its own bytes, but cannot thereby become
    // the room owner. The future stateful adapter must reject this mismatch.
    let pinned = anchor().verify().unwrap();
    let mut claims = invitation().claims().clone();
    claims.owner_device = key(55);
    let verified = UnsignedInvitation::new(claims)
        .unwrap()
        .sign(&signer(55))
        .unwrap()
        .verify()
        .unwrap();
    assert_ne!(verified.claims().owner_device, pinned.claims().owner_device);
    assert_eq!(verified.claims().validity.check_at(20), Err(Error::Time));
    assert_eq!(verified.claims().scope, pinned.scope());
}

#[test]
fn control_order_exhaustion_and_explicit_update_shape_are_checked() {
    let id = ControlId::from_bytes([9; 32]).unwrap();
    assert_eq!(ControlFloor::new(0, Some(id)), Err(Error::Sequence));
    assert_eq!(ControlFloor::new(1, None), Err(Error::Sequence));
    assert_eq!(
        ControlFloor::new(u64::MAX, Some(id))
            .unwrap()
            .next_sequence(),
        Err(Error::Sequence)
    );
    let mut c = control().claims().clone();
    c.parent = ControlFloor::new(u64::MAX, Some(id)).unwrap();
    assert_eq!(UnsignedOwnerControl::new(c), Err(Error::Sequence));
    let mut c = control().claims().clone();
    c.prior_epoch = u64::MAX;
    c.next_epoch = 0;
    assert_eq!(UnsignedOwnerControl::new(c), Err(Error::Sequence));
    let mut c = control().claims().clone();
    c.next_epoch = 2;
    assert_eq!(UnsignedOwnerControl::new(c), Err(Error::Sequence));
    let mut c = control().claims().clone();
    c.change = ControlChange::Membership {
        additions: vec![],
        removals: vec![],
    };
    assert_eq!(UnsignedOwnerControl::new(c.clone()), Err(Error::Membership));
    c.change = ControlChange::OwnerUpdate;
    let signed = UnsignedOwnerControl::new(c)
        .unwrap()
        .sign(&signer(3))
        .unwrap();
    assert_eq!(signed.claims().sequence(), Ok(1));
    assert_eq!(
        SignedOwnerControl::decode(&signed.encode())
            .unwrap()
            .verify()
            .unwrap()
            .signed(),
        &signed
    );
}

#[test]
fn membership_counts_order_duplicates_and_overlap_fail_before_acceptance() {
    let baseline = control();
    let changes = [
        ControlChange::Membership {
            additions: vec![addition(), addition()],
            removals: vec![],
        },
        ControlChange::Membership {
            additions: vec![addition()],
            removals: vec![addition().device],
        },
        ControlChange::Membership {
            additions: vec![],
            removals: vec![key(8), key(8)],
        },
        ControlChange::Membership {
            additions: vec![addition(); MAX_CHANGES + 1],
            removals: vec![],
        },
    ];
    for change in changes {
        let mut claims = baseline.claims().clone();
        claims.change = change;
        assert!(UnsignedOwnerControl::new(claims).is_err());
    }
    let mut keys = vec![key(8), key(9)];
    keys.sort();
    keys.reverse();
    let mut c = baseline.claims().clone();
    c.change = ControlChange::Membership {
        additions: vec![],
        removals: keys,
    };
    assert_eq!(UnsignedOwnerControl::new(c), Err(Error::Membership));
    // Count bytes come after prefix/scope/signer/parent/epochs/commit/change-kind.
    const COUNT: usize = 6 + 64 + 32 + 40 + 16 + 32 + 1;
    let mut raw = baseline.encode();
    assert_eq!(raw[COUNT], 1);
    raw[COUNT] = u8::MAX;
    assert_eq!(SignedOwnerControl::decode(&raw), Err(Error::Bounds));
    let mut raw = baseline.encode();
    raw[COUNT - 1] = 1;
    assert_eq!(SignedOwnerControl::decode(&raw), Err(Error::Membership));
}

#[test]
fn largest_delta_fits_record_bound_and_artifact_domains_are_distinct() {
    let mut keys: Vec<_> = (20..20 + MAX_CHANGES as u8).map(key).collect();
    keys.sort();
    let mut claims = control().claims().clone();
    claims.change = ControlChange::Membership {
        additions: vec![],
        removals: keys,
    };
    let signed = UnsignedOwnerControl::new(claims)
        .unwrap()
        .sign(&signer(3))
        .unwrap();
    assert!(signed.encode().len() <= MAX_RECORD_BYTES);
    assert!(SignedOwnerControl::decode(&signed.encode())
        .unwrap()
        .verify()
        .is_ok());
    let raw = b"same bytes, different exact artifact type";
    let kp = KeyPackageDigest::of_bytes(raw).unwrap();
    let commit = CommitDigest::of_bytes(raw).unwrap();
    let welcome = WelcomeDigest::of_bytes(raw).unwrap();
    assert_ne!(kp.as_bytes(), commit.as_bytes());
    assert_ne!(commit.as_bytes(), welcome.as_bytes());
    assert_eq!(kp.matches(raw), Ok(true));
    assert_eq!(kp.matches(b"different"), Ok(false));
    assert_eq!(CommitDigest::of_bytes(b""), Err(Error::Bounds));
    assert!(WelcomeDigest::of_bytes(&vec![0; MAX_ARTIFACT_BYTES]).is_ok());
    assert_eq!(
        WelcomeDigest::of_bytes(&vec![0; MAX_ARTIFACT_BYTES + 1]),
        Err(Error::Bounds)
    );
}
