//! Native tests for raw messages crossing the existing private worker boundary.
#[path = "../src/private/wire.rs"]
pub mod private_wire;
use ed25519_dalek::SigningKey;
use private_wire::*;
use vhalla_private_kernel::{
    protocol::{
        AnchorId, CommitDigest, ControlChange, ControlFloor, ControlId, Key, OwnerControlClaims,
        PrivateRoomScope, RoomId, UnsignedOwnerControl, Validity,
    },
    recovery::MAX_ARCHIVE_PAGE_BYTES,
    Context, OperationId, OutboxKind, Phase, Status, MAX_BODY_BYTES,
};
use zeroize::Zeroizing;

fn key() -> Key {
    // Public Ed25519 base point. No fixture private key or signing API is needed.
    let mut encoded = [0x66; 32];
    encoded[0] = 0x58;
    Key::from_bytes(encoded).unwrap()
}
fn context() -> Context {
    Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes([1; 32]).unwrap(),
            anchor: AnchorId::from_bytes([2; 32]).unwrap(),
        },
        account: key(),
        device: key(),
    }
}
fn op() -> OperationId {
    OperationId::from_bytes([3; 16]).unwrap()
}
fn validity() -> Validity {
    Validity::new(1, 2).unwrap()
}
fn bytes(n: usize) -> Bytes {
    Zeroizing::new(vec![7; n])
}
fn consent(body: usize) -> Consent {
    Consent {
        id: u64::MAX,
        context: context(),
        epoch: u64::MAX,
        roster: [4; 32],
        body: bytes(body),
    }
}

#[test]
fn every_command_rejects_all_truncations_trailing_and_unknown_tags() {
    let requests = vec![
        Request::Enter {
            vault: bytes(125),
            local_birth: false,
        },
        Request::PrepareOwner(validity()),
        Request::PrepareContact {
            offer: bytes(MAX_OFFER),
            owner: key(),
            validity: validity(),
        },
        Request::CommitCreation(context()),
        Request::Open(context()),
        Request::Membership,
        Request::PrepareMessage(bytes(MAX_BODY_BYTES)),
        Request::Send {
            operation: op(),
            consent: Box::new(consent(MAX_BODY_BYTES)),
        },
        Request::Offer {
            operation: op(),
            recipient: key(),
            validity: validity(),
        },
        Request::ContactRequest {
            operation: op(),
            offer: bytes(MAX_OFFER),
        },
        Request::Accept {
            operation: op(),
            request: bytes(23),
            validity: validity(),
        },
        Request::Join(bytes(23)),
        Request::Receive(bytes(23)),
        Request::Remove {
            operation: op(),
            device: key(),
        },
        Request::Renew {
            operation: op(),
            validity: validity(),
        },
        Request::ApplyControl(bytes(23)),
        Request::Controls {
            after: ControlFloor::new(0, None).unwrap(),
            limit: 16,
        },
        Request::ControlProofs {
            after: ControlFloor::new(0, None).unwrap(),
            limit: 16,
        },
        Request::ObserveControl(bytes(MAX_ARTIFACT)),
        Request::ForkEvidence,
        Request::Outbox {
            after: u64::MAX,
            limit: 1,
        },
        Request::Inbox {
            after: u64::MAX,
            limit: 16,
        },
        Request::ArchiveExport,
        Request::ArchiveExportNext,
        Request::ArchiveImportBegin {
            context: context(),
            archive_id: [9; 32],
        },
        Request::ArchiveImportFeed(bytes(MAX_ARCHIVE_PAGE_BYTES)),
        Request::ArchiveImportFinish(bytes(64)),
        Request::ArchiveOpen {
            context: context(),
            archive_id: [9; 32],
            final_page: bytes(64),
        },
        Request::ArchiveInspect,
        Request::ArchiveInbox {
            after: u64::MAX,
            limit: 16,
        },
        Request::ArchiveOutbox { after: 0, limit: 1 },
        Request::ArchiveClose,
    ];
    for request in requests {
        let raw = request.encode().unwrap();
        assert_eq!(Request::decode(&raw).unwrap().encode().unwrap(), raw);
        for length in 0..raw.len() {
            assert!(Request::decode(&raw[..length]).is_err());
        }
        let mut changed = raw.to_vec();
        changed.push(0);
        assert!(Request::decode(&changed).is_err());
        let tag = b"VHBRPRIVATE\x01".len();
        changed.truncate(raw.len());
        changed[tag] = 250;
        assert!(Request::decode(&changed).is_err());
        assert!(Response::decode(&raw).is_err());
    }
}

#[test]
fn untrusted_lengths_counts_boolean_and_floor_refuse_before_allocation() {
    let prefix = b"VHBRPRIVATE\x01".len();
    let mut raw = Request::PrepareMessage(bytes(1)).encode().unwrap();
    raw[prefix + 1..prefix + 5].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(Request::decode(&raw).is_err());
    assert!(Request::PrepareMessage(bytes(MAX_BODY_BYTES + 1))
        .encode()
        .is_err());
    assert!(Request::ContactRequest {
        operation: op(),
        offer: bytes(MAX_OFFER + 1)
    }
    .encode()
    .is_err());
    assert!(Request::Join(bytes(MAX_ARTIFACT + 1)).encode().is_err());
    assert!(
        Request::ArchiveImportFeed(bytes(MAX_ARCHIVE_PAGE_BYTES + 1))
            .encode()
            .is_err()
    );
    assert!(
        Request::ArchiveImportFinish(bytes(MAX_ARCHIVE_PAGE_BYTES + 1))
            .encode()
            .is_err()
    );
    for limit in [0, 17, usize::MAX] {
        assert!(Request::Outbox { after: 0, limit }.encode().is_err());
        assert!(Request::ArchiveInbox { after: 0, limit }.encode().is_err());
    }
    let mut raw = Request::Outbox { after: 0, limit: 1 }.encode().unwrap();
    *raw.last_mut().unwrap() = 255;
    assert!(Request::decode(&raw).is_err());
    let mut raw = Request::Enter {
        vault: bytes(125),
        local_birth: false,
    }
    .encode()
    .unwrap();
    *raw.last_mut().unwrap() = 2;
    assert!(Request::decode(&raw).is_err());
    let mut raw = Request::Controls {
        after: ControlFloor::new(0, None).unwrap(),
        limit: 1,
    }
    .encode()
    .unwrap();
    raw[prefix + 1 + 8] = 1;
    assert!(Request::decode(&raw).is_err());
    assert!(Request::decode(&vec![0; MAX_FRAME + 1]).is_err());
}

#[test]
fn disclosure_consent_binds_every_field_and_never_discards_text() {
    let original = consent(20);
    let same = consent(20);
    assert!(original.same(&same));
    let mut changed = consent(20);
    changed.id -= 1;
    assert!(!original.same(&changed));
    let mut changed = consent(20);
    changed.epoch -= 1;
    assert!(!original.same(&changed));
    let mut changed = consent(20);
    changed.roster[0] ^= 1;
    assert!(!original.same(&changed));
    let mut changed = consent(20);
    changed.context.scope.room = RoomId::from_bytes([9; 32]).unwrap();
    assert!(!original.same(&changed));
    let mut changed = consent(20);
    changed.context.scope.anchor = AnchorId::from_bytes([9; 32]).unwrap();
    assert!(!original.same(&changed));
    let mut changed = consent(20);
    changed.body[0] ^= 1;
    assert!(!original.same(&changed));
    assert_eq!(original.body.as_slice(), &[7; 20]);
}

#[test]
fn response_secret_metadata_cannot_be_substituted_with_artifact_bytes() {
    let secret = Response::Outbox {
        context: context(),
        head: 1,
        next: None,
        records: vec![Artifact {
            sequence: 1,
            operation: op(),
            kind: OutboxKind::ContactOffer,
            bytes: None,
        }],
    };
    let raw = secret.encode().unwrap();
    let restored = Response::decode(&raw).unwrap();
    assert_eq!(restored.encode().unwrap(), raw);
    assert!(matches!(restored, Response::Outbox { records, .. } if records[0].bytes.is_none()));
    let fake = Response::Artifact {
        context: context(),
        artifact: Artifact {
            sequence: 1,
            operation: op(),
            kind: OutboxKind::ContactOffer,
            bytes: Some(bytes(1)),
        },
    };
    assert!(fake.encode().is_err());
    let absent = Response::Artifact {
        context: context(),
        artifact: Artifact {
            sequence: 1,
            operation: op(),
            kind: OutboxKind::Application,
            bytes: None,
        },
    };
    assert!(absent.encode().is_err());
    for length in 0..raw.len() {
        assert!(Response::decode(&raw[..length]).is_err());
    }
    let mut trailing = raw.to_vec();
    trailing.push(0);
    assert!(Response::decode(&trailing).is_err());
    assert!(Request::decode(&raw).is_err());
}

#[test]
fn response_collection_count_and_blob_budgets_are_checked_on_raw_input() {
    let mut raw = Response::Inbox {
        context: context(),
        head: 0,
        next: None,
        records: vec![],
    }
    .encode()
    .unwrap();
    *raw.last_mut().unwrap() = 255;
    assert!(Response::decode(&raw).is_err());
    let mut raw = Response::Received {
        context: context(),
        message: Inbound {
            sequence: 1,
            sender: key(),
            body: bytes(1),
        },
    }
    .encode()
    .unwrap();
    let at = b"VHBRPRIVATE\x01".len() + 1 + 128 + 8 + 32;
    raw[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(Response::decode(&raw).is_err());
    assert!(Response::decode(&vec![0; MAX_FRAME + 1]).is_err());
}

fn floor(sequence: u64) -> ControlFloor {
    let id = (sequence != 0).then(|| ControlId::from_bytes([sequence as u8; 32]).unwrap());
    ControlFloor::new(sequence, id).unwrap()
}
fn status() -> Status {
    Status {
        context: context(),
        phase: Phase::MemberJoined,
        epoch: 7,
        control_sequence: 3,
        control_floor: floor(3),
        outbox_head: 4,
        inbox_head: 2,
        history_base: floor(1),
        roster: [5; 32],
        members: 1,
        quarantined: false,
    }
}

#[test]
fn archive_reports_round_trip_and_enforce_page_and_status_bounds() {
    let responses = vec![
        Response::ArchiveBegin {
            context: context(),
            archive_id: [9; 32],
        },
        Response::ArchivePage {
            context: context(),
            page: Some(bytes(MAX_ARCHIVE_PAGE_BYTES)),
        },
        Response::ArchivePage {
            context: context(),
            page: None,
        },
        Response::ArchiveProgress {
            context: context(),
            source_ready: true,
            next_page: u64::MAX,
            records: 100_000,
            bytes: u64::MAX,
        },
        Response::ArchiveInspect {
            context: context(),
            archive_id: [9; 32],
            source_revision: u64::MAX,
            status: status(),
        },
        Response::ArchiveClosed { context: context() },
    ];
    for response in responses {
        let raw = response.encode().unwrap();
        assert_eq!(Response::decode(&raw).unwrap().encode().unwrap(), raw);
        for length in 0..raw.len() {
            assert!(Response::decode(&raw[..length]).is_err());
        }
        let mut changed = raw.to_vec();
        changed.push(0);
        assert!(Response::decode(&changed).is_err());
        let tag = b"VHBRPRIVATE\x01".len();
        changed.truncate(raw.len());
        changed[tag] = 20;
        assert!(Response::decode(&changed).is_err());
        assert!(Request::decode(&raw).is_err());
    }
    // An oversized page or malformed status can never cross the local wire.
    assert!(Response::ArchivePage {
        context: context(),
        page: Some(bytes(MAX_ARCHIVE_PAGE_BYTES + 1)),
    }
    .encode()
    .is_err());
    let mut bad = status();
    bad.members = 0;
    assert!(Response::ArchiveInspect {
        context: context(),
        archive_id: [9; 32],
        source_revision: 1,
        status: bad,
    }
    .encode()
    .is_err());
    let mut bad = status();
    bad.history_base = floor(9);
    let raw = Response::ArchiveInspect {
        context: context(),
        archive_id: [9; 32],
        source_revision: 1,
        status: bad,
    }
    .encode()
    .unwrap();
    assert!(Response::decode(&raw).is_err());
    // A status claiming a context other than the bound one is refused on decode.
    let mut bad = status();
    bad.context.scope.anchor = AnchorId::from_bytes([7; 32]).unwrap();
    let raw = Response::ArchiveInspect {
        context: context(),
        archive_id: [9; 32],
        source_revision: 1,
        status: bad,
    }
    .encode()
    .unwrap();
    assert!(Response::decode(&raw).is_err());
}

fn owner() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn control(scope: PrivateRoomScope, parent: ControlFloor, commit: u8) -> Bytes {
    let claims = OwnerControlClaims {
        scope,
        owner_device: Key::from_bytes(owner().verifying_key().to_bytes()).unwrap(),
        parent,
        prior_epoch: parent.sequence(),
        next_epoch: parent.sequence() + 1,
        commit: CommitDigest::from_bytes([commit; 32]).unwrap(),
        change: ControlChange::OwnerUpdate,
    };
    Zeroizing::new(
        UnsignedOwnerControl::new(claims)
            .unwrap()
            .sign(&owner())
            .unwrap()
            .encode(),
    )
}
fn record_floor(control: &Bytes) -> ControlFloor {
    let verified = vhalla_private_kernel::protocol::SignedOwnerControl::decode(control)
        .unwrap()
        .verify()
        .unwrap();
    ControlFloor::new(verified.claims().sequence().unwrap(), Some(verified.id())).unwrap()
}

#[test]
fn signed_proofs_and_fork_evidence_verify_at_the_local_boundary() {
    let scope = context().scope;
    let first = control(scope, floor(0), 1);
    let second = control(scope, record_floor(&first), 2);
    let forked = control(scope, record_floor(&first), 9);
    let responses = vec![
        Response::ControlProofs {
            context: context(),
            base: floor(0),
            head: record_floor(&second),
            next: None,
            records: vec![
                Control {
                    floor: record_floor(&first),
                    bytes: first.clone(),
                },
                Control {
                    floor: record_floor(&second),
                    bytes: second.clone(),
                },
            ],
        },
        Response::Observed {
            context: context(),
            verdict: ObserveVerdict::Retained,
        },
        Response::Observed {
            context: context(),
            verdict: ObserveVerdict::UnknownHistory,
        },
        Response::ForkEvidence {
            context: context(),
            proof: None,
        },
        Response::ForkEvidence {
            context: context(),
            proof: Some(ForkProof {
                accepted: record_floor(&second),
                conflicting: forked.clone(),
                accepted_proof: second.clone(),
                accepted_from_checkpoint: false,
            }),
        },
        // A checkpoint-backed accepted floor carries the kernel-internal
        // checkpoint encoding, which the wire cannot decode; only the
        // conflicting side is signature-checked there.
        Response::ForkEvidence {
            context: context(),
            proof: Some(ForkProof {
                accepted: floor(1),
                conflicting: control(scope, floor(0), 4),
                accepted_proof: bytes(64),
                accepted_from_checkpoint: true,
            }),
        },
    ];
    for response in responses {
        let raw = response.encode().unwrap();
        assert_eq!(Response::decode(&raw).unwrap().encode().unwrap(), raw);
        for length in 0..raw.len() {
            assert!(Response::decode(&raw[..length]).is_err());
        }
        let mut changed = raw.to_vec();
        changed.push(0);
        assert!(Response::decode(&changed).is_err());
        let tag = b"VHBRPRIVATE\x01".len();
        changed.truncate(raw.len());
        changed[tag] = 20;
        assert!(Response::decode(&changed).is_err());
        assert!(Request::decode(&raw).is_err());
    }
    // An unknown verdict code or malformed signed record is refused on decode.
    let mut raw = Response::Observed {
        context: context(),
        verdict: ObserveVerdict::Retained,
    }
    .encode()
    .unwrap();
    *raw.last_mut().unwrap() = 4;
    assert!(Response::decode(&raw).is_err());
    // A proof whose signature, room scope, or committed floor disagrees with
    // the report cannot cross the local wire.
    let foreign = control(
        PrivateRoomScope {
            room: RoomId::from_bytes([9; 32]).unwrap(),
            ..scope
        },
        floor(0),
        1,
    );
    for (at, bytes) in [
        (record_floor(&first), bytes(64)),
        (record_floor(&first), foreign.clone()),
        (floor(2), first.clone()),
    ] {
        let raw = Response::ControlProofs {
            context: context(),
            base: floor(0),
            head: at,
            next: None,
            records: vec![Control { floor: at, bytes }],
        }
        .encode()
        .unwrap();
        assert!(Response::decode(&raw).is_err());
    }
    // Reported fork evidence must be a real contradiction: same-sequence
    // differing controls under this room's scope, with a matching retained
    // accepted-side record unless it is the joining checkpoint.
    for proof in [
        ForkProof {
            accepted: record_floor(&second),
            conflicting: second.clone(),
            accepted_proof: second.clone(),
            accepted_from_checkpoint: false,
        },
        ForkProof {
            accepted: record_floor(&first),
            conflicting: forked.clone(),
            accepted_proof: first.clone(),
            accepted_from_checkpoint: false,
        },
        ForkProof {
            accepted: record_floor(&second),
            conflicting: foreign.clone(),
            accepted_proof: second.clone(),
            accepted_from_checkpoint: false,
        },
        ForkProof {
            accepted: record_floor(&second),
            conflicting: forked.clone(),
            accepted_proof: first.clone(),
            accepted_from_checkpoint: false,
        },
        ForkProof {
            accepted: record_floor(&second),
            conflicting: forked.clone(),
            accepted_proof: bytes(64),
            accepted_from_checkpoint: false,
        },
    ] {
        let raw = Response::ForkEvidence {
            context: context(),
            proof: Some(proof),
        }
        .encode()
        .unwrap();
        assert!(Response::decode(&raw).is_err());
    }
}

// Local qualification can ask the owner worker to re-sign divergent claims at
// a retained floor; the fabricated control is still real signature-bearing
// evidence at this boundary, so the wire verifies it like any other proof.
#[cfg(feature = "local-qualification")]
#[test]
fn divergent_qualification_frames_round_trip_and_verify_the_signed_control() {
    let scope = context().scope;
    let raw = Request::Divergent { sequence: u64::MAX }.encode().unwrap();
    assert_eq!(Request::decode(&raw).unwrap().encode().unwrap(), raw);
    for length in 0..raw.len() {
        assert!(Request::decode(&raw[..length]).is_err());
    }
    let mut changed = raw.to_vec();
    changed.push(0);
    assert!(Request::decode(&changed).is_err());
    assert!(Response::decode(&raw).is_err());
    let raw = Response::Divergent {
        context: context(),
        control: control(scope, floor(0), 1),
    }
    .encode()
    .unwrap();
    assert_eq!(Response::decode(&raw).unwrap().encode().unwrap(), raw);
    for length in 0..raw.len() {
        assert!(Response::decode(&raw[..length]).is_err());
    }
    let mut changed = raw.to_vec();
    changed.push(0);
    assert!(Response::decode(&changed).is_err());
    assert!(Request::decode(&raw).is_err());
    // A foreign scope or unsigned payload is refused on decode; oversized
    // controls are refused on encode.
    let foreign = control(
        PrivateRoomScope {
            room: RoomId::from_bytes([9; 32]).unwrap(),
            ..scope
        },
        floor(0),
        1,
    );
    for control in [foreign, bytes(64)] {
        let raw = Response::Divergent {
            context: context(),
            control,
        }
        .encode()
        .unwrap();
        assert!(Response::decode(&raw).is_err());
    }
    assert!(Response::Divergent {
        context: context(),
        control: bytes(MAX_ARTIFACT + 1),
    }
    .encode()
    .is_err());
}

// The expired-envelope qualification request is a bounded blob plus a caller
// clock; it replies with the ordinary membership view.
#[cfg(feature = "local-qualification")]
#[test]
fn apply_control_at_frames_round_trip_and_answer_membership() {
    let raw = Request::ApplyControlAt {
        envelope: bytes(400),
        at: u64::MAX,
    }
    .encode()
    .unwrap();
    assert_eq!(Request::decode(&raw).unwrap().encode().unwrap(), raw);
    assert!(matches!(
        Request::decode(&raw).unwrap().reply_kind(),
        ReplyKind::Membership
    ));
    for length in 0..raw.len() {
        assert!(Request::decode(&raw[..length]).is_err());
    }
    let mut changed = raw.to_vec();
    changed.push(0);
    assert!(Request::decode(&changed).is_err());
    assert!(Response::decode(&raw).is_err());
    assert!(Request::ApplyControlAt {
        envelope: bytes(MAX_ARTIFACT + 1),
        at: 1,
    }
    .encode()
    .is_err());
}
