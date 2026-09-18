//! Settlement admission and ranking, pause and replace across an epoch bump,
//! a pre-reveal fill, and cancellation, at one receiver.

mod common;

use common::{live_manifest, passed_by_plain_run, policy, Signer, REALM, ROOM};
use vhalla_core::Epoch;
#[cfg(feature = "quorum")]
use vhalla_game_platonik::ids::SessionKey;
use vhalla_game_platonik::ids::{CheckpointHash, RulesetId};
use vhalla_game_platonik::manifest::MissingMember;
use vhalla_game_platonik::oracle::convert::convert;
use vhalla_game_platonik::platonik::PlatonikV1;
use vhalla_game_platonik::receiver::{Receiver, ReceiverError};
use vhalla_game_platonik::session::{
    bind_commit, derive_seed, fill_salt, seed_commitment, Session, State, Verdict,
};
use vhalla_game_platonik::settlement::SettleError;
use vhalla_game_platonik::wire::{
    Authority, EventBody, FillEvidence, ForkReason, Player, SessionOpen, Settlement,
};
use vhalla_witness::hash::ProgramHash;
use vhalla_witness::platform::ClaimedReceipt;
use vhalla_witness::world::EventKind;

/// Drives a live single-player session to its final seal and returns the
/// pieces a settlement needs.
struct Finished {
    session: Session,
    receiver: Receiver<PlatonikV1>,
    host: Signer,
    final_checkpoint: CheckpointHash,
    passed: bool,
    receipt: ClaimedReceipt,
}

fn finish_live(missing: MissingMember) -> Finished {
    let mut host = Signer::new(1);
    let mut player = Signer::new(2);
    let converted =
        convert(&platonik_core::fixtures::experiment("opening-normal").unwrap()).unwrap();
    let (manifest, template) = live_manifest(&converted, [11; 32], 64, missing, None);
    let slot = converted.programs[0].0;
    let program = converted.programs[0].1.clone();
    let host_salt = [7; 32];
    let open = SessionOpen {
        realm: REALM,
        room: ROOM,
        manifest: manifest.hash(),
        ruleset: RulesetId::V1,
        seed_commitment: seed_commitment(&host_salt, manifest.world),
        authority: Authority::Host { key: host.public() },
        players: vec![Player {
            key: player.public(),
            slots: vec![slot],
        }],
        epoch: Epoch(0),
        nonce: [5; 32],
    };
    let mut session = Session::open(manifest, open, REALM).unwrap();
    let mut receiver = Receiver::new(PlatonikV1, policy());
    let key = session.key();
    let salt = [3; 32];
    let commit = bind_commit(key, slot, &program, &salt);
    let mut order = Vec::new();
    for (record, digest) in [
        player.event(key, Epoch(0), EventBody::BindCommit { slot, commit }),
        host.event(
            key,
            Epoch(0),
            EventBody::BindClose {
                commits: vec![(slot, commit)],
            },
        ),
        player.event(
            key,
            Epoch(0),
            EventBody::BindReveal {
                slot,
                program: program.clone(),
                salt,
            },
        ),
    ] {
        receiver.admit(&mut session, &record, 1).unwrap();
        order.push(digest);
    }
    let mut task = template.clone();
    task.cases[0].seed = derive_seed(&host_salt, &[salt], 0);
    let (reveal, reveal_digest) = host.event(
        key,
        Epoch(0),
        EventBody::Reveal {
            task: task.clone(),
            host_salt,
        },
    );
    receiver.admit(&mut session, &reveal, 2).unwrap();
    order.push(reveal_digest);
    let (input, input_digest) = player.event(
        key,
        Epoch(0),
        EventBody::Input {
            case: 0,
            tick: 2,
            kind: EventKind::ClearMemory { cell: slot },
        },
    );
    receiver.admit(&mut session, &input, 3).unwrap();
    order.push(input_digest);
    let ticks = task.cases[0].ticks;
    let (seal, final_checkpoint) = host.seal(&session, 0, ticks, order);
    let verified = receiver.admit(&mut session, &seal, 4).unwrap().unwrap();
    assert!(verified.is_final());
    let mut full = task.clone();
    full.cases[0].events = vec![vhalla_witness::world::Event {
        tick: 2,
        event: EventKind::ClearMemory { cell: slot },
    }];
    let passed = passed_by_plain_run(&full, vec![(slot, program.clone())]);
    // The host reproduces the receipt exactly as a receiver does.
    let (task_final, candidate, through) = session.final_plan().cloned().unwrap();
    let valid = vhalla_witness::manifest::ValidManifest::validate(task_final).unwrap();
    let evidence = vhalla_game_platonik::engine::GameEngine::replay(
        &PlatonikV1,
        session.world(),
        &valid,
        candidate,
        vhalla_witness::platform::WorkAllowance {
            max_total: valid.fuel_total(),
        },
        through,
        vhalla_witness::platform::ReceiptBinding {
            challenge_id: key.0,
            subject_key: host.public(),
        },
    )
    .unwrap();
    let receipt = ClaimedReceipt::decode(&evidence.receipt.encode()).unwrap();
    Finished {
        session,
        receiver,
        host,
        final_checkpoint,
        passed,
        receipt,
    }
}

#[test]
fn a_reproduced_result_is_admitted_once_and_outranks_a_late_cancel() {
    let Finished {
        mut session,
        mut receiver,
        host,
        final_checkpoint,
        passed,
        receipt,
    } = finish_live(MissingMember::Pause);
    let key = session.key();
    let result = Settlement::Result {
        session: key,
        epoch: Epoch(0),
        checkpoint: final_checkpoint,
        receipt,
        passed,
    };
    // Wrong claims first, each refused without a verdict.
    let mut wrong = receipt;
    wrong.total += 1;
    for (label, bad, expected) in [
        (
            "checkpoint",
            Settlement::Result {
                session: key,
                epoch: Epoch(0),
                checkpoint: CheckpointHash([1; 32]),
                receipt,
                passed,
            },
            SettleError::WrongCheckpoint,
        ),
        (
            "passed",
            Settlement::Result {
                session: key,
                epoch: Epoch(0),
                checkpoint: final_checkpoint,
                receipt,
                passed: !passed,
            },
            SettleError::PassedMismatch,
        ),
        (
            "receipt",
            Settlement::Result {
                session: key,
                epoch: Epoch(0),
                checkpoint: final_checkpoint,
                receipt: wrong,
                passed,
            },
            SettleError::ReceiptMismatch,
        ),
        (
            "epoch",
            Settlement::Result {
                session: key,
                epoch: Epoch(1),
                checkpoint: final_checkpoint,
                receipt,
                passed,
            },
            SettleError::WrongEpoch,
        ),
    ] {
        assert_eq!(
            receiver
                .settle(&mut session, &host.settlement(key, &bad), 5)
                .err(),
            Some(ReceiverError::Settle(expected)),
            "{label}"
        );
        assert!(session.settled().is_none(), "{label}: no verdict");
    }
    let stranger = Signer::new(9);
    assert_eq!(
        receiver
            .settle(&mut session, &stranger.settlement(key, &result), 5)
            .err(),
        Some(ReceiverError::Settle(SettleError::NotHost))
    );
    let verified = receiver
        .settle(&mut session, &host.settlement(key, &result), 6)
        .unwrap();
    assert_eq!(verified.passed(), passed);
    assert!(matches!(session.settled(), Some(Verdict::Result { .. })));
    // A cancel after the final checkpoint is inadmissible, and a bare
    // unresolved never displaces a reproduced result.
    let cancel = Settlement::Unresolved {
        session: key,
        epoch: Epoch(0),
        reason: ForkReason::Cancelled,
        heads: vec![],
        evidence: vec![],
    };
    assert_eq!(
        receiver
            .settle(&mut session, &host.settlement(key, &cancel), 7)
            .err(),
        Some(ReceiverError::Settle(SettleError::CancelAfterFinal))
    );
    let silent = Settlement::Unresolved {
        session: key,
        epoch: Epoch(0),
        reason: ForkReason::HostSilent,
        heads: vec![],
        evidence: vec![],
    };
    assert_eq!(
        receiver
            .settle(&mut session, &host.settlement(key, &silent), 8)
            .err(),
        Some(ReceiverError::Settle(SettleError::Outranked))
    );
    // The same result again is idempotent; a contradicting result is host
    // equivocation over the settlement.
    receiver
        .settle(&mut session, &host.settlement(key, &result), 9)
        .unwrap();
    let contradicting = Settlement::Result {
        session: key,
        epoch: Epoch(0),
        checkpoint: final_checkpoint,
        receipt,
        passed: !passed,
    };
    assert_eq!(
        receiver
            .settle(&mut session, &host.settlement(key, &contradicting), 10)
            .err(),
        Some(ReceiverError::Settle(SettleError::PassedMismatch)),
        "a contradicting result must still reproduce, so it fails its own check first"
    );
    assert_eq!(session.state(), State::Finished);
}

#[test]
fn a_cancel_before_the_final_seal_ends_the_session_in_either_order() {
    let mut host = Signer::new(1);
    let mut player = Signer::new(2);
    let converted =
        convert(&platonik_core::fixtures::experiment("opening-normal").unwrap()).unwrap();
    let (manifest, template) = live_manifest(&converted, [11; 32], 64, MissingMember::Pause, None);
    let slot = converted.programs[0].0;
    let program = converted.programs[0].1.clone();
    let host_salt = [7; 32];
    let open = SessionOpen {
        realm: REALM,
        room: ROOM,
        manifest: manifest.hash(),
        ruleset: RulesetId::V1,
        seed_commitment: seed_commitment(&host_salt, manifest.world),
        authority: Authority::Host { key: host.public() },
        players: vec![Player {
            key: player.public(),
            slots: vec![slot],
        }],
        epoch: Epoch(0),
        nonce: [5; 32],
    };
    let mut session = Session::open(manifest, open, REALM).unwrap();
    let mut receiver = Receiver::new(PlatonikV1, policy());
    let key = session.key();
    let salt = [3; 32];
    let commit = bind_commit(key, slot, &program, &salt);
    for (record, _) in [
        player.event(key, Epoch(0), EventBody::BindCommit { slot, commit }),
        host.event(
            key,
            Epoch(0),
            EventBody::BindClose {
                commits: vec![(slot, commit)],
            },
        ),
    ] {
        receiver.admit(&mut session, &record, 1).unwrap();
    }
    // The player withholds the reveal; the host cancels with the closed set as evidence.
    let cancel = Settlement::Unresolved {
        session: key,
        epoch: Epoch(0),
        reason: ForkReason::Cancelled,
        heads: vec![],
        evidence: vec![[1; 32]],
    };
    let verified = receiver
        .settle(&mut session, &host.settlement(key, &cancel), 2)
        .unwrap();
    assert!(!verified.passed());
    assert_eq!(session.state(), State::Unresolved(ForkReason::Cancelled));
    // Nothing further is admitted, not even a reveal.
    let mut task = template;
    task.cases[0].seed = derive_seed(&host_salt, &[salt], 0);
    let (reveal, _) = host.event(key, Epoch(0), EventBody::Reveal { task, host_salt });
    assert!(matches!(
        receiver.admit(&mut session, &reveal, 3).err(),
        Some(ReceiverError::Session(_))
    ));
    let again = Settlement::Unresolved {
        session: key,
        epoch: Epoch(0),
        reason: ForkReason::HostSilent,
        heads: vec![],
        evidence: vec![],
    };
    assert_eq!(
        receiver
            .settle(&mut session, &host.settlement(key, &again), 4)
            .err(),
        Some(ReceiverError::Settle(SettleError::Terminal))
    );
}

#[test]
fn a_missing_member_pauses_and_a_sealed_replace_resumes_in_the_next_epoch() {
    let mut host = Signer::new(1);
    let mut player = Signer::new(2);
    let mut successor = Signer::new(4);
    let converted =
        convert(&platonik_core::fixtures::experiment("opening-normal").unwrap()).unwrap();
    let (manifest, template) = live_manifest(&converted, [11; 32], 64, MissingMember::Pause, None);
    let slot = converted.programs[0].0;
    let program = converted.programs[0].1.clone();
    let host_salt = [7; 32];
    let open = SessionOpen {
        realm: REALM,
        room: ROOM,
        manifest: manifest.hash(),
        ruleset: RulesetId::V1,
        seed_commitment: seed_commitment(&host_salt, manifest.world),
        authority: Authority::Host { key: host.public() },
        players: vec![Player {
            key: player.public(),
            slots: vec![slot],
        }],
        epoch: Epoch(0),
        nonce: [5; 32],
    };
    let mut session = Session::open(manifest, open, REALM).unwrap();
    let mut receiver = Receiver::new(PlatonikV1, policy());
    let key = session.key();
    let salt = [3; 32];
    let commit = bind_commit(key, slot, &program, &salt);
    let mut order = Vec::new();
    for (record, digest) in [
        player.event(key, Epoch(0), EventBody::BindCommit { slot, commit }),
        host.event(
            key,
            Epoch(0),
            EventBody::BindClose {
                commits: vec![(slot, commit)],
            },
        ),
        player.event(
            key,
            Epoch(0),
            EventBody::BindReveal {
                slot,
                program: program.clone(),
                salt,
            },
        ),
    ] {
        receiver.admit(&mut session, &record, 1).unwrap();
        order.push(digest);
    }
    let mut task = template.clone();
    task.cases[0].seed = derive_seed(&host_salt, &[salt], 0);
    let ticks = task.cases[0].ticks;
    let (reveal, reveal_digest) = host.event(
        key,
        Epoch(0),
        EventBody::Reveal {
            task: task.clone(),
            host_salt,
        },
    );
    receiver.admit(&mut session, &reveal, 2).unwrap();
    order.push(reveal_digest);
    let (seal_0, _) = host.seal(&session, 0, ticks / 3, order);
    receiver.admit(&mut session, &seal_0, 3).unwrap();
    assert_eq!(session.state(), State::Running(1));
    // The player goes silent; the receiver pauses on the missing member.
    session.pause_missing(slot, &[[2; 32]]).unwrap();
    assert_eq!(
        session.state(),
        State::Unresolved(ForkReason::MemberMissing)
    );
    let (late_input, _) = player.event(
        key,
        Epoch(0),
        EventBody::Input {
            case: 0,
            tick: ticks / 3 + 1,
            kind: EventKind::ClearMemory { cell: slot },
        },
    );
    assert!(
        receiver.admit(&mut session, &late_input, 4).is_err(),
        "players are not admitted while paused"
    );
    // The host replaces the member and seals the replace: the epoch bumps.
    let (replace, replace_digest) = host.event(
        key,
        Epoch(0),
        EventBody::Replace {
            slot,
            old: player.public(),
            new: successor.public(),
        },
    );
    receiver.admit(&mut session, &replace, 5).unwrap();
    let (seal_1, checkpoint_1) = host.seal(&session, 1, ticks / 2, vec![replace_digest]);
    let verified_1 = receiver.admit(&mut session, &seal_1, 6).unwrap().unwrap();
    assert_eq!(verified_1.hash(), checkpoint_1);
    assert_eq!(session.state(), State::Running(2));
    assert_eq!(session.epoch(), Epoch(1));
    assert_eq!(session.ledger().epoch(), Epoch(1));
    assert_eq!(
        session.ledger().height(),
        0,
        "the new epoch's genesis is anchored on the checkpoint"
    );
    assert_eq!(session.slot_owners()[&slot], successor.public());
    // The successor plays on in epoch 1 with the same program; sequences restart.
    host.sequence = 0;
    let (input, input_digest) = successor.event(
        key,
        Epoch(1),
        EventBody::Input {
            case: 0,
            tick: ticks / 2 + 1,
            kind: EventKind::ClearMemory { cell: slot },
        },
    );
    receiver.admit(&mut session, &input, 7).unwrap();
    let (old_epoch, _) = player.event(
        key,
        Epoch(0),
        EventBody::Input {
            case: 0,
            tick: ticks / 2 + 2,
            kind: EventKind::ClearMemory { cell: slot },
        },
    );
    assert!(matches!(
        receiver.admit(&mut session, &old_epoch, 8).err(),
        Some(ReceiverError::Session(
            vhalla_game_platonik::session::Rejection::WrongEpoch
        ))
    ));
    let (seal_2, checkpoint_2) = host.seal(&session, 2, ticks, vec![input_digest]);
    let verified_2 = receiver.admit(&mut session, &seal_2, 9).unwrap().unwrap();
    assert!(verified_2.is_final());
    assert_eq!(
        session.ledger().height(),
        1,
        "|order_2| in the new epoch, no seal event after the final seal"
    );
    // The result settles in the new epoch with the per-epoch height check.
    let (task_final, candidate, through) = session.final_plan().cloned().unwrap();
    let valid = vhalla_witness::manifest::ValidManifest::validate(task_final.clone()).unwrap();
    let evidence = vhalla_game_platonik::engine::GameEngine::replay(
        &PlatonikV1,
        session.world(),
        &valid,
        candidate.clone(),
        vhalla_witness::platform::WorkAllowance {
            max_total: valid.fuel_total(),
        },
        through,
        vhalla_witness::platform::ReceiptBinding {
            challenge_id: key.0,
            subject_key: host.public(),
        },
    )
    .unwrap();
    let receipt = ClaimedReceipt::decode(&evidence.receipt.encode()).unwrap();
    let result = Settlement::Result {
        session: key,
        epoch: Epoch(1),
        checkpoint: checkpoint_2,
        receipt,
        passed: evidence.passed,
    };
    receiver
        .settle(&mut session, &host.settlement(key, &result), 10)
        .unwrap();
    assert_eq!(
        evidence.passed,
        passed_by_plain_run(&task_final, candidate),
        "the replaced member's session reproduces the plain run"
    );
}

#[test]
fn a_pre_reveal_fill_binds_the_declared_fallback() {
    let mut host = Signer::new(1);
    let player = Signer::new(2);
    let converted =
        convert(&platonik_core::fixtures::experiment("opening-normal").unwrap()).unwrap();
    let slot = converted.programs[0].0;
    let program = converted.programs[0].1.clone();
    let fallback = ProgramHash::of(&vhalla_witness::codec::encode_candidate(&[(
        slot,
        program.clone(),
    )]));
    let (manifest, template) = live_manifest(
        &converted,
        [11; 32],
        64,
        MissingMember::Fill,
        Some(fallback),
    );
    let host_salt = [7; 32];
    let open = SessionOpen {
        realm: REALM,
        room: ROOM,
        manifest: manifest.hash(),
        ruleset: RulesetId::V1,
        seed_commitment: seed_commitment(&host_salt, manifest.world),
        authority: Authority::Host { key: host.public() },
        players: vec![Player {
            key: player.public(),
            slots: vec![slot],
        }],
        epoch: Epoch(0),
        nonce: [5; 32],
    };
    let mut session = Session::open(manifest, open, REALM).unwrap();
    let mut receiver = Receiver::new(PlatonikV1, policy());
    let key = session.key();
    // The player never commits; the host closes the empty set and fills.
    let (close, close_digest) = host.event(key, Epoch(0), EventBody::BindClose { commits: vec![] });
    receiver.admit(&mut session, &close, 1).unwrap();
    let evidence = FillEvidence {
        author: [0; 32],
        sequence: vhalla_core::Sequence(0),
        segment: 0,
    };
    let wrong = EventBody::Fill {
        slot,
        program_hash: ProgramHash([1; 32]),
        program: program.clone(),
        evidence,
    };
    let (wrong_fill, _) = host.event(key, Epoch(0), wrong);
    assert!(
        receiver.admit(&mut session, &wrong_fill, 2).is_err(),
        "a fill must hash to the declared fallback"
    );
    let (fill, fill_digest) = host.event(
        key,
        Epoch(0),
        EventBody::Fill {
            slot,
            program_hash: fallback,
            program: program.clone(),
            evidence,
        },
    );
    receiver.admit(&mut session, &fill, 3).unwrap();
    let mut task = template;
    task.cases[0].seed = derive_seed(&host_salt, &[fill_salt(fallback, slot)], 0);
    let (reveal, reveal_digest) = host.event(
        key,
        Epoch(0),
        EventBody::Reveal {
            task: task.clone(),
            host_salt,
        },
    );
    receiver.admit(&mut session, &reveal, 4).unwrap();
    let ticks = task.cases[0].ticks;
    let (seal, _) = host.seal(
        &session,
        0,
        ticks,
        vec![close_digest, fill_digest, reveal_digest],
    );
    let verified = receiver.admit(&mut session, &seal, 5).unwrap().unwrap();
    assert!(verified.is_final());
    assert_eq!(
        verified.passed(),
        passed_by_plain_run(&task, vec![(slot, program)])
    );
}

#[test]
fn a_verified_settlement_exports_a_receipt_claim_the_verifier_signed() {
    use vhalla_core::{PeerId, RealmId, Sequence};
    use vhalla_crypto::{
        peer_id_from_seed, verifying_key_from_seed, ClaimContext, ClaimDomain, SignedClaim,
        SubjectDigest,
    };
    let Finished {
        mut session,
        mut receiver,
        host,
        final_checkpoint,
        passed,
        receipt,
    } = finish_live(MissingMember::Pause);
    let key = session.key();
    let result = host.settlement(
        key,
        &Settlement::Result {
            session: key,
            epoch: Epoch(0),
            checkpoint: final_checkpoint,
            receipt,
            passed,
        },
    );
    let verified = receiver.settle(&mut session, &result, 9).unwrap();
    let seed = [77; 32];
    let audience = PeerId(9);
    let claim = verified.export_claim(
        RealmId(2),
        vhalla_crypto::SessionId(4),
        audience,
        Epoch(1),
        Sequence(1),
        1_000,
        2_000,
        seed,
    );
    let expected = ClaimContext {
        domain: ClaimDomain::Receipt,
        realm: RealmId(2),
        session: vhalla_crypto::SessionId(4),
        audience,
        epoch: Epoch(1),
    };
    claim
        .verify(&verifying_key_from_seed(seed), expected, 1_500)
        .unwrap();
    assert_eq!(claim.issuer, peer_id_from_seed(seed));
    assert_eq!(
        claim.claim.subject,
        SubjectDigest::from_digest(verified.hash())
    );
    // Round trip through the claim codec and under the wrong key or domain.
    let raw = claim.encode();
    let back = SignedClaim::decode(&raw).unwrap();
    assert_eq!(back, claim);
    assert!(back
        .verify(&verifying_key_from_seed([78; 32]), expected, 1_500)
        .is_err());
    let mut wrong = expected;
    wrong.domain = ClaimDomain::Session;
    assert!(back
        .verify(&verifying_key_from_seed(seed), wrong, 1_500)
        .is_err());
}

#[cfg(feature = "quorum")]
#[test]
fn a_certificate_attests_only_the_scoped_settlement_its_batch_names() {
    use vhalla_game_platonik::quorum::{attest, commitment, CommitmentError, QuorumError};
    use vhalla_rooms_consensus::{
        Batch, CommitCertificate, Frontier, GameCommitment, GameCommitmentKind,
    };
    let Finished {
        mut session,
        mut receiver,
        host,
        final_checkpoint,
        passed,
        receipt,
    } = finish_live(MissingMember::Pause);
    let key = session.key();
    let result = host.settlement(
        key,
        &Settlement::Result {
            session: key,
            epoch: Epoch(0),
            checkpoint: final_checkpoint,
            receipt,
            passed,
        },
    );
    let verified = receiver.settle(&mut session, &result, 9).unwrap();
    let named = commitment(&session, &result).unwrap();
    assert_eq!(named.kind, GameCommitmentKind::Settlement);
    assert_eq!(named.object, verified.hash());
    let mut invalid = result.clone();
    invalid.signature = [0; 64];
    assert_eq!(commitment(&session, &invalid), Err(CommitmentError::Record));
    let wrong_session = host.settlement(
        SessionKey([0xEE; 32]),
        &vhalla_game_platonik::wire::decode_settlement(&result.body).unwrap(),
    );
    assert_eq!(
        commitment(&session, &wrong_session),
        Err(CommitmentError::Scope)
    );
    let batch_with = |games: Vec<GameCommitment>| Batch {
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
        games,
        eligible: None,
        result_registry: [5; 32],
        result_social: [6; 32],
        result_control: [7; 32],
    };
    let batch = batch_with(vec![named]);
    let certificate = CommitCertificate {
        bytes: vec![0xC3; 96],
        value_commitment: batch.value_id(),
        height: 42,
    };
    let accept = |bytes: &[u8], height: u64, value: &[u8; 32]| {
        bytes == [0xC3; 96] && height == 42 && *value == batch.value_id()
    };
    let quorum = attest(&verified, &certificate, &batch.encode(), accept).unwrap();
    assert_eq!(quorum.hash(), verified.hash());
    assert_eq!(quorum.session(), key);
    assert_eq!(quorum.epoch(), 0);
    assert_eq!(quorum.height(), 42);
    assert_eq!(quorum.value(), batch.value_id());
    assert_eq!(
        attest(&verified, &certificate, &batch.encode(), |_, _, _| false).err(),
        Some(QuorumError::Certificate)
    );
    let other = batch_with(vec![
        named,
        GameCommitment {
            object: [9; 32],
            ..named
        },
    ]);
    assert_eq!(
        attest(&verified, &certificate, &other.encode(), accept).err(),
        Some(QuorumError::ValueMismatch)
    );
    for (games, expected) in [
        (Vec::new(), QuorumError::Unbound),
        (vec![named, named], QuorumError::Unbound),
        (
            vec![GameCommitment {
                object: [8; 32],
                ..named
            }],
            QuorumError::Mismatch,
        ),
        (
            vec![GameCommitment {
                room: vhalla_core::RoomId(verified.room().0 + 1),
                ..named
            }],
            QuorumError::Unbound,
        ),
    ] {
        let batch = batch_with(games);
        let certificate = CommitCertificate {
            bytes: vec![0xC3; 96],
            value_commitment: batch.value_id(),
            height: 42,
        };
        assert_eq!(
            attest(&verified, &certificate, &batch.encode(), |_, _, _| true).err(),
            Some(expected)
        );
    }
    assert_eq!(
        attest(&verified, &certificate, b"VRB1", accept).err(),
        Some(QuorumError::Batch)
    );
}
