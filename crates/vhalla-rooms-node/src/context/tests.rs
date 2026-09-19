use super::*;

use arc_malachitebft_codec::Codec;
use arc_malachitebft_core_consensus::{LivenessMsg, ProposedValue, SignedConsensusMsg};
use arc_malachitebft_core_types::{
    CommitSignature, ExtendedCommitCertificate, ExtendedCommitSignature, PolkaCertificate,
    PolkaSignature, SignedMessage, ValidatorProof, Validity, Value as _, VoteType,
};
use arc_malachitebft_engine::util::streaming::{StreamContent, StreamId, StreamMessage};
use arc_malachitebft_peer::PeerId;
use arc_malachitebft_sync::{
    RawDecidedValue, Request, Response, Status, ValueRequest, ValueResponse,
};

use crate::codec::RoomCodec;
use crate::signing::{verify_fin, RoomSigner, RoomVerifier};

fn key(seed: u8) -> PrivateKey {
    PrivateKey::from([seed; 32])
}

fn set4() -> (Vec<PrivateKey>, RoomValidatorSet) {
    let keys: Vec<_> = (1..=4).map(key).collect();
    let set = RoomValidatorSet::new(
        keys.iter()
            .map(|k| RoomValidator::new(k.public_key(), 1))
            .collect(),
    );
    (keys, set)
}

fn value(seed: u8) -> RoomValue {
    RoomValue::new([seed; 32], Bytes::from_static(b"canonical batch bytes"))
}

fn signed_vote(keys: &[PrivateKey], i: usize, h: u64, r: u32, id: RoomValueId) -> SignedVote {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        use arc_malachitebft_signing::Signer;
        RoomSigner::new(keys[i].clone())
            .sign_vote(RoomVote::new(
                VoteType::Precommit,
                Height::new(h),
                Round::new(r),
                NilOrVal::Val(id),
                Address::from_public_key(&keys[i].public_key()),
            ))
            .await
            .unwrap()
    })
}

type SignedVote = SignedMessage<RoomContext, RoomVote>;

#[test]
fn value_id_is_application_commitment() {
    let v = value(7);
    assert_eq!(v.id().0, [7; 32]);
}

#[test]
fn proposer_selection_is_deterministic() {
    let (_keys, set) = set4();
    let ctx = RoomContext;
    for h in 1..4u64 {
        for r in 0..4u32 {
            let a = ctx.select_proposer(&set, Height::new(h), Round::new(r));
            let b = ctx.select_proposer(&set, Height::new(h), Round::new(r));
            assert_eq!(a.address, b.address);
        }
    }
    // All four validators propose over a span of rounds.
    let mut seen = std::collections::BTreeSet::new();
    for r in 0..8u32 {
        seen.insert(
            ctx.select_proposer(&set, Height::new(1), Round::new(r))
                .address,
        );
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn validator_admission_rejects_unsafe_power_and_conflicting_duplicates() {
    let a = key(1).public_key();
    let b = key(2).public_key();
    let entries = vec![
        RoomValidator::new(a, 3),
        RoomValidator::new(b, 2),
        RoomValidator::new(a, 1),
    ];
    // Address duplicates are nonadjacent after sorting by power.
    let deduplicated = RoomValidatorSet::new(entries.clone());
    assert_eq!(deduplicated.count(), 2);
    assert_eq!(deduplicated.total_voting_power(), 5);
    assert_eq!(
        RoomValidatorSet::try_new(entries),
        Err(ValidatorSetError::ConflictingPower)
    );
    let repeated =
        RoomValidatorSet::try_new(vec![RoomValidator::new(a, 1), RoomValidator::new(a, 1)])
            .unwrap();
    assert_eq!(repeated.count(), 1);
    assert_eq!(
        RoomValidatorSet::try_new(vec![]),
        Err(ValidatorSetError::Empty)
    );
    for power in [u64::MAX / 3 + 1, u64::MAX] {
        assert_eq!(
            RoomValidatorSet::try_new(vec![RoomValidator::new(a, power)]),
            Err(ValidatorSetError::PowerOverflow)
        );
    }
    assert_eq!(
        RoomValidatorSet::try_new(vec![RoomValidator::new(a, 0)]),
        Err(ValidatorSetError::InvalidValidator)
    );
    let too_many = (1..=65)
        .map(|seed| RoomValidator::new(key(seed).public_key(), 1))
        .collect();
    assert_eq!(
        RoomValidatorSet::try_new(too_many),
        Err(ValidatorSetError::TooManyValidators)
    );
}

#[test]
fn validator_admission_rejects_reordered_public_sets() {
    let (_, equal_power) = set4();
    let different_power = RoomValidatorSet::new(vec![
        RoomValidator::new(key(1).public_key(), 3),
        RoomValidator::new(key(2).public_key(), 2),
        RoomValidator::new(key(3).public_key(), 1),
    ]);
    for canonical in [equal_power, different_power] {
        assert_eq!(canonical.validate(), Ok(()));
        let mut reordered = canonical.clone();
        reordered.validators.reverse();
        let height = Height::new(canonical.validators.len() as u64);
        assert_ne!(
            RoomContext.select_proposer(&canonical, height, Round::new(0)),
            RoomContext.select_proposer(&reordered, height, Round::new(0)),
            "public reordering changes the proposer despite identical membership"
        );
        assert_eq!(
            reordered.validate(),
            Err(ValidatorSetError::InvalidValidator)
        );
        assert_eq!(RoomValidatorSet::new(reordered.validators), canonical);
    }
}

#[test]
fn proposer_selection_handles_full_height_without_overflow_or_truncation() {
    let (_, set) = set4();
    let round = u32::MAX - 1;
    let expected = ((u128::from(u64::MAX) + u128::from(round)) % 4) as usize;
    assert_eq!(
        RoomContext.select_proposer(&set, Height::new(u64::MAX), Round::new(round)),
        &set.validators[expected]
    );
}

#[test]
fn certificate_quorum_is_exact_at_large_power_and_invalid_sets_fail_closed() {
    use crate::cert::{
        canonical_bytes, verify_canonical_certificate, verify_commit_certificate, CertError,
    };
    use arc_malachitebft_core_types::CommitCertificate;

    let keys: Vec<_> = (1..=3).map(key).collect();
    let power = (u64::MAX / 3) / 3;
    let set = RoomValidatorSet::try_new(
        keys.iter()
            .map(|key| RoomValidator::new(key.public_key(), power))
            .collect(),
    )
    .unwrap();
    let id = value(1).id;
    let certificate = |signers: usize| CommitCertificate::<RoomContext> {
        height: Height::new(1),
        round: Round::new(0),
        value_id: id,
        commit_signatures: (0..signers)
            .map(|i| {
                let vote = signed_vote(&keys, i, 1, 0, id);
                CommitSignature::new(vote.message.address, vote.signature)
            })
            .collect(),
    };
    let insufficient = certificate(2);
    assert_eq!(
        verify_commit_certificate(&insufficient, &set),
        Err(CertError::BelowQuorum)
    );
    assert!(!verify_canonical_certificate(
        &canonical_bytes(&insufficient),
        1,
        &id,
        &set
    ));
    let full = certificate(3);
    assert!(verify_commit_certificate(&full, &set).is_ok());
    assert!(verify_canonical_certificate(
        &canonical_bytes(&full),
        1,
        &id,
        &set
    ));
    let invalid = RoomValidatorSet::new(vec![RoomValidator::new(keys[0].public_key(), u64::MAX)]);
    assert_eq!(
        verify_commit_certificate(&full, &invalid),
        Err(CertError::InvalidValidatorSet)
    );
    assert!(!verify_canonical_certificate(
        &canonical_bytes(&full),
        1,
        &id,
        &invalid
    ));
}

#[test]
fn vote_sign_verify_round_trip() {
    let (keys, _set) = set4();
    let id = value(1).id;
    let sv = signed_vote(&keys, 0, 1, 0, id);
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        use arc_malachitebft_signing::Verifier;
        let pk = &keys[0].public_key();
        let ok = RoomVerifier
            .verify_signed_vote(&sv.message, &sv.signature, pk)
            .await
            .unwrap();
        assert!(ok.is_valid());
        // Wrong key fails.
        let bad = RoomVerifier
            .verify_signed_vote(&sv.message, &sv.signature, &keys[1].public_key())
            .await
            .unwrap();
        assert!(!bad.is_valid());
        // Tampered value id fails.
        let mut forged = sv.message.clone();
        forged.value = NilOrVal::Val(RoomValueId([9; 32]));
        let forged = RoomVerifier
            .verify_signed_vote(&forged, &sv.signature, pk)
            .await
            .unwrap();
        assert!(!forged.is_valid());
    });
}

#[test]
fn proposal_sign_verify_round_trip() {
    let (keys, _set) = set4();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        use arc_malachitebft_signing::{Signer, Verifier};
        let proposal = RoomContext.new_proposal(
            Height::new(1),
            Round::new(0),
            value(3),
            Round::Nil,
            Address::from_public_key(&keys[0].public_key()),
        );
        let signed = RoomSigner::new(keys[0].clone())
            .sign_proposal(proposal.clone())
            .await
            .unwrap();
        let ok = RoomVerifier
            .verify_signed_proposal(&signed.message, &signed.signature, &keys[0].public_key())
            .await
            .unwrap();
        assert!(ok.is_valid());
        let bad = RoomVerifier
            .verify_signed_proposal(&signed.message, &signed.signature, &keys[2].public_key())
            .await
            .unwrap();
        assert!(!bad.is_valid());
    });
}

#[test]
fn fin_part_binds_every_init_field_and_streamed_bytes() {
    let (keys, _set) = set4();
    let data = b"full canonical batch bytes";
    let init = ProposalInit {
        height: Height::new(2),
        round: Round::new(3),
        pol_round: Round::new(1),
        proposer: Address::from_public_key(&keys[0].public_key()),
    };
    let preimage = fin_sign_bytes(&init, data);
    assert_eq!(preimage.len(), 79);
    assert_eq!(&preimage[..3], b"RF2");
    assert_eq!(&preimage[3..11], &2u64.to_be_bytes());
    assert_eq!(&preimage[11..19], &3i64.to_be_bytes());
    assert_eq!(&preimage[19..39], &init.proposer.into_inner());
    assert_eq!(&preimage[39..47], &1i64.to_be_bytes());
    let sig = RoomSigner::new(keys[0].clone()).sign(&preimage);
    assert!(verify_fin(&keys[0].public_key(), &init, data, &sig));
    assert!(!verify_fin(
        &keys[0].public_key(),
        &init,
        b"other bytes",
        &sig
    ));
    assert!(!verify_fin(&keys[1].public_key(), &init, data, &sig));
    let mut changed = init.clone();
    changed.height = Height::new(3);
    assert!(!verify_fin(&keys[0].public_key(), &changed, data, &sig));
    let mut changed = init.clone();
    changed.round = Round::new(4);
    assert!(!verify_fin(&keys[0].public_key(), &changed, data, &sig));
    let mut changed = init.clone();
    changed.proposer = Address::from_public_key(&keys[1].public_key());
    assert!(!verify_fin(&keys[0].public_key(), &changed, data, &sig));
    let mut changed = init.clone();
    changed.pol_round = Round::Nil;
    assert!(!verify_fin(&keys[0].public_key(), &changed, data, &sig));
    let nil = fin_sign_bytes(&changed, data);
    assert_eq!(&nil[39..47], &(-1i64).to_be_bytes());
    changed.pol_round = Round::new(u32::MAX);
    assert_ne!(nil, fin_sign_bytes(&changed, data));
    changed.round = Round::Nil;
    let nil = fin_sign_bytes(&changed, data);
    changed.round = Round::new(u32::MAX);
    assert_ne!(nil, fin_sign_bytes(&changed, data));
    // The prior live domain must not be accepted after the migration.
    let mut legacy = b"RF1".to_vec();
    legacy.extend_from_slice(&init.height.as_u64().to_be_bytes());
    legacy.extend_from_slice(&init.round.as_u32().unwrap().to_be_bytes());
    legacy.extend_from_slice(&preimage[47..]);
    let old_sig = RoomSigner::new(keys[0].clone()).sign(&legacy);
    assert!(!verify_fin(&keys[0].public_key(), &init, data, &old_sig));
}

#[test]
fn codec_round_trips() {
    let (keys, _set) = set4();
    let codec = RoomCodec;
    let id = value(5).id;

    // ProposalPart
    for part in [
        RoomPart::Init(ProposalInit {
            height: Height::new(4),
            round: Round::new(1),
            pol_round: Round::Nil,
            proposer: Address::from_public_key(&keys[0].public_key()),
        }),
        RoomPart::Data(Bytes::from_static(b"chunk of canonical bytes")),
        RoomPart::Fin(ProposalFin {
            signature: RoomSigner::new(keys[0].clone()).sign(b"x"),
        }),
    ] {
        let enc = Codec::<RoomPart>::encode(&codec, &part).unwrap();
        assert_eq!(Codec::<RoomPart>::decode(&codec, enc).unwrap(), part);
    }

    // SignedConsensusMsg — vote + proposal
    let sv = signed_vote(&keys, 1, 2, 0, id);
    for msg in [
        SignedConsensusMsg::Vote(sv),
        SignedConsensusMsg::Proposal(SignedMessage {
            message: RoomContext.new_proposal(
                Height::new(2),
                Round::new(0),
                value(5),
                Round::new(0),
                Address::from_public_key(&keys[1].public_key()),
            ),
            signature: RoomSigner::new(keys[1].clone()).sign(b"p"),
        }),
    ] {
        let enc = Codec::<SignedConsensusMsg<RoomContext>>::encode(&codec, &msg).unwrap();
        assert_eq!(
            Codec::<SignedConsensusMsg<RoomContext>>::decode(&codec, enc).unwrap(),
            msg
        );
    }

    // PolkaCertificate + LivenessMsg
    let polka = PolkaCertificate {
        height: Height::new(2),
        round: Round::new(0),
        value_id: id,
        polka_signatures: vec![
            PolkaSignature::new(
                Address::from_public_key(&keys[0].public_key()),
                RoomSigner::new(keys[0].clone()).sign(b"a"),
            ),
            PolkaSignature::new(
                Address::from_public_key(&keys[1].public_key()),
                RoomSigner::new(keys[1].clone()).sign(b"b"),
            ),
        ],
    };
    let enc = Codec::<PolkaCertificate<RoomContext>>::encode(&codec, &polka).unwrap();
    assert_eq!(
        Codec::<PolkaCertificate<RoomContext>>::decode(&codec, enc).unwrap(),
        polka
    );
    let lm = LivenessMsg::PolkaCertificate(polka.clone());
    let enc = Codec::<LivenessMsg<RoomContext>>::encode(&codec, &lm).unwrap();
    assert_eq!(
        Codec::<LivenessMsg<RoomContext>>::decode(&codec, enc).unwrap(),
        lm
    );

    // StreamMessage
    let sm = StreamMessage::new(
        StreamId::new(Bytes::from_static(b"stream-1")),
        0,
        StreamContent::Data(RoomPart::Data(Bytes::from_static(b"payload"))),
    );
    let enc = Codec::<StreamMessage<RoomPart>>::encode(&codec, &sm).unwrap();
    assert_eq!(
        Codec::<StreamMessage<RoomPart>>::decode(&codec, enc).unwrap(),
        sm
    );

    // ValidatorProof
    let proof = ValidatorProof::new(
        keys[0].public_key().as_bytes().to_vec(),
        vec![1, 2, 3],
        RoomSigner::new(keys[0].clone()).sign(b"proof"),
    );
    let enc = Codec::<ValidatorProof<RoomContext>>::encode(&codec, &proof).unwrap();
    assert_eq!(
        Codec::<ValidatorProof<RoomContext>>::decode(&codec, enc).unwrap(),
        proof
    );

    // ProposedValue (WAL)
    let pv = ProposedValue {
        height: Height::new(9),
        round: Round::new(2),
        valid_round: Round::new(1),
        proposer: Address::from_public_key(&keys[2].public_key()),
        value: value(8),
        validity: Validity::Valid,
    };
    let enc = Codec::<ProposedValue<RoomContext>>::encode(&codec, &pv).unwrap();
    assert_eq!(
        Codec::<ProposedValue<RoomContext>>::decode(&codec, enc).unwrap(),
        pv
    );

    // Sync Status/Request/Response
    let status = Status {
        peer_id: PeerId::random(),
        tip_height: Height::new(7),
        history_min_height: Height::new(1),
    };
    let enc = Codec::<Status<RoomContext>>::encode(&codec, &status).unwrap();
    assert_eq!(
        Codec::<Status<RoomContext>>::decode(&codec, enc).unwrap(),
        status
    );

    let req = Request::ValueRequest(ValueRequest::new(Height::new(1)..=Height::new(5)));
    let enc = Codec::<Request<RoomContext>>::encode(&codec, &req).unwrap();
    assert_eq!(
        Codec::<Request<RoomContext>>::decode(&codec, enc).unwrap(),
        req
    );

    let ext = ExtendedCommitCertificate {
        height: Height::new(5),
        round: Round::new(0),
        value_id: id,
        commit_signatures: vec![
            ExtendedCommitSignature {
                address: Address::from_public_key(&keys[0].public_key()),
                signature: RoomSigner::new(keys[0].clone()).sign(b"c0"),
                extension: None,
            },
            ExtendedCommitSignature {
                address: Address::from_public_key(&keys[1].public_key()),
                signature: RoomSigner::new(keys[1].clone()).sign(b"c1"),
                extension: None,
            },
            ExtendedCommitSignature {
                address: Address::from_public_key(&keys[2].public_key()),
                signature: RoomSigner::new(keys[2].clone()).sign(b"c2"),
                extension: None,
            },
        ],
    };
    let resp = Response::ValueResponse(ValueResponse::new(
        Height::new(5),
        vec![RawDecidedValue {
            value_bytes: RoomCodec::encode_value(&value(5)),
            certificate: ext,
        }],
    ));
    let enc = Codec::<Response<RoomContext>>::encode(&codec, &resp).unwrap();
    assert_eq!(
        Codec::<Response<RoomContext>>::decode(&codec, enc.clone()).unwrap(),
        resp
    );
    use arc_malachitebft_codec::HasEncodedLen;
    assert_eq!(codec.encoded_len(&resp).unwrap(), enc.len());
}

#[test]
fn codec_rejects_trailing_and_truncated() {
    let codec = RoomCodec;
    let part = RoomPart::Data(Bytes::from_static(b"abc"));
    let mut enc = Codec::<RoomPart>::encode(&codec, &part).unwrap().to_vec();
    enc.push(0);
    assert!(Codec::<RoomPart>::decode(&codec, Bytes::from(enc)).is_err());
    let good = Codec::<RoomPart>::encode(&codec, &part).unwrap();
    assert!(Codec::<RoomPart>::decode(&codec, good.slice(..good.len() - 1)).is_err());
}

#[test]
fn value_codec_round_trip() {
    let v = RoomValue::new([42; 32], Bytes::from_static(b"some canonical bytes"));
    let enc = RoomCodec::encode_value(&v);
    assert_eq!(RoomCodec::decode_value(enc).unwrap(), v);
}

#[test]
fn commit_signature_field_codec_used() {
    // CommitSignature appears inside CommitCertificate (the decided path);
    // ensure the field order used by the cert-ack adapter stays encodable.
    let (keys, _set) = set4();
    let sig = CommitSignature::<RoomContext>::new(
        Address::from_public_key(&keys[0].public_key()),
        RoomSigner::new(keys[0].clone()).sign(b"s"),
    );
    assert_eq!(sig.address.into_inner().len(), 20);
}
