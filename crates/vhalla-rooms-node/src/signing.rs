//! `Signer`/`Verifier` implementations for `RoomContext`.
//!
//! Every signed message uses the canonical domain-separated preimages from
//! the crate root: `RV1` for votes, `RP1` for proposals, `RF2` for proposal
//! `Fin` parts, and the engine's own `ValidatorProof::signing_bytes` for
//! proof-of-validatorhood. Vote extensions are unsupported (`Extension` is
//! `()`) and fail closed.

use async_trait::async_trait;

use arc_malachitebft_core_types::{SignedMessage, ValidatorProof, VoteExtensionScope};
use arc_malachitebft_signing::{Error, Signer, VerificationResult, Verifier};

use crate::{
    fin_sign_bytes, proposal_sign_bytes, vote_sign_bytes, Ed25519, PrivateKey, PublicKey,
    RoomContext, RoomProposal, RoomVote, Signature,
};

/// Ed25519 signer for room consensus messages.
pub struct RoomSigner {
    private_key: PrivateKey,
}

impl RoomSigner {
    /// Wraps an Ed25519 private key.
    pub fn new(private_key: PrivateKey) -> Self {
        RoomSigner { private_key }
    }

    /// Signs arbitrary canonical bytes — used by the app layer for `Fin`
    /// proposal parts.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.private_key.sign(msg)
    }
}

#[async_trait]
impl Signer<RoomContext> for RoomSigner {
    async fn sign_vote(
        &self,
        vote: RoomVote,
    ) -> Result<SignedMessage<RoomContext, RoomVote>, Error> {
        let signature = self.private_key.sign(&vote_sign_bytes(&vote));
        Ok(SignedMessage::new(vote, signature))
    }

    async fn sign_proposal(
        &self,
        proposal: RoomProposal,
    ) -> Result<SignedMessage<RoomContext, RoomProposal>, Error> {
        let signature = self.private_key.sign(&proposal_sign_bytes(&proposal));
        Ok(SignedMessage::new(proposal, signature))
    }

    async fn sign_vote_extension(
        &self,
        _scope: VoteExtensionScope<RoomContext>,
        _extension: (),
    ) -> Result<SignedMessage<RoomContext, ()>, Error> {
        Err(Error::from_source(
            "room context does not use vote extensions",
        ))
    }

    async fn sign_validator_proof(
        &self,
        public_key: Vec<u8>,
        peer_id: Vec<u8>,
    ) -> Result<ValidatorProof<RoomContext>, Error> {
        let signature = self
            .private_key
            .sign(&ValidatorProof::<RoomContext>::signing_bytes(
                &public_key,
                &peer_id,
            ));
        Ok(ValidatorProof::new(public_key, peer_id, signature))
    }
}

/// Ed25519 verifier for room consensus messages.
#[derive(Copy, Clone, Debug, Default)]
pub struct RoomVerifier;

#[async_trait]
impl Verifier<RoomContext> for RoomVerifier {
    async fn verify_signed_vote(
        &self,
        vote: &RoomVote,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        Ok(VerificationResult::from_bool(
            public_key.verify(&vote_sign_bytes(vote), signature).is_ok(),
        ))
    }

    async fn verify_signed_proposal(
        &self,
        proposal: &RoomProposal,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        Ok(VerificationResult::from_bool(
            public_key
                .verify(&proposal_sign_bytes(proposal), signature)
                .is_ok(),
        ))
    }

    async fn verify_signed_vote_extension(
        &self,
        _scope: &VoteExtensionScope<RoomContext>,
        _extension: &(),
        _signature: &Signature,
        _public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        Ok(VerificationResult::Invalid)
    }

    async fn verify_validator_proof(
        &self,
        proof: &ValidatorProof<RoomContext>,
    ) -> Result<VerificationResult, Error> {
        use arc_malachitebft_core_types::SigningScheme;
        let Ok(public_key) = Ed25519::decode_public_key(&proof.public_key) else {
            return Ok(VerificationResult::Invalid);
        };
        Ok(VerificationResult::from_bool(
            public_key
                .verify(
                    &ValidatorProof::<RoomContext>::signing_bytes(
                        &proof.public_key,
                        &proof.peer_id,
                    ),
                    &proof.signature,
                )
                .is_ok(),
        ))
    }
}

/// Verifies a `Fin` proposal-part signature against the expected proposer's
/// key — the app-layer check for streamed parts.
pub fn verify_fin(
    public_key: &PublicKey,
    init: &crate::ProposalInit,
    data: &[u8],
    signature: &Signature,
) -> bool {
    public_key
        .verify(&fin_sign_bytes(init, data), signature)
        .is_ok()
}
