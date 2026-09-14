//! The Malachite `Context` for room consensus: `Value` carries bounded
//! canonical application bytes and `ValueId` IS the application's 32-byte
//! value commitment — not a fixture `u64`.
//!
//! Real room batch bytes cross the consensus wire inside streamed
//! proposal parts, and the commit certificate's `value_id` field is the
//! batch's own commitment.
//!
//! Reused from the pinned test crate (non-context-generic impls): `Height`,
//! `Address`, the `Ed25519` signing scheme, and `LinearTimeouts`. Everything
//! else — value, vote, proposal, proposal parts, validators, signer,
//! verifier, codec — is implemented here for `RoomContext`.

use core::fmt;

use bytes::Bytes;

use arc_malachitebft_core_types::{
    Context, NilOrVal, Proposal as ProposalTrait, ProposalPart as ProposalPartTrait, Round,
    SignedExtension, Validator as ValidatorTrait, ValidatorSet as ValidatorSetTrait,
    Vote as VoteTrait, VoteType,
};
pub use arc_malachitebft_test::{Address, Ed25519, Height, PrivateKey, PublicKey, Signature};

/// Maximum canonical value bytes carried inside a proposal. The room
/// registry's own batch bound is strictly smaller; this is the wire bound.
pub const MAX_VALUE_BYTES: usize = 256 * 1024;

/// The value identity: the application's own 32-byte value commitment.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoomValueId(pub [u8; 32]);

impl fmt::Display for RoomValueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…")
    }
}

/// The full proposed value: the application value commitment plus the
/// bounded canonical application bytes that travel inside proposal parts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RoomValue {
    /// The application value commitment (what votes and certificates name).
    pub id: RoomValueId,
    /// Canonical application bytes (e.g. an encoded room `Batch`).
    pub bytes: Bytes,
}

impl RoomValue {
    /// Wraps canonical application bytes under their value commitment.
    pub fn new(id: [u8; 32], bytes: Bytes) -> Self {
        RoomValue {
            id: RoomValueId(id),
            bytes,
        }
    }
}

impl arc_malachitebft_core_types::Value for RoomValue {
    type Id = RoomValueId;

    fn id(&self) -> Self::Id {
        self.id
    }
}

/// Streamed proposal content: an `Init` header, bounded `Data` chunks
/// carrying the canonical value bytes, and a `Fin` carrying the proposer's
/// signature over the content preimage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoomPart {
    /// Header: height, round, pol round, expected proposer.
    Init(ProposalInit),
    /// A chunk of the canonical value bytes.
    Data(Bytes),
    /// Proposer signature over the content preimage.
    Fin(ProposalFin),
}

/// The `Init` proposal part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalInit {
    /// Consensus height.
    pub height: Height,
    /// Consensus round.
    pub round: Round,
    /// Proof-of-lock round.
    pub pol_round: Round,
    /// The proposer address claimed by the stream.
    pub proposer: Address,
}

/// The `Fin` proposal part: signature over
/// `"RF1" || height || round || keccak256(data)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalFin {
    /// The proposer's Ed25519 signature over the content preimage.
    pub signature: Signature,
}

impl ProposalPartTrait<RoomContext> for RoomPart {
    fn is_first(&self) -> bool {
        matches!(self, RoomPart::Init(_))
    }

    fn is_last(&self) -> bool {
        matches!(self, RoomPart::Fin(_))
    }
}

/// A room proposal: the full value, consensus rounds, and the proposer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomProposal {
    /// Consensus height.
    pub height: Height,
    /// Consensus round.
    pub round: Round,
    /// The full proposed value (id + canonical bytes).
    pub value: RoomValue,
    /// Proof-of-lock round.
    pub pol_round: Round,
    /// The proposer's address.
    pub proposer: Address,
}

impl ProposalTrait<RoomContext> for RoomProposal {
    fn height(&self) -> Height {
        self.height
    }

    fn round(&self) -> Round {
        self.round
    }

    fn value(&self) -> &RoomValue {
        &self.value
    }

    fn take_value(self) -> RoomValue {
        self.value
    }

    fn pol_round(&self) -> Round {
        self.pol_round
    }

    fn validator_address(&self) -> &Address {
        &self.proposer
    }
}

/// A room vote: height, round, type, voted value id (or nil), and the
/// validator address. No vote extensions are used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomVote {
    /// Prevote or precommit.
    pub vote_type: VoteType,
    /// Consensus height.
    pub height: Height,
    /// Consensus round.
    pub round: Round,
    /// The voted value id, or nil.
    pub value: NilOrVal<RoomValueId>,
    /// The voting validator's address.
    pub address: Address,
    /// Vote extension slot (always `None` for this context).
    pub extension: Option<SignedExtension<RoomContext>>,
}

impl RoomVote {
    /// Builds an unsigned vote.
    pub fn new(
        vote_type: VoteType,
        height: Height,
        round: Round,
        value: NilOrVal<RoomValueId>,
        address: Address,
    ) -> Self {
        RoomVote {
            vote_type,
            height,
            round,
            value,
            address,
            extension: None,
        }
    }
}

impl VoteTrait<RoomContext> for RoomVote {
    fn height(&self) -> Height {
        self.height
    }

    fn round(&self) -> Round {
        self.round
    }

    fn value(&self) -> &NilOrVal<RoomValueId> {
        &self.value
    }

    fn take_value(self) -> NilOrVal<RoomValueId> {
        self.value
    }

    fn vote_type(&self) -> VoteType {
        self.vote_type
    }

    fn validator_address(&self) -> &Address {
        &self.address
    }

    fn extension(&self) -> Option<&SignedExtension<RoomContext>> {
        self.extension.as_ref()
    }

    fn take_extension(&mut self) -> Option<SignedExtension<RoomContext>> {
        self.extension.take()
    }

    fn extend(mut self, extension: SignedExtension<RoomContext>) -> Self {
        self.extension = Some(extension);
        self
    }
}

/// A room validator: consensus address, Ed25519 public key, voting power.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomValidator {
    /// Consensus address derived from the public key.
    pub address: Address,
    /// Ed25519 public key.
    pub public_key: PublicKey,
    /// Voting power.
    pub power: u64,
}

impl RoomValidator {
    /// Derives the address from the public key.
    pub fn new(public_key: PublicKey, power: u64) -> Self {
        RoomValidator {
            address: Address::from_public_key(&public_key),
            public_key,
            power,
        }
    }
}

impl ValidatorTrait<RoomContext> for RoomValidator {
    fn address(&self) -> &Address {
        &self.address
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn voting_power(&self) -> u64 {
        self.power
    }
}

/// A sorted room validator set: voting power descending, then address
/// ascending, matching the deterministic-order contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomValidatorSet {
    /// Sorted validators.
    pub validators: Vec<RoomValidator>,
}

impl RoomValidatorSet {
    /// Builds a sorted validator set.
    pub fn new(mut validators: Vec<RoomValidator>) -> Self {
        validators.sort_by(|a, b| {
            b.power
                .cmp(&a.power)
                .then_with(|| a.address.cmp(&b.address))
        });
        validators.dedup_by(|a, b| a.address == b.address);
        RoomValidatorSet { validators }
    }
}

impl ValidatorSetTrait<RoomContext> for RoomValidatorSet {
    fn count(&self) -> usize {
        self.validators.len()
    }

    fn total_voting_power(&self) -> u64 {
        self.validators.iter().map(|v| v.power).sum()
    }

    fn get_by_address(&self, address: &Address) -> Option<&RoomValidator> {
        self.validators.iter().find(|v| &v.address == address)
    }

    fn get_by_index(&self, index: usize) -> Option<&RoomValidator> {
        self.validators.get(index)
    }
}

/// The room consensus context. `Value` carries bounded canonical
/// application bytes; `ValueId` is the application's own 32-byte
/// commitment. Proposer selection is deterministic round-robin over the
/// sorted set: `(height + round) % count`.
#[derive(Copy, Clone, Debug, Default)]
pub struct RoomContext;

impl RoomContext {
    /// Deterministic round-robin proposer selection.
    pub fn select_proposer<'a>(
        &self,
        validator_set: &'a RoomValidatorSet,
        height: Height,
        round: Round,
    ) -> &'a RoomValidator {
        assert!(validator_set.count() > 0);
        assert!(round != Round::Nil && round.as_i64() >= 0);
        let index = (height.as_u64() as usize + round.as_i64() as usize) % validator_set.count();
        validator_set
            .get_by_index(index)
            .expect("proposer index within validator set")
    }
}

impl Context for RoomContext {
    type Address = Address;
    type Height = Height;
    type ProposalPart = RoomPart;
    type Proposal = RoomProposal;
    type Validator = RoomValidator;
    type ValidatorSet = RoomValidatorSet;
    type Timeouts = arc_malachitebft_core_types::LinearTimeouts;
    type Value = RoomValue;
    type Vote = RoomVote;
    type Extension = ();
    type SigningScheme = Ed25519;

    fn select_proposer<'a>(
        &self,
        validator_set: &'a Self::ValidatorSet,
        height: Self::Height,
        round: Round,
    ) -> &'a Self::Validator {
        RoomContext::select_proposer(self, validator_set, height, round)
    }

    fn new_proposal(
        &self,
        height: Height,
        round: Round,
        value: RoomValue,
        pol_round: Round,
        address: Address,
    ) -> RoomProposal {
        RoomProposal {
            height,
            round,
            value,
            pol_round,
            proposer: address,
        }
    }

    fn new_prevote(
        &self,
        height: Height,
        round: Round,
        value_id: NilOrVal<RoomValueId>,
        address: Address,
    ) -> RoomVote {
        RoomVote::new(VoteType::Prevote, height, round, value_id, address)
    }

    fn new_precommit(
        &self,
        height: Height,
        round: Round,
        value_id: NilOrVal<RoomValueId>,
        address: Address,
    ) -> RoomVote {
        RoomVote::new(VoteType::Precommit, height, round, value_id, address)
    }
}

/// Canonical sign bytes for a vote:
/// `"RV1" || vote_type || height || round || (nil | 0x01 || value_id) ||
/// address`.
pub fn vote_sign_bytes(vote: &RoomVote) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + 1 + 8 + 4 + 1 + 32 + 20);
    out.extend_from_slice(b"RV1");
    out.push(match vote.vote_type {
        VoteType::Prevote => 0,
        VoteType::Precommit => 1,
    });
    out.extend_from_slice(&vote.height.as_u64().to_be_bytes());
    out.extend_from_slice(&vote.round.as_u32().unwrap_or(u32::MAX).to_be_bytes());
    match &vote.value {
        NilOrVal::Nil => out.push(0),
        NilOrVal::Val(id) => {
            out.push(1);
            out.extend_from_slice(&id.0);
        }
    }
    out.extend_from_slice(&vote.address.into_inner());
    out
}

/// Canonical sign bytes for a proposal:
/// `"RP1" || height || round || pol_round || value_id || proposer`.
/// The signature binds the value commitment; the full bytes are bound
/// transitively by the commitment itself.
pub fn proposal_sign_bytes(proposal: &RoomProposal) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + 8 + 4 + 4 + 32 + 20);
    out.extend_from_slice(b"RP1");
    out.extend_from_slice(&proposal.height.as_u64().to_be_bytes());
    out.extend_from_slice(&proposal.round.as_u32().unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(
        &proposal
            .pol_round
            .as_u32()
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(&proposal.value.id.0);
    out.extend_from_slice(&proposal.proposer.into_inner());
    out
}

/// Canonical sign bytes for a `Fin` proposal part:
/// `"RF1" || height || round || keccak256(concat data bytes)`. The expected
/// proposer is bound by the verifier resolving `select_proposer` for
/// `(height, round)` and checking this signature against that validator's
/// key.
pub fn fin_sign_bytes(height: Height, round: Round, data: &[u8]) -> Vec<u8> {
    use sha3::Digest;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(data);
    let content_hash = hasher.finalize();

    let mut out = Vec::with_capacity(3 + 8 + 4 + 32);
    out.extend_from_slice(b"RF1");
    out.extend_from_slice(&height.as_u64().to_be_bytes());
    out.extend_from_slice(&round.as_u32().unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(&content_hash);
    out
}

#[cfg(test)]
mod tests;
