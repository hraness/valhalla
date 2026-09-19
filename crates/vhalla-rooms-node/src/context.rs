//! The Malachite `Context` for room consensus: `Value` carries bounded
//! canonical application bytes and `ValueId` IS the application's 32-byte
//! value commitment — not a fixture `u64`.
//!
//! Real room batch bytes cross the consensus wire inside streamed
//! proposal parts, and the commit certificate's `value_id` field is the
//! batch's own commitment.
//!
//! The `Ed25519` scheme and its keys come from the pinned signing crate;
//! `Height` and `Address` are the local context types below. Everything
//! else — value, vote, proposal, proposal parts, validators, signer,
//! verifier, codec — is implemented here for `RoomContext`. All of it is
//! portable: no filesystem, sockets, or engine runtime, so a wasm consumer
//! can verify certificates and replay decided values.

use core::fmt;

use bytes::Bytes;
use sha3::{Digest, Keccak256};

use arc_malachitebft_core_types::{
    Context, NilOrVal, Proposal as ProposalTrait, ProposalPart as ProposalPartTrait, Round,
    SignedExtension, Validator as ValidatorTrait, ValidatorSet as ValidatorSetTrait,
    Vote as VoteTrait, VoteType,
};
pub use arc_malachitebft_signing_ed25519::{Ed25519, PrivateKey, PublicKey, Signature};

/// A consensus address: the low 20 bytes of the validator public key's
/// Keccak-256 digest.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; Self::LENGTH]);

impl Address {
    const LENGTH: usize = 20;

    /// Wraps raw address bytes.
    pub const fn new(value: [u8; Self::LENGTH]) -> Self {
        Self(value)
    }

    /// Derives the consensus address for a public key.
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let hash: [u8; 32] = Keccak256::digest(public_key.as_bytes()).into();
        let mut address = [0; Self::LENGTH];
        address.copy_from_slice(&hash[..Self::LENGTH]);
        Self(address)
    }

    /// The raw address bytes.
    pub fn into_inner(self) -> [u8; Self::LENGTH] {
        self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self})")
    }
}

impl arc_malachitebft_core_types::Address for Address {}

/// A consensus height.
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Height(u64);

impl Height {
    /// Wraps a raw height.
    pub const fn new(height: u64) -> Self {
        Self(height)
    }

    /// The raw height number.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// The next height.
    pub fn increment(&self) -> Self {
        Self(self.0 + 1)
    }

    /// The previous height, when above zero.
    pub fn decrement(&self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }
}

impl fmt::Display for Height {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for Height {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Height({})", self.0)
    }
}

impl arc_malachitebft_core_types::Height for Height {
    const ZERO: Self = Self(0);
    const INITIAL: Self = Self(1);

    fn increment_by(&self, n: u64) -> Self {
        Self(self.0 + n)
    }

    fn decrement_by(&self, n: u64) -> Option<Self> {
        Some(Self(self.0.saturating_sub(n)))
    }

    fn as_u64(&self) -> u64 {
        self.0
    }
}

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
///
/// Equality and ordering key on `id` alone: the id is a binding
/// commitment to `bytes`, so two values with the same id name the same
/// content. This also lets a parts-assembled value pair with a
/// wire-received proposal, whose `bytes` are not transmitted.
#[derive(Clone, Debug)]
pub struct RoomValue {
    /// The application value commitment (what votes and certificates name).
    pub id: RoomValueId,
    /// Canonical application bytes (e.g. an encoded room `Batch`). Empty
    /// for a value decoded from a gossip proposal — the bytes arrive via
    /// the proposal-part stream instead.
    pub bytes: Bytes,
}

impl PartialEq for RoomValue {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for RoomValue {}

impl PartialOrd for RoomValue {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RoomValue {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
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
/// the RF2 preimage from [`fin_sign_bytes`], binding all `Init` fields and data.
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
    /// The proposed value commitment. Only `id` crosses the wire — a
    /// received proposal's `bytes` are empty; the canonical bytes
    /// arrive via the proposal-part stream.
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
    /// Builds a sorted, address-deduplicated validator set. Conflicting
    /// duplicates retain the greatest power; use `try_new` for configuration
    /// admission, which rejects conflicting powers and unsafe totals.
    pub fn new(mut validators: Vec<RoomValidator>) -> Self {
        validators.sort_by(|a, b| {
            b.power
                .cmp(&a.power)
                .then_with(|| a.address.cmp(&b.address))
        });
        let mut seen = std::collections::BTreeSet::new();
        validators.retain(|validator| seen.insert(validator.address));
        RoomValidatorSet { validators }
    }

    /// Admit a configuration, allowing repeated identical entries but never
    /// two different voting powers for the same identity.
    pub fn try_new(validators: Vec<RoomValidator>) -> Result<Self, ValidatorSetError> {
        let mut powers = std::collections::BTreeMap::new();
        for validator in &validators {
            if powers
                .insert(validator.address, validator.power)
                .is_some_and(|power| power != validator.power)
            {
                return Err(ValidatorSetError::ConflictingPower);
            }
        }
        let set = Self::new(validators);
        set.validate()?;
        Ok(set)
    }

    /// Check the trusted set before engine startup or certificate admission.
    /// The total leaves room for the engine's quorum multiplications in u64.
    pub fn validate(&self) -> Result<(), ValidatorSetError> {
        if self.validators.is_empty() {
            return Err(ValidatorSetError::Empty);
        }
        if self.validators.len() > crate::cert::MAX_CERT_SIGNATURES {
            return Err(ValidatorSetError::TooManyValidators);
        }
        // The vector is public, so callers can bypass new(). Identical
        // membership in a different order would select different proposers.
        if self.validators.windows(2).any(|pair| {
            pair[0].power < pair[1].power
                || (pair[0].power == pair[1].power && pair[0].address >= pair[1].address)
        }) {
            return Err(ValidatorSetError::InvalidValidator);
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut total = 0u64;
        for validator in &self.validators {
            if validator.power == 0
                || validator.address != Address::from_public_key(&validator.public_key)
                || !seen.insert(validator.address)
            {
                return Err(ValidatorSetError::InvalidValidator);
            }
            total = total
                .checked_add(validator.power)
                .filter(|total| *total <= u64::MAX / 3)
                .ok_or(ValidatorSetError::PowerOverflow)?;
        }
        Ok(())
    }
}

/// Invalid trusted-validator configuration; never a network vote failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidatorSetError {
    /// A voting set must contain at least one member.
    Empty,
    /// The certificate signature bound cannot represent the entire set.
    TooManyValidators,
    /// Membership has zero power, a mismatched/repeated address, or noncanonical order.
    InvalidValidator,
    /// Repeated configuration entries assign different powers to one identity.
    ConflictingPower,
    /// The total cannot safely support the engine's quorum arithmetic.
    PowerOverflow,
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
        let index = ((u128::from(height.as_u64()) + round.as_i64() as u128)
            % validator_set.count() as u128) as usize;
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
/// `"RF2" || height:u64be || round:i64be || proposer:20bytes ||
/// pol_round:i64be || keccak256(concat data bytes)`.
/// Both rounds use -1 for Nil; every u32 round remains distinct from Nil.
/// The verifier additionally resolves the scheduled proposer for this height
/// and round. RF1 signatures are not accepted on the live network.
pub fn fin_sign_bytes(init: &ProposalInit, data: &[u8]) -> Vec<u8> {
    use sha3::Digest;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(data);
    let content_hash = hasher.finalize();

    let mut out = Vec::with_capacity(3 + 8 + 8 + 20 + 8 + 32);
    out.extend_from_slice(b"RF2");
    out.extend_from_slice(&init.height.as_u64().to_be_bytes());
    out.extend_from_slice(&init.round.as_i64().to_be_bytes());
    out.extend_from_slice(&init.proposer.into_inner());
    out.extend_from_slice(&init.pol_round.as_i64().to_be_bytes());
    out.extend_from_slice(&content_hash);
    out
}

#[cfg(test)]
mod tests;
