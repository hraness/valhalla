//! The audience-free signed carrier. A game object must verify identically at
//! every receiver, so it travels as a `GameRecord` whose Ed25519 signature is
//! over the `vhalla/game/record/v1` transcript of the kind byte, the session
//! key, and the object's digest under its own domain. Room delivery may wrap
//! records in per-receiver transport envelopes; that is delivery, never
//! authority.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use vhalla_witness::codec::{CodecError, Field, Reader, Writer};
use vhalla_witness::hash::digest;

use crate::ids::{
    SessionKey, ARTIFACT_DOMAIN, CHECKPOINT_DOMAIN, EVENT_DOMAIN, MANIFEST_DOMAIN, RECORD_DOMAIN,
    SESSION_DOMAIN, SETTLEMENT_DOMAIN,
};
use crate::wire::{self, MAX_GAME_EVENT_BYTES};

/// What a record carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    /// A `GameManifest`; its session key is the manifest hash.
    Manifest = 1,
    /// A `SessionOpen`; its session key is its own digest.
    SessionOpen = 2,
    /// A `GameEvent`.
    Event = 3,
    /// A `Checkpoint`.
    Checkpoint = 4,
    /// A `Settlement`.
    Settlement = 5,
    /// An `ArtifactRequest`.
    ArtifactRequest = 6,
    /// An `ArtifactManifest`.
    ArtifactManifest = 7,
}

impl RecordKind {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Manifest,
            2 => Self::SessionOpen,
            3 => Self::Event,
            4 => Self::Checkpoint,
            5 => Self::Settlement,
            6 => Self::ArtifactRequest,
            7 => Self::ArtifactManifest,
            _ => return None,
        })
    }
    /// The digest domain of the carried object.
    #[must_use]
    pub const fn domain(self) -> &'static [u8] {
        match self {
            Self::Manifest => MANIFEST_DOMAIN,
            Self::SessionOpen => SESSION_DOMAIN,
            Self::Event => EVENT_DOMAIN,
            Self::Checkpoint => CHECKPOINT_DOMAIN,
            Self::Settlement => SETTLEMENT_DOMAIN,
            Self::ArtifactRequest => ARTIFACT_DOMAIN,
            Self::ArtifactManifest => ARTIFACT_DOMAIN,
        }
    }
    /// The byte bound of the carried object.
    #[must_use]
    pub const fn max_body_bytes(self) -> usize {
        match self {
            Self::Manifest => wire::MAX_GAME_MANIFEST_BYTES,
            Self::SessionOpen => wire::MAX_SESSION_OPEN_BYTES,
            Self::Event => MAX_GAME_EVENT_BYTES,
            Self::Checkpoint => wire::MAX_CHECKPOINT_BYTES,
            Self::Settlement => wire::MAX_SETTLEMENT_BYTES,
            Self::ArtifactRequest => wire::MAX_ARTIFACT_REQUEST_BYTES,
            Self::ArtifactManifest => wire::MAX_ARTIFACT_MANIFEST_BYTES,
        }
    }
}

/// Largest record: header, the widest body, signature.
pub const MAX_RECORD_BYTES: usize = 1 + 1 + 32 + 32 + 4 + MAX_GAME_EVENT_BYTES + 64;

/// A signed game object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GameRecord {
    /// What the body is.
    pub kind: RecordKind,
    /// The session the object belongs to.
    pub session: SessionKey,
    /// The signer's full key.
    pub signer: [u8; 32],
    /// The object's canonical bytes.
    pub body: Vec<u8>,
    /// Ed25519 over the transcript.
    pub signature: [u8; 64],
}

/// Why a record is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The bytes did not decode.
    Codec(CodecError),
    /// The body exceeds its kind's bound.
    BodyTooLarge,
    /// The signer key is invalid or a known weak point.
    WeakKey,
    /// The signature does not verify.
    Signature,
}

impl From<CodecError> for RecordError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

/// The signed message: domain, length, kind, session key, object digest.
#[must_use]
pub fn transcript(kind: RecordKind, session: SessionKey, body: &[u8]) -> Vec<u8> {
    let object = digest(kind.domain(), body);
    let mut inner = Vec::with_capacity(65);
    inner.push(kind as u8);
    inner.extend_from_slice(&session.0);
    inner.extend_from_slice(&object);
    let len = u32::try_from(inner.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(RECORD_DOMAIN.len() + 4 + inner.len());
    out.extend_from_slice(RECORD_DOMAIN);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&inner);
    out
}

impl GameRecord {
    /// Signs a body.
    pub fn sign(
        kind: RecordKind,
        session: SessionKey,
        body: Vec<u8>,
        key: &SigningKey,
    ) -> Result<Self, RecordError> {
        if body.len() > kind.max_body_bytes() {
            return Err(RecordError::BodyTooLarge);
        }
        let signature = key.sign(&transcript(kind, session, &body)).to_bytes();
        Ok(Self {
            kind,
            session,
            signer: key.verifying_key().to_bytes(),
            body,
            signature,
        })
    }
    /// A record carrying no signature: `author` names the actor, the
    /// signature is zero. Admission authority is consensus proof, not this
    /// record — under `Authority::Quorum` only the quorum actor may author
    /// these, and only with a `ProvenCommitment`.
    pub fn unsigned(
        kind: RecordKind,
        session: SessionKey,
        author: [u8; 32],
        body: Vec<u8>,
    ) -> Result<Self, RecordError> {
        if body.len() > kind.max_body_bytes() {
            return Err(RecordError::BodyTooLarge);
        }
        Ok(Self {
            kind,
            session,
            signer: author,
            body,
            signature: [0; 64],
        })
    }
    /// Verifies the signature under the carried signer key; who that key may
    /// be for this kind is the session's decision, not the carrier's.
    pub fn verify(&self) -> Result<(), RecordError> {
        if self.body.len() > self.kind.max_body_bytes() {
            return Err(RecordError::BodyTooLarge);
        }
        let key = VerifyingKey::from_bytes(&self.signer).map_err(|_| RecordError::WeakKey)?;
        if key.is_weak() {
            return Err(RecordError::WeakKey);
        }
        key.verify_strict(
            &transcript(self.kind, self.session, &self.body),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| RecordError::Signature)
    }
    /// The object digest under the kind's domain.
    #[must_use]
    pub fn object_digest(&self) -> [u8; 32] {
        digest(self.kind.domain(), &self.body)
    }
    /// Canonical bytes: version, kind, session, signer, body, signature.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(70 + self.body.len() + 64);
        writer.u8(wire::VERSION);
        writer.u8(self.kind as u8);
        writer.bytes(&self.session.0);
        writer.bytes(&self.signer);
        writer.u32(self.body.len() as u32);
        writer.bytes(&self.body);
        writer.bytes(&self.signature);
        writer.finish()
    }
    /// Decodes a record without verifying it.
    pub fn decode(raw: &[u8]) -> Result<Self, RecordError> {
        let mut reader = Reader::bounded(raw, MAX_RECORD_BYTES)?;
        let found = reader.u8(Field::Version)?;
        if found != wire::VERSION {
            return Err(CodecError::UnsupportedVersion { found }.into());
        }
        let found = reader.u8(Field::Status)?;
        let kind = RecordKind::from_u8(found).ok_or(CodecError::Discriminant {
            field: Field::Status,
            found,
        })?;
        let session = SessionKey(reader.hash()?);
        let signer = reader.hash()?;
        let len = reader.u32(Field::Count)? as usize;
        if len > kind.max_body_bytes() {
            return Err(RecordError::BodyTooLarge);
        }
        let mut body = Vec::with_capacity(len);
        for _ in 0..len {
            body.push(reader.u8(Field::Cell)?);
        }
        let mut signature = [0_u8; 64];
        signature[..32].copy_from_slice(&reader.hash()?);
        signature[32..].copy_from_slice(&reader.hash()?);
        reader.finish()?;
        Ok(Self {
            kind,
            session,
            signer,
            body,
            signature,
        })
    }
}
