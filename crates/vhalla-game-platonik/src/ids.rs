//! Identifiers and digest domains. Every digest is
//! `vhalla_witness::hash::digest(domain, bytes)`: SHA-256 over the domain, a
//! `u32` big-endian length, and the bytes.

use vhalla_witness::hash::digest;

/// Digest domain of a `GameManifest`.
pub const MANIFEST_DOMAIN: &[u8] = b"vhalla/game/manifest/v1";
/// Digest domain of a `SessionOpen`; its digest is the `SessionKey`.
pub const SESSION_DOMAIN: &[u8] = b"vhalla/game/session/v1";
/// Digest domain of a `GameEvent`.
pub const EVENT_DOMAIN: &[u8] = b"vhalla/game/event/v1";
/// Digest domain of a `Checkpoint`.
pub const CHECKPOINT_DOMAIN: &[u8] = b"vhalla/game/checkpoint/v1";
/// Digest domain of a `Settlement`.
pub const SETTLEMENT_DOMAIN: &[u8] = b"vhalla/game/settlement/v1";
/// Digest domain of one frame: tick, complete flag, and encoded state.
pub const FRAME_DOMAIN: &[u8] = b"vhalla/game/frame/v1";
/// Digest domain of the running trace head over frame digests.
pub const TRACE_DOMAIN: &[u8] = b"vhalla/game/trace/v1";
/// Digest domain of an `ArtifactManifest`.
pub const ARTIFACT_DOMAIN: &[u8] = b"vhalla/game/artifact/v1";
/// Digest domain of a `Block`.
pub const BLOCK_DOMAIN: &[u8] = b"vhalla/game/block/v1";
/// Signing domain of a `GameRecord`.
pub const RECORD_DOMAIN: &[u8] = b"vhalla/game/record/v1";
/// Commitment domain of the host salt in a live session.
pub const HOST_SALT_DOMAIN: &[u8] = b"vhalla/game/hostsalt/v1";

macro_rules! digest_newtype {
    ($(#[$doc:meta])* $name:ident, $domain:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            /// Digest of canonical bytes under this type's domain.
            #[must_use]
            pub fn of(bytes: &[u8]) -> Self {
                Self(digest($domain, bytes))
            }
        }
    };
}

digest_newtype!(
    /// Identity of a `GameManifest`.
    GameManifestHash,
    MANIFEST_DOMAIN
);
digest_newtype!(
    /// Identity of a `SessionOpen`; every later object carries it.
    SessionKey,
    SESSION_DOMAIN
);
digest_newtype!(
    /// Identity of a `GameEvent`; the ledger payload of an admitted event.
    GameEventDigest,
    EVENT_DOMAIN
);
digest_newtype!(
    /// Identity of a `Checkpoint`; the ledger payload of a `Seal`.
    CheckpointHash,
    CHECKPOINT_DOMAIN
);
digest_newtype!(
    /// Identity of a `Settlement`.
    SettlementHash,
    SETTLEMENT_DOMAIN
);
digest_newtype!(
    /// Identity of an `ArtifactManifest`.
    ArtifactManifestHash,
    ARTIFACT_DOMAIN
);

/// The 128-bit routing handle of a session: the first sixteen bytes of its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub u128);

impl From<SessionKey> for SessionId {
    fn from(key: SessionKey) -> Self {
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&key.0[..16]);
        Self(u128::from_be_bytes(bytes))
    }
}

/// The codec, language, and protocol a session is played under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RulesetId {
    /// `vhalla_witness::codec::VERSION`.
    pub codec: u8,
    /// `vhalla_witness::codec::LANGUAGE_FINITE_RULE_V1`.
    pub language: u8,
    /// The game protocol: `HABITAT_V1`.
    pub protocol: u8,
}

/// The only protocol: `platonik-habitat-v1`.
pub const HABITAT_V1: u8 = 1;

impl RulesetId {
    /// The v1 ruleset.
    pub const V1: Self = Self {
        codec: vhalla_witness::codec::VERSION,
        language: vhalla_witness::codec::LANGUAGE_FINITE_RULE_V1,
        protocol: HABITAT_V1,
    };
}

/// What an opaque inner artifact id hashes: the compact canonical JSON bytes of
/// the named Platonik object, or the adapter's frame trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum InnerKind {
    /// The `Experiment`; equal to Platonik's `experiment_hash`.
    PlatonikExperimentV1 = 1,
    /// The `RunResult`; equal to Platonik's `result_hash`.
    PlatonikResultV1 = 2,
    /// The whole `Receipt`; Platonik's `artifact_hash(&receipt)`.
    PlatonikReceiptV1 = 3,
    /// A habitat checkpoint object.
    PlatonikCheckpointV1 = 4,
    /// The adapter's frame trace for one `(segment, case)`.
    FrameTraceV1 = 5,
}

impl InnerKind {
    /// Decodes a discriminant.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::PlatonikExperimentV1,
            2 => Self::PlatonikResultV1,
            3 => Self::PlatonikReceiptV1,
            4 => Self::PlatonikCheckpointV1,
            5 => Self::FrameTraceV1,
            _ => return None,
        })
    }
}

/// An opaque inner artifact: the plain SHA-256 of the object its kind names.
/// Never recomputed on the default path; compared to fetched bytes only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InnerArtifactId {
    /// Which object the bytes must be.
    pub kind: InnerKind,
    /// Plain SHA-256 of the object's compact canonical bytes.
    pub sha256: [u8; 32],
}

impl InnerArtifactId {
    /// Parses Platonik's `sha256:<64 hex>` form.
    #[must_use]
    pub fn parse(kind: InnerKind, text: &str) -> Option<Self> {
        let hex = text.strip_prefix("sha256:")?;
        let bytes = vhalla_witness::vectors::unhex(hex)?;
        if bytes.len() != 32 {
            return None;
        }
        let mut sha256 = [0_u8; 32];
        sha256.copy_from_slice(&bytes);
        Some(Self { kind, sha256 })
    }
    /// Renders Platonik's `sha256:<64 hex>` form.
    #[must_use]
    pub fn render(&self) -> String {
        format!("sha256:{}", vhalla_witness::vectors::hex(&self.sha256))
    }
}
