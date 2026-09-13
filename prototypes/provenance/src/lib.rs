//! Disposable reference model for authenticated module provenance and lifecycle receipts.
//!
//! A manifest binds an artifact digest to an origin key and source locator. A bounded
//! registry validates signed manifests, signed revocations, and signed lifecycle receipts.
//! This is a protocol sketch: it intentionally does not persist state or provide consensus.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

const MANIFEST_DOMAIN: &[u8] = b"valhalla/provenance-manifest/v1";
const REVOCATION_DOMAIN: &[u8] = b"valhalla/provenance-revocation/v1";
const RECEIPT_DOMAIN: &[u8] = b"valhalla/provenance-receipt/v1";
const MAX_MODULE: usize = 128;
const MAX_SOURCE: usize = 512;
const MAX_REASON: usize = 256;
const MAX_DETAILS: usize = 1024;

/// A SHA-256 content address.
pub type Digest32 = [u8; 32];

/// A signing identity that is authorized to publish a module manifest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Origin(pub [u8; 32]);

/// A lifecycle event phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Phase {
    /// Module was admitted to a runtime.
    Attached,
    /// Module stopped responding or crashed.
    Crashed,
    /// Module was intentionally removed.
    Detached,
}

impl Phase {
    fn tag(self) -> u8 {
        match self {
            Self::Attached => 0,
            Self::Crashed => 1,
            Self::Detached => 2,
        }
    }
}

/// Unsigned module provenance statement. Every field is covered by the origin signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    /// Stable module name within an origin's namespace.
    pub module: String,
    /// Monotonic release version selected by the origin.
    pub version: u32,
    /// SHA-256 of the exact module bytes.
    pub content: Digest32,
    /// Human-readable or content-addressed source locator.
    pub source: String,
    /// Origin authorization key.
    pub origin: Origin,
    /// Issuance time in protocol seconds.
    pub issued_at: u64,
    /// Exclusive expiry time in protocol seconds.
    pub expires_at: u64,
}

impl Manifest {
    /// Build a manifest while hashing the supplied module bytes.
    #[must_use]
    pub fn new(
        module: impl Into<String>,
        version: u32,
        bytes: &[u8],
        source: impl Into<String>,
        origin: Origin,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            module: module.into(),
            version,
            content: digest(bytes),
            source: source.into(),
            origin,
            issued_at,
            expires_at,
        }
    }

    fn valid(&self) -> bool {
        !self.module.is_empty()
            && self.module.len() <= MAX_MODULE
            && !self.source.is_empty()
            && self.source.len() <= MAX_SOURCE
            && self.expires_at > self.issued_at
    }

    fn encode(&self, out: &mut Vec<u8>) -> bool {
        if !self.valid() {
            return false;
        }
        put_bytes(out, self.module.as_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.content);
        put_bytes(out, self.source.as_bytes());
        out.extend_from_slice(&self.origin.0);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        true
    }
}

/// A signed and content-addressed module manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedManifest {
    /// The signed statement.
    pub body: Manifest,
    /// Digest of the canonical signed transcript.
    pub id: Digest32,
    /// Origin signature over the transcript.
    pub signature: [u8; 64],
}

impl SignedManifest {
    /// Sign a manifest with its declared origin key.
    #[must_use]
    pub fn sign(key: &SigningKey, body: Manifest) -> Self {
        let origin = Origin(key.verifying_key().to_bytes());
        let mut body = body;
        body.origin = origin;
        let transcript = manifest_transcript(&body);
        let id = digest(&transcript);
        Self {
            body,
            id,
            signature: key.sign(&transcript).to_bytes(),
        }
    }

    fn verify(&self) -> Result<(), Reject> {
        let transcript = manifest_transcript_checked(&self.body).ok_or(Reject::InvalidBody)?;
        if digest(&transcript) != self.id {
            return Err(Reject::InvalidId);
        }
        let key =
            VerifyingKey::from_bytes(&self.body.origin.0).map_err(|_| Reject::InvalidSignature)?;
        key.verify(&transcript, &Signature::from_bytes(&self.signature))
            .map_err(|_| Reject::InvalidSignature)
    }
}

/// Signed authorization to revoke a manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Revocation {
    /// Manifest being revoked.
    pub manifest: Digest32,
    /// Reason recorded for operators and auditors.
    pub reason: String,
    /// Origin sequence number. Reusing it with different content is equivocation.
    pub sequence: u64,
    /// Revocation time in protocol seconds.
    pub at: u64,
    /// Origin key copied into the signed body.
    pub origin: Origin,
}

/// A signed revocation message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRevocation {
    /// Revocation body.
    pub body: Revocation,
    /// Content address of the canonical transcript.
    pub id: Digest32,
    /// Origin signature.
    pub signature: [u8; 64],
}

impl SignedRevocation {
    /// Sign a revocation with the manifest origin key.
    #[must_use]
    pub fn sign(key: &SigningKey, mut body: Revocation) -> Self {
        body.origin = Origin(key.verifying_key().to_bytes());
        let transcript = revocation_transcript(&body);
        Self {
            body,
            id: digest(&transcript),
            signature: key.sign(&transcript).to_bytes(),
        }
    }

    fn verify(&self) -> Result<(), Reject> {
        let transcript = revocation_transcript_checked(&self.body).ok_or(Reject::InvalidBody)?;
        if digest(&transcript) != self.id {
            return Err(Reject::InvalidId);
        }
        let key =
            VerifyingKey::from_bytes(&self.body.origin.0).map_err(|_| Reject::InvalidSignature)?;
        key.verify(&transcript, &Signature::from_bytes(&self.signature))
            .map_err(|_| Reject::InvalidSignature)
    }
}

/// Signed lifecycle evidence emitted by a runtime actor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Manifest whose bytes were observed.
    pub manifest: Digest32,
    /// Runtime actor identity. It must equal the signing key.
    pub actor: Origin,
    /// Monotonic sequence scoped to `(actor, manifest)`.
    pub sequence: u64,
    /// Lifecycle transition.
    pub phase: Phase,
    /// Observation time in protocol seconds.
    pub observed_at: u64,
    /// Optional bounded diagnostic data.
    pub details: Vec<u8>,
}

/// A signed lifecycle receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedReceipt {
    /// Receipt body.
    pub body: Receipt,
    /// Content address of the canonical transcript.
    pub id: Digest32,
    /// Actor signature.
    pub signature: [u8; 64],
}

impl SignedReceipt {
    /// Sign a receipt with the runtime actor key.
    #[must_use]
    pub fn sign(key: &SigningKey, mut body: Receipt) -> Self {
        body.actor = Origin(key.verifying_key().to_bytes());
        let transcript = receipt_transcript(&body);
        Self {
            body,
            id: digest(&transcript),
            signature: key.sign(&transcript).to_bytes(),
        }
    }

    fn verify(&self) -> Result<(), Reject> {
        let transcript = receipt_transcript_checked(&self.body).ok_or(Reject::InvalidBody)?;
        if digest(&transcript) != self.id {
            return Err(Reject::InvalidId);
        }
        let key =
            VerifyingKey::from_bytes(&self.body.actor.0).map_err(|_| Reject::InvalidSignature)?;
        key.verify(&transcript, &Signature::from_bytes(&self.signature))
            .map_err(|_| Reject::InvalidSignature)
    }
}

/// Why a signed provenance message was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    /// A field exceeded its protocol bound or had invalid chronology.
    InvalidBody,
    /// The content address did not match the canonical transcript.
    InvalidId,
    /// The Ed25519 signature did not verify.
    InvalidSignature,
    /// The manifest was already present.
    Duplicate,
    /// The manifest was expired at admission time.
    Expired,
    /// The source/origin supplied by the caller did not match the signed statement.
    SourceMismatch,
    /// The manifest is not known to this registry.
    MissingManifest,
    /// The manifest has been revoked.
    Revoked,
    /// The exact replay was already accepted.
    Replay,
    /// A sequence was reused with different signed content.
    Equivocation,
    /// The bounded registry cannot accept more records.
    Capacity,
    /// The revocation signer was not the manifest origin.
    UnauthorizedRevocation,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ReceiptKey {
    actor: Origin,
    manifest: Digest32,
    sequence: u64,
}

/// Bounded local provenance registry. It is deliberately not durable or a consensus log.
pub struct Registry {
    max_manifests: usize,
    max_receipts: usize,
    manifests: BTreeMap<Digest32, SignedManifest>,
    revoked: BTreeSet<Digest32>,
    revocation_sequences: BTreeMap<(Origin, u64), Digest32>,
    receipts: BTreeMap<ReceiptKey, Digest32>,
    receipt_log: Vec<SignedReceipt>,
}

impl Registry {
    /// Construct a registry with independent manifest and receipt capacities.
    #[must_use]
    pub fn with_limits(max_manifests: usize, max_receipts: usize) -> Self {
        Self {
            max_manifests,
            max_receipts,
            manifests: BTreeMap::new(),
            revoked: BTreeSet::new(),
            revocation_sequences: BTreeMap::new(),
            receipts: BTreeMap::new(),
            receipt_log: Vec::new(),
        }
    }

    /// Verify and store a manifest, binding it to the expected source and origin.
    pub fn admit_manifest(
        &mut self,
        manifest: SignedManifest,
        expected_origin: Origin,
        expected_source: &str,
        now: u64,
    ) -> Result<Digest32, Reject> {
        manifest.verify()?;
        if manifest.body.origin != expected_origin || manifest.body.source != expected_source {
            return Err(Reject::SourceMismatch);
        }
        if now < manifest.body.issued_at || now >= manifest.body.expires_at {
            return Err(Reject::Expired);
        }
        if self.manifests.contains_key(&manifest.id) {
            return Err(Reject::Duplicate);
        }
        if self.manifests.len() >= self.max_manifests {
            return Err(Reject::Capacity);
        }
        let id = manifest.id;
        self.manifests.insert(id, manifest);
        Ok(id)
    }

    /// Verify and apply a signed origin revocation.
    pub fn revoke(&mut self, revocation: SignedRevocation, now: u64) -> Result<(), Reject> {
        revocation.verify()?;
        let manifest = self
            .manifests
            .get(&revocation.body.manifest)
            .ok_or(Reject::MissingManifest)?;
        if revocation.body.origin != manifest.body.origin {
            return Err(Reject::UnauthorizedRevocation);
        }
        if now < revocation.body.at {
            return Err(Reject::InvalidBody);
        }
        let key = (revocation.body.origin, revocation.body.sequence);
        if let Some(existing) = self.revocation_sequences.get(&key) {
            return if *existing == revocation.id {
                Err(Reject::Replay)
            } else {
                Err(Reject::Equivocation)
            };
        }
        self.revocation_sequences.insert(key, revocation.id);
        self.revoked.insert(revocation.body.manifest);
        Ok(())
    }

    /// Verify and append a receipt, rejecting replay and equivocation.
    pub fn accept_receipt(&mut self, receipt: SignedReceipt, now: u64) -> Result<(), Reject> {
        receipt.verify()?;
        let manifest = self
            .manifests
            .get(&receipt.body.manifest)
            .ok_or(Reject::MissingManifest)?;
        if self.revoked.contains(&receipt.body.manifest) {
            return Err(Reject::Revoked);
        }
        if now >= manifest.body.expires_at || receipt.body.observed_at < manifest.body.issued_at {
            return Err(Reject::Expired);
        }
        if receipt.body.observed_at > now {
            return Err(Reject::InvalidBody);
        }
        let key = ReceiptKey {
            actor: receipt.body.actor,
            manifest: receipt.body.manifest,
            sequence: receipt.body.sequence,
        };
        if let Some(existing) = self.receipts.get(&key) {
            return if *existing == receipt.id {
                Err(Reject::Replay)
            } else {
                Err(Reject::Equivocation)
            };
        }
        if self.receipt_log.len() >= self.max_receipts {
            return Err(Reject::Capacity);
        }
        self.receipts.insert(key, receipt.id);
        self.receipt_log.push(receipt);
        Ok(())
    }

    /// Return accepted receipts in insertion order.
    #[must_use]
    pub fn receipts(&self) -> &[SignedReceipt] {
        &self.receipt_log
    }

    /// Check whether a manifest is currently revoked.
    #[must_use]
    pub fn is_revoked(&self, manifest: Digest32) -> bool {
        self.revoked.contains(&manifest)
    }
}

fn manifest_transcript(body: &Manifest) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MANIFEST_DOMAIN);
    // Signing is only used for test/reference inputs; verification applies bounds.
    put_bytes(&mut out, body.module.as_bytes());
    out.extend_from_slice(&body.version.to_be_bytes());
    out.extend_from_slice(&body.content);
    put_bytes(&mut out, body.source.as_bytes());
    out.extend_from_slice(&body.origin.0);
    out.extend_from_slice(&body.issued_at.to_be_bytes());
    out.extend_from_slice(&body.expires_at.to_be_bytes());
    out
}

fn manifest_transcript_checked(body: &Manifest) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    if !body.encode(&mut out) {
        return None;
    }
    let mut transcript = Vec::with_capacity(MANIFEST_DOMAIN.len() + out.len());
    transcript.extend_from_slice(MANIFEST_DOMAIN);
    transcript.extend_from_slice(&out);
    Some(transcript)
}

fn revocation_transcript(body: &Revocation) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(REVOCATION_DOMAIN);
    out.extend_from_slice(&body.manifest);
    put_bytes(&mut out, body.reason.as_bytes());
    out.extend_from_slice(&body.sequence.to_be_bytes());
    out.extend_from_slice(&body.at.to_be_bytes());
    out.extend_from_slice(&body.origin.0);
    out
}

fn revocation_transcript_checked(body: &Revocation) -> Option<Vec<u8>> {
    if body.reason.is_empty() || body.reason.len() > MAX_REASON {
        return None;
    }
    Some(revocation_transcript(body))
}

fn receipt_transcript(body: &Receipt) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(RECEIPT_DOMAIN);
    out.extend_from_slice(&body.manifest);
    out.extend_from_slice(&body.actor.0);
    out.extend_from_slice(&body.sequence.to_be_bytes());
    out.push(body.phase.tag());
    out.extend_from_slice(&body.observed_at.to_be_bytes());
    put_bytes(&mut out, &body.details);
    out
}

fn receipt_transcript_checked(body: &Receipt) -> Option<Vec<u8>> {
    if body.details.len() > MAX_DETAILS {
        return None;
    }
    Some(receipt_transcript(body))
}

fn digest(bytes: &[u8]) -> Digest32 {
    Sha256::digest(bytes).into()
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn manifest(origin: &SigningKey) -> SignedManifest {
        SignedManifest::sign(
            origin,
            Manifest::new(
                "worker",
                1,
                b"wasm",
                "ipfs://module",
                Origin([0; 32]),
                10,
                100,
            ),
        )
    }

    fn receipt(actor: &SigningKey, manifest: Digest32, sequence: u64) -> SignedReceipt {
        SignedReceipt::sign(
            actor,
            Receipt {
                manifest,
                actor: Origin([0; 32]),
                sequence,
                phase: Phase::Attached,
                observed_at: 20,
                details: Vec::new(),
            },
        )
    }

    #[test]
    fn source_and_origin_are_bound_before_admission() {
        let origin = key(1);
        let signed = manifest(&origin);
        let mut registry = Registry::with_limits(4, 4);
        assert_eq!(
            registry.admit_manifest(signed.clone(), Origin([9; 32]), "ipfs://module", 20),
            Err(Reject::SourceMismatch)
        );
        assert_eq!(
            registry.admit_manifest(
                signed,
                Origin(origin.verifying_key().to_bytes()),
                "ipfs://other",
                20
            ),
            Err(Reject::SourceMismatch)
        );
    }

    #[test]
    fn receipts_replay_and_equivocation_are_rejected() {
        let origin = key(1);
        let actor = key(2);
        let signed = manifest(&origin);
        let id = signed.id;
        let mut registry = Registry::with_limits(4, 4);
        registry
            .admit_manifest(
                signed,
                Origin(origin.verifying_key().to_bytes()),
                "ipfs://module",
                20,
            )
            .unwrap();
        let first = receipt(&actor, id, 1);
        assert_eq!(registry.accept_receipt(first.clone(), 20), Ok(()));
        assert_eq!(registry.accept_receipt(first, 20), Err(Reject::Replay));
        let mut conflict = receipt(&actor, id, 1);
        conflict.body.phase = Phase::Crashed;
        conflict = SignedReceipt::sign(&actor, conflict.body);
        assert_eq!(
            registry.accept_receipt(conflict, 20),
            Err(Reject::Equivocation)
        );
    }

    #[test]
    fn revocation_stops_future_receipts() {
        let origin = key(1);
        let actor = key(2);
        let signed = manifest(&origin);
        let id = signed.id;
        let mut registry = Registry::with_limits(4, 4);
        registry
            .admit_manifest(
                signed,
                Origin(origin.verifying_key().to_bytes()),
                "ipfs://module",
                20,
            )
            .unwrap();
        let revocation = SignedRevocation::sign(
            &origin,
            Revocation {
                manifest: id,
                reason: "compromised".into(),
                sequence: 1,
                at: 21,
                origin: Origin([0; 32]),
            },
        );
        registry.revoke(revocation, 21).unwrap();
        assert!(registry.is_revoked(id));
        assert_eq!(
            registry.accept_receipt(receipt(&actor, id, 1), 21),
            Err(Reject::Revoked)
        );
    }

    #[test]
    fn tampering_with_signed_transcripts_is_rejected() {
        let origin = key(1);
        let mut signed = manifest(&origin);
        signed.body.source = "ipfs://attacker".into();
        let mut registry = Registry::with_limits(4, 4);
        assert_eq!(
            registry.admit_manifest(
                signed,
                Origin(origin.verifying_key().to_bytes()),
                "ipfs://module",
                20
            ),
            Err(Reject::InvalidId)
        );
    }

    #[test]
    fn expiry_and_capacity_are_enforced() {
        let origin = key(1);
        let actor = key(2);
        let signed = manifest(&origin);
        let id = signed.id;
        let mut registry = Registry::with_limits(1, 1);
        registry
            .admit_manifest(
                signed,
                Origin(origin.verifying_key().to_bytes()),
                "ipfs://module",
                20,
            )
            .unwrap();
        assert_eq!(
            registry.accept_receipt(receipt(&actor, id, 1), 100),
            Err(Reject::Expired)
        );
        assert_eq!(registry.accept_receipt(receipt(&actor, id, 1), 20), Ok(()));
        assert_eq!(
            registry.accept_receipt(receipt(&actor, id, 2), 20),
            Err(Reject::Capacity)
        );
    }

    proptest! {
        #[test]
        fn content_hash_is_stable_and_mutation_changes_hash(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let first = digest(&bytes);
            let mut changed = bytes.clone();
            changed.push(0);
            prop_assert_ne!(first, digest(&changed));
            prop_assert_eq!(first, digest(&bytes));
        }
    }
}
