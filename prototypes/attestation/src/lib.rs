//! Portable attestation vocabulary for Valhalla design work.
//!
//! This crate intentionally has no vendor or cryptography dependency. It
//! models the claims and policy boundary that a real verifier must implement.
//! A boolean-looking evidence value is never accepted as cryptographic proof:
//! an external verifier must first establish `SignatureStatus::Verified`.

/// Scope bound into an attestation statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    /// Realm identifier.
    pub realm: u128,
    /// Room identifier.
    pub room: u128,
    /// Intended use, such as admission or capability negotiation.
    pub purpose: u8,
}

/// Evidence source. These categories must not be silently upgraded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceKind {
    /// Portable software statement; no hardware claim.
    PortableSoftware,
    /// Public-key proof backed by an external hardware-key verifier.
    HardwareKey,
    /// TEE/RATS quote or appraisal backed by an external verifier.
    TeeRats,
}

/// External verification status for a claim or signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureStatus {
    /// Bytes have not yet been checked by a trusted verifier.
    Unverified,
    /// A configured verifier validated the signature/quote and binding.
    Verified,
    /// Verification failed.
    Invalid,
}

/// Privacy policy for evidence disclosure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivacyPolicy {
    /// Whether to reveal a stable hardware key identifier.
    pub reveal_key_id: bool,
    /// Whether to reveal measurements or quote digests.
    pub reveal_measurements: bool,
    /// Whether platform/vendor labels may be disclosed.
    pub reveal_platform: bool,
}

/// A challenge-bound attestation statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    /// Fresh verifier challenge; prevents replay across sessions.
    pub challenge: [u8; 32],
    /// Subject identity or pseudonymous key handle.
    pub subject: [u8; 32],
    /// Realm/room/purpose binding.
    pub scope: Scope,
    /// Statement kind.
    pub kind: EvidenceKind,
    /// Issuance time.
    pub issued_at: u64,
    /// Expiry time.
    pub expires_at: u64,
    /// Digest of the implementation/model/runtime measurement, if any.
    pub measurement_digest: Option<[u8; 32]>,
    /// Hardware key handle, if any.
    pub key_id: Option<[u8; 32]>,
    /// Generic TEE/RATS quote or appraisal digest, if any.
    pub quote_digest: Option<[u8; 32]>,
    /// Platform/vendor label, kept optional for privacy.
    pub platform: Option<&'static str>,
    /// Status set only by an external verifier.
    pub status: SignatureStatus,
}

/// Why evidence was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    /// Evidence has not been externally verified.
    Unverified,
    /// Evidence was explicitly invalid.
    Invalid,
    /// Challenge mismatch makes the statement replayable in another session.
    WrongChallenge,
    /// Subject key mismatch.
    WrongSubject,
    /// Realm/room/purpose mismatch.
    WrongScope,
    /// Evidence is outside its validity interval.
    NotYetValid,
    /// Evidence has expired.
    Expired,
    /// Claimed kind does not satisfy the local policy.
    KindNotAllowed,
    /// Required evidence material is missing.
    MissingMaterial,
    /// The lifetime is malformed or excessive.
    InvalidLifetime,
}

/// Which evidence classes a local verifier accepts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptancePolicy {
    /// Current verifier time.
    pub now: u64,
    /// Maximum accepted lifetime.
    pub max_lifetime: u64,
    /// Expected challenge and scope.
    pub challenge: [u8; 32],
    /// Expected subject key.
    pub subject: [u8; 32],
    /// Expected realm/room/purpose.
    pub scope: Scope,
    /// Whether portable statements are accepted.
    pub allow_portable: bool,
    /// Whether hardware-key statements are accepted.
    pub allow_hardware: bool,
    /// Whether TEE/RATS statements are accepted.
    pub allow_tee: bool,
}

/// Validate an evidence statement against local policy.
pub fn accept(policy: AcceptancePolicy, evidence: &Evidence) -> Result<(), Reject> {
    if evidence.status == SignatureStatus::Unverified {
        return Err(Reject::Unverified);
    }
    if evidence.status == SignatureStatus::Invalid {
        return Err(Reject::Invalid);
    }
    if evidence.expires_at < evidence.issued_at
        || evidence.expires_at - evidence.issued_at > policy.max_lifetime
    {
        return Err(Reject::InvalidLifetime);
    }
    if policy.now < evidence.issued_at {
        return Err(Reject::NotYetValid);
    }
    if policy.now > evidence.expires_at {
        return Err(Reject::Expired);
    }
    if evidence.challenge != policy.challenge {
        return Err(Reject::WrongChallenge);
    }
    if evidence.subject != policy.subject {
        return Err(Reject::WrongSubject);
    }
    if evidence.scope != policy.scope {
        return Err(Reject::WrongScope);
    }
    let allowed = match evidence.kind {
        EvidenceKind::PortableSoftware => policy.allow_portable,
        EvidenceKind::HardwareKey => policy.allow_hardware,
        EvidenceKind::TeeRats => policy.allow_tee,
    };
    if !allowed {
        return Err(Reject::KindNotAllowed);
    }
    match evidence.kind {
        EvidenceKind::PortableSoftware if evidence.measurement_digest.is_none() => {
            Err(Reject::MissingMaterial)
        }
        EvidenceKind::HardwareKey if evidence.key_id.is_none() => Err(Reject::MissingMaterial),
        EvidenceKind::TeeRats if evidence.quote_digest.is_none() => Err(Reject::MissingMaterial),
        _ => Ok(()),
    }
}

/// A privacy-filtered copy suitable for sending to a peer.
pub fn disclose(evidence: &Evidence, policy: PrivacyPolicy) -> Evidence {
    let mut output = evidence.clone();
    if !policy.reveal_key_id {
        output.key_id = None;
    }
    if !policy.reveal_measurements {
        output.measurement_digest = None;
        output.quote_digest = None;
    }
    if !policy.reveal_platform {
        output.platform = None;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> AcceptancePolicy {
        AcceptancePolicy {
            now: 100,
            max_lifetime: 300,
            challenge: [1; 32],
            subject: [2; 32],
            scope: Scope {
                realm: 3,
                room: 4,
                purpose: 5,
            },
            allow_portable: true,
            allow_hardware: false,
            allow_tee: false,
        }
    }

    fn evidence() -> Evidence {
        Evidence {
            challenge: [1; 32],
            subject: [2; 32],
            scope: Scope {
                realm: 3,
                room: 4,
                purpose: 5,
            },
            kind: EvidenceKind::PortableSoftware,
            issued_at: 1,
            expires_at: 200,
            measurement_digest: Some([6; 32]),
            key_id: None,
            quote_digest: None,
            platform: Some("generic"),
            status: SignatureStatus::Verified,
        }
    }

    #[test]
    fn acceptance_requires_external_verification_and_context_binding() {
        let mut item = evidence();
        item.status = SignatureStatus::Unverified;
        assert_eq!(accept(policy(), &item), Err(Reject::Unverified));
        item = evidence();
        item.challenge[0] ^= 1;
        assert_eq!(accept(policy(), &item), Err(Reject::WrongChallenge));
        item = evidence();
        item.scope.room = 99;
        assert_eq!(accept(policy(), &item), Err(Reject::WrongScope));
    }

    #[test]
    fn evidence_classes_cannot_upgrade_each_other() {
        let mut item = evidence();
        item.kind = EvidenceKind::HardwareKey;
        assert_eq!(accept(policy(), &item), Err(Reject::KindNotAllowed));
        item = evidence();
        item.kind = EvidenceKind::TeeRats;
        assert_eq!(accept(policy(), &item), Err(Reject::KindNotAllowed));
    }

    #[test]
    fn disclosure_strips_sensitive_material_by_default() {
        let item = evidence();
        let redacted = disclose(
            &item,
            PrivacyPolicy {
                reveal_key_id: false,
                reveal_measurements: false,
                reveal_platform: false,
            },
        );
        assert_eq!(redacted.measurement_digest, None);
        assert_eq!(redacted.key_id, None);
        assert_eq!(redacted.platform, None);
        assert_eq!(redacted.challenge, item.challenge);
    }
}
