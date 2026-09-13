use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

pub type RealmId = u64;
pub type RequestId = u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Capability {
    ReadState,
    EmitEffect,
    JoinRealm,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub id: RequestId,
    pub realm: RealmId,
    pub capability: Capability,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Denial {
    UnknownRealm,
    Revoked,
    CapabilityNotGranted,
    Oversized,
    Replay,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Verdict {
    pub decision: Decision,
    pub denial: Option<Denial>,
}

#[derive(Clone, Debug)]
struct RealmPolicy {
    grants: BTreeSet<Capability>,
    revoked: bool,
    max_bytes: usize,
    epoch: u64,
}

#[derive(Clone, Debug)]
struct SeenRequest {
    fingerprint: [u8; 32],
    epoch: u64,
    verdict: Verdict,
}

#[derive(Clone, Debug)]
pub struct ControlPlane {
    policies: BTreeMap<RealmId, RealmPolicy>,
    seen: BTreeMap<RequestId, SeenRequest>,
    max_seen: usize,
}

impl ControlPlane {
    pub fn new() -> Self {
        Self::with_limits(1024)
    }
    pub fn with_limits(max_seen: usize) -> Self {
        Self {
            policies: BTreeMap::new(),
            seen: BTreeMap::new(),
            max_seen: max_seen.max(1),
        }
    }
    pub fn admit_realm(
        &mut self,
        id: RealmId,
        grants: impl IntoIterator<Item = Capability>,
        max_bytes: usize,
    ) {
        let epoch = self
            .policies
            .get(&id)
            .map_or(0, |policy| policy.epoch.saturating_add(1));
        self.policies.insert(
            id,
            RealmPolicy {
                grants: grants.into_iter().collect(),
                revoked: false,
                max_bytes,
                epoch,
            },
        );
    }
    pub fn revoke(&mut self, id: RealmId) {
        if let Some(policy) = self.policies.get_mut(&id) {
            policy.revoked = true;
            policy.epoch = policy.epoch.saturating_add(1);
        }
    }
    pub fn evaluate(&mut self, req: &Request) -> Verdict {
        let fingerprint = fingerprint(req);
        let epoch = self
            .policies
            .get(&req.realm)
            .map_or(0, |policy| policy.epoch);
        if let Some(seen) = self.seen.get(&req.id) {
            if seen.fingerprint != fingerprint {
                return deny(Denial::Conflict);
            }
            if seen.epoch == epoch {
                return seen.verdict;
            }
        }
        let verdict = match self.policies.get(&req.realm) {
            None => deny(Denial::UnknownRealm),
            Some(p) if p.revoked => deny(Denial::Revoked),
            Some(p) if req.bytes.len() > p.max_bytes => deny(Denial::Oversized),
            Some(p) if !p.grants.contains(&req.capability) => deny(Denial::CapabilityNotGranted),
            Some(_) => Verdict {
                decision: Decision::Allow,
                denial: None,
            },
        };
        if self.seen.len() >= self.max_seen {
            if let Some(oldest) = self.seen.keys().next().copied() {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(
            req.id,
            SeenRequest {
                fingerprint,
                epoch,
                verdict,
            },
        );
        verdict
    }
    /// Return a domain-separated, canonical digest of one realm's policy.
    ///
    /// This remains a local reference-model digest: it is not a signature and
    /// does not establish authority by itself.
    pub fn policy_digest(&self, id: RealmId) -> Option<[u8; 32]> {
        self.policies.get(&id).map(|p| {
            let mut hasher = Sha256::new();
            hasher.update(b"valhalla/control-plane/policy/v1\0");
            put_u64(&mut hasher, id);
            put_u64(&mut hasher, p.epoch);
            hasher.update([u8::from(p.revoked)]);
            put_u64(&mut hasher, p.max_bytes as u64);
            put_u64(&mut hasher, p.grants.len() as u64);
            for capability in &p.grants {
                hasher.update([*capability as u8]);
            }
            hasher.finalize().into()
        })
    }
}

fn fingerprint(req: &Request) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"valhalla/control-plane/request/v1\0");
    put_u64(&mut hasher, req.realm);
    hasher.update([req.capability as u8]);
    put_u64(&mut hasher, req.bytes.len() as u64);
    hasher.update(&req.bytes);
    hasher.finalize().into()
}

fn put_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_be_bytes());
}

impl Default for ControlPlane {
    fn default() -> Self {
        Self::new()
    }
}
fn deny(reason: Denial) -> Verdict {
    Verdict {
        decision: Decision::Deny,
        denial: Some(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grants_and_revocation_are_controlled() {
        let mut c = ControlPlane::new();
        c.admit_realm(1, [Capability::ReadState], 3);
        let req = Request {
            id: 1,
            realm: 1,
            capability: Capability::ReadState,
            bytes: vec![1],
        };
        assert_eq!(c.evaluate(&req).decision, Decision::Allow);
        c.revoke(1);
        assert_eq!(
            c.evaluate(&Request { id: 2, ..req }).denial,
            Some(Denial::Revoked)
        );
    }
    #[test]
    fn unknown_and_oversized_fail_closed() {
        let mut c = ControlPlane::new();
        assert_eq!(
            c.evaluate(&Request {
                id: 1,
                realm: 9,
                capability: Capability::ReadState,
                bytes: vec![]
            })
            .decision,
            Decision::Deny
        );
        c.admit_realm(1, [Capability::ReadState], 2);
        assert_eq!(
            c.evaluate(&Request {
                id: 2,
                realm: 1,
                capability: Capability::ReadState,
                bytes: vec![0; 3]
            })
            .denial,
            Some(Denial::Oversized)
        );
    }
    #[test]
    fn replay_is_rechecked_after_revoke() {
        let mut c = ControlPlane::new();
        c.admit_realm(1, [Capability::ReadState], 10);
        let r = Request {
            id: 7,
            realm: 1,
            capability: Capability::ReadState,
            bytes: vec![],
        };
        assert_eq!(c.evaluate(&r).decision, Decision::Allow);
        c.revoke(1);
        assert_eq!(c.evaluate(&r).decision, Decision::Deny);
        assert_eq!(c.evaluate(&Request { id: 8, ..r }).decision, Decision::Deny);
    }

    #[test]
    fn request_id_cannot_cross_context() {
        let mut c = ControlPlane::new();
        c.admit_realm(1, [Capability::ReadState], 10);
        let request = Request {
            id: 1,
            realm: 1,
            capability: Capability::ReadState,
            bytes: vec![1],
        };
        assert_eq!(c.evaluate(&request).decision, Decision::Allow);
        assert_eq!(
            c.evaluate(&Request {
                capability: Capability::EmitEffect,
                ..request
            }),
            Verdict {
                decision: Decision::Deny,
                denial: Some(Denial::Conflict)
            }
        );
    }

    #[test]
    fn replay_retention_is_bounded() {
        let mut c = ControlPlane::with_limits(1);
        c.admit_realm(1, [Capability::ReadState], 10);
        for id in 1..=3 {
            assert_eq!(
                c.evaluate(&Request {
                    id,
                    realm: 1,
                    capability: Capability::ReadState,
                    bytes: vec![],
                })
                .decision,
                Decision::Allow
            );
        }
        assert_eq!(
            c.evaluate(&Request {
                id: 1,
                realm: 1,
                capability: Capability::ReadState,
                bytes: vec![],
            })
            .decision,
            Decision::Allow
        );
    }

    #[test]
    fn policy_digest_binds_epoch_and_revocation() {
        let mut c = ControlPlane::new();
        c.admit_realm(1, [Capability::ReadState], 10);
        let admitted = c.policy_digest(1).expect("admitted policy");
        c.revoke(1);
        let revoked = c.policy_digest(1).expect("revoked policy");
        assert_ne!(admitted, revoked);
    }
}
