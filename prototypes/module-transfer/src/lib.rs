//! Controlled horizontal module transfer model. Transparent reference path only.
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
pub type Hash = [u8; 32];
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Module {
    pub name: String,
    pub hash: Hash,
    pub lineage: Hash,
    pub abi: u16,
    pub capabilities: BTreeSet<String>,
    pub realm: String,
    pub version: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transfer {
    pub module: Module,
    pub source: String,
    pub target: String,
    pub nonce: u64,
    pub expires: u64,
    pub receipt: Hash,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    Invalid,
    Replay,
    Downgrade,
    CrossRealm,
    Expired,
    Revoked,
    Capability,
}
#[derive(Default)]
pub struct Broker {
    seen: BTreeSet<Hash>,
    revoked: BTreeSet<Hash>,
    installed: BTreeMap<(String, String), Module>,
    now: u64,
}
impl Transfer {
    pub fn new(module: Module, source: &str, target: &str, nonce: u64, expires: u64) -> Self {
        let receipt = hash(&encode(&module, source, target, nonce, expires));
        Self {
            module,
            source: source.into(),
            target: target.into(),
            nonce,
            expires,
            receipt,
        }
    }
}
impl Broker {
    pub fn at(now: u64) -> Self {
        Self {
            now,
            ..Default::default()
        }
    }
    pub fn revoke(&mut self, h: Hash) {
        self.revoked.insert(h);
    }
    pub fn install(&mut self, t: Transfer) -> Result<Hash, Reject> {
        if t.expires < self.now {
            return Err(Reject::Expired);
        }
        if t.receipt != hash(&encode(&t.module, &t.source, &t.target, t.nonce, t.expires)) {
            return Err(Reject::Invalid);
        }
        if self.seen.contains(&t.receipt) {
            return Err(Reject::Replay);
        }
        if self.revoked.contains(&t.module.hash) {
            return Err(Reject::Revoked);
        }
        if t.source == t.target || t.module.realm != t.target {
            return Err(Reject::CrossRealm);
        }
        if t.module
            .capabilities
            .iter()
            .any(|x| x.starts_with("undeclared:"))
        {
            return Err(Reject::Capability);
        }
        let k = (t.target.clone(), t.module.name.clone());
        if let Some(old) = self.installed.get(&k) {
            if old.lineage != t.module.lineage
                || t.module.version < old.version
                || (t.module.version == old.version && old.hash != t.module.hash)
            {
                return Err(Reject::Downgrade);
            }
        }
        self.seen.insert(t.receipt);
        self.installed.insert(k, t.module);
        Ok(t.receipt)
    }
    pub fn get(&self, realm: &str, name: &str) -> Option<&Module> {
        let module = self.installed.get(&(realm.into(), name.into()))?;
        if self.revoked.contains(&module.hash) {
            None
        } else {
            Some(module)
        }
    }
}
fn encode(m: &Module, s: &str, t: &str, n: u64, e: u64) -> Vec<u8> {
    let mut v = Vec::new();
    put_bytes(&mut v, m.name.as_bytes());
    v.extend_from_slice(&m.hash);
    v.extend_from_slice(&m.lineage);
    v.extend_from_slice(&m.abi.to_be_bytes());
    v.extend_from_slice(&m.version.to_be_bytes());
    put_bytes(&mut v, m.realm.as_bytes());
    put_bytes(&mut v, s.as_bytes());
    put_bytes(&mut v, t.as_bytes());
    v.extend_from_slice(&n.to_be_bytes());
    v.extend_from_slice(&e.to_be_bytes());
    v.extend_from_slice(&(m.capabilities.len() as u32).to_be_bytes());
    for c in &m.capabilities {
        put_bytes(&mut v, c.as_bytes());
    }
    v
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn hash(x: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"valhalla/module-transfer/v1");
    h.update(x);
    h.finalize().into()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn m(v: u32, r: &str) -> Module {
        Module {
            name: "skill".into(),
            hash: [4; 32],
            lineage: [5; 32],
            abi: 1,
            capabilities: ["read".into()].into(),
            realm: r.into(),
            version: v,
        }
    }
    #[test]
    fn atomic_transfer_and_replay() {
        let mut b = Broker::at(1);
        let t = Transfer::new(m(1, "dst"), "src", "dst", 7, 2);
        let h = b.install(t.clone()).unwrap();
        assert_eq!(b.get("dst", "skill").unwrap().version, 1);
        assert_eq!(b.install(t), Err(Reject::Replay));
        assert_ne!(h, [0; 32]);
    }
    #[test]
    fn rejects_downgrade_and_cross_realm() {
        let mut b = Broker::at(1);
        let t = Transfer::new(m(2, "dst"), "src", "dst", 1, 3);
        b.install(t).unwrap();
        assert_eq!(
            b.install(Transfer::new(m(1, "dst"), "src", "dst", 2, 3)),
            Err(Reject::Downgrade)
        );
        assert_eq!(
            b.install(Transfer::new(m(3, "other"), "src", "dst", 3, 3)),
            Err(Reject::CrossRealm)
        );
    }
    #[test]
    fn rejects_same_version_equivocation_and_hides_revoked_module() {
        let mut b = Broker::at(1);
        let first = Transfer::new(m(1, "dst"), "src", "dst", 1, 3);
        let module_hash = first.module.hash;
        b.install(first).unwrap();

        let mut replacement = m(1, "dst");
        replacement.hash = [8; 32];
        assert_eq!(
            b.install(Transfer::new(replacement, "src", "dst", 2, 3)),
            Err(Reject::Downgrade)
        );

        b.revoke(module_hash);
        assert!(b.get("dst", "skill").is_none());
    }
    #[test]
    fn failure_leaves_target_unchanged() {
        let mut b = Broker::at(1);
        let t = Transfer::new(m(1, "dst"), "src", "dst", 1, 0);
        assert_eq!(b.install(t), Err(Reject::Expired));
        assert!(b.get("dst", "skill").is_none());
    }
}
