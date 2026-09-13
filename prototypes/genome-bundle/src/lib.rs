//! Reference model for signed, versioned agent/realm bundles and organelle lifecycle.
//! Not a sandbox, loader, signature system, or WASM ABI verifier.
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub type Digest32 = [u8; 32];
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Component {
    pub name: String,
    pub digest: Digest32,
    pub abi: u16,
    pub imports: BTreeSet<String>,
    pub capabilities: BTreeSet<String>,
    pub memory: u64,
    pub fuel: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Genome {
    pub id: String,
    pub version: u32,
    pub lineage: Digest32,
    pub components: Vec<Component>,
    pub policy: Digest32,
    pub revoked: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bundle {
    pub genome: Genome,
    pub parent: Option<Digest32>,
    pub digest: Digest32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    Invalid,
    Duplicate,
    Capacity,
    Revoked,
    Stale,
    Abi,
    Import,
    Capability,
    Resource,
    Lineage,
    Missing,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Attached,
    Crashed,
    Detached,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub bundle: Digest32,
    pub component: String,
    pub phase: Phase,
}
#[derive(Default)]
pub struct Registry {
    bundles: BTreeMap<Digest32, Bundle>,
    active: BTreeMap<String, Digest32>,
    revoked: BTreeSet<Digest32>,
    receipts: Vec<Receipt>,
    max_memory: u64,
    max_fuel: u64,
    max_receipts: usize,
}
impl Component {
    fn valid(&self) -> bool {
        !self.name.is_empty()
            && self.name.len() <= 64
            && self.abi > 0
            && self.memory > 0
            && self.fuel > 0
            && self.imports.is_subset(&self.capabilities)
    }
}
impl Bundle {
    pub fn new(genome: Genome, parent: Option<Digest32>) -> Self {
        let digest = hash(&canonical(&genome, parent));
        Self {
            genome,
            parent,
            digest,
        }
    }
}
impl Registry {
    pub fn with_limits(max_memory: u64, max_fuel: u64) -> Self {
        Self::with_bounds(max_memory, max_fuel, 1024)
    }

    pub fn with_bounds(max_memory: u64, max_fuel: u64, max_receipts: usize) -> Self {
        Self {
            max_memory,
            max_fuel,
            max_receipts,
            ..Default::default()
        }
    }
    pub fn admit(&mut self, b: Bundle) -> Result<Digest32, Reject> {
        if b.digest != hash(&canonical(&b.genome, b.parent)) {
            return Err(Reject::Invalid);
        }
        if self.bundles.contains_key(&b.digest) {
            return Err(Reject::Duplicate);
        }
        if b.genome.revoked || self.revoked.contains(&b.digest) {
            return Err(Reject::Revoked);
        }
        if let Some(p) = b.parent {
            let prev = self.bundles.get(&p).ok_or(Reject::Missing)?;
            if prev.genome.id != b.genome.id || b.genome.version <= prev.genome.version {
                return Err(Reject::Stale);
            };
            if b.genome.lineage != prev.genome.lineage {
                return Err(Reject::Lineage);
            }
        }
        let mut names = BTreeSet::new();
        for c in &b.genome.components {
            if !names.insert(c.name.as_str()) {
                return Err(Reject::Duplicate);
            }
            if !c.valid() {
                return Err(Reject::Import);
            };
            if c.abi != 1 {
                return Err(Reject::Abi);
            };
            if c.memory > self.max_memory {
                return Err(Reject::Resource);
            };
            if c.fuel > self.max_fuel {
                return Err(Reject::Resource);
            };
            if !c.imports.is_subset(&c.capabilities) {
                return Err(Reject::Capability);
            }
        }
        self.bundles.insert(b.digest, b.clone());
        Ok(b.digest)
    }
    pub fn activate(&mut self, id: &str, d: Digest32) -> Result<(), Reject> {
        let b = self.bundles.get(&d).ok_or(Reject::Missing)?;
        if b.genome.id != id || self.revoked.contains(&d) {
            return Err(Reject::Revoked);
        };
        self.active.insert(id.to_string(), d);
        Ok(())
    }
    pub fn revoke(&mut self, d: Digest32) {
        self.revoked.insert(d);
    }
    pub fn lifecycle(&mut self, id: &str, c: &str, p: Phase) -> Result<Receipt, Reject> {
        let d = *self.active.get(id).ok_or(Reject::Missing)?;
        if self.revoked.contains(&d) {
            return Err(Reject::Revoked);
        };
        let b = self.bundles.get(&d).ok_or(Reject::Missing)?;
        if !b.genome.components.iter().any(|x| x.name == c) {
            return Err(Reject::Missing);
        };
        if self.receipts.len() >= self.max_receipts {
            return Err(Reject::Capacity);
        }
        let r = Receipt {
            bundle: d,
            component: c.to_string(),
            phase: p,
        };
        self.receipts.push(r.clone());
        Ok(r)
    }
    pub fn rollback(&mut self, id: &str, parent: Digest32) -> Result<(), Reject> {
        let current = *self.active.get(id).ok_or(Reject::Missing)?;
        let b = self.bundles.get(&parent).ok_or(Reject::Missing)?;
        if b.genome.id != id || self.revoked.contains(&parent) {
            return Err(Reject::Revoked);
        }
        let mut cursor = Some(current);
        let mut is_ancestor = false;
        while let Some(digest) = cursor {
            if digest == parent {
                is_ancestor = true;
                break;
            }
            cursor = self.bundles.get(&digest).and_then(|bundle| bundle.parent);
        }
        if !is_ancestor {
            return Err(Reject::Lineage);
        }
        self.active.insert(id.to_string(), parent);
        Ok(())
    }
    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }

    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }
}
fn canonical(g: &Genome, p: Option<Digest32>) -> Vec<u8> {
    let mut v = Vec::new();
    put_bytes(&mut v, g.id.as_bytes());
    v.extend_from_slice(&g.version.to_be_bytes());
    v.extend_from_slice(&g.lineage);
    v.extend_from_slice(&g.policy);
    v.push(g.revoked as u8);
    match p {
        Some(parent) => {
            v.push(1);
            v.extend_from_slice(&parent);
        }
        None => v.push(0),
    }
    v.extend_from_slice(&(g.components.len() as u32).to_be_bytes());
    for c in &g.components {
        put_bytes(&mut v, c.name.as_bytes());
        v.extend_from_slice(&c.digest);
        v.extend_from_slice(&c.abi.to_be_bytes());
        v.extend_from_slice(&c.memory.to_be_bytes());
        v.extend_from_slice(&c.fuel.to_be_bytes());
        v.extend_from_slice(&(c.imports.len() as u32).to_be_bytes());
        for x in &c.imports {
            put_bytes(&mut v, x.as_bytes());
        }
        v.extend_from_slice(&(c.capabilities.len() as u32).to_be_bytes());
        for x in &c.capabilities {
            put_bytes(&mut v, x.as_bytes());
        }
    }
    v
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn hash(x: &[u8]) -> Digest32 {
    let mut h = Sha256::new();
    h.update(b"valhalla/genome/v1");
    h.update(x);
    h.finalize().into()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn c() -> Component {
        Component {
            name: "tool".into(),
            digest: [1; 32],
            abi: 1,
            imports: ["read".into()].into(),
            capabilities: ["read".into()].into(),
            memory: 4,
            fuel: 10,
        }
    }
    fn g(v: u32, l: Digest32) -> Genome {
        Genome {
            id: "a".into(),
            version: v,
            lineage: l,
            components: vec![c()],
            policy: [2; 32],
            revoked: false,
        }
    }
    #[test]
    fn upgrade_and_rollback() {
        let mut r = Registry::with_limits(8, 20);
        let x = Bundle::new(g(1, [9; 32]), None);
        let xd = r.admit(x).unwrap();
        r.activate("a", xd).unwrap();
        assert!(r.lifecycle("a", "tool", Phase::Attached).is_ok());
        let y = Bundle::new(g(2, [9; 32]), Some(xd));
        let yd = r.admit(y).unwrap();
        r.activate("a", yd).unwrap();
        r.rollback("a", xd).unwrap()
    }
    #[test]
    fn rejects_smuggling_and_stale() {
        let mut r = Registry::with_limits(8, 20);
        let mut x = c();
        x.imports.insert("write".into());
        let mut g = g(1, [1; 32]);
        g.components = vec![x];
        assert_eq!(r.admit(Bundle::new(g, None)), Err(Reject::Import));
    }
    #[test]
    fn rejects_duplicate_components_and_frames_canonical_sets() {
        let mut duplicate = g(1, [1; 32]);
        duplicate.components.push(c());
        let mut r = Registry::with_limits(8, 20);
        assert_eq!(
            r.admit(Bundle::new(duplicate, None)),
            Err(Reject::Duplicate)
        );

        let mut left = c();
        left.imports = ["ab".into()].into();
        left.capabilities = ["a".into(), "b".into(), "ab".into()].into();
        let mut right = c();
        right.imports = ["a".into(), "b".into()].into();
        right.capabilities = ["a".into(), "b".into(), "ab".into()].into();
        let mut left_genome = g(1, [2; 32]);
        left_genome.components = vec![left];
        let mut right_genome = g(1, [2; 32]);
        right_genome.components = vec![right];
        assert_ne!(
            Bundle::new(left_genome, None).digest,
            Bundle::new(right_genome, None).digest
        );
    }

    #[test]
    fn rollback_requires_an_ancestor_of_active_bundle() {
        let mut r = Registry::with_limits(8, 20);
        let root = r.admit(Bundle::new(g(1, [3; 32]), None)).unwrap();
        r.activate("a", root).unwrap();
        let active = r.admit(Bundle::new(g(2, [3; 32]), Some(root))).unwrap();
        let mut sibling_genome = g(2, [3; 32]);
        sibling_genome.policy = [7; 32];
        let sibling = r.admit(Bundle::new(sibling_genome, Some(root))).unwrap();
        r.activate("a", active).unwrap();
        assert_eq!(r.rollback("a", sibling), Err(Reject::Lineage));
    }
    #[test]
    fn revocation_blocks_lifecycle() {
        let mut r = Registry::with_limits(8, 20);
        let d = r.admit(Bundle::new(g(1, [1; 32]), None)).unwrap();
        r.activate("a", d).unwrap();
        r.revoke(d);
        assert_eq!(
            r.lifecycle("a", "tool", Phase::Crashed),
            Err(Reject::Revoked)
        );
    }

    #[test]
    fn lifecycle_receipts_fail_closed_at_capacity() {
        let mut r = Registry::with_bounds(8, 20, 1);
        let d = r.admit(Bundle::new(g(1, [4; 32]), None)).unwrap();
        r.activate("a", d).unwrap();
        assert!(r.lifecycle("a", "tool", Phase::Attached).is_ok());
        assert_eq!(r.receipt_count(), 1);
        assert_eq!(
            r.lifecycle("a", "tool", Phase::Detached),
            Err(Reject::Capacity)
        );
        assert_eq!(r.receipt_count(), 1);
    }
}
