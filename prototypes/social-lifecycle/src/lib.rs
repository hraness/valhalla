#![no_std]
#![forbid(unsafe_code)]
//! Disposable lifecycle model. Signed facts are inert; this is not a wire protocol.
extern crate alloc;
use alloc::{collections::BTreeSet, vec::Vec};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

pub type Hash = [u8; 32];
pub const LIMIT: usize = 64;
pub const HEAD_LIMIT: usize = 8;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct OwnerId(Hash);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AgentId(Hash);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct GrantId(Hash);
fn hash(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"vhalla/social-lifecycle/spike-v0/");
    h.update((domain.len() as u32).to_be_bytes());
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}
fn verifies(key: Hash, bytes: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(&key).is_ok_and(|k| {
        !k.is_weak()
            && k.verify_strict(bytes, &Signature::from_bytes(signature))
                .is_ok()
    })
}
#[derive(Clone)]
pub struct Genesis {
    controller: Hash,
    recovery: Option<Hash>,
}
impl Genesis {
    pub fn new(controller: Hash, recovery: Option<Hash>) -> Self {
        Self {
            controller,
            recovery,
        }
    }
    pub fn id(&self) -> OwnerId {
        let mut b = self.controller.to_vec();
        b.push(u8::from(self.recovery.is_some()));
        if let Some(k) = self.recovery {
            b.extend(k);
        }
        OwnerId(hash(b"owner", &b))
    }
}
#[derive(Clone)]
pub struct Binding {
    owner: OwnerId,
    control_head: Hash,
    key: Hash,
    nonce: Hash,
    owner_signature: [u8; 64],
    agent_signature: [u8; 64],
}
impl Binding {
    pub fn sign(owner: &Genesis, controller: &SigningKey, agent: &SigningKey, nonce: Hash) -> Self {
        Self::sign_at(owner.id(), owner.id().0, controller, agent, nonce)
    }
    pub fn sign_at(
        owner: OwnerId,
        control_head: Hash,
        controller: &SigningKey,
        agent: &SigningKey,
        nonce: Hash,
    ) -> Self {
        let mut b = Self {
            owner,
            control_head,
            key: agent.verifying_key().to_bytes(),
            nonce,
            owner_signature: [0; 64],
            agent_signature: [0; 64],
        };
        let bytes = b.transcript();
        b.owner_signature = controller.sign(&bytes).to_bytes();
        b.agent_signature = agent.sign(&bytes).to_bytes();
        b
    }
    fn transcript(&self) -> Hash {
        let mut b = self.owner.0.to_vec();
        b.extend(self.control_head);
        b.extend(self.key);
        b.extend(self.nonce);
        hash(b"binding", &b)
    }
    pub fn id(&self) -> AgentId {
        AgentId(self.transcript())
    }
    fn agent_valid(&self) -> bool {
        verifies(self.key, &self.transcript(), &self.agent_signature)
    }
    fn enrollment_valid(&self, control_head: Hash, controller: Hash) -> bool {
        self.control_head == control_head
            && verifies(controller, &self.transcript(), &self.owner_signature)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Grant {
    pub agent: AgentId,
    pub scope: Hash,
    pub expires: u64,
    pub nonce: Hash,
}
impl Grant {
    pub fn id(&self) -> GrantId {
        GrantId(hash(b"grant", &self.bytes()))
    }
    fn bytes(&self) -> Vec<u8> {
        let mut b = self.agent.0.to_vec();
        b.extend(self.scope);
        b.extend(self.expires.to_be_bytes());
        b.extend(self.nonce);
        b
    }
}
#[derive(Clone)]
pub enum Action {
    Grant(Grant),
    Revoke(GrantId),
    Retire(AgentId),
    Seal { grant: GrantId, heads: Vec<Hash> },
    Rotate(Hash),
}
#[derive(Clone)]
pub struct Control {
    owner: OwnerId,
    parent: Hash,
    action: Action,
    signature: [u8; 64],
    acknowledgement: [u8; 64],
}
impl Control {
    pub fn sign(
        owner: OwnerId,
        parent: Hash,
        action: Action,
        controller: &SigningKey,
        new_controller: Option<&SigningKey>,
    ) -> Self {
        let mut c = Self {
            owner,
            parent,
            action,
            signature: [0; 64],
            acknowledgement: [0; 64],
        };
        c.signature = controller.sign(&c.id()).to_bytes();
        if let Some(k) = new_controller {
            c.acknowledgement = k.sign(&c.id()).to_bytes();
        }
        c
    }
    pub fn id(&self) -> Hash {
        let mut b = self.owner.0.to_vec();
        b.extend(self.parent);
        match &self.action {
            Action::Grant(g) => {
                b.push(0);
                b.extend(g.bytes());
            }
            Action::Revoke(g) => {
                b.push(1);
                b.extend(g.0);
            }
            Action::Retire(a) => {
                b.push(2);
                b.extend(a.0);
            }
            Action::Seal { grant, heads } => {
                b.push(3);
                b.extend(grant.0);
                b.extend((heads.len() as u32).to_be_bytes());
                for h in heads {
                    b.extend(h);
                }
            }
            Action::Rotate(key) => {
                b.push(4);
                b.extend(key);
            }
        }
        hash(b"control", &b)
    }
    fn valid(&self, controller: Hash) -> bool {
        verifies(controller, &self.id(), &self.signature)
            && match &self.action {
                Action::Rotate(k) => verifies(*k, &self.id(), &self.acknowledgement),
                Action::Seal { heads, .. } => {
                    heads.len() <= HEAD_LIMIT && heads.windows(2).all(|w| w[0] < w[1])
                }
                _ => true,
            }
    }
}
/// Social register semantics live in the reducer; this lifecycle layer signs
/// and seals the typed payload without treating agent presence as retention.
#[derive(Clone)]
pub enum SocialPayload {
    Contribution(Hash),
    Follow {
        target: OwnerId,
        follows: bool,
        supersedes: Option<Hash>,
    },
    Reaction {
        target: Hash,
        value: i8,
        supersedes: Option<Hash>,
    },
}
impl SocialPayload {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let supersedes = match self {
            Self::Contribution(content) => {
                bytes.push(0);
                bytes.extend(content);
                None
            }
            Self::Follow {
                target,
                follows,
                supersedes,
            } => {
                bytes.push(1);
                bytes.extend(target.0);
                bytes.push(u8::from(*follows));
                *supersedes
            }
            Self::Reaction {
                target,
                value,
                supersedes,
            } => {
                bytes.push(2);
                bytes.extend(target);
                bytes.push(*value as u8);
                *supersedes
            }
        };
        bytes.push(u8::from(supersedes.is_some()));
        if let Some(id) = supersedes {
            bytes.extend(id);
        }
        bytes
    }
}
#[derive(Clone)]
pub struct SocialOp {
    owner: OwnerId,
    agent: AgentId,
    grant: GrantId,
    scope: Hash,
    sequence: u64,
    parent: Option<Hash>,
    payload: SocialPayload,
    claimed_time: u64,
    signature: [u8; 64],
}
/// Compatibility alias for the initial post-only counterexamples.
pub type Post = SocialOp;
impl SocialOp {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        owner: OwnerId,
        agent: AgentId,
        grant: GrantId,
        scope: Hash,
        sequence: u64,
        parent: Option<Hash>,
        content: Hash,
        claimed_time: u64,
        signer: &SigningKey,
    ) -> Self {
        Self::sign_social(
            owner,
            agent,
            grant,
            scope,
            sequence,
            parent,
            SocialPayload::Contribution(content),
            claimed_time,
            signer,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn sign_social(
        owner: OwnerId,
        agent: AgentId,
        grant: GrantId,
        scope: Hash,
        sequence: u64,
        parent: Option<Hash>,
        payload: SocialPayload,
        claimed_time: u64,
        signer: &SigningKey,
    ) -> Self {
        let mut p = Self {
            owner,
            agent,
            grant,
            scope,
            sequence,
            parent,
            payload,
            claimed_time,
            signature: [0; 64],
        };
        p.signature = signer.sign(&p.id()).to_bytes();
        p
    }
    pub fn id(&self) -> Hash {
        let mut b = self.owner.0.to_vec();
        b.extend(self.agent.0);
        b.extend(self.grant.0);
        b.extend(self.scope);
        b.extend(self.sequence.to_be_bytes());
        b.push(u8::from(self.parent.is_some()));
        if let Some(p) = self.parent {
            b.extend(p);
        }
        b.extend(self.payload.bytes());
        b.extend(self.claimed_time.to_be_bytes());
        hash(b"social-op", &b)
    }
}
#[derive(Clone, Default)]
struct Branch {
    grants: Vec<Grant>,
    revoked: BTreeSet<GrantId>,
    retired: BTreeSet<AgentId>,
}
#[derive(Clone, Default)]
pub struct View {
    branch: Branch,
    pub frozen: bool,
    pub incomplete: bool,
    /// A signed seal names history whose exact dependencies are still missing.
    /// This is independent of current grant/control completeness.
    pub history_incomplete: bool,
    /// All owner-sealed operations, including owner preferences delegated to agents.
    pub accepted_history: BTreeSet<Hash>,
    /// Only contribution operations form the declared capital cohort.
    pub cohort: BTreeSet<Hash>,
    head: Hash,
}
/// Snapshot-bound display admission, not a host effect or durable authorization.
///
/// ```compile_fail
/// use vhalla_social_lifecycle_spike::{Admission, GrantId};
/// fn fabricate(grant: GrantId) -> Admission { Admission { snapshot: [0; 32], grant } }
/// ```
///
/// ```compile_fail
/// use vhalla_social_lifecycle_spike::Admission;
/// fn duplicate(a: Admission) { let _other = a.clone(); }
/// ```
pub struct Admission {
    snapshot: Hash,
    grant: GrantId,
}
#[derive(Clone)]
pub struct Model {
    genesis: Genesis,
    bindings: Vec<Binding>,
    controls: Vec<Control>,
    posts: Vec<Post>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    Capacity,
    Invalid,
}
impl Model {
    pub fn new(genesis: Genesis) -> Self {
        Self {
            genesis,
            bindings: Vec::new(),
            controls: Vec::new(),
            posts: Vec::new(),
        }
    }
    pub fn root(&self) -> Hash {
        self.genesis.id().0
    }
    pub fn add_binding(&mut self, b: Binding) -> Result<(), Reject> {
        if b.owner != self.genesis.id() || !b.agent_valid() {
            return Err(Reject::Invalid);
        }
        if self.bindings.iter().any(|p| {
            p.id() == b.id()
                && p.owner_signature == b.owner_signature
                && p.agent_signature == b.agent_signature
        }) {
            return Ok(());
        }
        if self.bindings.len() == LIMIT {
            return Err(Reject::Capacity);
        }
        self.bindings.push(b);
        Ok(())
    }
    pub fn add_control(&mut self, c: Control) -> Result<(), Reject> {
        if c.owner != self.genesis.id()
            || matches!(&c.action,Action::Seal{heads,..} if heads.len()>HEAD_LIMIT)
        {
            return Err(Reject::Invalid);
        }
        // Keep signature variants: an invalid variant must not poison a later valid ID.
        if self.controls.iter().any(|x| {
            x.id() == c.id() && x.signature == c.signature && x.acknowledgement == c.acknowledgement
        }) {
            return Ok(());
        }
        if self.controls.len() == LIMIT {
            return Err(Reject::Capacity);
        }
        self.controls.push(c);
        Ok(())
    }
    pub fn add_post(&mut self, p: Post) -> Result<(), Reject> {
        if p.owner != self.genesis.id() {
            return Err(Reject::Invalid);
        }
        if self
            .posts
            .iter()
            .any(|x| x.id() == p.id() && x.signature == p.signature)
        {
            return Ok(());
        }
        if self.posts.len() == LIMIT {
            return Err(Reject::Capacity);
        }
        self.posts.push(p);
        Ok(())
    }
    fn binding(&self, a: AgentId) -> Option<&Binding> {
        self.bindings.iter().find(|b| b.id() == a)
    }
    fn accepted_closure(&self, grant: &Grant, heads: &[Hash]) -> (BTreeSet<Hash>, bool) {
        let mut out = BTreeSet::new();
        let mut incomplete = false;
        for head in heads {
            let mut cursor = Some(*head);
            let mut path = Vec::new();
            let mut expected = None;
            while let Some(id) = cursor {
                if path.len() == LIMIT || path.contains(&id) {
                    path.clear();
                    break;
                }
                let found = self.posts.iter().find(|p| {
                    p.id() == id
                        && p.grant == grant.id()
                        && p.agent == grant.agent
                        && p.scope == grant.scope
                        && self
                            .binding(p.agent)
                            .is_some_and(|b| verifies(b.key, &p.id(), &p.signature))
                });
                let Some(p) = found else {
                    incomplete |= !self.posts.iter().any(|p| p.id() == id);
                    path.clear();
                    break;
                };
                if expected.is_some_and(|n| n != p.sequence) {
                    path.clear();
                    break;
                }
                if p.parent.is_none() && p.sequence != 0 {
                    path.clear();
                    break;
                }
                path.push(id);
                cursor = p.parent;
                expected = p.sequence.checked_sub(1);
                if cursor.is_some() && expected.is_none() {
                    path.clear();
                    break;
                }
            }
            out.extend(path);
        }
        (out, incomplete)
    }
    pub fn view(&self) -> View {
        let mut out = View::default();
        // All authenticated branches retain committed cohort evidence. A fork
        // freezes current projections, not the signed historical evidence set.
        self.walk(
            self.root(),
            self.genesis.controller,
            Branch::default(),
            0,
            &mut out,
        );
        out
    }
    fn walk(&self, head: Hash, key: Hash, branch: Branch, depth: usize, out: &mut View) {
        if depth > LIMIT {
            out.frozen = true;
            return;
        }
        let mut children: Vec<&Control> = Vec::new();
        for c in &self.controls {
            if c.parent != head || !c.valid(key) || children.iter().any(|x| x.id() == c.id()) {
                continue;
            }
            match &c.action {
                Action::Grant(g)
                    if branch.retired.contains(&g.agent)
                        || branch.revoked.contains(&g.id())
                        || branch.grants.iter().any(|old| old.id() == g.id()) =>
                {
                    continue
                }
                Action::Grant(g) if self.binding(g.agent).is_none() => {
                    out.incomplete = true;
                    continue;
                }
                Action::Grant(g)
                    if !branch.grants.iter().any(|old| old.agent == g.agent)
                        && !self.bindings.iter().any(|binding| {
                            binding.id() == g.agent && binding.enrollment_valid(head, key)
                        }) =>
                {
                    continue;
                }
                Action::Seal { grant, .. } if !branch.grants.iter().any(|g| g.id() == *grant) => {
                    continue
                }
                _ => children.push(c),
            }
        }
        if children.len() > 1 {
            out.frozen = true;
        }
        if children.is_empty() {
            out.branch = branch;
            out.head = head;
            return;
        }
        for c in children {
            let mut b = branch.clone();
            let mut next_key = key;
            match &c.action {
                Action::Grant(g) => {
                    if self.binding(g.agent).is_none()
                        || b.retired.contains(&g.agent)
                        || b.revoked.contains(&g.id())
                        || b.grants.iter().any(|old| old.id() == g.id())
                    {
                        continue;
                    }
                    b.grants.push(*g);
                }
                Action::Revoke(g) => {
                    b.revoked.insert(*g);
                }
                Action::Retire(a) => {
                    b.retired.insert(*a);
                }
                Action::Seal { grant, heads } => {
                    let Some(g) = b.grants.iter().find(|g| g.id() == *grant) else {
                        continue;
                    };
                    let (accepted, incomplete) = self.accepted_closure(g, heads);
                    out.history_incomplete |= incomplete;
                    out.cohort.extend(accepted.iter().copied().filter(|id| {
                        self.posts.iter().any(|p| {
                            p.id() == *id && matches!(p.payload, SocialPayload::Contribution(_))
                        })
                    }));
                    out.accepted_history.extend(accepted);
                }
                Action::Rotate(k) => next_key = *k,
            }
            self.walk(c.id(), next_key, b, depth + 1, out);
        }
    }
    fn snapshot(&self) -> Hash {
        let mut ids: Vec<Hash> = self.controls.iter().map(Control::id).collect();
        ids.sort();
        ids.dedup();
        let mut b = self.root().to_vec();
        for id in ids {
            b.extend(id);
        }
        hash(b"snapshot", &b)
    }
    pub fn admit(&self, grant: GrantId, scope: Hash, now: u64) -> Option<Admission> {
        let v = self.view();
        let g = v.branch.grants.iter().find(|g| g.id() == grant)?;
        (!v.frozen
            && !v.incomplete
            && !v.branch.retired.contains(&g.agent)
            && !v.branch.revoked.contains(&grant)
            && g.scope == scope
            && now < g.expires)
            .then(|| Admission {
                snapshot: self.snapshot(),
                grant,
            })
    }
    pub fn recheck(&self, a: &Admission, scope: Hash, now: u64) -> bool {
        a.snapshot == self.snapshot() && self.admit(a.grant, scope, now).is_some()
    }
    /// Public-v1 choice: planned rotation only. Even well-signed recovery
    /// evidence cannot activate a replacement policy or erase disputed history.
    pub fn activate_recovery(
        &mut self,
        _proposal: RecoveryProposal,
    ) -> Result<(), RecoveryDisabled> {
        Err(RecoveryDisabled)
    }
    /// Recovery is an explicit signer check over a selected exact frontier and
    /// new key acknowledgement. Selection/fork resolution is not auto-applied.
    pub fn recovery_evidence(
        &self,
        frontier: Hash,
        new_key: Hash,
        signature: [u8; 64],
        ack: [u8; 64],
    ) -> bool {
        let Some(recovery) = self.genesis.recovery else {
            return false;
        };
        let transcript = recovery_transcript(self.genesis.id(), frontier, new_key);
        verifies(recovery, &transcript, &signature) && verifies(new_key, &transcript, &ack)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryDisabled;
pub struct RecoveryProposal {
    pub frontier: Hash,
    pub new_key: Hash,
    pub signature: [u8; 64],
    pub acknowledgement: [u8; 64],
}
pub fn recovery_transcript(owner: OwnerId, frontier: Hash, new_key: Hash) -> Hash {
    let mut b = owner.0.to_vec();
    b.extend(frontier);
    b.extend(new_key);
    hash(b"recovery", &b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;
    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }
    fn fixture() -> (Model, SigningKey, SigningKey, Grant, Control) {
        fixture_with_recovery(None)
    }
    fn fixture_with_recovery(
        recovery: Option<Hash>,
    ) -> (Model, SigningKey, SigningKey, Grant, Control) {
        let owner = key(1);
        let agent = key(2);
        let genesis = Genesis::new(owner.verifying_key().to_bytes(), recovery);
        let binding = Binding::sign(&genesis, &owner, &agent, [0; 32]);
        let id = binding.id();
        let mut m = Model::new(genesis);
        m.add_binding(binding).unwrap();
        let g = Grant {
            agent: id,
            scope: [3; 32],
            expires: 100,
            nonce: [0; 32],
        };
        let c = Control::sign(m.genesis.id(), m.root(), Action::Grant(g), &owner, None);
        m.add_control(c.clone()).unwrap();
        (m, owner, agent, g, c)
    }
    #[test]
    fn dual_owner_bindings_are_distinct_geneses() {
        let a = key(1);
        let b = key(3);
        let agent = key(2);
        let ga = Genesis::new(a.verifying_key().to_bytes(), None);
        let gb = Genesis::new(b.verifying_key().to_bytes(), None);
        let ba = Binding::sign(&ga, &a, &agent, [0; 32]);
        let bb = Binding::sign(&gb, &b, &agent, [0; 32]);
        assert_eq!(ba.key, bb.key);
        assert_ne!(ba.id(), bb.id());
        assert_eq!(Model::new(ga).add_binding(bb), Err(Reject::Invalid));
    }
    #[test]
    fn sealed_owner_preferences_survive_delegate_lifecycle_and_successor_updates() {
        let (mut m, owner, old_agent, grant, granted) = fixture();
        let owner_id = m.genesis.id();
        let target_owner = Genesis::new(key(8).verifying_key().to_bytes(), None).id();
        let contribution = Post::sign(
            owner_id,
            grant.agent,
            grant.id(),
            grant.scope,
            0,
            None,
            [11; 32],
            1,
            &old_agent,
        );
        let follow = SocialOp::sign_social(
            owner_id,
            grant.agent,
            grant.id(),
            grant.scope,
            1,
            Some(contribution.id()),
            SocialPayload::Follow {
                target: target_owner,
                follows: true,
                supersedes: None,
            },
            1,
            &old_agent,
        );
        let reaction = SocialOp::sign_social(
            owner_id,
            grant.agent,
            grant.id(),
            grant.scope,
            2,
            Some(follow.id()),
            SocialPayload::Reaction {
                target: [22; 32],
                value: 1,
                supersedes: None,
            },
            1,
            &old_agent,
        );
        let unsealed = SocialOp::sign_social(
            owner_id,
            grant.agent,
            grant.id(),
            grant.scope,
            3,
            Some(reaction.id()),
            SocialPayload::Follow {
                target: target_owner,
                follows: false,
                supersedes: Some(follow.id()),
            },
            1,
            &old_agent,
        );
        for op in [&contribution, &follow, &reaction, &unsealed] {
            m.add_post(op.clone()).unwrap();
        }
        let seal = Control::sign(
            owner_id,
            granted.id(),
            Action::Seal {
                grant: grant.id(),
                heads: vec![reaction.id()],
            },
            &owner,
            None,
        );
        m.add_control(seal.clone()).unwrap();
        let sealed_history = BTreeSet::from([contribution.id(), follow.id(), reaction.id()]);
        let cohort = BTreeSet::from([contribution.id()]);
        assert_eq!(m.view().accepted_history, sealed_history);
        assert_eq!(m.view().cohort, cohort);
        assert!(m.admit(grant.id(), grant.scope, grant.expires).is_none());
        assert_eq!(m.view().accepted_history, sealed_history);

        let revoke = Control::sign(
            owner_id,
            seal.id(),
            Action::Revoke(grant.id()),
            &owner,
            None,
        );
        m.add_control(revoke.clone()).unwrap();
        let retire = Control::sign(
            owner_id,
            revoke.id(),
            Action::Retire(grant.agent),
            &owner,
            None,
        );
        m.add_control(retire.clone()).unwrap();
        assert!(m.admit(grant.id(), grant.scope, 1).is_none());
        assert_eq!(m.view().accepted_history, sealed_history);
        assert!(!m.view().accepted_history.contains(&unsealed.id()));

        let successor = key(7);
        let binding = Binding::sign_at(owner_id, retire.id(), &owner, &successor, [9; 32]);
        let next_grant = Grant {
            agent: binding.id(),
            expires: 200,
            nonce: [10; 32],
            ..grant
        };
        m.add_binding(binding).unwrap();
        let next_control = Control::sign(
            owner_id,
            retire.id(),
            Action::Grant(next_grant),
            &owner,
            None,
        );
        m.add_control(next_control.clone()).unwrap();
        assert!(m.admit(next_grant.id(), grant.scope, 101).is_some());
        // Grant-local stream ancestry resets; owner-register causality refers
        // explicitly to the retained predecessor from the retired incarnation.
        let unfollow = SocialOp::sign_social(
            owner_id,
            next_grant.agent,
            next_grant.id(),
            grant.scope,
            0,
            None,
            SocialPayload::Follow {
                target: target_owner,
                follows: false,
                supersedes: Some(follow.id()),
            },
            101,
            &successor,
        );
        let clear = SocialOp::sign_social(
            owner_id,
            next_grant.agent,
            next_grant.id(),
            grant.scope,
            1,
            Some(unfollow.id()),
            SocialPayload::Reaction {
                target: [22; 32],
                value: 0,
                supersedes: Some(reaction.id()),
            },
            101,
            &successor,
        );
        m.add_post(unfollow.clone()).unwrap();
        m.add_post(clear.clone()).unwrap();
        let next_seal = Control::sign(
            owner_id,
            next_control.id(),
            Action::Seal {
                grant: next_grant.id(),
                heads: vec![clear.id()],
            },
            &owner,
            None,
        );
        m.add_control(next_seal).unwrap();
        let mut expected = sealed_history;
        expected.extend([unfollow.id(), clear.id()]);
        assert_eq!(m.view().accepted_history, expected);
        assert_eq!(m.view().cohort, cohort);
        assert!(!m.view().accepted_history.contains(&unsealed.id()));
        assert!(
            matches!(unfollow.payload, SocialPayload::Follow { supersedes: Some(id), .. } if id == follow.id())
        );
        assert!(
            matches!(clear.payload, SocialPayload::Reaction { supersedes: Some(id), .. } if id == reaction.id())
        );
    }
    #[test]
    fn exact_seal_rejects_sequence_sibling_and_scope_forgery() {
        let (mut m, owner, agent, g, c) = fixture();
        let make = |content, scope| {
            Post::sign(
                m.genesis.id(),
                g.agent,
                g.id(),
                scope,
                0,
                None,
                [content; 32],
                1,
                &agent,
            )
        };
        let p = make(1, g.scope);
        let sibling = make(2, g.scope);
        let wrong = make(3, [4; 32]);
        // Counterexample to the abandoned sequence-only cutoff.
        assert!(sibling.sequence <= p.sequence);
        assert_ne!(sibling.id(), p.id());
        m.add_post(p.clone()).unwrap();
        m.add_post(sibling.clone()).unwrap();
        m.add_post(wrong.clone()).unwrap();
        let mut heads = vec![p.id(), wrong.id()];
        heads.sort();
        let seal = Control::sign(
            m.genesis.id(),
            c.id(),
            Action::Seal {
                grant: g.id(),
                heads,
            },
            &owner,
            None,
        );
        m.add_control(seal).unwrap();
        assert_eq!(m.view().cohort, BTreeSet::from([p.id()]));
        assert!(!m.view().cohort.contains(&sibling.id()));
    }
    #[test]
    fn revoke_renew_retire_replay_never_reopens_old_authority() {
        let (mut m, owner, _, g, c) = fixture();
        let admission = m.admit(g.id(), g.scope, 1).unwrap();
        let revoke = Control::sign(m.genesis.id(), c.id(), Action::Revoke(g.id()), &owner, None);
        m.add_control(revoke.clone()).unwrap();
        assert!(!m.recheck(&admission, g.scope, 1));
        let next = Grant {
            nonce: [8; 32],
            ..g
        };
        let renew = Control::sign(
            m.genesis.id(),
            revoke.id(),
            Action::Grant(next),
            &owner,
            None,
        );
        m.add_control(renew.clone()).unwrap();
        assert!(m.admit(next.id(), g.scope, 1).is_some());
        let retire = Control::sign(
            m.genesis.id(),
            renew.id(),
            Action::Retire(g.agent),
            &owner,
            None,
        );
        m.add_control(retire.clone()).unwrap();
        let invalid = Control::sign(
            m.genesis.id(),
            retire.id(),
            Action::Grant(Grant {
                nonce: [9; 32],
                ..g
            }),
            &owner,
            None,
        );
        m.add_control(invalid).unwrap();
        m.add_control(c).unwrap();
        assert!(m.admit(g.id(), g.scope, 1).is_none());
        assert!(m.admit(next.id(), g.scope, 1).is_none());
    }
    #[test]
    fn fork_freezes_cached_admission_and_rotation_requires_both_keys() {
        let (mut m, owner, _, g, c) = fixture();
        let admission = m.admit(g.id(), g.scope, 1).unwrap();
        let new = key(4);
        let invalid = Control::sign(
            m.genesis.id(),
            c.id(),
            Action::Rotate(new.verifying_key().to_bytes()),
            &owner,
            None,
        );
        m.add_control(invalid).unwrap();
        assert!(!m.view().frozen);
        let rotate = Control::sign(
            m.genesis.id(),
            c.id(),
            Action::Rotate(new.verifying_key().to_bytes()),
            &owner,
            Some(&new),
        );
        m.add_control(rotate.clone()).unwrap();
        let sibling = Control::sign(m.genesis.id(), c.id(), Action::Revoke(g.id()), &owner, None);
        m.add_control(sibling).unwrap();
        assert!(m.view().frozen);
        assert!(!m.recheck(&admission, g.scope, 1));
        let revoked = Control::sign(
            m.genesis.id(),
            rotate.id(),
            Action::Revoke(g.id()),
            &new,
            None,
        );
        m.add_control(revoked).unwrap();
        assert!(m.admit(g.id(), g.scope, 1).is_none());
    }
    #[test]
    fn recovery_needs_predeclared_key_and_new_key_acknowledgement() {
        let owner = key(1);
        let recovery = key(5);
        let new = key(6);
        let make = |r| Model::new(Genesis::new(owner.verifying_key().to_bytes(), r));
        let m = make(Some(recovery.verifying_key().to_bytes()));
        let t = recovery_transcript(m.genesis.id(), m.root(), new.verifying_key().to_bytes());
        assert!(m.recovery_evidence(
            m.root(),
            new.verifying_key().to_bytes(),
            recovery.sign(&t).to_bytes(),
            new.sign(&t).to_bytes()
        ));
        assert!(!m.recovery_evidence(
            m.root(),
            new.verifying_key().to_bytes(),
            owner.sign(&t).to_bytes(),
            new.sign(&t).to_bytes()
        ));
        assert!(!make(None).recovery_evidence(
            m.root(),
            new.verifying_key().to_bytes(),
            recovery.sign(&t).to_bytes(),
            new.sign(&t).to_bytes()
        ));
    }
    #[test]
    fn signed_invalid_variant_cannot_poison_valid_control_or_forge_scope() {
        let (mut m, owner, agent, g, c) = fixture();
        let action = Action::Grant(Grant {
            scope: [7; 32],
            nonce: [6; 32],
            ..g
        });
        let forged = Control::sign(m.genesis.id(), c.id(), action.clone(), &agent, None);
        let forged_grant = match action {
            Action::Grant(g) => g,
            _ => unreachable!(),
        };
        m.add_control(forged).unwrap();
        assert!(!m.view().frozen);
        assert!(m.admit(forged_grant.id(), [7; 32], 1).is_none());
        let valid = Control::sign(
            m.genesis.id(),
            c.id(),
            Action::Grant(forged_grant),
            &owner,
            None,
        );
        m.add_control(valid).unwrap();
        assert!(m.admit(forged_grant.id(), [7; 32], 1).is_some());
        assert!(m.admit(forged_grant.id(), g.scope, 1).is_none());
    }
    #[test]
    fn sealed_ancestry_waits_for_dependencies_and_survives_retirement_and_fork() {
        let (mut m, owner, agent, g, c) = fixture();
        let first = Post::sign(
            m.genesis.id(),
            g.agent,
            g.id(),
            g.scope,
            0,
            None,
            [1; 32],
            u64::MAX,
            &agent,
        );
        let next = Post::sign(
            m.genesis.id(),
            g.agent,
            g.id(),
            g.scope,
            1,
            Some(first.id()),
            [2; 32],
            0,
            &agent,
        );
        let seal = Control::sign(
            m.genesis.id(),
            c.id(),
            Action::Seal {
                grant: g.id(),
                heads: vec![next.id()],
            },
            &owner,
            None,
        );
        m.add_control(seal.clone()).unwrap();
        assert!(m.view().history_incomplete);
        assert!(!m.view().incomplete);
        assert!(m.admit(g.id(), g.scope, 1).is_some());
        m.add_post(next.clone()).unwrap();
        assert!(m.view().cohort.is_empty());
        assert!(m.view().history_incomplete);
        m.add_post(first.clone()).unwrap();
        assert!(!m.view().history_incomplete);
        let cohort = BTreeSet::from([first.id(), next.id()]);
        assert_eq!(m.view().cohort, cohort);
        let retire = Control::sign(
            m.genesis.id(),
            seal.id(),
            Action::Retire(g.agent),
            &owner,
            None,
        );
        m.add_control(retire).unwrap();
        assert_eq!(m.view().cohort, cohort);
        assert!(m.admit(g.id(), g.scope, 1).is_none());
        let competing = Control::sign(
            m.genesis.id(),
            seal.id(),
            Action::Revoke(g.id()),
            &owner,
            None,
        );
        m.add_control(competing).unwrap();
        assert!(m.view().frozen);
        assert_eq!(m.view().cohort, cohort);
    }
    #[test]
    fn rotated_old_controller_cannot_append_new_control() {
        let (mut m, owner, _, g, c) = fixture();
        let next = key(9);
        let rotate = Control::sign(
            m.genesis.id(),
            c.id(),
            Action::Rotate(next.verifying_key().to_bytes()),
            &owner,
            Some(&next),
        );
        m.add_control(rotate.clone()).unwrap();
        let wrong = Control::sign(
            m.genesis.id(),
            rotate.id(),
            Action::Revoke(g.id()),
            &owner,
            None,
        );
        m.add_control(wrong).unwrap();
        assert!(m.admit(g.id(), g.scope, 1).is_some());
        let valid = Control::sign(
            m.genesis.id(),
            rotate.id(),
            Action::Revoke(g.id()),
            &next,
            None,
        );
        m.add_control(valid).unwrap();
        assert!(m.admit(g.id(), g.scope, 1).is_none());
    }
    #[test]
    fn invalid_control_does_not_fork_and_missing_binding_stays_pending() {
        let (mut m, owner, _, g, c) = fixture();
        let duplicate = Control::sign(m.genesis.id(), c.id(), Action::Grant(g), &owner, None);
        m.add_control(duplicate).unwrap();
        assert!(!m.view().frozen);
        assert!(m.admit(g.id(), g.scope, 1).is_some());
        let new_agent = key(7);
        let binding = Binding::sign_at(m.genesis.id(), c.id(), &owner, &new_agent, [3; 32]);
        let new_grant = Grant {
            agent: binding.id(),
            nonce: [1; 32],
            ..g
        };
        let pending = Control::sign(
            m.genesis.id(),
            c.id(),
            Action::Grant(new_grant),
            &owner,
            None,
        );
        m.add_control(pending).unwrap();
        assert!(m.view().incomplete);
        assert!(!m.view().frozen);
        assert!(m.admit(g.id(), g.scope, 1).is_none());
        m.add_binding(binding).unwrap();
        assert!(!m.view().incomplete);
        assert!(!m.view().frozen);
        assert!(m.admit(new_grant.id(), g.scope, 1).is_some());
    }
    #[test]
    fn postrotation_enrollment_requires_exact_current_head_and_controller() {
        let (mut m, owner, _, g, c) = fixture();
        let controller = key(8);
        let agent = key(9);
        let rotate = Control::sign(
            m.genesis.id(),
            c.id(),
            Action::Rotate(controller.verifying_key().to_bytes()),
            &owner,
            Some(&controller),
        );
        m.add_control(rotate.clone()).unwrap();
        let bad = Binding::sign_at(m.genesis.id(), rotate.id(), &owner, &agent, [8; 32]);
        let good = Binding::sign_at(m.genesis.id(), rotate.id(), &controller, &agent, [8; 32]);
        assert_eq!(bad.id(), good.id()); // Signature variants must not poison this identity.
        let fresh = Grant {
            agent: good.id(),
            nonce: [1; 32],
            ..g
        };
        let grant = Control::sign(
            m.genesis.id(),
            rotate.id(),
            Action::Grant(fresh),
            &controller,
            None,
        );
        m.add_control(grant).unwrap();
        m.add_binding(bad).unwrap();
        assert!(m.admit(fresh.id(), g.scope, 1).is_none());
        m.add_binding(good).unwrap();
        assert!(m.admit(fresh.id(), g.scope, 1).is_some());
        let stale_binding =
            Binding::sign_at(m.genesis.id(), c.id(), &controller, &key(10), [9; 32]);
        let stale_grant = Grant {
            agent: stale_binding.id(),
            nonce: [2; 32],
            ..g
        };
        m.add_binding(stale_binding).unwrap();
        let stale = Control::sign(
            m.genesis.id(),
            rotate.id(),
            Action::Grant(stale_grant),
            &controller,
            None,
        );
        m.add_control(stale).unwrap();
        assert!(!m.view().frozen);
        assert!(m.admit(stale_grant.id(), g.scope, 1).is_none());
    }
    #[test]
    fn unseen_historical_and_backdated_compromised_key_commits_are_indistinguishable() {
        let (m, owner, agent, g, c) = fixture();
        // World H: signed before compromise and withheld. World A: forged after
        // compromise with the same payload/claimed time and available old keys.
        // Actual creation moment has no authenticated witness in this protocol.
        let make = || {
            Post::sign(
                m.genesis.id(),
                g.agent,
                g.id(),
                g.scope,
                0,
                None,
                [4; 32],
                7,
                &agent,
            )
        };
        let historical = make();
        let forged_later = make();
        assert_eq!(historical.id(), forged_later.id());
        assert_eq!(historical.signature, forged_later.signature);
        let seal = |p: &Post| {
            Control::sign(
                m.genesis.id(),
                c.id(),
                Action::Seal {
                    grant: g.id(),
                    heads: vec![p.id()],
                },
                &owner,
                None,
            )
        };
        let before = seal(&historical);
        let after = seal(&forged_later);
        assert_eq!(before.id(), after.id());
        assert_eq!(before.signature, after.signature);
        let mut keep_all = m.clone();
        keep_all.add_post(forged_later).unwrap();
        keep_all.add_control(after).unwrap();
        assert!(keep_all.view().cohort.contains(&historical.id())); // Accept-all also admits World A.
        assert!(!m.view().cohort.contains(&historical.id())); // Fixed known cutoff also excludes World H.
    }
    #[test]
    fn recovery_disabled_is_explicit_and_preserves_retirement_cohort_and_frozen_control() {
        let recovery = key(5);
        let next = key(6);
        let (mut m, owner, agent, g, c) =
            fixture_with_recovery(Some(recovery.verifying_key().to_bytes()));
        let post = Post::sign(
            m.genesis.id(),
            g.agent,
            g.id(),
            g.scope,
            0,
            None,
            [0xdd; 32],
            1,
            &agent,
        );
        m.add_post(post.clone()).unwrap();
        let seal = Control::sign(
            m.genesis.id(),
            c.id(),
            Action::Seal {
                grant: g.id(),
                heads: vec![post.id()],
            },
            &owner,
            None,
        );
        m.add_control(seal.clone()).unwrap();
        let retire = Control::sign(
            m.genesis.id(),
            seal.id(),
            Action::Retire(g.agent),
            &owner,
            None,
        );
        m.add_control(retire).unwrap();
        let conflicting = Control::sign(
            m.genesis.id(),
            seal.id(),
            Action::Revoke(g.id()),
            &owner,
            None,
        );
        m.add_control(conflicting).unwrap();
        let transcript =
            recovery_transcript(m.genesis.id(), seal.id(), next.verifying_key().to_bytes());
        let proposal = RecoveryProposal {
            frontier: seal.id(),
            new_key: next.verifying_key().to_bytes(),
            signature: recovery.sign(&transcript).to_bytes(),
            acknowledgement: next.sign(&transcript).to_bytes(),
        };
        assert!(m.recovery_evidence(
            proposal.frontier,
            proposal.new_key,
            proposal.signature,
            proposal.acknowledgement
        ));
        let snapshot = m.snapshot();
        let cohort = m.view().cohort;
        assert_eq!(m.activate_recovery(proposal), Err(RecoveryDisabled));
        assert_eq!(m.snapshot(), snapshot);
        assert_eq!(m.view().cohort, cohort);
        assert!(m.view().frozen);
        assert!(m.admit(g.id(), g.scope, 1).is_none());
    }
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]fn expiry_reordering_and_replay_preserve_sealed_cohort(order in any::<[u8;4]>(), now in 0u64..200){
            let(m,owner,agent,g,c)=fixture();let p=Post::sign(m.genesis.id(),g.agent,g.id(),g.scope,0,None,[1;32],0,&agent);
            let seal=Control::sign(m.genesis.id(),c.id(),Action::Seal{grant:g.id(),heads:vec![p.id()]},&owner,None);
            let revoke=Control::sign(m.genesis.id(),seal.id(),Action::Revoke(g.id()),&owner,None);
            let mut a=Model::new(m.genesis.clone());a.add_binding(m.bindings[0].clone()).unwrap();
            let controls=[c,seal,revoke];let mut indexes=[0,1,2];indexes.sort_by_key(|i|order[*i]);
            for i in indexes {a.add_control(controls[i].clone()).unwrap();a.add_control(controls[i].clone()).unwrap();}
            a.add_post(p.clone()).unwrap();prop_assert_eq!(a.view().cohort,BTreeSet::from([p.id()]));
            prop_assert!(a.admit(g.id(),g.scope,now).is_none());
            prop_assert_eq!(m.admit(g.id(),g.scope,now).is_some(),now<g.expires);
        }
    }
}
