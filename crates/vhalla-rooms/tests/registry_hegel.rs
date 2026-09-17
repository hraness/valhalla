//! Generative registry command sequences under Hegel's interleaved draw model.
//!
//! `registry.rs` pins each rule with a fixed trace; these properties draw the
//! trace instead. Every command is generated against the state accumulated so
//! far — open grants, current revision heads, awarded support tuples, stale
//! bases — and a model replaying the registry's own check order predicts each
//! outcome, so an order-dependent divergence fails the case and shrinks.
//!
//! Two properties split the oracle naturally: the first interleaves every
//! command kind and asserts full model agreement after each step; the second
//! forces a snapshot/restore between commands and asserts the restored
//! registry is byte-identical and still enforces dedup afterwards.
mod common;
use common::*;

use ed25519_dalek::SigningKey;
use hegel::generators as gs;
use hegel::TestCase;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use vhalla_rooms::{
    awards::AwardDenial,
    registry::{Account, Applied, DirectoryPolicy, Registry, RegistryError},
    CreateAction, CreationIntent, Denial, Description, OwnerPermit, PolicyId, RoomControl,
    RoomGenesisId, RoomRecordId, RoomUpdate, SignedRecord, Slug, UpdateAction, VerifiedRecord,
};
use vhalla_social::{
    archive::{Archive, Limits},
    control::ControlView,
    wire::VerifiedRecord as SocialVerified,
    Actor, Body, Operation, OwnerId, Reaction, RecordId, References,
};

/// The drawn policy: a tight lifetime bound so drawn traces reach `Slot`
/// exhaustion within a few dozen commands.
fn gen_policy() -> DirectoryPolicy {
    DirectoryPolicy {
        base_cost: 1,
        window_seconds: EPOCH,
        max_in_window: 1,
        support_epoch_seconds: EPOCH,
        max_lifetime_rooms: 2,
    }
}

/// Generous archive bounds: capacity pressure never gates the social evidence
/// these tests mint, so authority denials come only from the drawn claims.
fn gen_limits() -> Limits {
    Limits {
        records: 4096,
        control_reserve: 512,
        data_per_owner: 512,
        data_per_writer: 256,
        control_per_owner: 256,
        pending: 1024,
        pending_per_signer: 128,
    }
}

/// `common::react_to_post` keyed by beneficiary id, so a creator can react to
/// its own post (self-support denial) without a conflicting borrow.
fn react(archive: &mut Archive, source: &mut Owner, beneficiary: OwnerId) -> SocialVerified {
    let post = archive
        .records()
        .find_map(|r| match r.body() {
            Body::Social {
                actor,
                operation: Operation::Post { .. },
                ..
            } if actor.owner() == beneficiary => Some(r.id()),
            _ => None,
        })
        .unwrap();
    let record = sign(
        Body::Social {
            actor: Actor::Agent {
                owner: source.id,
                agent: source.agent,
                grant: source.grant,
            },
            realm: REALM,
            sequence: source.social_seq,
            previous: source.social_head,
            operation: Operation::React {
                post,
                reaction: Reaction::Up(post),
                supersedes: References::default(),
            },
        },
        &source.agent_key,
        None,
    );
    source.social_seq += 1;
    source.social_head = Some(record.id());
    ingest(archive, &record);
    seal(archive, source, &[record.id()]);
    vhalla_social::SignedRecord::decode(&record.encode())
        .unwrap()
        .verify()
        .unwrap()
}

/// One owner's agreed room-control chain as the model tracks it.
#[derive(Default)]
struct ChainModel {
    head: Option<RoomRecordId>,
    sequence: u64,
    /// Every admitted control record; all but the last are stale bases.
    history: Vec<RoomRecordId>,
    /// Currently open `GrantCreate` records.
    open: Vec<RoomRecordId>,
    /// Revoked grant ids — real records that no longer authorize.
    closed: Vec<RoomRecordId>,
    /// Open grants to their `maximum_charge` bound.
    max_charge: BTreeMap<RoomRecordId, u64>,
}

/// A finalized room mirrored for expectation checks, tombstones included.
struct RoomModel {
    slug: String,
    genesis: RoomGenesisId,
    /// Index into `World::creators`.
    owner: usize,
    head: RoomRecordId,
    /// Creation record id plus every admitted update, in chain order.
    history: Vec<RoomRecordId>,
    archived: bool,
    description: String,
}

/// The drawn world: a real archive and registry plus the model state each
/// command's oracle needs.
struct World {
    archive: Archive,
    registry: Registry,
    /// Beneficiary owners that create rooms; each holds one committed post.
    creators: Vec<Owner>,
    /// Award sources admitted eligible at genesis.
    sources: Vec<Owner>,
    /// A real owner that never creates: the non-owner identity.
    outsider: Owner,
    /// The agreed clock; monotonically advances by drawn deltas.
    now: u64,
    last_time: u64,
    revision: u64,
    /// Monotonic salt for record nonces and never-admitted ids.
    nonce: u64,
    slugs: u64,
    eligible: BTreeSet<OwnerId>,
    /// Accepted `(beneficiary, source, epoch)` dedup triples.
    awarded: BTreeSet<(OwnerId, OwnerId, u64)>,
    /// Evidence the registry retained (accepted or tuple-deduplicated).
    accepted: Vec<(SocialVerified, OwnerId, OwnerId)>,
    /// Evidence assessment denied; resubmission re-derives the denial.
    rejected: Vec<(SocialVerified, OwnerId, OwnerId)>,
    /// Admitted creation records, kept for exact-retry commands.
    creates: Vec<SignedRecord>,
    /// Room-control chains per creator.
    chains: Vec<ChainModel>,
    /// Superseded social heads per creator — stale-basis ammunition.
    prev_social: Vec<Vec<RecordId>>,
    rooms: Vec<RoomModel>,
    by_genesis: BTreeMap<RoomGenesisId, usize>,
    accounts: BTreeMap<OwnerId, Account>,
    windows: BTreeMap<OwnerId, VecDeque<u64>>,
    /// Every admitted room record id, for `source_proof` round-trips.
    proofs: Vec<RoomRecordId>,
}

impl World {
    fn new(tc: &TestCase) -> Self {
        let mut archive = Archive::new(REALM, gen_limits()).unwrap();
        let creators_n = 1 + tc.draw(gs::integers::<usize>().max_value(2));
        let sources_n = 1 + tc.draw(gs::integers::<usize>().max_value(3));
        let creators: Vec<Owner> = (1..=creators_n as u8)
            .map(|seed| beneficiary(&mut archive, seed))
            .collect();
        let sources: Vec<Owner> = (0..sources_n as u8)
            .map(|seed| owner(&mut archive, 60 + seed))
            .collect();
        let outsider = owner(&mut archive, 120);
        let eligible: BTreeSet<OwnerId> = sources.iter().map(|s| s.id).collect();
        let ids: Vec<OwnerId> = eligible.iter().copied().collect();
        let registry = Registry::new(DIRECTORY, REALM, gen_policy(), &ids).unwrap();
        World {
            archive,
            registry,
            chains: (0..creators_n).map(|_| ChainModel::default()).collect(),
            prev_social: (0..creators_n).map(|_| Vec::new()).collect(),
            creators,
            sources,
            outsider,
            now: 1_000,
            last_time: 0,
            revision: 0,
            nonce: 0,
            slugs: 0,
            eligible,
            awarded: BTreeSet::new(),
            accepted: Vec::new(),
            rejected: Vec::new(),
            creates: Vec::new(),
            rooms: Vec::new(),
            by_genesis: BTreeMap::new(),
            accounts: BTreeMap::new(),
            windows: BTreeMap::new(),
            proofs: Vec::new(),
        }
    }

    /// A nonzero per-case salt: record nonces and never-admitted record ids.
    fn salt(&mut self) -> [u8; 32] {
        self.nonce += 1;
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&self.nonce.to_be_bytes());
        out
    }

    /// Mostly stay inside one support epoch and rate window; sometimes cross.
    fn advance(&mut self, tc: &TestCase) {
        let pick = tc.draw(gs::integers::<usize>().max_value(9));
        self.now += [0, 0, 0, 1, 600, 3_600, EPOCH, EPOCH, 2 * EPOCH, 5 * EPOCH][pick];
    }

    fn apply_verified(&mut self, record: &VerifiedRecord) -> Result<Applied, RegistryError> {
        let view = ControlView::new(&self.archive, self.now);
        self.registry.apply(record, &view, self.now)
    }

    fn award_verified(&mut self, record: &SocialVerified) -> Result<Applied, RegistryError> {
        let view = ControlView::new(&self.archive, self.now);
        self.registry.award(record, &view, self.now)
    }

    /// The claimed owner's accepted social head and controller key.
    fn owner_basis(&self, owner: OwnerId) -> (RecordId, [u8; 32]) {
        if owner == self.outsider.id {
            (
                self.outsider.head,
                self.outsider.key.verifying_key().to_bytes(),
            )
        } else {
            let creator = self.creators.iter().find(|c| c.id == owner).unwrap();
            (creator.head, creator.key.verifying_key().to_bytes())
        }
    }

    /// Draw one command from the accumulated state and check it against the
    /// model. `allow_snapshot` gates the snapshot/restore command for the
    /// restore-every-step property.
    fn command(&mut self, tc: &TestCase, allow_snapshot: bool) {
        match tc.draw(gs::integers::<u8>().max_value(14)) {
            0..=2 => self.award(tc),
            3 | 4 => self.control(tc),
            5..=7 => self.create(tc),
            8 | 9 => {
                if self.rooms.is_empty() {
                    self.award(tc);
                } else {
                    self.update(tc);
                }
            }
            10 => {
                if self.creates.is_empty() {
                    self.award(tc);
                } else {
                    self.retry(tc);
                }
            }
            11 => self.award_probe(tc),
            12 => self.configure(tc),
            13 => {
                if allow_snapshot {
                    self.restore_and_verify();
                } else {
                    self.search_check(tc);
                }
            }
            _ => self.search_check(tc),
        }
    }

    /// One committed up-reaction applied through `Registry::award`, with the
    /// `(beneficiary, source, epoch)` dedup tuple mirrored in the model.
    /// Sources are drawn from the eligible pool plus the creators: a creator
    /// reacting to its own post exercises `SelfSupport`, and `set_eligible`
    /// can admit creators as sources.
    fn award(&mut self, tc: &TestCase) {
        let pool = self.sources.len() + self.creators.len();
        let pick = tc.draw(gs::integers::<usize>().max_value(pool - 1));
        let bi = tc.draw(gs::integers::<usize>().max_value(self.creators.len() - 1));
        let beneficiary = self.creators[bi].id;
        let source = if pick < self.sources.len() {
            self.sources[pick].id
        } else {
            self.creators[pick - self.sources.len()].id
        };
        let record = if pick < self.sources.len() {
            react(&mut self.archive, &mut self.sources[pick], beneficiary)
        } else {
            let ci = pick - self.sources.len();
            // Sealing the source chain moves its accepted social basis.
            self.prev_social[ci].push(self.creators[ci].head);
            react(&mut self.archive, &mut self.creators[ci], beneficiary)
        };
        self.submit_award(record, source, beneficiary);
    }

    /// Resubmit retained or previously denied evidence, or offer a committed
    /// non-react record that can never justify credit.
    fn award_probe(&mut self, tc: &TestCase) {
        let pool = self.accepted.len() + self.rejected.len();
        if pool == 0 || tc.draw(gs::booleans()) {
            let post = self
                .archive
                .records()
                .find(|r| {
                    matches!(
                        r.body(),
                        Body::Social {
                            operation: Operation::Post { .. },
                            ..
                        }
                    )
                })
                .unwrap()
                .clone();
            assert_eq!(
                self.award_verified(&post),
                Err(RegistryError::Award(AwardDenial::NotSupport))
            );
            return;
        }
        let pick = tc.draw(gs::integers::<usize>().max_value(pool - 1));
        let (record, source, beneficiary) = if pick < self.accepted.len() {
            self.accepted[pick].clone()
        } else {
            self.rejected[pick - self.accepted.len()].clone()
        };
        self.submit_award(record, source, beneficiary);
    }

    /// Apply one piece of award evidence with the model's expectation. The
    /// order mirrors `Registry::award`: retained evidence id, then
    /// `assess_support`, then the dedup tuple, then the credit.
    fn submit_award(&mut self, record: SocialVerified, source: OwnerId, beneficiary: OwnerId) {
        let epoch = self.now / EPOCH;
        let key = (beneficiary, source, epoch);
        let expected = if self.accepted.iter().any(|(r, ..)| r.id() == record.id()) {
            Ok(Applied::DuplicateAward)
        } else if source == beneficiary {
            Err(RegistryError::Award(AwardDenial::SelfSupport))
        } else if !self.eligible.contains(&source) {
            Err(RegistryError::Award(AwardDenial::Ineligible))
        } else if self.awarded.contains(&key) {
            Ok(Applied::DuplicateAward)
        } else {
            Ok(Applied::Awarded)
        };
        assert_eq!(self.award_verified(&record), expected);
        match expected {
            Ok(Applied::Awarded) => {
                self.awarded.insert(key);
                self.accepted.push((record, source, beneficiary));
                self.accounts.entry(beneficiary).or_default().earned += 1;
                self.last_time = self.now;
                self.revision += 1;
            }
            // Tuple-deduplicated evidence is still retained; it moves nothing.
            Ok(Applied::DuplicateAward) => self.accepted.push((record, source, beneficiary)),
            Err(_) => self.rejected.push((record, source, beneficiary)),
            _ => unreachable!("award yields only award outcomes"),
        }
    }

    /// A room-control record: mostly a fresh `GrantCreate` on the current
    /// head, sometimes a `RevokeGrant` of an open, closed or foreign grant.
    fn control(&mut self, tc: &TestCase) {
        let ci = tc.draw(gs::integers::<usize>().max_value(self.creators.len() - 1));
        if self.chains[ci].open.is_empty() || tc.draw(gs::booleans()) {
            self.grant(tc, ci);
        } else {
            self.revoke(tc, ci);
        }
    }

    /// A drawn `GrantCreate`: occasionally a stale social basis or an
    /// already-closed deadline to reach authority denials.
    fn grant(&mut self, tc: &TestCase, ci: usize) {
        let stale =
            !self.prev_social[ci].is_empty() && tc.draw(gs::integers::<u8>().max_value(4)) == 4;
        let social_control = if stale {
            let pick = tc.draw(gs::integers::<usize>().max_value(self.prev_social[ci].len() - 1));
            self.prev_social[ci][pick]
        } else {
            self.creators[ci].head
        };
        let expires = if tc.draw(gs::integers::<u8>().max_value(9)) == 9 {
            self.now
        } else {
            EXPIRES
        };
        // A tiny maximum lets later creates reach the Charge denial.
        let maximum = if tc.draw(gs::booleans()) { 1 } else { 1_000 };
        self.grant_inner(ci, social_control, expires, maximum);
    }

    fn grant_inner(&mut self, ci: usize, social_control: RecordId, expires: u64, maximum: u64) {
        let nonce = self.salt();
        let chain = &self.chains[ci];
        let record = RoomControl {
            directory: DIRECTORY,
            realm: REALM,
            owner: self.creators[ci].id,
            social_control,
            controller_key: self.creators[ci].key.verifying_key().to_bytes(),
            previous: chain.head,
            sequence: chain.sequence,
            action: CreateAction::GrantCreate {
                agent: self.creators[ci].agent,
                agent_key: self.creators[ci].agent_key.verifying_key().to_bytes(),
                expires_at: expires,
                maximum_charge: maximum,
                nonce,
            },
        }
        .sign_with_key(&self.creators[ci].key)
        .unwrap()
        .verify()
        .unwrap();
        // admit(): owner status, agent status, then the grant deadline.
        let expected = if social_control != self.creators[ci].head {
            Err(RegistryError::Authority(Denial::StaleSocialBasis))
        } else if expires <= self.now {
            Err(RegistryError::Authority(Denial::Expired))
        } else {
            Ok(Applied::Control)
        };
        assert_eq!(self.apply_verified(&record), expected);
        if expected.is_ok() {
            let chain = &mut self.chains[ci];
            chain.head = Some(record.id());
            chain.sequence += 1;
            chain.history.push(record.id());
            chain.open.push(record.id());
            chain.max_charge.insert(record.id(), maximum);
            self.proofs.push(record.id());
            self.last_time = self.now;
            self.revision += 1;
        }
    }

    /// A `RevokeGrant` naming an open grant, a closed one, or an id the chain
    /// never admitted — the latter two are denied by `Denial::Grant`.
    fn revoke(&mut self, tc: &TestCase, ci: usize) {
        let mode = tc.draw(gs::integers::<u8>().max_value(9));
        let (open_len, closed_len) = (self.chains[ci].open.len(), self.chains[ci].closed.len());
        let target = match mode {
            0..=5 if open_len > 0 => {
                let pick = tc.draw(gs::integers::<usize>().max_value(open_len - 1));
                self.chains[ci].open[pick]
            }
            6 | 7 if closed_len > 0 => {
                let pick = tc.draw(gs::integers::<usize>().max_value(closed_len - 1));
                self.chains[ci].closed[pick]
            }
            _ => RoomRecordId::from_bytes(self.salt()),
        };
        let chain = &self.chains[ci];
        let record = RoomControl {
            directory: DIRECTORY,
            realm: REALM,
            owner: self.creators[ci].id,
            social_control: self.creators[ci].head,
            controller_key: self.creators[ci].key.verifying_key().to_bytes(),
            previous: chain.head,
            sequence: chain.sequence,
            action: CreateAction::RevokeGrant { grant: target },
        }
        .sign_with_key(&self.creators[ci].key)
        .unwrap()
        .verify()
        .unwrap();
        // The chain order is always right; only grant openness decides.
        let expected = if self.chains[ci].open.contains(&target) {
            Ok(Applied::Control)
        } else {
            Err(RegistryError::Authority(Denial::Grant))
        };
        assert_eq!(self.apply_verified(&record), expected);
        if expected.is_ok() {
            let chain = &mut self.chains[ci];
            chain.head = Some(record.id());
            chain.sequence += 1;
            chain.history.push(record.id());
            chain.open.retain(|grant| *grant != target);
            chain.max_charge.remove(&target);
            chain.closed.push(target);
            self.proofs.push(record.id());
            self.last_time = self.now;
            self.revision += 1;
        }
    }

    /// A drawn creation intent. Most draws are fully consistent with the live
    /// state; the rest corrupt fields independently — stale social or room
    /// bases, unadmitted or closed grants, foreign policies, taken slugs,
    /// wrong slots and charges — so denials compose with accounting checks in
    /// the registry's own order.
    fn create(&mut self, tc: &TestCase) {
        let ci = tc.draw(gs::integers::<usize>().max_value(self.creators.len() - 1));
        let fully_valid = tc.draw(gs::integers::<u8>().max_value(9)) < 6;
        if fully_valid && self.chains[ci].open.is_empty() {
            // The agreed order admits a grant first — issue it inline so the
            // intent reaches accounting rather than dying at authority.
            let head = self.creators[ci].head;
            self.grant_inner(ci, head, EXPIRES, 1_000);
        }
        let stale_basis = !fully_valid
            && !self.prev_social[ci].is_empty()
            && tc.draw(gs::integers::<u8>().max_value(4)) == 4;
        let social_control = if stale_basis {
            let pick = tc.draw(gs::integers::<usize>().max_value(self.prev_social[ci].len() - 1));
            self.prev_social[ci][pick]
        } else {
            self.creators[ci].head
        };
        let outsider_key = self.outsider.key.verifying_key().to_bytes();
        let owner_key = if !fully_valid && tc.draw(gs::integers::<u8>().max_value(9)) == 9 {
            outsider_key
        } else {
            self.creators[ci].key.verifying_key().to_bytes()
        };
        let owner_signing = if owner_key == outsider_key {
            self.outsider.key.clone()
        } else {
            self.creators[ci].key.clone()
        };
        let outsider_agent_key = self.outsider.agent_key.verifying_key().to_bytes();
        let agent_key = if !fully_valid && tc.draw(gs::integers::<u8>().max_value(9)) == 9 {
            outsider_agent_key
        } else {
            self.creators[ci].agent_key.verifying_key().to_bytes()
        };
        let agent_signing = if agent_key == outsider_agent_key {
            self.outsider.agent_key.clone()
        } else {
            self.creators[ci].agent_key.clone()
        };
        let chain_head = self.chains[ci].head;
        let chain_history = self.chains[ci].history.clone();
        let room_control = if fully_valid {
            chain_head.unwrap_or_else(|| RoomRecordId::from_bytes(self.salt()))
        } else {
            match tc.draw(gs::integers::<u8>().max_value(9)) {
                // A superseded chain head — a real record, just not the basis.
                7 | 8 if chain_history.len() > 1 => {
                    let pick = tc.draw(gs::integers::<usize>().max_value(chain_history.len() - 2));
                    chain_history[pick]
                }
                0..=6 => chain_head.unwrap_or_else(|| RoomRecordId::from_bytes(self.salt())),
                _ => RoomRecordId::from_bytes(self.salt()),
            }
        };
        let open = self.chains[ci].open.clone();
        let closed = self.chains[ci].closed.clone();
        let grant = if fully_valid {
            open[tc.draw(gs::integers::<usize>().max_value(open.len() - 1))]
        } else {
            match tc.draw(gs::integers::<u8>().max_value(9)) {
                0..=5 if !open.is_empty() => {
                    open[tc.draw(gs::integers::<usize>().max_value(open.len() - 1))]
                }
                6 | 7 if !closed.is_empty() => {
                    closed[tc.draw(gs::integers::<usize>().max_value(closed.len() - 1))]
                }
                _ => RoomRecordId::from_bytes(self.salt()),
            }
        };
        // The shared fixture policy is a real commitment — just not ours.
        let policy_id = if !fully_valid && tc.draw(gs::integers::<u8>().max_value(9)) == 9 {
            policy().id()
        } else {
            gen_policy().id()
        };
        let slug = if !fully_valid
            && !self.rooms.is_empty()
            && tc.draw(gs::integers::<u8>().max_value(4)) == 4
        {
            let pick = tc.draw(gs::integers::<usize>().max_value(self.rooms.len() - 1));
            self.rooms[pick].slug.clone()
        } else {
            self.slugs += 1;
            format!("room-{}", self.slugs)
        };
        let next_slot = self
            .accounts
            .get(&self.creators[ci].id)
            .map_or(0, |account| account.lifetime_slots)
            + 1;
        let slot = if fully_valid {
            next_slot
        } else {
            match tc.draw(gs::integers::<u8>().max_value(9)) {
                0..=6 => next_slot,
                7 | 8 => next_slot + 1,
                _ => 1,
            }
        };
        let correct_cost = gen_policy().cost(slot).unwrap_or(1);
        let charge = if fully_valid {
            correct_cost
        } else {
            match tc.draw(gs::integers::<u8>().max_value(9)) {
                0..=5 => correct_cost,
                6 | 7 => correct_cost + 1,
                8 => 1,
                _ => 9_999,
            }
        };
        let expires = if !fully_valid && tc.draw(gs::integers::<u8>().max_value(9)) == 9 {
            self.now
        } else {
            EXPIRES
        };
        let nonce = self.salt();
        let intent = CreationIntent {
            directory: DIRECTORY,
            realm: REALM,
            policy: policy_id,
            initial_settings: PolicyId::from_bytes([6; 32]),
            owner: self.creators[ci].id,
            agent: self.creators[ci].agent,
            owner_key,
            agent_key,
            social_control,
            room_control,
            grant,
            slug: Slug::new(&slug).unwrap(),
            description: Description::new("a room").unwrap(),
            slot,
            charge,
            expires_at: expires,
            nonce,
        };
        let record = OwnerPermit::sign_with_key(intent.clone(), &owner_signing)
            .unwrap()
            .verify()
            .unwrap()
            .propose_with_key(&agent_signing)
            .unwrap()
            .into_record();
        let genesis = record.genesis_id().unwrap();
        let expected = self.expect_create(ci, &intent, genesis);
        let verified = record.clone().verify().unwrap();
        assert_eq!(self.apply_verified(&verified), expected);
        match expected {
            Ok(Applied::Created(id)) => {
                assert_eq!(id, genesis);
                let account = self.accounts.entry(self.creators[ci].id).or_default();
                account.spent += charge;
                account.lifetime_slots = slot;
                self.windows
                    .entry(self.creators[ci].id)
                    .or_default()
                    .push_back(self.now);
                self.by_genesis.insert(genesis, self.rooms.len());
                self.rooms.push(RoomModel {
                    slug,
                    genesis,
                    owner: ci,
                    head: record.id(),
                    history: vec![record.id()],
                    archived: false,
                    description: String::from("a room"),
                });
                self.proofs.push(record.id());
                self.creates.push(record);
                self.last_time = self.now;
                self.revision += 1;
            }
            Ok(Applied::Existing(_)) => {
                self.last_time = self.now;
                self.revision += 1;
            }
            _ => {}
        }
    }

    /// The registry's own check order, replayed against the model: dedup by
    /// genesis, policy commitment, authority re-evaluation, then slug, slot,
    /// cost, credit and the rolling window.
    fn expect_create(
        &self,
        ci: usize,
        intent: &CreationIntent,
        genesis: RoomGenesisId,
    ) -> Result<Applied, RegistryError> {
        if self.by_genesis.contains_key(&genesis) {
            return Ok(Applied::Existing(genesis));
        }
        if intent.policy != gen_policy().id() {
            return Err(RegistryError::WrongPolicy);
        }
        let creator = &self.creators[ci];
        if intent.social_control != creator.head {
            return Err(RegistryError::Authority(Denial::StaleSocialBasis));
        }
        if intent.owner_key != creator.key.verifying_key().to_bytes() {
            return Err(RegistryError::Authority(Denial::ControllerKey));
        }
        if intent.agent_key != creator.agent_key.verifying_key().to_bytes() {
            return Err(RegistryError::Authority(Denial::AgentKey));
        }
        let chain = &self.chains[ci];
        if chain.head != Some(intent.room_control) {
            return Err(RegistryError::Authority(Denial::StaleRoomBasis));
        }
        let Some(&maximum) = chain.max_charge.get(&intent.grant) else {
            return Err(RegistryError::Authority(Denial::Grant));
        };
        if intent.expires_at <= self.now {
            return Err(RegistryError::Authority(Denial::Expired));
        }
        if intent.charge > maximum {
            return Err(RegistryError::Authority(Denial::Charge));
        }
        if self.rooms.iter().any(|r| r.slug == intent.slug.as_str()) {
            return Err(RegistryError::Taken);
        }
        let account = self.accounts.get(&creator.id).copied().unwrap_or_default();
        let slot = account.lifetime_slots + 1;
        if intent.slot != slot {
            return Err(RegistryError::Slot);
        }
        match gen_policy().cost(slot) {
            Err(error) => return Err(error),
            Ok(cost) if intent.charge != cost => return Err(RegistryError::Cost),
            _ => {}
        }
        if account.spent + intent.charge > account.earned {
            return Err(RegistryError::InsufficientCredit);
        }
        let window_seconds = gen_policy().window_seconds;
        let in_window = self
            .windows
            .get(&creator.id)
            .map(|window| {
                window
                    .iter()
                    .filter(|t| self.now.saturating_sub(**t) < window_seconds)
                    .count()
            })
            .unwrap_or(0);
        if in_window >= usize::from(gen_policy().max_in_window) {
            return Err(RegistryError::RateLimit);
        }
        Ok(Applied::Created(genesis))
    }

    /// An exact retry of an already finalized creation: the same identity
    /// again, charged nothing more — whatever the current authority state is.
    fn retry(&mut self, tc: &TestCase) {
        let record = self.creates
            [tc.draw(gs::integers::<usize>().max_value(self.creates.len() - 1))]
        .clone();
        let genesis = record.genesis_id().unwrap();
        let verified = record.verify().unwrap();
        assert_eq!(
            self.apply_verified(&verified),
            Ok(Applied::Existing(genesis))
        );
        self.last_time = self.now;
        self.revision += 1;
    }

    /// A drawn room update: owner-signed describes and archives against the
    /// live revision chain, mixed with non-owner claims, foreign controller
    /// keys, stale bases, missing genesis and stale predecessors.
    fn update(&mut self, tc: &TestCase) {
        let ri = tc.draw(gs::integers::<usize>().max_value(self.rooms.len() - 1));
        let ci = self.rooms[ri].owner;
        let mode = tc.draw(gs::integers::<u8>().max_value(9));
        let (owner, signing, owner_head): (OwnerId, SigningKey, RecordId) = match mode {
            // A fully authenticated non-owner: survives assessment, dies at
            // OwnerMismatch. Prefer a fellow creator when one exists.
            5 => {
                let others: Vec<usize> = (0..self.creators.len()).filter(|i| *i != ci).collect();
                if others.is_empty() || tc.draw(gs::booleans()) {
                    (
                        self.outsider.id,
                        self.outsider.key.clone(),
                        self.outsider.head,
                    )
                } else {
                    let oi = others[tc.draw(gs::integers::<usize>().max_value(others.len() - 1))];
                    (
                        self.creators[oi].id,
                        self.creators[oi].key.clone(),
                        self.creators[oi].head,
                    )
                }
            }
            // Claims the room owner but proves a foreign controller key.
            6 => (
                self.creators[ci].id,
                self.outsider.key.clone(),
                self.creators[ci].head,
            ),
            _ => (
                self.creators[ci].id,
                self.creators[ci].key.clone(),
                self.creators[ci].head,
            ),
        };
        let controller_key = signing.verifying_key().to_bytes();
        let social_control = if mode == 7 && !self.prev_social[ci].is_empty() {
            let pick = tc.draw(gs::integers::<usize>().max_value(self.prev_social[ci].len() - 1));
            self.prev_social[ci][pick]
        } else {
            owner_head
        };
        let genesis = if mode == 8 {
            RoomGenesisId::from_bytes(self.salt())
        } else {
            self.rooms[ri].genesis
        };
        let history_len = self.rooms[ri].history.len();
        let previous = if mode == 9 {
            if history_len > 1 && tc.draw(gs::booleans()) {
                let pick = tc.draw(gs::integers::<usize>().max_value(history_len - 2));
                self.rooms[ri].history[pick]
            } else {
                RoomRecordId::from_bytes(self.salt())
            }
        } else {
            self.rooms[ri].head
        };
        let expires = if tc.draw(gs::integers::<u8>().max_value(9)) == 9 {
            self.now
        } else {
            EXPIRES
        };
        let nonce = self.salt();
        let (action, description, archiving) = if tc.draw(gs::booleans()) {
            (UpdateAction::Archive, None, true)
        } else {
            let text = format!("desc {}", nonce[0]);
            (
                UpdateAction::Describe(Description::new(&text).unwrap()),
                Some(text),
                false,
            )
        };
        let update = RoomUpdate {
            directory: DIRECTORY,
            realm: REALM,
            genesis,
            previous,
            owner,
            social_control,
            controller_key,
            expires_at: expires,
            nonce,
            action,
        };
        let verified = update
            .clone()
            .sign_with_key(&signing)
            .unwrap()
            .verify()
            .unwrap();
        let expected = self.expect_update(&update, verified.id());
        assert_eq!(self.apply_verified(&verified), expected);
        if expected.is_ok() {
            let room = &mut self.rooms[ri];
            room.head = verified.id();
            room.history.push(verified.id());
            if archiving {
                room.archived = true;
            } else {
                room.description = description.unwrap();
            }
            self.proofs.push(verified.id());
            self.last_time = self.now;
            self.revision += 1;
        }
    }

    /// `Registry::update` order replayed: authority re-assessment, then
    /// genesis resolution, tombstone, owner and predecessor checks.
    fn expect_update(
        &self,
        update: &RoomUpdate,
        record_id: RoomRecordId,
    ) -> Result<Applied, RegistryError> {
        let (head, key) = self.owner_basis(update.owner);
        if update.social_control != head {
            return Err(RegistryError::Authority(Denial::StaleSocialBasis));
        }
        if update.controller_key != key {
            return Err(RegistryError::Authority(Denial::ControllerKey));
        }
        if update.expires_at <= self.now {
            return Err(RegistryError::Authority(Denial::Expired));
        }
        let Some(&ri) = self.by_genesis.get(&update.genesis) else {
            return Err(RegistryError::Missing);
        };
        let room = &self.rooms[ri];
        if room.archived {
            return Err(RegistryError::Archived);
        }
        if self.creators[room.owner].id != update.owner {
            return Err(RegistryError::OwnerMismatch);
        }
        if room.head != update.previous {
            return Err(RegistryError::StaleRevision);
        }
        Ok(Applied::Updated(record_id))
    }

    /// A committed eligible-set transition, or a social seal advancing one
    /// creator's accepted head (which stales every outstanding basis).
    fn configure(&mut self, tc: &TestCase) {
        if tc.draw(gs::booleans()) {
            let ids: Vec<OwnerId> = match tc.draw(gs::integers::<u8>().max_value(3)) {
                0 => self.sources.iter().map(|s| s.id).collect(),
                1 => {
                    let drop_i = tc.draw(gs::integers::<usize>().max_value(self.sources.len() - 1));
                    self.sources
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != drop_i)
                        .map(|(_, s)| s.id)
                        .collect()
                }
                2 => Vec::new(),
                _ => {
                    let ci = tc.draw(gs::integers::<usize>().max_value(self.creators.len() - 1));
                    self.sources
                        .iter()
                        .map(|s| s.id)
                        .chain([self.creators[ci].id])
                        .collect()
                }
            };
            assert_eq!(self.registry.set_eligible(&ids, self.now), Ok(()));
            self.eligible = ids.iter().copied().collect();
            self.last_time = self.now;
            self.revision += 1;
            assert_eq!(self.registry.eligible(), &self.eligible);
        } else {
            let ci = tc.draw(gs::integers::<usize>().max_value(self.creators.len() - 1));
            self.prev_social[ci].push(self.creators[ci].head);
            seal(&mut self.archive, &mut self.creators[ci], &[]);
        }
    }

    /// Snapshot must round-trip byte-identically and carry every retained
    /// fact: accounts, rooms, chains, proofs and dedup evidence.
    fn restore_and_verify(&mut self) {
        let snapshot = self.registry.snapshot();
        let digest = self.registry.digest();
        let restored = Registry::restore(&snapshot).unwrap();
        assert_eq!(restored.snapshot(), snapshot);
        assert_eq!(restored.digest(), digest);
        assert_eq!(restored.revision(), self.registry.revision());
        assert_eq!(restored.last_time(), self.registry.last_time());
        assert_eq!(restored.eligible(), self.registry.eligible());
        for creator in &self.creators {
            assert_eq!(
                restored.authority().head(creator.id),
                self.registry.authority().head(creator.id)
            );
            assert_eq!(
                restored.authority().sequence(creator.id),
                self.registry.authority().sequence(creator.id)
            );
            assert_eq!(
                restored.account(creator.id),
                self.registry.account(creator.id)
            );
        }
        for room in &self.rooms {
            let slug = Slug::new(&room.slug).unwrap();
            let restored_room = restored.room(&slug).unwrap();
            assert_eq!(restored_room.head(), room.head);
            assert_eq!(restored_room.archived(), room.archived);
            assert_eq!(restored_room.description().as_str(), room.description);
            assert_eq!(
                restored.room_by_genesis(room.genesis).unwrap().slug(),
                &slug
            );
        }
        for id in &self.proofs {
            assert_eq!(restored.source_proof(*id), self.registry.source_proof(*id));
        }
        for (record, ..) in &self.accepted {
            assert_eq!(
                restored.evidence_proof(record.id()),
                self.registry.evidence_proof(record.id())
            );
        }
        self.registry = restored;
    }

    /// Search returns exactly the non-archived matching rooms — tombstones
    /// stay allocated but hidden.
    fn search_check(&mut self, tc: &TestCase) {
        const TERMS: [&str; 7] = ["room", "rust", "a", "desc", "zz", "-", "ROOM"];
        let term_count = tc.draw(gs::integers::<usize>().max_value(2));
        let mut terms = Vec::new();
        for _ in 0..term_count {
            terms.push(TERMS[tc.draw(gs::integers::<usize>().max_value(TERMS.len() - 1))]);
        }
        let query = terms.join(" ");
        let result = self.registry.search(&query, 64, 4_096).unwrap();
        let mut want: Vec<&str> = self
            .rooms
            .iter()
            .filter(|room| {
                !room.archived
                    && terms.iter().all(|term| {
                        fold_contains(&room.slug, term) || fold_contains(&room.description, term)
                    })
            })
            .map(|room| room.slug.as_str())
            .collect();
        want.sort_unstable();
        let got: Vec<&str> = result
            .rooms
            .iter()
            .map(|room| room.slug().as_str())
            .collect();
        assert_eq!(got, want);
        assert!(!result.partial);
        assert_eq!(result.retained, self.rooms.len());
        assert_eq!(result.examined, self.rooms.len());
        assert_eq!(result.revision, self.revision);
    }

    /// After every command the registry must equal the model exactly.
    fn assert_model(&self) {
        assert_eq!(self.registry.revision(), self.revision);
        assert_eq!(self.registry.last_time(), self.last_time);
        assert_eq!(self.registry.eligible(), &self.eligible);
        for creator in &self.creators {
            let account = self.accounts.get(&creator.id).copied().unwrap_or_default();
            assert_eq!(self.registry.account(creator.id), account);
            let slot = account.lifetime_slots + 1;
            assert_eq!(
                self.registry.quote(creator.id),
                gen_policy().cost(slot).map(|cost| (slot, cost))
            );
        }
        for room in &self.rooms {
            let current = self.registry.room(&Slug::new(&room.slug).unwrap()).unwrap();
            assert_eq!(current.genesis(), room.genesis);
            assert_eq!(current.head(), room.head);
            assert_eq!(current.archived(), room.archived);
            assert_eq!(current.description().as_str(), room.description);
            assert_eq!(current.owner(), self.creators[room.owner].id);
            assert_eq!(current.revisions().len() + 1, room.history.len());
        }
    }
}

/// `registry::search` ASCII-folding term match, mirrored for the oracle.
fn fold_contains(text: &str, term: &str) -> bool {
    !term.is_empty()
        && text
            .as_bytes()
            .windows(term.len())
            .any(|s| s.eq_ignore_ascii_case(term.as_bytes()))
}

/// Interleaved grant/award/create/update/retry/configure commands drawn
/// against the live state, each checked against the model's replay of the
/// registry's check order: dedup by `(source, beneficiary, epoch)`, revision
/// chains that only move forward through authorized owners, tombstones that
/// hold their slugs, bounded slots and windows, and denials that never admit.
#[hegel::test(test_cases = 64)]
fn interleaved_registry_commands_match_the_model(tc: TestCase) {
    let mut world = World::new(&tc);
    let steps = tc.draw(gs::integers::<usize>().max_value(31));
    for _ in 0..steps {
        world.advance(&tc);
        world.command(&tc, true);
        world.assert_model();
    }
}

/// The same command stream with a snapshot/restore forced between commands:
/// every intermediate state must restore byte-identically, and the restored
/// registry must keep enforcing the agreed order — retained evidence still
/// dedups, tombstones still hold, accounting still bounds.
#[hegel::test(test_cases = 64)]
fn restores_mid_stream_preserve_state_and_dedup(tc: TestCase) {
    let mut world = World::new(&tc);
    let steps = tc.draw(gs::integers::<usize>().max_value(23));
    for _ in 0..steps {
        world.advance(&tc);
        world.command(&tc, false);
        world.restore_and_verify();
        // Continuity probe: evidence retained before the snapshot still
        // dedups on the restored registry at the same clock.
        if let Some((record, ..)) = world.accepted.last().cloned() {
            assert_eq!(world.award_verified(&record), Ok(Applied::DuplicateAward));
        }
        world.assert_model();
    }
}
