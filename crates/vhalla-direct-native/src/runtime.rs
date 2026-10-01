//! Derived state under the exclusive immutable journal contract. The open path
//! verifies all durable evidence; live paths extend these proofs after publish.
use crate::{codec::*, *};
use vhalla_direct_room::{
    AnchorReconciliation, AuthorChain, AuthorHead, PreparedPolicy, SealHead, SignedPolicy,
    VerifiedPolicy, MAX_CHAIN_PAGE,
};

pub(crate) struct CachedAuthor {
    chain: AuthorChain,
    checked_anchor: Option<AuthorHead>,
    anchor: Option<AnchorReconciliation>,
    known_high: u64,
    more: bool,
    failure: Option<vhalla_direct_room::Error>,
    latest_current: Option<SealHead>,
    seal_scan: Option<u64>,
}
impl CachedAuthor {
    fn pending(&self) -> bool {
        self.more
            || self.anchor.is_some()
            || self.seal_scan.is_some()
            || self.known_high > self.chain.head().sequence
    }
}

pub(crate) struct PolicyReplay {
    prepared: PreparedPolicy,
    // At most MAX_WRITERS entries; each position is the last checked sequence.
    positions: Vec<([u8; 32], u64, u64)>,
    index: usize,
    invalid: bool,
}

impl RoomSession {
    pub(crate) fn sync_author_cache(&mut self, changed_policy: bool) -> Result<()> {
        let local = self.author_key();
        self.author_cache
            .retain(|author, _| *author == local || self.policy.allows(author));
        let mut authors = self.policy.writers().to_vec();
        if !authors.contains(&local) {
            authors.push(local);
        }
        if authors.len() > MAX_CACHED_AUTHORS {
            return Err(Error::Corrupt);
        }
        for author in authors {
            if let Some(cached) = self.author_cache.get_mut(&author) {
                if changed_policy {
                    cached.anchor = None;
                    cached.latest_current = None;
                    let floor = self
                        .policy
                        .sealed_head(&author)
                        .map_or(0, |head| head.sequence);
                    cached.seal_scan = (cached.chain.head().sequence > floor)
                        .then_some(cached.chain.head().sequence);
                }
                continue;
            }
            let failure = self
                .store
                .read(key(AUTHOR_FORK, &author))?
                .map(|_| vhalla_direct_room::Error::Fork);
            self.author_cache.insert(
                author,
                CachedAuthor {
                    chain: AuthorChain::new(self.room_id(), author)?,
                    checked_anchor: None,
                    anchor: None,
                    known_high: 0,
                    more: true,
                    failure,
                    latest_current: None,
                    seal_scan: None,
                },
            );
        }
        Ok(())
    }

    /// The offered record has already been published. Derived cache progress may
    /// lag behind durable records, but is never allowed to lead them.
    pub(crate) fn event_persisted(&mut self, event: &VerifiedEvent) -> Result<()> {
        let author = event.claims().author;
        let Some(mut cached) = self.author_cache.remove(&author) else {
            return Ok(());
        };
        let result = (|| {
            if self.store.read(key(AUTHOR_FORK, &author))?.is_some() {
                cached.failure = Some(vhalla_direct_room::Error::Fork);
            }
            cached.known_high = cached.known_high.max(event.claims().sequence);
            if event.claims().sequence > cached.chain.head().sequence {
                cached.more = true;
            }
            Ok(())
        })();
        self.author_cache.insert(author, cached);
        result
    }

    pub(crate) fn observe_cached(&mut self, update: VerifiedPolicy) -> Result<()> {
        let mut next = self.policy.clone();
        self.replay_observation(&mut next, update)?;
        self.policy = next;
        Ok(())
    }

    pub(crate) fn author_chain(
        &mut self,
        author: [u8; 32],
        policy: &PolicyState,
    ) -> Result<AuthorChain> {
        if policy.head() != self.policy.head() || policy.room() != self.room_id() {
            return Err(Error::Corrupt);
        }
        let cached = self
            .author_cache
            .get(&author)
            .ok_or(vhalla_direct_room::Error::Author)?;
        if let Some(error) = cached.failure {
            return Err(error.into());
        }
        if cached.more || cached.anchor.is_some() {
            return Err(vhalla_direct_room::Error::Gap.into());
        }
        Ok(cached.chain.clone())
    }

    pub(crate) fn current_seals(&mut self) -> Result<Vec<SealHead>> {
        let mut seals = Vec::new();
        for author in self.policy.writers() {
            let cached = self.author_cache.get(author).ok_or(Error::Corrupt)?;
            if cached.failure.is_some() {
                continue;
            }
            if cached.more || cached.anchor.is_some() || cached.seal_scan.is_some() {
                return Err(vhalla_direct_room::Error::Gap.into());
            }
            if let Some(seal) = cached.latest_current {
                seals.push(seal);
            }
        }
        Ok(seals)
    }

    pub(crate) fn reconciliation_pending(&self) -> bool {
        self.image.pending_event.is_some()
            || self.image.pending_policy.is_some()
            || self.policy.pending().is_some()
            || self.policy_replay.is_some()
            || self.author_cache.values().any(CachedAuthor::pending)
    }

    pub(crate) fn advance_authors(&mut self, budget: &mut usize) -> Result<()> {
        let authors: Vec<_> = self.author_cache.keys().copied().collect();
        if authors.is_empty() {
            return Ok(());
        }
        let start = self.author_rotation % authors.len();
        for index in 0..authors.len() {
            if *budget == 0 {
                break;
            }
            let position = (start + index) % authors.len();
            let author = authors[position];
            self.author_rotation = (position + 1) % authors.len();
            let mut cached = self.author_cache.remove(&author).ok_or(Error::Corrupt)?;
            let mut quota = (*budget).min(MAX_CHAIN_PAGE);
            let before = quota;
            let result = self.advance_author(author, &mut cached, &mut quota);
            *budget -= before - quota;
            self.author_cache.insert(author, cached);
            result?;
        }
        Ok(())
    }

    fn advance_author(
        &mut self,
        author: [u8; 32],
        cached: &mut CachedAuthor,
        budget: &mut usize,
    ) -> Result<()> {
        if cached.failure.is_some() {
            return Ok(());
        }
        let seal = self.policy.sealed_head(&author);
        if let Some(seal) = seal {
            if cached.chain.head().sequence >= seal.sequence && cached.checked_anchor != Some(seal)
            {
                if cached.anchor.is_none() {
                    match cached.chain.prepare_anchor_reconciliation(&self.policy) {
                        Ok(proof) => cached.anchor = Some(proof),
                        Err(error) => {
                            cached.failure = Some(error);
                            return Ok(());
                        }
                    }
                }
                let proof = cached.anchor.as_mut().ok_or(Error::Corrupt)?;
                while !proof.is_ready() && *budget > 0 {
                    let sequence = proof
                        .progress()
                        .sequence
                        .checked_add(1)
                        .ok_or(Error::Bounds)?;
                    let Some(event) = self.indexed_event(author, sequence)? else {
                        return Ok(());
                    };
                    *budget -= 1;
                    if let Err(error) = proof.push(&[event]) {
                        cached.failure = Some(error);
                        return Ok(());
                    }
                }
                if !proof.is_ready() {
                    return Ok(());
                }
                cached
                    .chain
                    .reconcile_anchor(cached.anchor.take().ok_or(Error::Corrupt)?, &self.policy)?;
                cached.checked_anchor = Some(seal);
            }
        }
        while cached.more && *budget > 0 {
            let sequence = cached
                .chain
                .head()
                .sequence
                .checked_add(1)
                .ok_or(Error::Bounds)?;
            let Some(event) = self.indexed_event(author, sequence)? else {
                cached.more = false;
                break;
            };
            *budget -= 1;
            let step = match cached.chain.prepare_continuity(event.clone(), &self.policy) {
                Ok(step) => step,
                Err(error) => {
                    cached.failure = Some(error);
                    return Ok(());
                }
            };
            cached
                .chain
                .commit_continuity_after_persist(step, &self.policy)?;
            cached.known_high = cached.known_high.max(sequence);
            if seal.is_none_or(|seal| sequence >= seal.sequence) {
                cached.checked_anchor = seal;
            }
            if event.claims().policy == self.policy.head().id
                && sequence > seal.map_or(0, |seal| seal.sequence)
            {
                cached.latest_current = Some(SealHead {
                    author,
                    sequence,
                    event: event.id(),
                });
                cached.seal_scan = None;
            }
        }
        // A policy can arrive after future-policy events. Search the existing
        // verified prefix backwards once for its most recent eligible terminal.
        while let Some(sequence) = cached.seal_scan {
            if *budget == 0 {
                break;
            }
            let floor = seal.map_or(0, |seal| seal.sequence);
            if sequence <= floor {
                cached.seal_scan = None;
                break;
            }
            let event = self
                .indexed_event(author, sequence)?
                .ok_or(Error::Corrupt)?;
            *budget -= 1;
            if event.claims().policy == self.policy.head().id {
                cached.latest_current = Some(SealHead {
                    author,
                    sequence,
                    event: event.id(),
                });
                cached.seal_scan = None;
            } else {
                cached.seal_scan = Some(sequence - 1);
            }
        }
        Ok(())
    }

    pub(crate) fn apply_policies(&mut self) -> Result<()> {
        let mut budget = MAX_REPLAY_FRAMES;
        if !self.policy.is_forked()
            && !self.policy.observation_overflow()
            && self.image.blocked.is_none()
        {
            for _ in 0..MAX_POLICY_COMMITS {
                let next = self
                    .policy
                    .head()
                    .revision
                    .checked_add(1)
                    .ok_or(Error::Bounds)?;
                if self.policy_replay.is_none() {
                    let Some(update) = self.indexed_policy(OBSERVED, next)? else {
                        break;
                    };
                    let prepared = match self
                        .policy
                        .prepare_update(SignedPolicy::decode(&update.encode())?)
                    {
                        Ok(prepared) => prepared,
                        Err(_) => break,
                    };
                    let positions = update
                        .claims()
                        .sealed_heads
                        .iter()
                        .map(|seal| {
                            (
                                seal.author,
                                self.policy
                                    .sealed_head(&seal.author)
                                    .map_or(0, |head| head.sequence),
                                seal.sequence,
                            )
                        })
                        .collect();
                    self.policy_replay = Some(PolicyReplay {
                        prepared,
                        positions,
                        index: 0,
                        invalid: false,
                    });
                }
                let mut replay = self.policy_replay.take().ok_or(Error::Corrupt)?;
                let result = self.advance_policy(&mut replay, &mut budget);
                if let Err(error) = result {
                    self.policy_replay = Some(replay);
                    return Err(error);
                }
                if replay.invalid || !replay.prepared.is_ready() {
                    self.policy_replay = Some(replay);
                    break;
                }
                let update = replay.prepared.update().clone();
                let mut next_state = self.policy.clone();
                next_state.commit_after_persist(replay.prepared)?;
                let records = [
                    record(
                        revision_key(COMMITTED, next),
                        &index_bytes(&next.to_be_bytes(), *update.id().as_bytes()),
                    )?,
                    record(
                        raw_key(POLICY_INDEX, *update.id().as_bytes()),
                        &next.to_be_bytes(),
                    )?,
                ];
                if let Err(error) = self.publish(self.image.clone(), &records, true) {
                    if error == Error::Capacity {
                        return self.capacity_fence(record(
                            raw_key(POLICY, *update.id().as_bytes()),
                            &update.encode(),
                        )?);
                    }
                    return Err(error);
                }
                self.policy = next_state;
                self.sync_author_cache(true)?;
            }
        }
        self.advance_authors(&mut budget)
    }

    fn advance_policy(&mut self, replay: &mut PolicyReplay, budget: &mut usize) -> Result<()> {
        if replay.invalid {
            return Ok(());
        }
        while replay.index < replay.positions.len() {
            let (author, sequence, target) = &mut replay.positions[replay.index];
            if sequence == target {
                replay.index += 1;
                continue;
            }
            if *budget == 0 {
                break;
            }
            let next = sequence.checked_add(1).ok_or(Error::Bounds)?;
            let Some(event) = self.indexed_event(*author, next)? else {
                break;
            };
            *budget -= 1;
            match replay.prepared.push_seal(author, &[event]) {
                Ok(()) => *sequence = next,
                Err(_) => {
                    replay.invalid = true;
                    break;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn rebuild_author_cache(&mut self) -> Result<()> {
        self.author_cache.clear();
        self.policy_replay = None;
        self.sync_author_cache(false)?;
        let mut after = 0;
        loop {
            let page = self
                .store
                .page(after, vhalla_direct_store::MAX_PAGE_RECORDS)?;
            for entry in &page.records {
                if entry.key[0] == EVENT {
                    let event = self.event_raw(&entry.data)?;
                    if let Some(cached) = self.author_cache.get_mut(&event.claims().author) {
                        cached.known_high = cached.known_high.max(event.claims().sequence);
                    }
                }
            }
            let Some(next) = page.next else {
                break;
            };
            after = next;
        }
        // Open/recovery alone may walk the full retained history. Each author
        // starts at zero once; live calls retain progress instead of restarting.
        let authors: Vec<_> = self.author_cache.keys().copied().collect();
        for author in authors {
            let mut cached = self.author_cache.remove(&author).ok_or(Error::Corrupt)?;
            let mut budget = usize::MAX;
            let result = self.advance_author(author, &mut cached, &mut budget);
            self.author_cache.insert(author, cached);
            result?;
        }
        Ok(())
    }
}
