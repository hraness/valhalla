//! Locally derived, immutable query documents. Inputs are real signed social views.
use crate::{
    Budget, DiscoveryState, Error, Filters, Kind, Query, Subscription, MAX_DOCUMENTS, MAX_PAGE,
    POLICY_VERSION,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::cmp::Reverse;
use vhalla_core::RoomId;
use vhalla_social::{
    archive::Archive,
    view::{Content, EvaluationBasis, RecordState, Register, RevisionText, View},
    Actor, AgentId, Body, Facet, FacetKind, Operation, OwnerId, Placement, PostRef, Reaction,
    RecordId,
};

/// Whether provisional live activity is explicitly requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Visibility {
    /// Durable owner-accepted evidence only.
    Committed,
    /// Include currently authorized provisional evidence with its badge.
    Live,
}
/// Predictable subscriptions or explicitly personalized ranking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedMode {
    /// Recent local observation, no popularity rank.
    Following,
    /// Private integer ranking and owner/root diversity.
    Discover,
}

/// Cursor lifetime in caller-supplied monotonic seconds. A caller must use the
/// same trusted clock source as social authorization evaluation.
pub const MAX_CURSOR_AGE_SECONDS: u64 = 300;

/// Separate known-corpus, dependency and query-work completeness axes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Coverage {
    /// Canonical archive records, including control/history.
    pub retained_records: usize,
    /// Derived exact visible revision candidates retained by this snapshot.
    pub documents: usize,
    /// All candidates represented within snapshot construction limits.
    pub corpus_complete: bool,
    /// Known retained dependencies resolve, never global completeness.
    pub history_complete: bool,
    /// Entire selected local scan completed within caller work limits.
    pub query_complete: bool,
    /// Documents examined, including no-match and filtered data.
    pub examined: usize,
    /// Text bytes charged by this query.
    pub bytes: usize,
    /// Work steps charged by this query.
    pub steps: usize,
}
/// Exact inert result. Text/facets are untrusted presentation data, never instructions.
#[derive(Clone, Debug)]
pub struct Hit<'a> {
    /// Exact original/revision binding, also for old endorsed repost revisions.
    pub reference: PostRef,
    /// Validated original author owner.
    pub owner: OwnerId,
    /// Original agent incarnation when applicable.
    pub agent: Option<AgentId>,
    /// Validated conversation root.
    pub root: RecordId,
    /// Public original placement.
    pub placement: Placement,
    /// Exact inert original text, not latest fallback for a repost.
    pub text: &'a str,
    /// Signed exact revision facets.
    pub facets: &'a [Facet],
    /// Original/revision's displayed commitment state.
    pub state: RecordState,
    /// Whether the original is a reply.
    pub reply: bool,
    /// Admitted owners reposting this exact revision, deduplicated.
    pub reposted_by: Vec<OwnerId>,
    /// Persisted local freshness ordinal, unknown until explicitly observed.
    pub first_observed: Option<u64>,
    /// [follow, subscription, topic, selected endorsement, freshness, unseen].
    pub why: [i16; 6],
}
/// Bounded query result; matches are only a lower bound when query_complete=false.
pub struct Page<'a> {
    /// At most MAX_PAGE exact hydrated rows.
    pub hits: Vec<Hit<'a>>,
    /// Matching candidates observed in the completed portion. Cursor pages
    /// retain the frozen count; `Cursor::remaining` reports unconsumed rows.
    pub matches: usize,
    /// Explicit evidence/work coverage.
    pub coverage: Coverage,
}
struct Row<'a> {
    hit: Hit<'a>,
    original_visible: bool,
    endorsements: BTreeSet<OwnerId>,
}

/// Borrowed immutable projection with private admission constructors.
/// It may retain up to 4096 rows; a 64-row page is not a 64-row peak-memory claim.
pub struct DiscoverySnapshot<'a> {
    rows: Vec<Row<'a>>,
    basis: EvaluationBasis,
    state: DiscoveryState,
    reader_owner: OwnerId,
    visibility: Visibility,
    followed: BTreeSet<OwnerId>,
    coverage: Coverage,
    known_owners: BTreeSet<OwnerId>,
    learned_topics: BTreeMap<alloc::string::String, i16>,
}
impl<'a> DiscoverySnapshot<'a> {
    /// Derive candidates internally from a real current View paired with its
    /// canonical Archive. Foreign indexes cannot mark their own records admitted.
    pub fn new(
        archive: &Archive,
        view: &View<'a>,
        reader_owner: OwnerId,
        state: &DiscoveryState,
        visibility: Visibility,
    ) -> Result<Self, Error> {
        if !view.matches_archive(archive) || !view.owner_known(reader_owner) {
            return Err(Error::Evidence);
        }
        let known_owners: BTreeSet<_> = archive
            .records()
            .filter_map(|r| match r.body() {
                Body::OwnerGenesis { .. } => Some(OwnerId::from_bytes(*r.id().as_bytes())),
                _ => None,
            })
            .filter(|id| view.owner_known(*id))
            .collect();
        let followed=known_owners.iter().filter(|id|matches!(view.follow(reader_owner,**id),Ok(p)if matches!(p.committed,Register::Resolved{value:true,..}))).copied().collect();
        let mut snapshot = Self {
            rows: Vec::new(),
            basis: view.basis(),
            state: state.clone(),
            reader_owner,
            visibility,
            followed,
            coverage: Coverage {
                retained_records: archive.len(),
                documents: 0,
                corpus_complete: true,
                history_complete: view.basis().known_history_complete,
                query_complete: true,
                examined: 0,
                bytes: 0,
                steps: 0,
            },
            known_owners,
            learned_topics: BTreeMap::new(),
        };
        let posts = view.posts(None);
        for p in posts {
            let content = match visibility {
                Visibility::Committed => &p.committed,
                Visibility::Live => &p.observed,
            };
            if visibility == Visibility::Committed && p.state != RecordState::Committed {
                continue;
            }
            let values: Vec<RevisionText<'a>> = match content {
                Content::Present(Register::Resolved { value, .. }) => alloc::vec![*value],
                Content::Present(Register::Conflict { alternatives, .. }) => alternatives.clone(),
                _ => continue,
            };
            for value in values {
                let revision_state = view.state(value.revision).ok_or(Error::Evidence)?;
                if !matches!(
                    revision_state,
                    RecordState::Committed | RecordState::Provisional
                ) {
                    continue;
                }
                let hit = Hit {
                    reference: PostRef {
                        post: p.id,
                        revision: value.revision,
                    },
                    owner: p.attribution.owner,
                    agent: match p.attribution.actor {
                        Actor::Agent { agent, .. } => Some(agent),
                        _ => None,
                    },
                    root: p.root,
                    placement: p.placement,
                    text: value.text,
                    facets: value.facets,
                    state: revision_state,
                    reply: p.reply.is_some(),
                    reposted_by: Vec::new(),
                    first_observed: state.ordinal(p.id),
                    why: [0; 6],
                };
                snapshot.add(hit, true, None);
            }
        }
        // Deduplicate preference slots before calling causal reducers. One actor's
        // replay/toggle volume cannot generate multiple endorsement contributions.
        let mut repost_slots = BTreeSet::new();
        let mut reaction_slots = BTreeSet::new();
        for r in archive.records() {
            if let Body::Social {
                actor, operation, ..
            } = r.body()
            {
                if view.state(r.id()) != Some(RecordState::Committed) {
                    continue;
                }
                match operation {
                    Operation::Repost { post, .. } => {
                        repost_slots.insert((actor.owner(), *post));
                    }
                    Operation::React { post, .. } => {
                        reaction_slots.insert((actor.owner(), *post));
                    }
                    _ => {}
                }
            }
        }
        for (owner, post) in repost_slots {
            if state.preferences().muted.contains(&owner)
                || state.preferences().blocked.contains(&owner)
            {
                continue;
            }
            let Ok(repost) = view.repost(owner, post) else {
                continue;
            };
            let Register::Resolved {
                value: Some(revision),
                ..
            } = repost.committed
            else {
                continue;
            };
            let reference = PostRef { post, revision };
            let Ok(value) = view.exact_revision_text(reference) else {
                continue;
            };
            let Ok(p) = view.post(post) else {
                continue;
            };
            if p.state != RecordState::Committed
                || view.state(revision) != Some(RecordState::Committed)
            {
                continue;
            }
            let hit = Hit {
                reference,
                owner: p.attribution.owner,
                agent: match p.attribution.actor {
                    Actor::Agent { agent, .. } => Some(agent),
                    _ => None,
                },
                root: p.root,
                placement: p.placement,
                text: value.text,
                facets: value.facets,
                state: RecordState::Committed,
                reply: p.reply.is_some(),
                reposted_by: Vec::new(),
                first_observed: state.ordinal(post),
                why: [0; 6],
            };
            snapshot.add(hit, false, Some(owner));
        }
        let selected = snapshot.selected_owners();
        for (owner, post) in reaction_slots {
            if !selected.contains(&owner) {
                continue;
            }
            let Ok(p) = view.reaction(owner, post) else {
                continue;
            };
            if let Register::Resolved {
                value: Reaction::Up(revision),
                ..
            } = p.committed
            {
                if let Some(row) = snapshot.rows.iter_mut().find(|r| {
                    r.hit.reference == PostRef { post, revision }
                        && r.hit.owner != owner
                        && r.hit.state == RecordState::Committed
                }) {
                    row.endorsements.insert(owner);
                }
            }
        }
        for row in &mut snapshot.rows {
            row.hit.reposted_by.sort_unstable();
            row.hit.reposted_by.dedup();
            row.endorsements.extend(
                row.hit
                    .reposted_by
                    .iter()
                    .filter(|o| **o != row.hit.owner && selected.contains(o))
                    .copied(),
            );
        }
        snapshot.rows.sort_by_key(|r| r.hit.reference);
        let mut private_signals: BTreeMap<RecordId, (PostRef, i8)> = state
            .learning_bookmarks()
            .map(|r| (r.post, (r, 1)))
            .collect();
        for (reference, value) in state.feedback_entries() {
            private_signals.insert(reference.post, (reference, value));
        }
        for (_, (reference, value)) in private_signals {
            if view.state(reference.post) != Some(RecordState::Committed)
                || view.state(reference.revision) != Some(RecordState::Committed)
            {
                continue;
            }
            let Ok(exact) = view.exact_revision_text(reference) else {
                continue;
            };
            let tags: BTreeSet<_> = exact
                .facets
                .iter()
                .filter_map(|f| {
                    if let FacetKind::Tag(t) = &f.kind {
                        Some(t.as_str())
                    } else {
                        None
                    }
                })
                .collect();
            for tag in tags {
                *snapshot
                    .learned_topics
                    .entry(alloc::string::String::from(tag))
                    .or_default() += i16::from(value);
            }
        }
        snapshot.coverage.documents = snapshot.rows.len();
        Ok(snapshot)
    }
    fn add(&mut self, mut hit: Hit<'a>, original: bool, reposter: Option<OwnerId>) {
        if let Some(row) = self
            .rows
            .iter_mut()
            .find(|r| r.hit.reference == hit.reference)
        {
            row.original_visible |= original;
            if let Some(owner) = reposter {
                row.hit.reposted_by.push(owner);
            }
            return;
        }
        if self.rows.len() == MAX_DOCUMENTS {
            self.coverage.corpus_complete = false;
            return;
        }
        if let Some(owner) = reposter {
            hit.reposted_by.push(owner);
        }
        self.rows.push(Row {
            hit,
            original_visible: original,
            endorsements: BTreeSet::new(),
        });
    }
    fn selected_owners(&self) -> BTreeSet<OwnerId> {
        self.followed
            .iter()
            .copied()
            .chain(
                self.state
                    .preferences()
                    .subscriptions
                    .iter()
                    .filter_map(|s| {
                        if let Subscription::Owner(id) = s {
                            Some(*id)
                        } else {
                            None
                        }
                    }),
            )
            .filter(|owner| {
                !self.state.preferences().muted.contains(owner)
                    && !self.state.preferences().blocked.contains(owner)
            })
            .collect()
    }
    /// Coverage prior to executing a query.
    pub const fn coverage(&self) -> Coverage {
        self.coverage
    }
    /// Exact social interpretation basis. Time is authorization evaluation only.
    pub const fn basis(&self) -> EvaluationBasis {
        self.basis
    }
    fn hidden(&self, row: &Row<'_>) -> bool {
        let p = self.state.preferences();
        p.muted.contains(&row.hit.owner)
            || p.blocked.contains(&row.hit.owner)
            || p.muted_threads.contains(&row.hit.root)
    }
    fn subscribed(&self, row: &Row<'_>) -> bool {
        self.state
            .preferences()
            .subscriptions
            .iter()
            .any(|s| match s {
                Subscription::Owner(o) => *o == row.hit.owner,
                Subscription::Agent(a) => Some(*a) == row.hit.agent,
                Subscription::Channel(c) => row.hit.placement == Placement::Channel(*c),
                Subscription::Thread(r) => *r == row.hit.root,
                Subscription::Tag(t) => row
                    .hit
                    .facets
                    .iter()
                    .any(|f| matches!(&f.kind,FacetKind::Tag(tag)if tag.as_str()==t)),
            })
            || self
                .state
                .preferences()
                .bookmarks
                .contains(&row.hit.reference)
    }
    fn following(&self, row: &Row<'_>) -> bool {
        row.hit.owner == self.reader_owner
            || self.followed.contains(&row.hit.owner)
            || self.subscribed(row)
            || row
                .hit
                .reposted_by
                .iter()
                .any(|o| self.followed.contains(o))
    }
    fn matches(&self, row: &Row<'_>, f: &Filters) -> bool {
        let h = &row.hit;
        f.state.is_none_or(|state| h.state == state)
            && f.kind.is_none_or(|k| match k {
                Kind::Post => row.original_visible && !h.reply,
                Kind::Reply => row.original_visible && h.reply,
                Kind::Repost => !h.reposted_by.is_empty(),
            })
            && f.owner.is_none_or(|v| v == h.owner)
            && f.agent.is_none_or(|v| Some(v) == h.agent)
            && f.channel
                .is_none_or(|v| h.placement == Placement::Channel(v))
            && f.root.is_none_or(|v| h.root == v)
            && f.reply.is_none_or(|v| h.reply == v)
            && (!f.repost_only || !h.reposted_by.is_empty())
            && f.tag.as_ref().is_none_or(|t| {
                h.facets
                    .iter()
                    .any(|f| matches!(&f.kind,FacetKind::Tag(tag)if tag.as_str()==t))
            })
            && f.mention.is_none_or(|m| {
                h.facets
                    .iter()
                    .any(|f| matches!(&f.kind,FacetKind::Mention(target)if *target==m))
            })
    }
    fn scored(&self, row: &Row<'a>) -> Hit<'a> {
        let mut hit = row.hit.clone();
        let p = self.state.preferences();
        let affinity: i16 = hit
            .facets
            .iter()
            .filter_map(|f| {
                if let FacetKind::Tag(tag) = &f.kind {
                    Some(tag.as_str())
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter_map(|tag| {
                p.interests.get(tag).copied().map(i16::from).or_else(|| {
                    self.learned_topics
                        .get(tag)
                        .copied()
                        .map(|n| n.clamp(-4, 4))
                })
            })
            .sum::<i16>()
            .clamp(-4, 4);
        let age = hit
            .first_observed
            .map(|n| self.state.cutoff().saturating_sub(n))
            .unwrap_or(u64::MAX);
        hit.why = [
            if self.followed.contains(&hit.owner) {
                128
            } else {
                0
            },
            if self.subscribed(row) { 64 } else { 0 },
            affinity * 16,
            if hit.state == RecordState::Committed {
                row.endorsements.len().min(4) as i16 * 8
            } else {
                0
            },
            15 - age.min(15) as i16,
            if self.state.seen(hit.reference) { 0 } else { 8 },
        ];
        hit
    }
    fn select(
        &self,
        q: &Query,
        filters: &Filters,
        mode: Option<FeedMode>,
        mut budget: Budget,
        limit: usize,
    ) -> Result<Page<'a>, Error> {
        filters.check()?;
        budget.check()?;
        if limit == 0 || limit > MAX_DOCUMENTS {
            return Err(Error::Bounds);
        }
        let initial = budget;
        let mut coverage = self.coverage;
        let mut candidates = Vec::new();
        let mut matches = 0;
        let key = |h: &Hit<'_>| {
            (
                if mode == Some(FeedMode::Discover) {
                    Reverse(h.why.iter().sum::<i16>())
                } else {
                    Reverse(0)
                },
                Reverse(h.first_observed.unwrap_or(0)),
                h.reference,
            )
        };
        // Large cursor/Discover sets are sorted once. Repeated sorted insertion
        // would shift a quadratic number of descriptors beyond the per-row work
        // allowance. Ordinary short search pages retain bounded top-k storage.
        let full_candidates = mode == Some(FeedMode::Discover) || limit > MAX_PAGE;
        for row in &self.rows {
            if budget
                .document(
                    row.hit.text.len(),
                    256 + row.hit.facets.len() * 80
                        + self.state.preferences().subscriptions.len()
                            * (64 + row.hit.facets.len() * 2)
                        + row.hit.reposted_by.len() * 64,
                )
                .is_err()
            {
                coverage.query_complete = false;
                break;
            }
            if self.hidden(row) || !self.matches(row, filters) {
                continue;
            }
            if mode.is_some()
                && !self.following(row)
                && !(mode == Some(FeedMode::Discover)
                    && (self.state.preferences().wider || !row.endorsements.is_empty()))
            {
                continue;
            }
            if mode == Some(FeedMode::Discover) && row.hit.state != RecordState::Committed {
                continue;
            }
            // Search ordinary current content, plus an explicit repost-only query
            // for superseded exact endorsements. Feeds may carry reposted history.
            if mode.is_none()
                && !row.original_visible
                && !filters.repost_only
                && filters.kind != Some(Kind::Repost)
            {
                continue;
            }
            match q.matches(row.hit.text, &mut budget) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(_) => {
                    coverage.query_complete = false;
                    break;
                }
            }
            matches += 1;
            let hit = if mode == Some(FeedMode::Discover) {
                self.scored(row)
            } else {
                row.hit.clone()
            };
            if full_candidates {
                candidates.push(hit);
                continue;
            }
            let at = candidates.partition_point(|h| key(h) < key(&hit));
            if at < limit {
                if candidates.len() == limit {
                    candidates.pop();
                }
                candidates.insert(at, hit);
            }
        }
        if full_candidates {
            candidates.sort_unstable_by_key(key);
        }
        if mode == Some(FeedMode::Discover) && limit <= MAX_PAGE {
            let mut owners = BTreeMap::new();
            let mut roots = BTreeSet::new();
            candidates.retain(|h| {
                let n = owners.entry(h.owner).or_insert(0);
                if *n == 2 || !roots.insert(h.root) {
                    false
                } else {
                    *n += 1;
                    true
                }
            });
            candidates.truncate(limit);
        }
        coverage.examined = initial.documents - budget.documents;
        coverage.bytes = initial.bytes - budget.bytes;
        coverage.steps = initial.steps - budget.steps;
        Ok(Page {
            hits: candidates,
            matches,
            coverage,
        })
    }
    /// Bounded literal search of current visible revisions, with explicit repost mode.
    pub fn search(
        &self,
        query: &Query,
        filters: &Filters,
        budget: Budget,
        limit: usize,
    ) -> Result<Page<'a>, Error> {
        if limit > MAX_PAGE {
            return Err(Error::Bounds);
        }
        self.select(query, filters, None, budget, limit)
    }
    /// Intersect a bounded canonical set of untrusted exact references with one
    /// ordinary verified local query. References cannot manufacture documents,
    /// replace exact revisions, bypass local filters or supply authored snippets.
    /// Coverage describes the full attempted local scan, including zero matches.
    /// `matches` counts matching requested references, not other local matches.
    pub fn search_references(
        &self,
        query: &Query,
        filters: &Filters,
        budget: Budget,
        references: &[PostRef],
    ) -> Result<Page<'a>, Error> {
        if references.len() > MAX_PAGE || references.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::Bounds);
        }
        let mut page = self.select(query, filters, None, budget, MAX_DOCUMENTS)?;
        // Keep full-query descriptors as scratch, without retaining their 4096-
        // row allocation in a result containing at most 64 requested references.
        let mut hits = Vec::with_capacity(references.len());
        for hit in page.hits {
            if references.binary_search(&hit.reference).is_ok() {
                hits.push(hit);
            }
        }
        page.matches = hits.len();
        page.hits = hits;
        Ok(page)
    }
    /// Following is recent observation; Discover is private integer relevance.
    pub fn feed(&self, mode: FeedMode, budget: Budget, limit: usize) -> Result<Page<'a>, Error> {
        if limit > MAX_PAGE {
            return Err(Error::Bounds);
        }
        self.select(
            &Query::parse("")?,
            &Filters::default(),
            Some(mode),
            budget,
            limit,
        )
    }
    /// Bounded known channel roots and reply/activity counts, never global totals.
    pub fn boards(&self, limit: usize) -> Result<Vec<Board>, Error> {
        self.boards_page(0, limit)
    }
    /// Browse stable channel-ID pages of the known local directory.
    pub fn boards_page(&self, offset: usize, limit: usize) -> Result<Vec<Board>, Error> {
        if limit == 0 || limit > MAX_PAGE {
            return Err(Error::Bounds);
        }
        let mut map: BTreeMap<RoomId, Board> = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for row in &self.rows {
            if self.hidden(row) || !row.original_visible || !seen.insert(row.hit.reference.post) {
                continue;
            }
            if let Placement::Channel(channel) = row.hit.placement {
                let board = map.entry(channel).or_insert(Board {
                    channel,
                    roots: 0,
                    replies: 0,
                    last_observed: None,
                });
                if row.hit.reply {
                    board.replies += 1;
                } else {
                    board.roots += 1;
                }
                board.last_observed = board.last_observed.max(row.hit.first_observed);
            }
        }
        Ok(map
            .into_values()
            .skip(offset.min(MAX_DOCUMENTS))
            .take(limit)
            .collect())
    }
    /// Bounded known owner directory; display profiles must be fetched from View.
    pub fn directory(&self, limit: usize) -> Result<Vec<OwnerId>, Error> {
        self.directory_page(0, limit)
    }
    /// Browse stable owner-ID pages, applying mute/block before paging.
    pub fn directory_page(&self, offset: usize, limit: usize) -> Result<Vec<OwnerId>, Error> {
        if limit == 0 || limit > MAX_PAGE {
            return Err(Error::Bounds);
        }
        Ok(self
            .known_owners
            .iter()
            .filter(|o| {
                !self.state.preferences().muted.contains(o)
                    && !self.state.preferences().blocked.contains(o)
            })
            .skip(offset.min(MAX_DOCUMENTS))
            .take(limit)
            .copied()
            .collect())
    }
    /// Freeze exact result IDs and query basis. Snapshot cursor does not retain text
    /// or an archive borrow; callers can ingest revocations before the next page.
    pub fn cursor(
        &self,
        query: Query,
        filters: Filters,
        mode: Option<FeedMode>,
        budget: Budget,
    ) -> Result<Cursor, Error> {
        let page = self.select(&query, &filters, mode, budget, MAX_DOCUMENTS)?;
        Ok(Cursor {
            basis: self.basis,
            state: self.state.digest(),
            owner: self.reader_owner,
            visibility: self.visibility,
            query,
            filters,
            mode,
            refs: page.hits.iter().map(|h| h.reference).collect(),
            last_time: self.basis.now,
            coverage: page.coverage,
            matches: page.matches,
            budget,
        })
    }
}
/// Known local channel activity, counted once per original post despite revisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Board {
    /// Realm-local channel identifier.
    pub channel: RoomId,
    /// Distinct visible roots.
    pub roots: usize,
    /// Distinct visible replies.
    pub replies: usize,
    /// Highest private local observed ordinal.
    pub last_observed: Option<u64>,
}

/// Exact, finite, private cursor. Not serializable as a remote authority token.
/// Each retains at most MAX_DOCUMENTS IDs for MAX_CURSOR_AGE_SECONDS; the host
/// owns its simultaneous-handle memory policy, without a global core registry.
pub struct Cursor {
    basis: EvaluationBasis,
    state: [u8; 32],
    owner: OwnerId,
    visibility: Visibility,
    query: Query,
    filters: Filters,
    mode: Option<FeedMode>,
    refs: Vec<PostRef>,
    last_time: u64,
    coverage: Coverage,
    matches: usize,
    budget: Budget,
}
impl Cursor {
    /// Rebuild from a fresh actual social view and recheck exact effective revision
    /// membership before returning any body. Additions or an age exceeding
    /// MAX_CURSOR_AGE_SECONDS require an explicit refresh. `View` time must be
    /// trusted caller-supplied monotonic seconds, as for authorization expiry.
    pub fn page<'a>(
        &mut self,
        archive: &Archive,
        view: &View<'a>,
        state: &DiscoveryState,
        limit: usize,
    ) -> Result<Page<'a>, Error> {
        if limit == 0 || limit > MAX_PAGE {
            return Err(Error::Bounds);
        }
        let b = view.basis();
        if b.now < self.last_time {
            return Err(Error::Clock);
        }
        self.last_time = b.now;
        if b.now.saturating_sub(self.basis.now) > MAX_CURSOR_AGE_SECONDS {
            return Err(Error::Stale);
        }
        if b.archive_root != self.basis.archive_root
            || b.limits_digest != self.basis.limits_digest
            || b.eligibility_digest != self.basis.eligibility_digest
            || b.policy_version != self.basis.policy_version
            || state.digest() != self.state
        {
            return Err(Error::Stale);
        }
        let fresh = DiscoverySnapshot::new(archive, view, self.owner, state, self.visibility)?;
        let current = fresh.select(
            &self.query,
            &self.filters,
            self.mode,
            self.budget,
            MAX_DOCUMENTS,
        )?;
        let mut hits = Vec::with_capacity(limit.min(self.refs.len()));
        let mut owners = BTreeMap::new();
        let mut roots = BTreeSet::new();
        let mut consumed = BTreeSet::new();
        let current_by_reference: BTreeMap<_, _> = current
            .hits
            .iter()
            .map(|hit| (hit.reference, hit))
            .collect();
        for reference in &self.refs {
            let Some(&hit) = current_by_reference.get(reference) else {
                return Err(Error::Stale);
            };
            if self.mode == Some(FeedMode::Discover) {
                let n = owners.entry(hit.owner).or_insert(0);
                if *n == 2 || !roots.insert(hit.root) {
                    continue;
                }
                *n += 1;
            }
            hits.push(hit.clone());
            consumed.insert(*reference);
            if hits.len() == limit {
                break;
            }
        }
        self.refs.retain(|reference| !consumed.contains(reference));
        Ok(Page {
            matches: self.matches,
            hits,
            coverage: self.coverage,
        })
    }
    /// Number of frozen rows still available, not an unseen corpus count.
    pub fn remaining(&self) -> usize {
        self.refs.len()
    }
    /// Skip a bounded number of frozen ranked IDs without observing or opening
    /// them. Discover's diversity remains enforced on the subsequently shown page.
    pub fn skip(&mut self, count: usize) {
        let end = count.min(self.refs.len());
        self.refs.drain(..end);
    }
    /// Fixed discovery algorithm version.
    pub const fn policy_version(&self) -> u16 {
        POLICY_VERSION
    }
}
