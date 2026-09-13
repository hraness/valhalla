use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use vhalla_attention::{Attention, AttentionPolicy, NotificationSnapshot};
use vhalla_discovery::{
    Budget, Change, DiscoverySnapshot, DiscoveryState, Filters, Subscription, Visibility,
};
use vhalla_social::{
    archive::{Archive, Limits},
    view::{Content, Eligibility, Register, View},
    Actor, Body,
};

fn current_revisions(post: &vhalla_social::view::PostView<'_>) -> Result<CurrentRevisions, Error> {
    match &post.committed {
        Content::Present(Register::Resolved { value, .. }) => {
            Ok(CurrentRevisions::Resolved(value.revision))
        }
        Content::Present(Register::Conflict { alternatives, .. }) => Ok(
            CurrentRevisions::Conflict(alternatives.iter().map(|value| value.revision).collect()),
        ),
        Content::Present(Register::Empty)
        | Content::Present(Register::Incomplete)
        | Content::Retracted { .. }
        | Content::Incomplete => Err(Error::Evidence),
    }
}

const MAGIC: &[u8; 8] = b"VHUIS\0\0\x01";

/// Host-only storage image. It contains public source and private reader bytes;
/// it is never a public archive export or a component projection.
#[derive(Clone)]
pub struct Image {
    pub(crate) scope: ReaderScope,
    pub(crate) archive: Archive,
    pub(crate) attention: Attention,
    pub(crate) discovery: DiscoveryState,
}
impl Image {
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = MAGIC.to_vec();
        raw.extend_from_slice(&self.scope.digest());
        for part in [
            self.archive.snapshot(),
            self.attention.encode(),
            self.discovery.encode(),
        ] {
            raw.extend_from_slice(&(part.len() as u32).to_be_bytes());
            raw.extend_from_slice(&part);
        }
        let checksum = hash(&raw);
        raw.extend_from_slice(&checksum);
        raw
    }
    pub fn digest(&self) -> [u8; 32] {
        hash(&self.encode())
    }
    pub fn decode(raw: &[u8], scope: ReaderScope, limits: Limits) -> Result<Self, Error> {
        if raw.len() > MAX_IMAGE_BYTES
            || raw.len() < 84
            || &raw[..8] != MAGIC
            || raw[8..40] != scope.digest()
            || hash(&raw[..raw.len() - 32]) != raw[raw.len() - 32..]
        {
            return Err(Error::Corrupt);
        }
        let mut at = 40;
        let mut parts = Vec::new();
        for _ in 0..3 {
            let next = at + 4;
            let length = u32::from_be_bytes(
                raw.get(at..next)
                    .ok_or(Error::Corrupt)?
                    .try_into()
                    .map_err(|_| Error::Corrupt)?,
            ) as usize;
            at = next;
            let end = at.checked_add(length).ok_or(Error::Bounds)?;
            parts.push(raw.get(at..end).ok_or(Error::Corrupt)?);
            at = end;
        }
        if at + 32 != raw.len() {
            return Err(Error::Corrupt);
        }
        // The versioned social snapshot declares its record count before signed
        // records. Enforce this UI spike's smaller cap before signature work;
        // the maintained decoder still validates all framing and actual records.
        if parts[0].get(..8) != Some(b"VHSA\0\0\0\x01") {
            return Err(Error::Corrupt);
        }
        let count = u32::from_be_bytes(
            parts[0]
                .get(24..28)
                .ok_or(Error::Corrupt)?
                .try_into()
                .map_err(|_| Error::Corrupt)?,
        );
        if count as usize > MAX_SOURCE_RECORDS {
            return Err(Error::Bounds);
        }
        let image = Self {
            scope,
            archive: Archive::from_snapshot(scope.realm(), limits, parts[0])?,
            attention: Attention::decode(parts[1], scope)?,
            discovery: DiscoveryState::decode(parts[2], scope.digest())?,
        };
        image.validate()?;
        Ok(image)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.archive.realm() != self.scope.realm()
            || self.archive.len() > MAX_SOURCE_RECORDS
            || self.encode().len() > MAX_IMAGE_BYTES
            || self.attention.reader() != self.scope
            || *self.discovery.reader() != self.scope.digest()
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    pub(crate) fn validate_delta(&self, previous: &Self) -> Result<(), Error> {
        self.validate()?;
        if self.scope != previous.scope || !self.archive.is_extension_of(&previous.archive) {
            return Err(Error::Stale);
        }
        for id in self
            .attention
            .new_claim_sources(&previous.attention)?
            .into_iter()
            .chain(self.discovery.new_claim_sources(&previous.discovery)?)
        {
            if self.archive.get(id).is_none() {
                return Err(Error::MissingSource);
            }
        }
        for (before, after, before_bytes, after_bytes) in [
            (
                previous.attention.generation(),
                self.attention.generation(),
                previous.attention.encode(),
                self.attention.encode(),
            ),
            (
                previous.discovery.generation(),
                self.discovery.generation(),
                previous.discovery.encode(),
                self.discovery.encode(),
            ),
        ] {
            if after < before || after == before && before_bytes != after_bytes {
                return Err(Error::Stale);
            }
        }
        Ok(())
    }
}
fn hash(raw: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"vhalla/ui/storage-spike/v1\0");
    h.update(raw);
    h.finalize().into()
}
struct Issued {
    receipt: Receipt,
    screen: Screen,
    posts: BTreeSet<PostRef>,
    inbox: Option<NotificationSnapshot>,
}
pub(crate) struct Prepared {
    pub(crate) previous: [u8; 32],
    pub(crate) image: Image,
    pub(crate) screen: Screen,
}

/// One locally configured reader and at most one issued projection. Switching
/// readers constructs another engine; route strings cannot change its namespace.
pub struct Engine {
    image: Image,
    issued: Option<Issued>,
    serial: u64,
    last_time: Option<u64>,
    persistence: Persistence,
}
impl Engine {
    pub fn new(
        archive: Archive,
        scope: ReaderScope,
        attention: Attention,
        discovery: DiscoveryState,
    ) -> Result<Self, Error> {
        Self::from_image(
            Image {
                archive,
                scope,
                attention,
                discovery,
            },
            Persistence::Ephemeral,
        )
    }
    pub fn from_image(image: Image, persistence: Persistence) -> Result<Self, Error> {
        image.validate()?;
        Ok(Self {
            image,
            issued: None,
            serial: 0,
            last_time: None,
            persistence,
        })
    }
    pub fn image(&self) -> Image {
        self.image.clone()
    }
    pub fn reader(&self) -> ReaderScope {
        self.image.scope
    }
    fn time(&mut self, now: u64) -> Result<(), Error> {
        if self.last_time.is_some_and(|last| now < last) {
            return Err(Error::Clock);
        }
        self.last_time = Some(now);
        Ok(())
    }
    pub fn project(&mut self, screen: Screen, now: u64) -> Result<Projection, Error> {
        self.time(now)?;
        let eligibility = Eligibility::default();
        let view = View::new(&self.image.archive, now, &eligibility);
        let snapshot = DiscoverySnapshot::new(
            &self.image.archive,
            &view,
            self.image.scope.owner(),
            &self.image.discovery,
            Visibility::Committed,
        )?;
        let query = Query::parse("")?;
        let page = match &screen {
            Screen::Feed(mode) => snapshot.feed(*mode, Budget::default(), MAX_ROWS)?,
            Screen::Search(query) => {
                snapshot.search(query, &Filters::default(), Budget::default(), MAX_ROWS)?
            }
            Screen::FilteredSearch { query, filters } => {
                snapshot.search(query, filters, Budget::default(), MAX_ROWS)?
            }
            Screen::Thread(root) => snapshot.search(
                &query,
                &Filters {
                    root: Some(*root),
                    ..Filters::default()
                },
                Budget::default(),
                MAX_ROWS,
            )?,
            Screen::Profile(owner) => snapshot.search(
                &query,
                &Filters {
                    owner: Some(*owner),
                    ..Filters::default()
                },
                Budget::default(),
                MAX_ROWS,
            )?,
            Screen::Inbox => {
                snapshot.search_references(&query, &Filters::default(), Budget::default(), &[])?
            }
        };
        let posts: Vec<_> = page
            .hits
            .iter()
            .map(|h| {
                let post = view.post(h.reference.post).map_err(|_| Error::Evidence)?;
                let current = current_revisions(&post)?;
                // Join against admitted exact content before projecting actor claims.
                // A signed but unauthorized record never supplies affiliation here.
                let exact = view.exact_revision_text(h.reference)?;
                if exact.text != h.text || exact.facets != h.facets {
                    return Err(Error::Evidence);
                }
                let record = self
                    .image
                    .archive
                    .get(h.reference.revision)
                    .ok_or(Error::Evidence)?;
                let Body::Social { actor, .. } = record.body() else {
                    return Err(Error::Evidence);
                };
                let revision_signer = Attribution {
                    owner: actor.owner(),
                    actor: *actor,
                };
                let revision_key = *record.primary_key();
                let is_current = match &current {
                    CurrentRevisions::Resolved(id) => *id == h.reference.revision,
                    CurrentRevisions::Conflict(ids) => ids.contains(&h.reference.revision),
                };
                let position = if is_current {
                    RevisionPosition::Current
                } else {
                    RevisionPosition::Historical
                };
                Ok(PostRow {
                    reference: h.reference,
                    owner: h.owner,
                    agent: h.agent,
                    root: h.root,
                    text: h.text.into(),
                    facets: h.facets.to_vec(),
                    state: h.state,
                    why: h.why,
                    evidence: PostEvidence {
                        original: post.attribution,
                        revision_signer,
                        revision_key,
                        position,
                        current,
                        original_state: post.state,
                        revision_state: view.state(h.reference.revision).ok_or(Error::Evidence)?,
                        placement: post.placement,
                        profile_owner: post.profile_owner,
                        reply: post.reply,
                        quote: post.quote,
                        quote_attribution: post.quote_attribution,
                        reposted_by: h.reposted_by.clone(),
                        first_observed: h.first_observed,
                    },
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let profile = if let Screen::Profile(owner) = screen {
            let p = view.profile(owner)?;
            Some(ProfileRow {
                owner,
                bio: bio(&p.profile.committed),
                agents: p
                    .active_bios
                    .items
                    .iter()
                    .map(|a| AgentBio {
                        owner: a.owner,
                        agent: a.agent,
                        bio: bio(&a.bio.committed),
                    })
                    .collect(),
                incomplete: p.incomplete || p.active_bios.next_offset.is_some(),
                frozen: p.frozen,
                capacity_blocked: p.capacity_blocked,
                roster_total: p.active_bios.known_total,
                next_offset: p.active_bios.next_offset,
            })
        } else {
            None
        };
        let inbox = if screen == Screen::Inbox {
            Some(self.image.attention.notifications(
                &self.image.archive,
                now,
                &policy(&self.image.discovery)?,
                0,
                MAX_ROWS,
            )?)
        } else {
            None
        };
        let notifications = inbox
            .as_ref()
            .map(|s| {
                s.entries()
                    .iter()
                    .map(|n| InboxRow {
                        id: n.id(),
                        reason: n.update.group.reason,
                        source_owner: n.source.owner,
                        source_agent: match n.source.actor {
                            Actor::Agent { agent, .. } => Some(agent),
                            _ => None,
                        },
                        read: n.read,
                        priority: n.priority,
                        detail: n.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.serial = self.serial.checked_add(1).ok_or(Error::Bounds)?;
        let receipt = Receipt {
            namespace: self.image.scope.digest(),
            serial: self.serial,
            image: self.image.digest(),
        };
        let inbox_coverage = inbox.as_ref().map(|s| s.coverage());
        let notifications_total = inbox.as_ref().map_or(0, |s| s.total());
        self.issued = Some(Issued {
            receipt,
            screen: screen.clone(),
            posts: posts.iter().map(|p| p.reference).collect(),
            inbox,
        });
        Ok(Projection {
            screen,
            reader: self.image.scope,
            posts,
            profile,
            notifications,
            inbox_coverage,
            notifications_total,
            coverage: page.coverage,
            basis: view.basis(),
            post_matches: page.matches,
            receipt,
            persistence: self.persistence,
        })
    }
    fn receipt(&self, receipt: Receipt) -> Result<&Issued, Error> {
        self.issued
            .as_ref()
            .filter(|issued| issued.receipt == receipt && receipt.image == self.image.digest())
            .ok_or(Error::Stale)
    }
    pub(crate) fn prepare(&mut self, intent: Intent, now: u64) -> Result<Prepared, Error> {
        self.time(now)?;
        let mut next = self.image.clone();
        let screen = self
            .issued
            .as_ref()
            .map(|i| i.screen.clone())
            .unwrap_or(Screen::Inbox);
        match intent.action {
            Action::Ack(receipt, ids) => {
                let issued = self.receipt(receipt)?;
                let snapshot = issued.inbox.as_ref().ok_or(Error::Stale)?.select(&ids)?;
                next.attention = next.attention.acknowledge(&snapshot, &next.archive)?;
            }
            Action::Seen(receipt, reference) | Action::Bookmark(receipt, reference, _) => {
                if !self.receipt(receipt)?.posts.contains(&reference) {
                    return Err(Error::Stale);
                }
                let eligibility = Eligibility::default();
                let view = View::new(&next.archive, now, &eligibility);
                view.exact_revision_text(reference)?;
                match intent.action {
                    Action::Seen(..) => next.discovery.mark_seen(&view, reference)?,
                    Action::Bookmark(_, _, enabled) => {
                        next.discovery.apply(Change::Bookmark(reference, enabled))?
                    }
                    _ => unreachable!(),
                }
            }
            Action::Mute(owner, enabled) => {
                next.discovery.apply(Change::MuteOwner(owner, enabled))?
            }
        }
        next.validate_delta(&self.image)?;
        Ok(Prepared {
            previous: self.image.digest(),
            image: next,
            screen,
        })
    }
    pub(crate) fn confirm(
        &mut self,
        prepared: Prepared,
        persistence: Persistence,
        now: u64,
    ) -> Result<Projection, Error> {
        if self.image.digest() != prepared.previous {
            return Err(Error::Stale);
        }
        self.image = prepared.image;
        self.issued = None;
        self.persistence = persistence;
        self.project(prepared.screen, now)
    }
    /// Explicit disposable adapter. Success is labelled Ephemeral, never saved.
    pub fn apply_ephemeral(&mut self, intent: Intent, now: u64) -> Result<Projection, Error> {
        let prepared = self.prepare(intent, now)?;
        self.confirm(prepared, Persistence::Ephemeral, now)
    }
}
fn bio(value: &Register<&str>) -> Bio {
    match value {
        Register::Empty => Bio::Empty,
        Register::Resolved { value, .. } => Bio::Text((*value).into()),
        Register::Conflict { alternatives, .. } => {
            Bio::Conflict(alternatives.iter().map(|v| (*v).into()).collect())
        }
        Register::Incomplete => Bio::Incomplete,
    }
}
fn policy(state: &DiscoveryState) -> Result<AttentionPolicy, Error> {
    let prefs = state.preferences();
    let mut selected = BTreeSet::new();
    let mut watched = BTreeSet::new();
    for s in prefs.subscriptions() {
        match s {
            Subscription::Owner(o) => {
                selected.insert(*o);
            }
            Subscription::Thread(root) => {
                watched.insert(*root);
            }
            _ => {}
        }
    }
    let muted = prefs
        .muted_owners()
        .union(prefs.blocked_owners())
        .copied()
        .collect();
    Ok(AttentionPolicy::new(
        selected.into_iter().collect(),
        muted,
        watched.into_iter().collect(),
        false,
    )?
    .with_muted_threads(prefs.muted_threads().iter().copied().collect())?)
}

/// Deterministic transaction model; not browser persistence evidence.
pub struct MemoryStorage {
    raw: Vec<u8>,
}
impl MemoryStorage {
    pub fn new(image: &Image) -> Self {
        Self {
            raw: image.encode(),
        }
    }
    pub fn reopen(&self, scope: ReaderScope, limits: Limits) -> Result<Image, Error> {
        Image::decode(&self.raw, scope, limits)
    }
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn submit(
        &mut self,
        engine: &mut Engine,
        intent: Intent,
        now: u64,
        abort: bool,
    ) -> Result<Projection, Error> {
        let pending = engine.prepare(intent, now)?;
        let current = self.reopen(engine.reader(), engine.image.archive.limits())?;
        if current.digest() != pending.previous {
            return Err(Error::Stale);
        }
        pending.image.validate_delta(&current)?;
        if abort {
            return Err(Error::Storage);
        }
        self.raw = pending.image.encode();
        engine.confirm(pending, Persistence::Ephemeral, now)
    }
}
