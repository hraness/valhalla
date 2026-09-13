//! Canonical private reader preferences. Never included in public social export.
use crate::{Error, Query, MAX_DOCUMENTS};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use sha2::{Digest, Sha256};
use vhalla_core::RoomId;
use vhalla_social::{
    view::{RecordState, View},
    AgentId, OwnerId, PostRef, RecordId,
};

/// Maximum canonical private discovery blob.
pub const MAX_STATE_BYTES: usize = 1024 * 1024;
/// Bounded list size for a reader preference category.
pub const MAX_PREFERENCES: usize = 256;

/// Inert local subscription, never a public Follow or permission.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Subscription {
    /// Owner's public content.
    Owner(OwnerId),
    /// Exact agent incarnation.
    Agent(AgentId),
    /// Realm-local channel.
    Channel(RoomId),
    /// Canonical ASCII topic.
    Tag(String),
    /// Exact conversation root.
    Thread(RecordId),
}

/// Explicit private edits. Remote records cannot apply these commands.
#[derive(Clone, Debug)]
pub enum Change {
    /// Add/remove an inert subscription (Thread also implements watch/unwatch).
    Subscribe(Subscription, bool),
    /// Hide an owner locally; does not discard control evidence.
    MuteOwner(OwnerId, bool),
    /// Local presentation/interaction block, not global deletion.
    BlockOwner(OwnerId, bool),
    /// Hide one conversation root.
    MuteThread(RecordId, bool),
    /// Remember an exact post/revision; unresolved references are allowed.
    Bookmark(PostRef, bool),
    /// Explicit more/less feedback; cumulative affinity clamps at -4..4.
    Interest {
        /// Canonical ASCII topic.
        tag: String,
        /// Explicit signed adjustment, from -4 through 4.
        delta: i8,
    },
    /// Remove all learned topic preferences.
    ClearInterests,
    /// Save bounded literal query text under a local name.
    SaveSearch {
        /// Bounded local label.
        name: String,
        /// Bounded literal query, no executable expression.
        query: String,
    },
    /// Remove a saved query.
    RemoveSearch(String),
    /// Opt in to the retained wider local corpus for Discover.
    Wider(bool),
}

/// Immutable-borrow view of all local settings; edits go through checked changes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Preferences {
    pub(crate) subscriptions: BTreeSet<Subscription>,
    pub(crate) muted: BTreeSet<OwnerId>,
    pub(crate) blocked: BTreeSet<OwnerId>,
    pub(crate) muted_threads: BTreeSet<RecordId>,
    pub(crate) bookmarks: BTreeSet<PostRef>,
    pub(crate) interests: BTreeMap<String, i8>,
    pub(crate) searches: BTreeMap<String, String>,
    pub(crate) wider: bool,
}
impl Preferences {
    /// Exact subscription set.
    pub fn subscriptions(&self) -> &BTreeSet<Subscription> {
        &self.subscriptions
    }
    /// Locally muted owners.
    pub fn muted_owners(&self) -> &BTreeSet<OwnerId> {
        &self.muted
    }
    /// Locally blocked owners.
    pub fn blocked_owners(&self) -> &BTreeSet<OwnerId> {
        &self.blocked
    }
    /// Locally muted conversation roots.
    pub fn muted_threads(&self) -> &BTreeSet<RecordId> {
        &self.muted_threads
    }
    /// Exact bookmarked references, including unresolved suggestions.
    pub fn bookmarks(&self) -> &BTreeSet<PostRef> {
        &self.bookmarks
    }
    /// Private explicit topic affinity.
    pub fn interests(&self) -> &BTreeMap<String, i8> {
        &self.interests
    }
    /// Named bounded literal queries.
    pub fn saved_searches(&self) -> &BTreeMap<String, String> {
        &self.searches
    }
    /// Whether wider local candidate selection was explicitly enabled.
    pub const fn wider(&self) -> bool {
        self.wider
    }
}

/// One reader's bounded state. Reader bytes are a namespace, never authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryState {
    reader: [u8; 32],
    generation: u64,
    preferences: Preferences,
    observations: BTreeMap<RecordId, u64>,
    next_ordinal: u64,
    seen: BTreeSet<PostRef>,
    feedback: BTreeMap<RecordId, (PostRef, i8)>,
    learning_ignored: BTreeSet<PostRef>,
}
impl DiscoveryState {
    /// Create an empty local namespace; the host binds its validated ReaderScope.
    pub fn new(reader: [u8; 32]) -> Self {
        Self {
            reader,
            generation: 0,
            preferences: Preferences::default(),
            observations: BTreeMap::new(),
            next_ordinal: 0,
            seen: BTreeSet::new(),
            feedback: BTreeMap::new(),
            learning_ignored: BTreeSet::new(),
        }
    }
    /// Namespace digest supplied by the validated local reader scope.
    pub const fn reader(&self) -> &[u8; 32] {
        &self.reader
    }
    /// Checked monotonic private mutation generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Read preferences without allowing unchecked mutation.
    pub const fn preferences(&self) -> &Preferences {
        &self.preferences
    }
    /// Persisted first eligible observation; absence is unknown, not oldest time.
    pub fn ordinal(&self, id: RecordId) -> Option<u64> {
        self.observations.get(&id).copied()
    }
    /// Latest private observation ordinal, not a publication clock.
    pub const fn cutoff(&self) -> u64 {
        self.next_ordinal
    }
    /// Exact explicitly acknowledged content, independent of notifications.
    pub fn seen(&self, reference: PostRef) -> bool {
        self.seen.contains(&reference)
    }
    /// Digest binds cursors to the exact settings and seen/observation metadata.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"vhalla/discovery/private/v1");
        h.update(self.encode());
        h.finalize().into()
    }
    fn mutate(&mut self, change: impl FnOnce(&mut Self) -> Result<(), Error>) -> Result<(), Error> {
        let mut next = self.clone();
        change(&mut next)?;
        if next != *self {
            next.generation = self.generation.checked_add(1).ok_or(Error::Bounds)?;
            *self = next;
        }
        Ok(())
    }
    /// Apply one bounded explicit local preference edit atomically.
    pub fn apply(&mut self, change: Change) -> Result<(), Error> {
        self.mutate(|next| {
            let p = &mut next.preferences;
            match change {
                Change::Subscribe(s, yes) => {
                    if let Subscription::Tag(tag) = &s {
                        valid_tag(tag)?;
                    }
                    toggle(&mut p.subscriptions, s, yes, MAX_PREFERENCES)?;
                }
                Change::MuteOwner(o, yes) => toggle(&mut p.muted, o, yes, MAX_PREFERENCES)?,
                Change::BlockOwner(o, yes) => toggle(&mut p.blocked, o, yes, MAX_PREFERENCES)?,
                Change::MuteThread(r, yes) => {
                    toggle(&mut p.muted_threads, r, yes, MAX_PREFERENCES)?
                }
                Change::Bookmark(r, yes) => {
                    toggle(&mut p.bookmarks, r, yes, MAX_PREFERENCES)?;
                    if !yes {
                        next.learning_ignored.remove(&r);
                    }
                }
                Change::Interest { tag, delta } => {
                    valid_tag(&tag)?;
                    if !(-4..=4).contains(&delta) {
                        return Err(Error::Bounds);
                    }
                    if !p.interests.contains_key(&tag) && p.interests.len() == MAX_PREFERENCES {
                        return Err(Error::Budget);
                    }
                    let value = (p.interests.get(&tag).copied().unwrap_or(0) + delta).clamp(-4, 4);
                    if value == 0 {
                        p.interests.remove(&tag);
                    } else {
                        p.interests.insert(tag, value);
                    }
                }
                Change::ClearInterests => {
                    p.interests.clear();
                    next.feedback.clear();
                    next.learning_ignored = p.bookmarks.clone();
                }
                Change::SaveSearch { name, query } => {
                    valid_name(&name)?;
                    Query::parse(&query)?;
                    if !p.searches.contains_key(&name) && p.searches.len() == 32 {
                        return Err(Error::Budget);
                    }
                    p.searches.insert(name, query);
                }
                Change::RemoveSearch(name) => {
                    valid_name(&name)?;
                    p.searches.remove(&name);
                }
                Change::Wider(wider) => p.wider = wider,
            }
            Ok(())
        })
    }
    /// Record first semantic eligibility from an actual social view. Raw signed
    /// pending content cannot assign freshness; later sealing does not bump it.
    pub fn observe(&mut self, view: &View<'_>) -> Result<(), Error> {
        let ids: BTreeSet<_> = view
            .posts(None)
            .into_iter()
            .filter(|post| {
                matches!(
                    post.state,
                    RecordState::Committed | RecordState::Provisional
                )
            })
            .map(|p| p.id)
            .collect();
        self.mutate(|next| {
            for id in ids {
                if next.observations.contains_key(&id) {
                    continue;
                }
                if next.observations.len() == MAX_DOCUMENTS {
                    return Err(Error::Budget);
                }
                next.next_ordinal = next.next_ordinal.checked_add(1).ok_or(Error::Bounds)?;
                next.observations.insert(id, next.next_ordinal);
            }
            Ok(())
        })
    }
    /// Mark exact currently visible/evidenced content explicitly opened/seen.
    /// Querying, importing and prefetching never call this implicitly.
    pub fn mark_seen(&mut self, view: &View<'_>, reference: PostRef) -> Result<(), Error> {
        view.exact_revision_text(reference)
            .map_err(|_| Error::Evidence)?;
        self.mutate(|next| toggle(&mut next.seen, reference, true, MAX_DOCUMENTS))
    }
    /// Set this reader's own up/down/clear feedback on one exact reviewed post.
    /// Repeating or toggling this slot cannot accumulate interest weight.
    pub fn feedback(
        &mut self,
        view: &View<'_>,
        reference: PostRef,
        value: i8,
    ) -> Result<(), Error> {
        if !(-1..=1).contains(&value) {
            return Err(Error::Bounds);
        }
        if value != 0 {
            view.exact_revision_text(reference)
                .map_err(|_| Error::Evidence)?;
        }
        self.mutate(|next| {
            if value == 0 {
                next.feedback.remove(&reference.post);
            } else {
                if !next.feedback.contains_key(&reference.post)
                    && next.feedback.len() == MAX_DOCUMENTS
                {
                    return Err(Error::Budget);
                }
                next.feedback.insert(reference.post, (reference, value));
            }
            Ok(())
        })
    }
    /// Exact private feedback slots for local ranking only.
    pub fn feedback_entries(&self) -> impl Iterator<Item = (PostRef, i8)> + '_ {
        self.feedback.values().copied()
    }
    /// Bookmarks created since the last learning reset; reset preserves the
    /// bookmark list itself and prevents old entries immediately relearning topics.
    pub fn learning_bookmarks(&self) -> impl Iterator<Item = PostRef> + '_ {
        self.preferences
            .bookmarks
            .iter()
            .filter(|r| !self.learning_ignored.contains(r))
            .copied()
    }
    /// Exact evidence claims checked by the native store before publication.
    /// Bookmarks and future subscriptions are suggestions and excluded.
    pub fn required_sources(&self) -> Vec<RecordId> {
        self.observations
            .keys()
            .copied()
            .chain(self.seen.iter().flat_map(|r| [r.post, r.revision]))
            .chain(
                self.feedback
                    .values()
                    .flat_map(|(r, _)| [r.post, r.revision]),
            )
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    /// Sources for newly created or changed semantic claims, even when another
    /// older claim already referred to the same record. This prevents a prior
    /// observation from standing in for a new acknowledgement after partial restore.
    pub fn new_claim_sources(&self, previous: &Self) -> Result<Vec<RecordId>, Error> {
        if self.reader != previous.reader {
            return Err(Error::Stale);
        }
        let mut ids = BTreeSet::new();
        for (id, ordinal) in &self.observations {
            if previous.observations.get(id) != Some(ordinal) {
                ids.insert(*id);
            }
        }
        for reference in self.seen.difference(&previous.seen) {
            ids.extend([reference.post, reference.revision]);
        }
        for (post, claim) in &self.feedback {
            if previous.feedback.get(post) != Some(claim) {
                ids.extend([claim.0.post, claim.0.revision]);
            }
        }
        Ok(ids.into_iter().collect())
    }
    /// Canonical bounded versioned bytes, for the private store only.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = b"VHDS\0\0\0\x01".to_vec();
        o.extend(self.reader);
        o.extend(self.generation.to_be_bytes());
        o.extend(self.next_ordinal.to_be_bytes());
        count(&mut o, self.preferences.subscriptions.len());
        for s in &self.preferences.subscriptions {
            match s {
                Subscription::Owner(id) => {
                    o.push(0);
                    o.extend(id.as_bytes());
                }
                Subscription::Agent(id) => {
                    o.push(1);
                    o.extend(id.as_bytes());
                }
                Subscription::Channel(id) => {
                    o.push(2);
                    o.extend(id.0.to_be_bytes());
                }
                Subscription::Tag(tag) => {
                    o.push(3);
                    text(&mut o, tag);
                }
                Subscription::Thread(id) => {
                    o.push(4);
                    o.extend(id.as_bytes());
                }
            }
        }
        for set in [&self.preferences.muted, &self.preferences.blocked] {
            count(&mut o, set.len());
            for id in set {
                o.extend(id.as_bytes());
            }
        }
        count(&mut o, self.preferences.muted_threads.len());
        for id in &self.preferences.muted_threads {
            o.extend(id.as_bytes());
        }
        for set in [&self.preferences.bookmarks, &self.seen] {
            count(&mut o, set.len());
            for r in set {
                o.extend(r.post.as_bytes());
                o.extend(r.revision.as_bytes());
            }
        }
        count(&mut o, self.feedback.len());
        for (r, v) in self.feedback.values() {
            o.extend(r.post.as_bytes());
            o.extend(r.revision.as_bytes());
            o.push((*v + 1) as u8);
        }
        count(&mut o, self.learning_ignored.len());
        for r in &self.learning_ignored {
            o.extend(r.post.as_bytes());
            o.extend(r.revision.as_bytes());
        }
        count(&mut o, self.preferences.interests.len());
        for (tag, v) in &self.preferences.interests {
            text(&mut o, tag);
            o.push((*v + 4) as u8);
        }
        count(&mut o, self.preferences.searches.len());
        for (name, q) in &self.preferences.searches {
            text(&mut o, name);
            text(&mut o, q);
        }
        o.push(u8::from(self.preferences.wider));
        count(&mut o, self.observations.len());
        for (id, ordinal) in &self.observations {
            o.extend(id.as_bytes());
            o.extend(ordinal.to_be_bytes());
        }
        o
    }
    /// Decode with an externally chosen reader namespace and strict bounds.
    pub fn decode(raw: &[u8], reader: [u8; 32]) -> Result<Self, Error> {
        if raw.len() > MAX_STATE_BYTES {
            return Err(Error::Bounds);
        }
        let mut d = Decoder { raw, at: 0 };
        if d.take(8)? != b"VHDS\0\0\0\x01" {
            return Err(Error::Encoding);
        }
        if d.array::<32>()? != reader {
            return Err(Error::Stale);
        }
        let generation = d.u64()?;
        let next_ordinal = d.u64()?;
        let mut s = Self::new(reader);
        s.generation = generation;
        s.next_ordinal = next_ordinal;
        for _ in 0..d.count(MAX_PREFERENCES)? {
            let item = match d.byte()? {
                0 => Subscription::Owner(OwnerId::from_bytes(d.array()?)),
                1 => Subscription::Agent(AgentId::from_bytes(d.array()?)),
                2 => Subscription::Channel(RoomId(u128::from_be_bytes(d.array()?))),
                3 => {
                    let tag = d.text(48)?;
                    valid_tag(&tag)?;
                    Subscription::Tag(tag)
                }
                4 => Subscription::Thread(RecordId::from_bytes(d.array()?)),
                _ => return Err(Error::Encoding),
            };
            s.preferences.subscriptions.insert(item);
        }
        for set in [&mut s.preferences.muted, &mut s.preferences.blocked] {
            for _ in 0..d.count(MAX_PREFERENCES)? {
                set.insert(OwnerId::from_bytes(d.array()?));
            }
        }
        for _ in 0..d.count(MAX_PREFERENCES)? {
            s.preferences
                .muted_threads
                .insert(RecordId::from_bytes(d.array()?));
        }
        for (set, max) in [
            (&mut s.preferences.bookmarks, MAX_PREFERENCES),
            (&mut s.seen, MAX_DOCUMENTS),
        ] {
            for _ in 0..d.count(max)? {
                set.insert(PostRef {
                    post: RecordId::from_bytes(d.array()?),
                    revision: RecordId::from_bytes(d.array()?),
                });
            }
        }
        for _ in 0..d.count(MAX_DOCUMENTS)? {
            let r = PostRef {
                post: RecordId::from_bytes(d.array()?),
                revision: RecordId::from_bytes(d.array()?),
            };
            let v = d.byte()?;
            if v != 0 && v != 2 {
                return Err(Error::Encoding);
            }
            s.feedback.insert(r.post, (r, v as i8 - 1));
        }
        for _ in 0..d.count(MAX_PREFERENCES)? {
            let r = PostRef {
                post: RecordId::from_bytes(d.array()?),
                revision: RecordId::from_bytes(d.array()?),
            };
            if !s.preferences.bookmarks.contains(&r) {
                return Err(Error::Encoding);
            }
            s.learning_ignored.insert(r);
        }
        for _ in 0..d.count(MAX_PREFERENCES)? {
            let tag = d.text(48)?;
            valid_tag(&tag)?;
            let n = d.byte()?;
            if n > 8 || n == 4 {
                return Err(Error::Encoding);
            }
            s.preferences.interests.insert(tag, n as i8 - 4);
        }
        for _ in 0..d.count(32)? {
            let name = d.text(48)?;
            valid_name(&name)?;
            let q = d.text(256)?;
            Query::parse(&q)?;
            s.preferences.searches.insert(name, q);
        }
        s.preferences.wider = match d.byte()? {
            0 => false,
            1 => true,
            _ => return Err(Error::Encoding),
        };
        let mut ordinals = BTreeSet::new();
        for _ in 0..d.count(MAX_DOCUMENTS)? {
            let id = RecordId::from_bytes(d.array()?);
            let n = d.u64()?;
            if n == 0 || n > next_ordinal || !ordinals.insert(n) {
                return Err(Error::Encoding);
            }
            s.observations.insert(id, n);
        }
        if next_ordinal != s.observations.len() as u64 || d.at != raw.len() || s.encode() != raw {
            return Err(Error::Encoding);
        }
        Ok(s)
    }
}

pub(crate) fn valid_tag(s: &str) -> Result<(), Error> {
    let b = s.as_bytes();
    if b.is_empty()
        || b.len() > 48
        || !b[0].is_ascii_lowercase() && !b[0].is_ascii_digit() && b[0] != b'_'
        || b.iter()
            .any(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && *c != b'_' && *c != b'-')
    {
        Err(Error::Bounds)
    } else {
        Ok(())
    }
}
fn valid_name(s: &str) -> Result<(), Error> {
    if s.is_empty() || s.len() > 48 || s.bytes().any(|b| b.is_ascii_control()) {
        Err(Error::Bounds)
    } else {
        Ok(())
    }
}
fn toggle<T: Ord>(set: &mut BTreeSet<T>, v: T, yes: bool, max: usize) -> Result<(), Error> {
    if yes {
        if !set.contains(&v) && set.len() == max {
            return Err(Error::Budget);
        }
        set.insert(v);
    } else {
        set.remove(&v);
    }
    Ok(())
}
fn count(out: &mut Vec<u8>, n: usize) {
    out.extend((n as u16).to_be_bytes());
}
fn text(out: &mut Vec<u8>, s: &str) {
    count(out, s.len());
    out.extend(s.as_bytes());
}
struct Decoder<'a> {
    raw: &'a [u8],
    at: usize,
}
impl Decoder<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Error> {
        let end = self.at.checked_add(n).ok_or(Error::Bounds)?;
        let b = self.raw.get(self.at..end).ok_or(Error::Encoding)?;
        self.at = end;
        Ok(b)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn count(&mut self, max: usize) -> Result<usize, Error> {
        let n = u16::from_be_bytes(self.array()?) as usize;
        if n > max {
            Err(Error::Bounds)
        } else {
            Ok(n)
        }
    }
    fn text(&mut self, max: usize) -> Result<String, Error> {
        let n = self.count(max)?;
        core::str::from_utf8(self.take(n)?)
            .map(String::from)
            .map_err(|_| Error::Encoding)
    }
}
