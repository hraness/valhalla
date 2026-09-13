#![no_std]
#![forbid(unsafe_code)]
//! Disposable query/ranking models. `Document` is fixture data, never admission.
extern crate alloc;
use alloc::{collections::BTreeSet, string::String, vec::Vec};
use core::cmp::Reverse;

pub type Id = [u8; 32];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    Owner(Id),
    Agent(Id),
}
pub const MAX_DOCS: usize = 4096;
pub const MAX_TEXT: usize = 4096;
pub const MAX_TERMS: usize = 8;
pub const MAX_QUERY: usize = 256;
pub const MAX_PAGE: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bounds,
    Syntax,
    Budget,
    Stale,
    Clock,
}

#[derive(Clone, Debug)]
pub struct Query {
    terms: Vec<String>,
}
impl Query {
    /// ASCII whitespace outside quotes; quoted whitespace and punctuation literal.
    /// Backslash and embedded/mixed quotes are rejected rather than guessed.
    pub fn parse(input: &str) -> Result<Self, Error> {
        if input.len() > MAX_QUERY {
            return Err(Error::Bounds);
        }
        let b = input.as_bytes();
        let mut i = 0;
        let mut terms = Vec::new();
        while i < b.len() {
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i == b.len() {
                break;
            }
            let quoted = b[i] == b'"';
            if quoted {
                i += 1;
            }
            let start = i;
            while i < b.len()
                && if quoted {
                    b[i] != b'"'
                } else {
                    !b[i].is_ascii_whitespace()
                }
            {
                if b[i] == b'\\' || (!quoted && b[i] == b'"') {
                    return Err(Error::Syntax);
                }
                i += 1;
            }
            if quoted && i == b.len() {
                return Err(Error::Syntax);
            }
            if i == start {
                return Err(Error::Syntax);
            }
            let term = &input[start..i];
            if term.len() > 96 || terms.len() == MAX_TERMS {
                return Err(Error::Bounds);
            }
            terms.push(String::from(term));
            if quoted {
                i += 1;
                if i < b.len() && !b[i].is_ascii_whitespace() {
                    return Err(Error::Syntax);
                }
            }
        }
        Ok(Self { terms })
    }
    pub fn terms(&self) -> &[String] {
        &self.terms
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Document<'a> {
    pub id: Id,
    pub revision: Id,
    pub owner: Id,
    pub agent: Option<Id>,
    pub channel: Option<u32>,
    pub root: Id,
    pub text: &'a str,
    pub tags: &'a [&'a str],
    pub mentions: &'a [Target],
    pub first_observed: u64,
    pub committed: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Filter<'a> {
    pub owner: Option<Id>,
    pub agent: Option<Id>,
    pub channel: Option<u32>,
    pub root: Option<Id>,
    pub tag: Option<&'a str>,
    pub mention: Option<Target>,
    pub committed_only: bool,
}
impl Filter<'_> {
    fn matches(self, d: &Document<'_>) -> bool {
        self.owner.is_none_or(|x| x == d.owner)
            && self.agent.is_none_or(|x| d.agent == Some(x))
            && self.channel.is_none_or(|x| d.channel == Some(x))
            && self.root.is_none_or(|x| x == d.root)
            && self.tag.is_none_or(|x| d.tags.contains(&x))
            && self.mention.is_none_or(|x| d.mentions.contains(&x))
            && (!self.committed_only || d.committed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    pub documents: usize,
    pub bytes: usize,
    pub comparisons: usize,
}
impl Budget {
    pub const fn standard() -> Self {
        Self {
            documents: MAX_DOCS,
            bytes: MAX_DOCS * MAX_TEXT,
            comparisons: 16 * 1024 * 1024,
        }
    }
    fn document(&mut self, d: &Document<'_>) -> Result<(), Error> {
        if self.documents == 0 || d.text.len() > self.bytes {
            return Err(Error::Budget);
        }
        self.documents -= 1;
        self.bytes -= d.text.len();
        Ok(())
    }
    fn compare(&mut self) -> Result<(), Error> {
        if self.comparisons == 0 {
            return Err(Error::Budget);
        }
        self.comparisons -= 1;
        Ok(())
    }
}

fn literal(haystack: &[u8], needle: &[u8], budget: &mut Budget) -> Result<bool, Error> {
    if needle.len() > haystack.len() {
        return Ok(false);
    }
    for window in haystack.windows(needle.len()) {
        let mut matched = true;
        for (a, b) in window.iter().zip(needle) {
            budget.compare()?;
            if !a.eq_ignore_ascii_case(b) {
                matched = false;
                break;
            }
        }
        if matched {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hit {
    pub id: Id,
    pub revision: Id,
    pub observed: u64,
}
impl Hit {
    fn key(&self) -> (Reverse<u64>, Id, Id) {
        (Reverse(self.observed), self.id, self.revision)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Results {
    pub hits: Vec<Hit>,
    /// Exact only if complete; otherwise lower bound over examined documents.
    pub matches: usize,
    pub examined: usize,
    pub complete: bool,
    pub remaining: Budget,
}

fn checked_docs(docs: &[Document<'_>]) -> Result<(), Error> {
    if docs.len() > MAX_DOCS
        || docs.iter().any(|d| {
            d.text.len() > MAX_TEXT
                || d.tags.len() > 8
                || d.mentions.len() > 8
                || d.tags.iter().any(|tag| tag.len() > 48)
        })
    {
        return Err(Error::Bounds);
    }
    Ok(())
}

pub fn scan(
    docs: &[Document<'_>],
    query: &Query,
    filter: Filter<'_>,
    budget: Budget,
    limit: usize,
) -> Result<Results, Error> {
    run(docs, query, filter, budget, limit, None)
}

fn run(
    docs: &[Document<'_>],
    query: &Query,
    filter: Filter<'_>,
    mut budget: Budget,
    limit: usize,
    candidates: Option<&BTreeSet<usize>>,
) -> Result<Results, Error> {
    checked_docs(docs)?;
    if limit == 0 || limit > MAX_PAGE || filter.tag.is_some_and(|tag| tag.len() > 48) {
        return Err(Error::Bounds);
    }
    let mut out = Results {
        hits: Vec::with_capacity(limit),
        matches: 0,
        examined: 0,
        complete: true,
        remaining: budget,
    };
    for (position, d) in docs.iter().enumerate() {
        // Charge unsuccessful, filtered and index-excluded documents too.
        if budget.document(d).is_err() {
            out.complete = false;
            break;
        }
        out.examined += 1;
        if !filter.matches(d) || candidates.is_some_and(|ids| !ids.contains(&position)) {
            continue;
        }
        let mut matched = true;
        for term in &query.terms {
            match literal(d.text.as_bytes(), term.as_bytes(), &mut budget) {
                Ok(true) => (),
                Ok(false) => {
                    matched = false;
                    break;
                }
                Err(_) => {
                    out.complete = false;
                    matched = false;
                    break;
                }
            }
        }
        if !out.complete {
            break;
        }
        if matched {
            out.matches += 1;
            let hit = Hit {
                id: d.id,
                revision: d.revision,
                observed: d.first_observed,
            };
            let at = out.hits.partition_point(|prior| prior.key() < hit.key());
            if at < limit {
                // Remove before insertion: capacity never temporarily needs k+1.
                if out.hits.len() == limit {
                    out.hits.pop();
                }
                out.hits.insert(at, hit);
            }
        }
    }
    out.remaining = budget;
    Ok(out)
}

/// Flat sorted byte trigrams. Only an acceleration hint; every candidate is rechecked.
pub struct Index<'a, 'd> {
    entries: Vec<([u8; 3], usize)>,
    docs: &'a [Document<'d>],
}
impl<'a, 'd> Index<'a, 'd> {
    /// Builds all or fails; an incomplete index must never claim no matches.
    pub fn build(docs: &'a [Document<'d>], max_entries: usize) -> Result<Self, Error> {
        checked_docs(docs)?;
        let mut entries = Vec::new();
        for (i, d) in docs.iter().enumerate() {
            let mut distinct = BTreeSet::new();
            for w in d.text.as_bytes().windows(3) {
                distinct.insert([
                    w[0].to_ascii_lowercase(),
                    w[1].to_ascii_lowercase(),
                    w[2].to_ascii_lowercase(),
                ]);
            }
            if distinct.len() > max_entries.saturating_sub(entries.len()) {
                return Err(Error::Budget);
            }
            entries.extend(distinct.into_iter().map(|trigram| (trigram, i)));
        }
        entries.sort_unstable();
        Ok(Self { entries, docs })
    }
    pub fn entries(&self) -> usize {
        self.entries.len()
    }
    /// Vector payload only: allocator metadata, build scratch and text are excluded.
    pub fn retained_payload_bytes(&self) -> usize {
        self.entries.capacity() * core::mem::size_of::<([u8; 3], usize)>()
    }
    pub fn search(
        &self,
        query: &Query,
        filter: Filter<'_>,
        mut budget: Budget,
        limit: usize,
    ) -> Result<Results, Error> {
        // Select the narrowest first trigram among query terms. This never assumes
        // word boundaries and safely falls back for one/two-byte terms.
        let mut best: Option<&[([u8; 3], usize)]> = None;
        for term in &query.terms {
            if term.len() < 3 {
                continue;
            }
            let b = term.as_bytes();
            let gram = [
                b[0].to_ascii_lowercase(),
                b[1].to_ascii_lowercase(),
                b[2].to_ascii_lowercase(),
            ];
            // Binary-search upper bound costs are explicitly charged conservatively.
            for _ in 0..(2 * (usize::BITS - self.entries.len().leading_zeros()) as usize + 2) {
                budget.compare()?;
            }
            let start = self.entries.partition_point(|(g, _)| g < &gram);
            let end = self.entries.partition_point(|(g, _)| g <= &gram);
            let range = &self.entries[start..end];
            if best.is_none_or(|prior| range.len() < prior.len()) {
                best = Some(range);
            }
        }
        let candidates = if let Some(range) = best {
            let mut ids = BTreeSet::new();
            for (_, i) in range {
                budget.compare()?;
                ids.insert(*i);
            }
            Some(ids)
        } else {
            None
        };
        run(self.docs, query, filter, budget, limit, candidates.as_ref())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Basis {
    pub corpus: Id,
    pub reader: Id,
    pub preferences: u64,
    pub observations: u64,
    pub policy: u16,
    pub ranking_cutoff: u64,
}

#[derive(Default)]
pub struct Observations {
    ordinals: alloc::collections::BTreeMap<Id, u64>,
    next: u64,
}
impl Observations {
    /// Caller supplies only IDs eligible in a freshly verified semantic view.
    /// Pending/signature-only records are intentionally absent from this interface.
    pub fn observe_eligible(&mut self, eligible: &[Id]) -> Result<(), Error> {
        if eligible.len() > MAX_DOCS {
            return Err(Error::Bounds);
        }
        let incoming: BTreeSet<_> = eligible
            .iter()
            .filter(|id| !self.ordinals.contains_key(*id))
            .copied()
            .collect();
        if incoming.len() > MAX_DOCS - self.ordinals.len() {
            return Err(Error::Budget);
        }
        self.next
            .checked_add(incoming.len() as u64)
            .ok_or(Error::Bounds)?;
        // Stable within one batch; separate batch ordering is explicitly local.
        for id in incoming {
            self.next += 1;
            self.ordinals.insert(id, self.next);
        }
        Ok(())
    }
    pub fn ordinal(&self, id: Id) -> Option<u64> {
        self.ordinals.get(&id).copied()
    }
}
pub struct Cursor {
    basis: Basis,
    query: String,
    ids: Vec<(Id, Id)>,
    next: usize,
    last_authority_time: u64,
}
impl Cursor {
    pub fn new(
        basis: Basis,
        query: String,
        ids: Vec<(Id, Id)>,
        authority_time: u64,
    ) -> Result<Self, Error> {
        if ids.len() > MAX_DOCS || query.len() > MAX_QUERY {
            return Err(Error::Bounds);
        }
        Ok(Self {
            basis,
            query,
            ids,
            next: 0,
            last_authority_time: authority_time,
        })
    }
    /// Scope equality is separate from a mandatory fresh authorization callback.
    /// No body is retained. A single withdrawn/expired item invalidates the page.
    pub fn page(
        &mut self,
        current: Basis,
        query: &str,
        now: u64,
        limit: usize,
        mut currently_visible: impl FnMut((Id, Id), u64) -> bool,
    ) -> Result<&[(Id, Id)], Error> {
        if current != self.basis || self.query != query {
            return Err(Error::Stale);
        }
        if now < self.last_authority_time {
            return Err(Error::Clock);
        }
        if limit == 0 || limit > MAX_PAGE {
            return Err(Error::Bounds);
        }
        self.last_authority_time = now;
        let end = self.ids.len().min(self.next + limit);
        if self.ids[self.next..end]
            .iter()
            .any(|id| !currently_visible(*id, now))
        {
            return Err(Error::Stale);
        }
        let start = self.next;
        self.next = end;
        Ok(&self.ids[start..end])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RankInput<'a> {
    pub id: Id,
    pub revision: Id,
    pub owner: Id,
    pub root: Id,
    pub followed: bool,
    pub subscribed: bool,
    /// Reader-local explicit feedback, not public reaction count or dwell time.
    pub topic_affinity: i8,
    pub endorsers: &'a [Id],
    pub observed: u64,
    pub unseen: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ranked {
    pub id: Id,
    pub revision: Id,
    pub owner: Id,
    pub root: Id,
    pub score: i16,
    pub why: [i16; 6],
}
pub fn rank(
    rows: &[RankInput<'_>],
    selected: &BTreeSet<Id>,
    cutoff: u64,
    limit: usize,
) -> Result<Vec<Ranked>, Error> {
    if rows.len() > MAX_DOCS
        || selected.len() > MAX_DOCS
        || limit == 0
        || limit > MAX_PAGE
        || rows.iter().any(|x| x.endorsers.len() > MAX_DOCS)
    {
        return Err(Error::Bounds);
    }
    let mut merged = alloc::collections::BTreeMap::new();
    let mut ranked = Vec::new();
    let mut endorsement_steps = 1_048_576usize;
    for r in rows {
        if r.endorsers.len() > endorsement_steps {
            return Err(Error::Budget);
        }
        endorsement_steps -= r.endorsers.len();
        let (prior, endorsements) = merged
            .entry((r.id, r.revision))
            .or_insert((*r, BTreeSet::<Id>::new()));
        if (
            prior.owner,
            prior.root,
            prior.topic_affinity,
            prior.observed,
            prior.unseen,
        ) != (r.owner, r.root, r.topic_affinity, r.observed, r.unseen)
        {
            return Err(Error::Bounds);
        }
        prior.followed |= r.followed;
        prior.subscribed |= r.subscribed;
        endorsements.extend(
            r.endorsers
                .iter()
                .filter(|id| **id != r.owner && selected.contains(*id))
                .copied(),
        );
    }
    for (_, (r, endorsements)) in merged {
        let age = cutoff.saturating_sub(r.observed.min(cutoff));
        let why = [
            if r.followed { 128 } else { 0 },
            if r.subscribed { 64 } else { 0 },
            i16::from(r.topic_affinity.clamp(-4, 4)) * 16,
            endorsements.len().min(4) as i16 * 8,
            15 - age.min(15) as i16,
            if r.unseen { 8 } else { 0 },
        ];
        ranked.push(Ranked {
            id: r.id,
            revision: r.revision,
            owner: r.owner,
            root: r.root,
            score: why.iter().sum(),
            why,
        });
    }
    ranked.sort_unstable_by_key(|r| (Reverse(r.score), r.id, r.revision));
    let mut owners = alloc::collections::BTreeMap::new();
    let mut roots = BTreeSet::new();
    let mut output = Vec::with_capacity(limit);
    for row in ranked {
        let count = owners.entry(row.owner).or_insert(0);
        if *count == 2 || !roots.insert(row.root) {
            continue;
        }
        *count += 1;
        output.push(row);
        if output.len() == limit {
            break;
        }
    }
    Ok(output)
}
