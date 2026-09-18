//! Verus pilot: a verified model of the vhalla-ledger admission machine.
//!
//! This is a proof-oriented reference, not the production type: ids are
//! `u64` stand-ins for 32-byte digests, and the retained event set is a
//! vector — the log itself is the single source of truth. The production
//! `BTreeMap`s (`events`, `last_sequences`) are caches over it; here the
//! duplicate check and the per-actor last sequence are computed by scanning
//! the log, which is exactly what those maps answer. What is *faithful* is
//! the transition function — `Ledger::append` applies the same checks in
//! the same order as `crates/vhalla-ledger/src/lib.rs` and fails closed.
//!
//! Proven, with no bounds assumed:
//!   * append-only: the retained log only ever grows by push
//!   * linear tip: every event's parent is the previous event's id
//!   * no double admission: ids are pairwise distinct
//!   * monotonicity: per-actor sequences strictly increase along the log
//!   * capacity: the log never exceeds the configured bound
//!   * atomicity: every rejection leaves the state unchanged
//!
//! Verify with: verus --crate-type=lib verify/ledger.rs

use vstd::prelude::*;

verus! {

/// Maximum event payload, mirroring `MAX_PAYLOAD` in the production crate.
pub const MAX_PAYLOAD: u64 = 1024;

/// One retained event. `payload_len` models the bounded opaque payload.
#[derive(Clone, Copy)]
pub struct Event {
    pub id: u64,
    pub parent: Option<u64>,
    pub realm: u64,
    pub epoch: u64,
    pub actor: u64,
    pub sequence: u64,
    pub payload_len: u64,
}

/// Fail-closed ledger errors, mirroring the production `Error` order.
pub enum LErr {
    PayloadTooLarge,
    WrongContext,
    DuplicateEvent,
    NonMonotonicSequence,
    UnknownOrForkedParent,
    Capacity,
}

/// The verified ledger model: the retained log plus the current tip.
pub struct Ledger {
    pub realm: u64,
    pub epoch: u64,
    pub max_events: usize,
    pub events: Vec<Event>,
    pub head: Option<u64>,
}

/// The sequence of the last event by `actor`, scanning the log from the
/// back. What the production `last_sequences` map caches.
pub closed spec fn last_in_log(events: Seq<Event>, actor: u64) -> Option<u64>
    decreases events.len(),
{
    if events.len() == 0 {
        None
    } else if events.last().actor == actor {
        Some(events.last().sequence)
    } else {
        last_in_log(events.drop_last(), actor)
    }
}

/// If the lookup is `Some`, some index records it and nothing later matches.
proof fn lemma_last_in_log_some(events: Seq<Event>, actor: u64, s: u64)
    requires
        last_in_log(events, actor) == Some(s),
    ensures
        exists|m: int|
            0 <= m < events.len() && events[m].actor == actor && events[m].sequence == s
                && forall|j: int|
                m < j < events.len() ==> events[j].actor != actor,
    decreases events.len(),
{
    if events.len() == 0 {
    } else if events.last().actor == actor {
        let m = events.len() - 1;
        assert(events[m].actor == actor && events[m].sequence == s);
        assert forall|j: int| m < j < events.len() implies events[j].actor != actor by {
        }
    } else {
        let dl = events.drop_last();
        lemma_last_in_log_some(dl, actor, s);
        let m = choose|m: int|
            0 <= m < dl.len() && dl[m].actor == actor && dl[m].sequence == s && forall|j: int|
                m < j < dl.len() ==> dl[j].actor != actor;
        assert(events[m].actor == actor && events[m].sequence == s);
        assert forall|j: int| m < j < events.len() implies events[j].actor != actor by {
            if j < dl.len() {
                assert(dl[j].actor != actor);
                assert(events[j] == dl[j]);
            } else {
                assert(j == dl.len());
                assert(events[j] == events.last());
            }
        }
    }
}

/// If the lookup is absent, no event is by `actor`.
proof fn lemma_last_in_log_none(events: Seq<Event>, actor: u64)
    requires
        last_in_log(events, actor).is_none(),
    ensures
        forall|j: int| 0 <= j < events.len() ==> events[j].actor != actor,
    decreases events.len(),
{
    if events.len() == 0 {
    } else if events.last().actor == actor {
        assert(last_in_log(events, actor) == Some(events.last().sequence));
    } else {
        let dl = events.drop_last();
        lemma_last_in_log_none(dl, actor);
        assert forall|j: int| 0 <= j < events.len() implies events[j].actor != actor by {
            if j < dl.len() {
                assert(dl[j].actor != actor);
                assert(events[j] == dl[j]);
            } else {
                assert(j == dl.len());
                assert(events[j] == events.last());
            }
        }
    }
}

/// Pushing an event by a different actor preserves every other lookup.
proof fn lemma_last_in_log_push(events: Seq<Event>, actor: u64, ev: Event)
    requires
        ev.actor != actor,
    ensures
        last_in_log(events.push(ev), actor) == last_in_log(events, actor),
{
    assert(events.push(ev).drop_last() =~= events);
}

impl Ledger {
    /// The state invariant maintained by every transition.
    pub closed spec fn inv(&self) -> bool {
        &&& self.events@.len() <= self.max_events
        // No double admission: retained ids are pairwise distinct.
        &&& forall|i: int, j: int|
            0 <= i < j < self.events@.len() ==> self.events@[i].id != self.events@[j].id
        // The tip is the last admitted event, or None iff the log is empty.
        &&& (self.events@.len() == 0 ==> self.head.is_none())
        &&& (self.events@.len() > 0 ==> self.head == Some(self.events@.last().id))
        // Linear chain: each event's parent is the previous event's id.
        &&& forall|i: int|
            #![trigger self.events@[i]]
            0 <= i < self.events@.len() ==> self.events@[i].parent == if i == 0 {
                None
            } else {
                Some(self.events@[i - 1].id)
            }
        // Per-actor sequences strictly increase along the log.
        &&& forall|i: int, j: int|
            0 <= i < j < self.events@.len() && self.events@[i].actor
                == self.events@[j].actor ==> self.events@[i].sequence
                < self.events@[j].sequence
        // Every retained event is in context and within the payload bound.
        &&& forall|i: int|
            #![trigger self.events@[i]]
            0 <= i < self.events@.len() ==> (self.events@[i].realm == self.realm
                && self.events@[i].epoch == self.epoch
                && self.events@[i].payload_len <= MAX_PAYLOAD)
    }

    /// Create an empty ledger, mirroring `Ledger::new`.
    pub fn new(realm: u64, epoch: u64, max_events: usize) -> (out: Self)
        ensures
            out.inv(),
            out.events@.len() == 0,
    {
        Ledger {
            realm,
            epoch,
            max_events,
            events: Vec::new(),
            head: None,
        }
    }

    /// Whether `id` is already retained — what the production `events` map
    /// answers with `contains_key`.
    fn has_id(&self, id: u64) -> (r: bool)
        ensures
            r == exists|i: int| 0 <= i < self.events@.len() && self.events@[i].id == id,
    {
        let mut i: usize = 0;
        while i < self.events.len()
            invariant
                i <= self.events@.len(),
                forall|k: int| 0 <= k < i ==> self.events@[k].id != id,
            decreases self.events@.len() - i,
        {
            if self.events[i].id == id {
                return true;
            }
            i += 1;
        }
        false
    }

    /// The last accepted sequence for `actor` — what the production
    /// `last_sequences.get` answers.
    fn last_seq(&self, actor: u64) -> (r: Option<u64>)
        ensures
            r == last_in_log(self.events@, actor),
    {
        let mut i: usize = self.events.len();
        proof {
            assert(self.events@.take(self.events@.len() as int) =~= self.events@);
        }
        while i > 0
            invariant
                i <= self.events@.len(),
                last_in_log(self.events@, actor) == last_in_log(
                    self.events@.take(i as int),
                    actor,
                ),
            decreases i,
        {
            i -= 1;
            if self.events[i].actor == actor {
                proof {
                    let evs = self.events@;
                    assert(evs.take(i as int + 1).last() == evs[i as int]);
                    assert(evs.take(i as int + 1).drop_last() =~= evs.take(i as int));
                }
                return Some(self.events[i].sequence);
            }
            proof {
                let evs = self.events@;
                assert(evs.take(i as int + 1).drop_last() =~= evs.take(i as int));
            }
        }
        proof {
            assert(self.events@.take(0) =~= Seq::empty());
        }
        None
    }

    /// Admit an event whose guards have all passed: extend the chain and the
    /// tip. This is the commit half of the production `append` — the
    /// invariant proof lives here.
    fn commit(&mut self, ev: Event)
        requires
            old(self).inv(),
            ev.payload_len <= MAX_PAYLOAD,
            ev.realm == old(self).realm && ev.epoch == old(self).epoch,
            !(exists|i: int| 0 <= i < old(self).events@.len() && old(self).events@[i].id
                == ev.id),
            match last_in_log(old(self).events@, ev.actor) {
                Some(prev) => ev.sequence > prev,
                None => true,
            },
            ev.parent == old(self).head,
            old(self).events@.len() < old(self).max_events,
        ensures
            final(self).inv(),
            final(self).events@ =~= old(self).events@.push(ev),
            final(self).head == Some(ev.id),
    {
        self.events.push(ev);
        self.head = Some(ev.id);
        proof {
            let s = self.events@;
            let o = old(self).events@;
            assert(s =~= o.push(ev));
            // Distinct ids: ev.id was absent from o.
            assert forall|i: int, j: int|
                0 <= i < j < s.len() implies s[i].id != s[j].id by {
                if j == s.len() - 1 {
                    assert(!(exists|k: int| 0 <= k < o.len() && o[k].id == ev.id));
                }
            }
            // Per-actor monotonicity: a prior event by ev.actor sits at or
            // before the last such log position, whose sequence the guard
            // exceeded.
            let prior = last_in_log(o, ev.actor);
            assert forall|i: int, j: int|
                0 <= i < j < s.len() && s[i].actor == s[j].actor implies s[i].sequence
                < s[j].sequence by {
                if j == s.len() - 1 && s[i].actor == ev.actor {
                    match prior {
                        Some(prev) => {
                            lemma_last_in_log_some(o, ev.actor, prev);
                            let m = choose|m: int|
                                0 <= m < o.len() && o[m].actor == ev.actor && o[m].sequence
                                    == prev && forall|jj: int|
                                    m < jj < o.len() ==> o[jj].actor != ev.actor;
                            assert(ev.sequence > prev);
                            assert(i <= m);
                            if i < m {
                                assert(s[i].sequence < s[m].sequence);
                            }
                        }
                        None => {
                            lemma_last_in_log_none(o, ev.actor);
                        }
                    }
                }
            }
        }
    }

    /// Append an event only when it extends the current tip — the same
    /// checks in the same order as the production `Ledger::append`.
    pub fn append(&mut self, ev: Event) -> (r: Result<(), LErr>)
        requires
            old(self).inv(),
        ensures
            final(self).inv(),
            r.is_ok() ==> final(self).events@ =~= old(self).events@.push(ev)
                && final(self).head == Some(ev.id),
            r.is_err() ==> final(self).events@ =~= old(self).events@ && final(self).head
                == old(self).head,
    {
        if ev.payload_len > MAX_PAYLOAD {
            return Err(LErr::PayloadTooLarge);
        }
        if ev.realm != self.realm || ev.epoch != self.epoch {
            return Err(LErr::WrongContext);
        }
        if self.has_id(ev.id) {
            return Err(LErr::DuplicateEvent);
        }
        match self.last_seq(ev.actor) {
            Some(prev) => {
                if ev.sequence <= prev {
                    return Err(LErr::NonMonotonicSequence);
                }
            }
            None => {}
        }
        if ev.parent != self.head {
            return Err(LErr::UnknownOrForkedParent);
        }
        if self.events.len() >= self.max_events {
            return Err(LErr::Capacity);
        }
        self.commit(ev);
        Ok(())
    }
}

} // verus!
