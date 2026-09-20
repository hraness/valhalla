use super::*;
use crate::{
    history::{HistoryFrontier, HistoryScope},
    Access,
};
use vhalla_room_activity::{Content, Text};

fn unsigned(text: &str) -> UnsignedEvent {
    // Canonical unsigned fixture with RFC 8032's public test key.
    let key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let key: Vec<u8> = key
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect();
    let mut raw = b"VHRA\x01".to_vec();
    raw.extend_from_slice(&[7; 32]);
    raw.extend_from_slice(&77u128.to_be_bytes());
    raw.extend_from_slice(&[5; 32]);
    raw.extend_from_slice(&[8; 32]);
    raw.extend_from_slice(&[9; 32]);
    raw.extend_from_slice(&key);
    raw.extend_from_slice(&1u64.to_be_bytes());
    raw.extend_from_slice(&[0; 32]);
    raw.extend_from_slice(&1234u64.to_be_bytes());
    raw.push(0);
    raw.extend_from_slice(&(text.len() as u16).to_be_bytes());
    raw.extend_from_slice(text.as_bytes());
    UnsignedEvent::decode(&raw).unwrap()
}
fn policy(height: u64) -> HistoryHead {
    HistoryHead::new(
        HistoryScope::new([7; 32], [10; 32]),
        HistoryFrontier {
            height,
            value: [1; 32],
            registry: [2; 32],
            social: [3; 32],
            control: [4; 32],
            time: 1234,
        },
        [5; 32],
    )
    .unwrap()
}
fn draft(text: &str) -> ReservedDraft {
    let request = unsigned(text);
    let scope = AuthorScope::new(request.claims().scope, request.claims().author);
    ReservedDraft::new(
        AuthorHead::fresh_scope_authorized(scope),
        policy(1),
        request,
    )
    .unwrap()
}

#[test]
fn reservations_roundtrip_exact_bytes_and_reject_corrupt_or_discontinuous_intents() {
    let draft = draft("reserved forever");
    assert_eq!(ReservedDraft::decode(draft.as_bytes()).unwrap(), draft);
    assert_eq!(
        AuthorHead::decode(&draft.base().encode()).unwrap(),
        draft.base()
    );
    for length in 0..draft.as_bytes().len() {
        assert!(ReservedDraft::decode(&draft.as_bytes()[..length]).is_err());
    }
    let mut extra = draft.as_bytes().to_vec();
    extra.push(0);
    assert_eq!(ReservedDraft::decode(&extra), Err(Error::Corrupt));
    let mut claims = draft.request().claims().clone();
    claims.sequence = 2;
    claims.previous = EventId::from_bytes([99; 32]);
    assert_eq!(
        ReservedDraft::new(draft.base(), policy(1), UnsignedEvent::new(claims).unwrap()),
        Err(Error::Stale)
    );
    let mut claims = draft.request().claims().clone();
    claims.scope.network[0] ^= 1;
    assert_ne!(
        prefix(draft.base().scope()),
        prefix(AuthorScope::new(claims.scope, claims.author)),
        "another network must never reuse this author's sequence namespace"
    );
    assert_eq!(
        ReservedDraft::new(draft.base(), policy(1), UnsignedEvent::new(claims).unwrap()),
        Err(Error::WrongScope)
    );
}

#[test]
fn rebase_keeps_exact_unsigned_intent_and_requires_current_monotone_same_scope_basis() {
    let old = draft("unchanged possibly signed intent");
    let new = ReservedDraft::new(old.base(), policy(2), old.request().clone()).unwrap();
    let head = old.base().encode();
    let current = new.policy_head().encode();
    assert_eq!(
        check_rebase(
            &old,
            &new,
            Some(&head),
            Some(old.as_bytes()),
            Some(&current)
        ),
        Ok(())
    );
    assert_eq!(
        check_rebase(
            &old,
            &new,
            Some(&head),
            Some(new.as_bytes()),
            Some(&current)
        ),
        Ok(())
    );
    assert_eq!(old.request().encode(), new.request().encode());
    assert_eq!(old.request().id(), new.request().id());
    let changed = ReservedDraft::new(old.base(), policy(2), unsigned("different content")).unwrap();
    assert_eq!(rebase_shape(&old, &changed), Err(Error::Stale));
    assert_eq!(rebase_shape(&old, &old), Err(Error::Stale));
    assert_eq!(rebase_shape(&new, &old), Err(Error::Stale));
    let different_pin = HistoryHead::new(
        HistoryScope::new([7; 32], [11; 32]),
        policy(2).frontier(),
        [5; 32],
    )
    .unwrap();
    let other = ReservedDraft::new(old.base(), different_pin, old.request().clone()).unwrap();
    assert_eq!(rebase_shape(&old, &other), Err(Error::WrongScope));
    let mut other_base = old.base();
    other_base.event = old.request().id();
    other_base.sequence = 1;
    let mut claims = old.request().claims().clone();
    claims.previous = other_base.event;
    claims.sequence = 2;
    let other =
        ReservedDraft::new(other_base, policy(2), UnsignedEvent::new(claims).unwrap()).unwrap();
    assert_eq!(rebase_shape(&old, &other), Err(Error::Stale));
    assert_eq!(
        check_rebase(
            &old,
            &new,
            Some(&other_base.encode()),
            Some(old.as_bytes()),
            Some(&current)
        ),
        Err(Error::Stale)
    );
    assert_eq!(
        check_rebase(
            &old,
            &new,
            Some(&head),
            Some(old.as_bytes()),
            Some(&old.policy_head().encode())
        ),
        Err(Error::Stale)
    );
    assert_eq!(
        check_rebase(
            &old,
            &new,
            Some(&head),
            Some(changed.as_bytes()),
            Some(&current)
        ),
        Err(Error::Stale)
    );
    assert_eq!(
        check_rebase(&old, &new, Some(&head), None, Some(&current)),
        Err(Error::Stale)
    );
}

#[test]
fn uncertain_rebase_reconciles_only_old_or_exact_new_pending_without_reusing_sequence() {
    let old = draft("same bytes before and after a crash");
    let new = ReservedDraft::new(old.base(), policy(2), old.request().clone()).unwrap();
    let author = old.base().encode();
    let policy = new.policy_head().encode();
    for commit_before_cancel in [false, true] {
        let mut pending = old.as_bytes().to_vec();
        let mut access = Access::Ready;
        access.begin().unwrap();
        check_rebase(&old, &new, Some(&author), Some(&pending), Some(&policy)).unwrap();
        if commit_before_cancel {
            pending = new.as_bytes().to_vec();
        }
        // A canceled publication never clears the latch, whichever image survived.
        assert_eq!(access.ready(), Err(Error::NeedsReopen));
        let reopened = ReservedDraft::decode(&pending).unwrap();
        assert_eq!(reopened.request().encode(), old.request().encode());
        assert_eq!(reopened.base(), old.base());
        check_rebase(&old, &new, Some(&author), Some(&pending), Some(&policy)).unwrap();
        pending = new.as_bytes().to_vec();
        check_reservation(&new, Some(&author), Some(&pending), Some(&policy)).unwrap();
        let competing = draft("replacement must never be signed");
        assert_eq!(
            check_reservation(&competing, Some(&author), Some(&pending), Some(&policy)),
            Err(Error::Stale)
        );
    }
}

// Shares exact production reservation/finalization predicates. Browser event
// scheduling and IDB quota/cancellation remain separate live qualification.
struct Store {
    head: Vec<u8>,
    pending: Option<Vec<u8>>,
    policy: Vec<u8>,
    events: Vec<Vec<u8>>,
}
impl Store {
    fn new(draft: &ReservedDraft) -> Self {
        Self {
            head: draft.base().encode(),
            pending: None,
            policy: draft.policy_head().encode(),
            events: Vec::new(),
        }
    }
    fn reserve(&mut self, draft: &ReservedDraft) -> Result<(), Error> {
        check_reservation(
            draft,
            Some(&self.head),
            self.pending.as_deref(),
            Some(&self.policy),
        )?;
        if self.pending.is_none() {
            self.pending = Some(draft.as_bytes().to_vec());
        }
        Ok(())
    }
    fn finalize(&mut self, draft: &ReservedDraft, publish: bool) -> Result<(), Error> {
        check_finalize(
            draft,
            Some(&self.head),
            self.pending.as_deref(),
            Some(&self.policy),
        )?;
        if publish {
            self.head = AuthorHead {
                scope: draft.base.scope,
                sequence: draft.request.claims().sequence,
                event: draft.request.id(),
            }
            .encode();
            self.events.push(draft.request.encode());
            self.pending = None;
        }
        Ok(())
    }
}

#[test]
fn competing_tabs_reserve_before_signing_and_policy_changes_never_release_sequence() {
    let first = draft("first");
    let different = draft("competing");
    let mut store = Store::new(&first);
    store.reserve(&first).unwrap();
    assert_eq!(store.reserve(&different), Err(Error::Stale));
    assert_eq!(store.pending.as_deref(), Some(first.as_bytes()));
    // Same exact retained request may be retried after a worker/tab crash.
    store
        .reserve(&ReservedDraft::decode(store.pending.as_ref().unwrap()).unwrap())
        .unwrap();

    // A policy revocation/advance races signing: finalize refuses but retains
    // the possibly-signed intent. Even a new policy basis cannot reuse its slot.
    store.policy = policy(2).encode();
    assert_eq!(store.finalize(&first, true), Err(Error::Stale));
    let replacement =
        ReservedDraft::new(first.base(), policy(2), different.request.clone()).unwrap();
    assert_eq!(store.reserve(&replacement), Err(Error::Stale));
    assert_eq!(store.pending.as_deref(), Some(first.as_bytes()));
    assert_eq!(store.head, first.base().encode());
    assert!(store.events.is_empty());

    let mut absent = Store::new(&first);
    assert_eq!(
        absent.finalize(&first, true),
        Err(Error::Stale),
        "signing alone grants no durable reservation"
    );
    absent.policy = policy(2).encode();
    assert_eq!(absent.reserve(&first), Err(Error::Stale));
    assert!(absent.pending.is_none());
}

#[test]
fn uncertain_reserve_and_finalize_require_reload_without_reusing_intent() {
    let draft = draft("exact same bytes after uncertainty");
    for committed in [false, true] {
        let mut store = Store::new(&draft);
        let mut access = Access::Ready;
        access.begin().unwrap();
        if committed {
            store.reserve(&draft).unwrap();
        }
        assert_eq!(access.ready(), Err(Error::NeedsReopen));
        // No worker may be dispatched by the uncertain caller. After reopen,
        // reserve the identical draft, regardless of whether it first survived.
        store.reserve(&draft).unwrap();
        assert_eq!(store.pending.as_deref(), Some(draft.as_bytes()));
    }
    for committed in [false, true] {
        let mut store = Store::new(&draft);
        store.reserve(&draft).unwrap();
        let mut access = Access::Ready;
        access.begin().unwrap();
        store.finalize(&draft, committed).unwrap();
        assert_eq!(access.ready(), Err(Error::NeedsReopen));
        assert_eq!(store.events.len(), usize::from(committed));
        assert_eq!(store.pending.is_none(), committed);
        if committed {
            assert_eq!(store.reserve(&draft), Err(Error::Stale));
            assert_eq!(
                AuthorHead::decode(&store.head).unwrap().event_id(),
                draft.request().id()
            );
        } else {
            assert_eq!(store.pending.as_deref(), Some(draft.as_bytes()));
        }
    }
}

#[test]
fn deterministic_signatures_are_bound_to_the_exact_reserved_event() {
    // Reuse the frozen vault without generating an extra production-cost seal.
    let envelope = include_str!("../../../vhalla-browser-vault/vectors/v1-envelope.hex").trim();
    let raw: Vec<u8> = envelope
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect();
    let identity =
        vhalla_browser_vault::unlock(&raw, b"Valhalla public fixture password v1").unwrap();
    let mut claims = unsigned("exact reserved text").claims().clone();
    claims.author = identity.public_key();
    let request = UnsignedEvent::new(claims.clone()).unwrap();
    let scope = AuthorScope::new(claims.scope, claims.author);
    let draft = ReservedDraft::new(
        AuthorHead::fresh_scope_authorized(scope),
        policy(1),
        request,
    )
    .unwrap();
    let first = identity
        .sign_activity(draft.request().clone())
        .unwrap()
        .verify()
        .unwrap();
    let second = identity
        .sign_activity(UnsignedEvent::decode(&draft.request().encode()).unwrap())
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(first.encode(), second.encode());
    assert_eq!(
        draft.signed_head(&first).unwrap().event_id(),
        draft.request().id()
    );
    claims.content = Content::Text(Text::new("different text").unwrap());
    let wrong = identity
        .sign_activity(UnsignedEvent::new(claims).unwrap())
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(draft.signed_head(&wrong), Err(Error::Stale));
    assert!(identity.sign_activity(unsigned("foreign author")).is_err());
}
