//! Per-room author reservations and immutable signed local outbox.
mod delivery;
mod recovery;
use super::{
    history::{bounded, transaction, Transaction},
    identity::read_identity,
    IndexedStorage,
};
use crate::{
    history,
    identity::{fresh_author_check, IdentitySnapshot},
    outbox::{
        check_finalize, check_rebase, check_reservation, prefix, rebase_shape, AuthorHead,
        AuthorScope, OutboxPage, ReservedDraft, AUTHOR_HEAD_BYTES, MAX_OUTBOX_PAGE_BYTES,
        MAX_OUTBOX_PAGE_RECORDS, MAX_RESERVATION_BYTES,
    },
    Access, Error, Namespace, PublishError,
};
use std::rc::Rc;
use vhalla_room_activity::{SignedEvent, VerifiedEvent, MAX_EVENT_BYTES};
use wasm_bindgen::{JsCast, JsValue};
use web_sys::IdbKeyRange;

/// Durable local authoring state, not server acceptance or global freshness.
/// No pending-abort, sequence-reset, pruning or peer-delivery-ack API exists.
pub struct IndexedOutbox {
    inner: IndexedStorage,
}
impl IndexedOutbox {
    /// Open only schema under the same profile as certified history.
    pub async fn open(namespace: Namespace) -> Result<Self, Error> {
        Ok(Self {
            inner: IndexedStorage::open(namespace).await?,
        })
    }
    /// An uncertain write or schema change requires drop/open/load reconciliation.
    #[must_use]
    pub fn needs_reopen(&self) -> bool {
        self.inner.needs_reopen()
    }
    async fn read<T: 'static>(
        &mut self,
        setup: impl FnOnce(&Rc<Transaction<T>>) -> Result<(), Error>,
    ) -> Result<T, Error> {
        self.inner.access.borrow().ready()?;
        let result = transaction(&self.inner.database, false, setup)
            .await
            .and_then(|value| {
                self.inner.access.borrow().ready()?;
                Ok(value)
            });
        if result.is_err() {
            *self.inner.access.borrow_mut() = Access::NeedsReopen;
        }
        result
    }
    async fn write(
        &mut self,
        setup: impl FnOnce(&Rc<Transaction<()>>) -> Result<(), Error>,
    ) -> Result<(), PublishError> {
        self.inner
            .access
            .borrow_mut()
            .begin()
            .map_err(PublishError::Rejected)?;
        match transaction(&self.inner.database, true, setup).await {
            Ok(()) => self
                .inner
                .access
                .borrow_mut()
                .completed()
                .map_err(PublishError::ReopenRequired),
            Err(error) => {
                *self.inner.access.borrow_mut() = Access::NeedsReopen;
                Err(PublishError::ReopenRequired(error))
            }
        }
    }
    /// Initialize a controller-authorized never-used room/key scope.
    ///
    /// Absence is not authorization. In particular, restoring a key must not call
    /// this without independently proving it has never authored in this scope.
    /// Any existing scope key refuses initialization; load it instead.
    pub async fn initialize_fresh_author(
        &mut self,
        genesis: &AuthorHead,
    ) -> Result<(), PublishError> {
        if genesis.sequence() != 0 {
            return Err(PublishError::Rejected(Error::Corrupt));
        }
        let genesis = *genesis;
        self.write(move |state| initialize_empty_scope(state, genesis, None))
            .await
    }
    /// Atomically bind a fresh author scope to this profile's local key creation.
    ///
    /// The caller must have authenticated the exact snapshot's vault and must
    /// honor the single-author-device contract. The transaction compares both
    /// vault and birth, checks their author binding, and requires the entire
    /// author namespace to be absent before adding its zero-sequence head.
    /// Imported/legacy keys without birth metadata cannot call this successfully.
    /// No saved floor or pending reservation is ever overwritten or reset.
    pub async fn initialize_locally_created_author(
        &mut self,
        scope: AuthorScope,
        expected: &IdentitySnapshot,
    ) -> Result<AuthorHead, PublishError> {
        expected
            .local_creation(scope.author())
            .map_err(PublishError::Rejected)?;
        let expected = expected.clone();
        let genesis = AuthorHead::fresh_scope_authorized(scope);
        self.write(move |state| {
            read_identity(state, move |state, observed| {
                initialize_empty_scope(state, genesis, Some((expected, observed)))
            })
        })
        .await?;
        Ok(genesis)
    }
    /// Read the retained floor without inferring a new sequence from absence.
    pub async fn load_head(&mut self, scope: AuthorScope) -> Result<Option<AuthorHead>, Error> {
        let key = format!("{}head", prefix(scope));
        self.read(move |state| {
            state.read(&JsValue::from_str(&key), move |state, value| {
                let head = bounded(value, AUTHOR_HEAD_BYTES)?
                    .map(|raw| AuthorHead::decode(&raw))
                    .transpose()?;
                if head.is_some_and(|head| head.scope() != scope) {
                    return Err(Error::WrongScope);
                }
                *state.result.borrow_mut() = Some(Ok(head));
                Ok(())
            })
        })
        .await
    }
    /// Read exact surviving intent. Never discard it after a worker or tab crash.
    pub async fn load_pending(
        &mut self,
        scope: AuthorScope,
    ) -> Result<Option<ReservedDraft>, Error> {
        let key = format!("{}pending", prefix(scope));
        self.read(move |state| {
            state.read(&JsValue::from_str(&key), move |state, value| {
                let draft = bounded(value, MAX_RESERVATION_BYTES)?
                    .map(|raw| ReservedDraft::decode(&raw))
                    .transpose()?;
                if draft.as_ref().is_some_and(|d| d.base().scope() != scope) {
                    return Err(Error::WrongScope);
                }
                *state.result.borrow_mut() = Some(Ok(draft));
                Ok(())
            })
        })
        .await
    }
    /// Persist exact unsigned bytes before signing. An identical pending intent
    /// may resume only under the same author floor and certified policy head.
    /// Competing content never replaces it. Successful completion alone permits
    /// dispatch; signature/policy admission remains the controller's responsibility.
    pub async fn reserve(&mut self, draft: &ReservedDraft) -> Result<(), PublishError> {
        self.publish(draft.clone(), None).await
    }
    /// Refresh only a reservation's policy basis after unrelated certified
    /// history advances. The caller must first admit the unchanged request under
    /// its freshly replayed registry and exact original signed policy revision.
    ///
    /// Requires identical author base and unsigned bytes, the same bootstrap
    /// scope, and a strictly higher certified height. One transaction compares
    /// the retained author, old pending (or exact new pending after an uncertain
    /// retry), and new current history head before replacing policy metadata.
    /// Never changes content, frees a sequence, or authorizes a revoked policy.
    pub async fn rebase_reservation(
        &mut self,
        old: &ReservedDraft,
        new: &ReservedDraft,
    ) -> Result<(), PublishError> {
        rebase_shape(old, new).map_err(PublishError::Rejected)?;
        let old = old.clone();
        let new = new.clone();
        self.write(move |state| {
            let start = prefix(old.base().scope());
            state.read(
                &JsValue::from_str(&format!("{start}head")),
                move |state, value| {
                    let head = bounded(value, AUTHOR_HEAD_BYTES)?;
                    let pending_key = format!("{start}pending");
                    state.read(&JsValue::from_str(&pending_key), move |state, value| {
                        let pending = bounded(value, MAX_RESERVATION_BYTES)?;
                        let policy_key =
                            format!("{}head", history::prefix(new.policy_head().scope()));
                        state.read(&JsValue::from_str(&policy_key), move |state, value| {
                            let policy = bounded(value, 248)?;
                            check_rebase(
                                &old,
                                &new,
                                head.as_deref(),
                                pending.as_deref(),
                                policy.as_deref(),
                            )?;
                            if pending.as_deref() != Some(new.as_bytes()) {
                                state.put(&pending_key, new.as_bytes())?;
                            }
                            *state.result.borrow_mut() = Some(Ok(()));
                            Ok(())
                        })
                    })
                },
            )
        })
        .await
    }
    /// Atomically finalize the exact reserved signature, author floor and outbox.
    /// A stale policy basis preserves the possibly-signed pending intent forever;
    /// no failure makes that sequence reusable for different bytes.
    pub async fn finalize(
        &mut self,
        draft: &ReservedDraft,
        event: &VerifiedEvent,
    ) -> Result<(), PublishError> {
        let next = draft.signed_head(event).map_err(PublishError::Rejected)?;
        self.publish(draft.clone(), Some((next, event.encode())))
            .await
    }
    async fn publish(
        &mut self,
        draft: ReservedDraft,
        signed: Option<(AuthorHead, Vec<u8>)>,
    ) -> Result<(), PublishError> {
        self.write(move |state| {
            let author_prefix = prefix(draft.base().scope());
            let head_key = format!("{author_prefix}head");
            state.read(&JsValue::from_str(&head_key), move |state, value| {
                let observed_head = bounded(value, AUTHOR_HEAD_BYTES)?;
                let pending_key = format!("{author_prefix}pending");
                state.read(&JsValue::from_str(&pending_key), move |state, value| {
                    let observed_pending = bounded(value, MAX_RESERVATION_BYTES)?;
                    let policy_key =
                        format!("{}head", history::prefix(draft.policy_head().scope()));
                    state.read(&JsValue::from_str(&policy_key), move |state, value| {
                        let observed_policy = bounded(value, 248)?;
                        if let Some((next, bytes)) = signed {
                            check_finalize(
                                &draft,
                                observed_head.as_deref(),
                                observed_pending.as_deref(),
                                observed_policy.as_deref(),
                            )?;
                            let suffix = format!("{:016x}", next.sequence());
                            state.add(&format!("{author_prefix}event/{suffix}"), &bytes)?;
                            state.add(&format!("{author_prefix}outbox/{suffix}"), &bytes)?;
                            state.put(&head_key, &next.encode())?;
                            state
                                .store
                                .delete(&JsValue::from_str(&pending_key))
                                .map_err(super::storage)?;
                        } else {
                            check_reservation(
                                &draft,
                                observed_head.as_deref(),
                                observed_pending.as_deref(),
                                observed_policy.as_deref(),
                            )?;
                            if observed_pending.is_none() {
                                state.add(&pending_key, draft.as_bytes())?;
                            }
                        }
                        *state.result.borrow_mut() = Some(Ok(()));
                        Ok(())
                    })
                })
            })
        })
        .await
    }

    /// Read a bounded signed outbox page under one snapshotted author floor.
    /// These are locally retained events awaiting explicit peer submission;
    /// no event in this API is marked delivered or remotely admitted.
    pub async fn read_page(
        &mut self,
        scope: AuthorScope,
        start: u64,
        limit: usize,
        byte_budget: usize,
    ) -> Result<OutboxPage, Error> {
        if start == 0
            || limit == 0
            || limit > MAX_OUTBOX_PAGE_RECORDS
            || byte_budget == 0
            || byte_budget > MAX_OUTBOX_PAGE_BYTES
        {
            return Err(Error::Bounds);
        }
        let key = format!("{}head", prefix(scope));
        let (head, raw) = self
            .read(move |state| {
                state.read(&JsValue::from_str(&key), move |state, value| {
                    let raw = bounded(value, AUTHOR_HEAD_BYTES)?.ok_or(Error::Corrupt)?;
                    let head = AuthorHead::decode(&raw)?;
                    if head.scope() != scope {
                        return Err(Error::WrongScope);
                    }
                    if start > head.sequence() {
                        *state.result.borrow_mut() = Some(Ok((head, Vec::new())));
                        return Ok(());
                    }
                    read_next(state, head, Vec::new(), start, limit, byte_budget)
                })
            })
            .await?;
        // Signature verification happens after the read transaction, so IDB
        // auto-commit cannot split a transaction around asynchronous work.
        let mut events: Vec<VerifiedEvent> = Vec::with_capacity(raw.len());
        for raw in raw {
            let event = match SignedEvent::decode(&raw).and_then(SignedEvent::verify) {
                Ok(event) => event,
                Err(_) => {
                    *self.inner.access.borrow_mut() = Access::NeedsReopen;
                    return Err(Error::Corrupt);
                }
            };
            if AuthorScope::new(event.claims().scope, event.claims().author) != scope
                || Some(event.claims().sequence) != start.checked_add(events.len() as u64)
                || events
                    .last()
                    .is_some_and(|previous| previous.id() != event.claims().previous)
                || (event.claims().sequence == head.sequence() && event.id() != head.event_id())
            {
                *self.inner.access.borrow_mut() = Access::NeedsReopen;
                return Err(Error::Corrupt);
            }
            events.push(event);
        }
        Ok(OutboxPage { head, events })
    }
}

fn initialize_empty_scope(
    state: &Rc<Transaction<()>>,
    genesis: AuthorHead,
    identity: Option<(IdentitySnapshot, IdentitySnapshot)>,
) -> Result<(), Error> {
    let start = prefix(genesis.scope());
    let range = IdbKeyRange::bound(
        &JsValue::from_str(&start),
        &JsValue::from_str(&format!("{start}\u{ffff}")),
    )
    .map_err(super::storage)?;
    let request = state.store.get_key(&range).map_err(super::storage)?;
    state.handle(request, move |state, value| {
        if let Some((expected, observed)) = identity {
            fresh_author_check(
                &expected,
                &observed,
                genesis.scope().author(),
                !value.is_undefined(),
            )?;
        }
        if !value.is_undefined() {
            return Err(Error::Stale);
        }
        state.add(&format!("{start}head"), &genesis.encode())?;
        *state.result.borrow_mut() = Some(Ok(()));
        Ok(())
    });
    Ok(())
}

type RawPage = (AuthorHead, Vec<Vec<u8>>);
fn read_next(
    state: &Rc<Transaction<RawPage>>,
    head: AuthorHead,
    mut values: Vec<Vec<u8>>,
    sequence: u64,
    remaining: usize,
    budget: usize,
) -> Result<(), Error> {
    let key = format!("{}outbox/{sequence:016x}", prefix(head.scope()));
    state.read(&JsValue::from_str(&key), move |state, value| {
        let bytes = value
            .dyn_into::<js_sys::Uint8Array>()
            .map_err(|_| Error::Corrupt)?;
        let size = bytes.length() as usize;
        if size > MAX_EVENT_BYTES {
            return Err(Error::Bounds);
        }
        if size > budget {
            if values.is_empty() {
                return Err(Error::Bounds);
            }
            *state.result.borrow_mut() = Some(Ok((head, values)));
            return Ok(());
        }
        values.push(bytes.to_vec());
        if remaining == 1 || sequence == head.sequence() {
            *state.result.borrow_mut() = Some(Ok((head, values)));
            return Ok(());
        }
        read_next(
            state,
            head,
            values,
            sequence.checked_add(1).ok_or(Error::Bounds)?,
            remaining - 1,
            budget - size,
        )
    })
}
