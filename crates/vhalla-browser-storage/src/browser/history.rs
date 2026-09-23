//! IndexedDB append-only history. Stored metadata remains untrusted until replay.
use super::{durability, storage, EventCallback, IndexedStorage, OBJECT_STORE};
use crate::{
    history::{
        append_check, page_bounds, page_record, prefix, record_key, HistoryHead, HistoryPage,
        HistoryRecord, HistoryScope, MAX_HISTORY_BOOTSTRAP_BYTES, MAX_HISTORY_RECORD_BYTES,
    },
    Access, Error, Namespace, PublishError,
};
use futures_channel::oneshot;
use js_sys::Uint8Array;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use wasm_bindgen::{closure::Closure, JsCast, JsValue};
use web_sys::{Event, IdbDatabase, IdbKeyRange, IdbObjectStore, IdbRequest, IdbTransaction};

pub(super) fn bounded(value: JsValue, maximum: usize) -> Result<Option<Vec<u8>>, Error> {
    if value.is_undefined() {
        return Ok(None);
    }
    let bytes = value.dyn_into::<Uint8Array>().map_err(|_| Error::Corrupt)?;
    if bytes.length() as usize > maximum {
        return Err(Error::Bounds);
    }
    Ok(Some(bytes.to_vec()))
}
fn head(value: JsValue, scope: HistoryScope) -> Result<Option<HistoryHead>, Error> {
    let Some(raw) = bounded(value, 248)? else {
        return Ok(None);
    };
    let head = HistoryHead::decode(&raw)?;
    if head.scope() != scope {
        return Err(Error::WrongScope);
    }
    Ok(Some(head))
}

type Reply<T> = oneshot::Sender<Result<T, Error>>;
pub(super) struct Transaction<T> {
    transaction: IdbTransaction,
    pub(super) store: IdbObjectStore,
    pub(super) result: RefCell<Option<Result<T, Error>>>,
    sender: RefCell<Option<Reply<T>>>,
    finished: Cell<bool>,
    requests: RefCell<Vec<IdbRequest>>,
    callbacks: RefCell<Vec<EventCallback>>,
}
impl<T: 'static> Transaction<T> {
    fn fail(&self, error: Error) {
        if self.finished.get() {
            return;
        }
        if !self.result.borrow().as_ref().is_some_and(Result::is_err) {
            *self.result.borrow_mut() = Some(Err(error));
        }
        let _ = self.transaction.abort();
    }
    fn finish(&self, aborted: bool) {
        if self.finished.replace(true) {
            return;
        }
        let result = self
            .result
            .borrow_mut()
            .take()
            .unwrap_or(Err(Error::Storage));
        let result = if aborted && result.is_ok() {
            Err(Error::Storage)
        } else {
            result
        };
        let sender = self.sender.borrow_mut().take();
        if let Some(sender) = sender {
            let _ = sender.send(result);
        }
    }
    pub(super) fn read(
        self: &Rc<Self>,
        key: &JsValue,
        callback: impl FnOnce(&Rc<Self>, JsValue) -> Result<(), Error> + 'static,
    ) -> Result<(), Error> {
        let request = self.store.get(key).map_err(storage)?;
        self.handle(request, callback);
        Ok(())
    }
    pub(super) fn handle(
        self: &Rc<Self>,
        request: IdbRequest,
        callback: impl FnOnce(&Rc<Self>, JsValue) -> Result<(), Error> + 'static,
    ) {
        let current = self.clone();
        let source = request.clone();
        let mut callback = Some(callback);
        let handler = Closure::<dyn FnMut(Event)>::new(move |_| {
            if current.finished.get() {
                return;
            }
            let result = source.result().map_err(storage).and_then(|value| {
                let callback = callback.take().ok_or(Error::Corrupt)?;
                callback(&current, value)
            });
            if let Err(error) = result {
                current.fail(error);
            }
        });
        request.set_onsuccess(Some(handler.as_ref().unchecked_ref()));
        self.requests.borrow_mut().push(request);
        self.callbacks.borrow_mut().push(handler);
    }
    pub(super) fn add(&self, key: &str, bytes: &[u8]) -> Result<(), Error> {
        self.store
            .add_with_key(&Uint8Array::from(bytes), &JsValue::from_str(key))
            .map_err(storage)?;
        Ok(())
    }
    pub(super) fn put(&self, key: &str, bytes: &[u8]) -> Result<(), Error> {
        self.store
            .put_with_key(&Uint8Array::from(bytes), &JsValue::from_str(key))
            .map_err(storage)?;
        Ok(())
    }
    /// Remove one retained private-delivery record. Only the `private-rooms`
    /// delivery journal uses deletion; other histories are append-only.
    #[cfg(feature = "private-rooms")]
    pub(super) fn delete(&self, key: &str) -> Result<(), Error> {
        self.store
            .delete(&JsValue::from_str(key))
            .map_err(storage)?;
        Ok(())
    }
}
struct Guard<T>(Rc<Transaction<T>>);
impl<T> Drop for Guard<T> {
    fn drop(&mut self) {
        if !self.0.finished.get() {
            let _ = self.0.transaction.abort();
        }
        for request in self.0.requests.borrow_mut().drain(..) {
            request.set_onsuccess(None);
        }
        self.0.transaction.set_oncomplete(None);
        self.0.transaction.set_onabort(None);
        self.0.transaction.set_onerror(None);
        // wasm-bindgen's active-invocation refcount protects any callback that
        // is still returning; detached callbacks cannot fire again.
        self.0.callbacks.borrow_mut().clear();
    }
}
pub(super) async fn transaction<T: 'static>(
    database: &IdbDatabase,
    write: bool,
    setup: impl FnOnce(&Rc<Transaction<T>>) -> Result<(), Error>,
) -> Result<T, Error> {
    let transaction = durability::begin(database, write)?;
    let store = match transaction.object_store(OBJECT_STORE) {
        Ok(store) => store,
        Err(error) => {
            let _ = transaction.abort();
            return Err(storage(error));
        }
    };
    let (sender, receiver) = oneshot::channel();
    let state = Rc::new(Transaction {
        transaction,
        store,
        result: RefCell::new(None),
        sender: RefCell::new(Some(sender)),
        finished: Cell::new(false),
        requests: RefCell::new(Vec::new()),
        callbacks: RefCell::new(Vec::new()),
    });
    let guard = Guard(state.clone());
    let current = state.clone();
    let complete = Closure::<dyn FnMut(Event)>::new(move |_| current.finish(false));
    let current = state.clone();
    let abort = Closure::<dyn FnMut(Event)>::new(move |_| current.finish(true));
    let current = state.clone();
    let error = Closure::<dyn FnMut(Event)>::new(move |_| current.fail(Error::Storage));
    state
        .transaction
        .set_oncomplete(Some(complete.as_ref().unchecked_ref()));
    state
        .transaction
        .set_onabort(Some(abort.as_ref().unchecked_ref()));
    state
        .transaction
        .set_onerror(Some(error.as_ref().unchecked_ref()));
    state
        .callbacks
        .borrow_mut()
        .extend([complete, abort, error]);
    if let Err(error) = setup(&state) {
        state.fail(error);
    }
    let result = receiver.await.map_err(|_| Error::Storage)?;
    drop(guard);
    result
}

/// One exact profile/network/bootstrap history. No pruning or reset API exists.
///
/// Shares the profile's versioned database with opaque image slots, using a
/// disjoint fixed prefix. Individual appends publish an immutable height record
/// and the exact next head in one transaction. Transactions provide logical
/// atomicity, not protection from eviction, same-origin tampering or rollback.
pub struct IndexedHistory {
    inner: IndexedStorage,
    scope: HistoryScope,
}
impl IndexedHistory {
    /// Open schema only. The caller selects the profile and independently pinned scope.
    pub async fn open(namespace: Namespace, scope: HistoryScope) -> Result<Self, Error> {
        Ok(Self {
            inner: IndexedStorage::open(namespace).await?,
            scope,
        })
    }
    /// A canceled/failed publication or version change requires drop/open/replay.
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
        // Cancellation after this latch is set leaves the handle unavailable.
        let result = transaction(&self.inner.database, true, setup).await;
        match result {
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

    /// Read bounded exact bootstrap bytes. Decode against the independently
    /// retained pin before using them; storage never authenticates the pin.
    pub async fn load_bootstrap(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let key = format!("{}bootstrap", prefix(self.scope));
        self.read(move |state| {
            state.read(&JsValue::from_str(&key), |state, value| {
                *state.result.borrow_mut() = Some(Ok(bounded(value, MAX_HISTORY_BOOTSTRAP_BYTES)?));
                Ok(())
            })
        })
        .await
    }
    /// Read canonical head framing only. Never install it without retained replay.
    pub async fn load_head(&mut self) -> Result<Option<HistoryHead>, Error> {
        let scope = self.scope;
        let key = format!("{}head", prefix(scope));
        self.read(move |state| {
            state.read(&JsValue::from_str(&key), move |state, value| {
                *state.result.borrow_mut() = Some(Ok(head(value, scope)?));
                Ok(())
            })
        })
        .await
    }

    /// Atomically retain exact bootstrap bytes and a height-zero head.
    ///
    /// Identical complete genesis initialization is idempotent. Existing advanced
    /// history, a different bootstrap, or any partial scope fails closed. Load and
    /// replay existing history instead of using this method as recovery/reset.
    pub async fn initialize(
        &mut self,
        bootstrap: &[u8],
        genesis: &HistoryHead,
    ) -> Result<(), PublishError> {
        if bootstrap.is_empty() || bootstrap.len() > MAX_HISTORY_BOOTSTRAP_BYTES {
            return Err(PublishError::Rejected(Error::Bounds));
        }
        if genesis.scope() != self.scope {
            return Err(PublishError::Rejected(Error::WrongScope));
        }
        if genesis.frontier().height != 0 {
            return Err(PublishError::Rejected(Error::Corrupt));
        }
        let genesis = *genesis;
        let bootstrap = bootstrap.to_vec();
        let scope = self.scope;
        self.write(move |state| {
            let head_key = format!("{}head", prefix(scope));
            state.read(&JsValue::from_str(&head_key), move |state, value| {
                match head(value, scope)? {
                    Some(observed) => {
                        if observed != genesis {
                            return Err(Error::Stale);
                        }
                        let bootstrap_key = format!("{}bootstrap", prefix(scope));
                        state.read(&JsValue::from_str(&bootstrap_key), move |state, value| {
                            if bounded(value, MAX_HISTORY_BOOTSTRAP_BYTES)?.as_deref()
                                != Some(bootstrap.as_slice())
                            {
                                return Err(Error::Stale);
                            }
                            let start = format!("{}height/", prefix(scope));
                            let range = IdbKeyRange::bound(
                                &JsValue::from_str(&start),
                                &JsValue::from_str(&format!("{start}\u{ffff}")),
                            )
                            .map_err(storage)?;
                            let request = state.store.get_key(&range).map_err(storage)?;
                            state.handle(request, |state, value| {
                                if !value.is_undefined() {
                                    return Err(Error::Stale);
                                }
                                *state.result.borrow_mut() = Some(Ok(()));
                                Ok(())
                            });
                            Ok(())
                        })
                    }
                    None => {
                        // A bounded first-key query detects every partial scope,
                        // including orphan later heights; never silently reset.
                        let start = prefix(scope);
                        let range = IdbKeyRange::bound(
                            &JsValue::from_str(&start),
                            &JsValue::from_str(&format!("{start}\u{ffff}")),
                        )
                        .map_err(storage)?;
                        let request = state.store.get_key(&range).map_err(storage)?;
                        state.handle(request, move |state, value| {
                            if !value.is_undefined() {
                                return Err(Error::Stale);
                            }
                            state.add(&format!("{}bootstrap", prefix(scope)), &bootstrap)?;
                            state.add(&head_key, &genesis.encode())?;
                            *state.result.borrow_mut() = Some(Ok(()));
                            Ok(())
                        });
                        Ok(())
                    }
                }
            })
        })
        .await
    }

    /// Publish one immutable next-height record and exact next head atomically.
    /// The controller must have verified the candidate before calling this.
    /// Only successful transaction completion permits commit_after_persist.
    pub async fn append(
        &mut self,
        expected: &HistoryHead,
        record: &HistoryRecord,
    ) -> Result<(), PublishError> {
        append_check(self.scope, Some(&expected.encode()), expected, record)
            .map_err(PublishError::Rejected)?;
        let expected = *expected;
        let record = record.clone();
        let scope = self.scope;
        self.write(move |state| {
            let head_key = format!("{}head", prefix(scope));
            state.read(&JsValue::from_str(&head_key), move |state, value| {
                let observed = bounded(value, 248)?;
                append_check(scope, observed.as_deref(), &expected, &record)?;
                // add rejects every existing height, including same-byte retries.
                // Uncertain outcomes must load/replay rather than blindly append.
                state.add(
                    &record_key(scope, record.head().frontier().height),
                    record.as_bytes(),
                )?;
                state.put(&head_key, &record.head().encode())?;
                *state.result.borrow_mut() = Some(Ok(()));
                Ok(())
            })
        })
        .await
    }

    /// Read at most limit records within byte_budget, from a single transaction.
    /// Stops at its snapshotted head; published gaps and malformed framing reject.
    /// A budget unable to fit even the first record returns Bounds, never a
    /// misleading empty page. Reads past the snapshotted head return an empty page.
    pub async fn read_page(
        &mut self,
        start_height: u64,
        limit: usize,
        byte_budget: usize,
    ) -> Result<HistoryPage, Error> {
        page_bounds(start_height, limit, byte_budget)?;
        let scope = self.scope;
        let key = format!("{}head", prefix(scope));
        self.read(move |state| {
            state.read(&JsValue::from_str(&key), move |state, value| {
                let head = head(value, scope)?.ok_or(Error::Corrupt)?;
                let page = HistoryPage {
                    head,
                    records: Vec::new(),
                };
                if start_height > head.frontier().height {
                    *state.result.borrow_mut() = Some(Ok(page));
                    return Ok(());
                }
                read_next(state, page, start_height, limit, byte_budget)
            })
        })
        .await
    }
}

fn read_next(
    state: &Rc<Transaction<HistoryPage>>,
    mut page: HistoryPage,
    height: u64,
    remaining: usize,
    budget: usize,
) -> Result<(), Error> {
    let key = record_key(page.head.scope(), height);
    state.read(&JsValue::from_str(&key), move |state, value| {
        let bytes = value.dyn_into::<Uint8Array>().map_err(|_| Error::Corrupt)?;
        let size = bytes.length() as usize;
        if size > MAX_HISTORY_RECORD_BYTES {
            return Err(Error::Bounds);
        }
        if size > budget {
            if page.records.is_empty() {
                return Err(Error::Bounds);
            }
            *state.result.borrow_mut() = Some(Ok(page));
            return Ok(());
        }
        // Byte budget was checked before any Rust copy or decoded allocation.
        let record = page_record(&page, height, &bytes.to_vec())?;
        page.records.push(record);
        if remaining == 1 || height == page.head.frontier().height {
            *state.result.borrow_mut() = Some(Ok(page));
            return Ok(());
        }
        let next = height.checked_add(1).ok_or(Error::Bounds)?;
        read_next(state, page, next, remaining - 1, budget - size)
    })
}
