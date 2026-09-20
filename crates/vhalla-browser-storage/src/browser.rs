//! Rust/WASM IndexedDB adapter. Actual browser execution is a separate gate.
//!
//! Adapted from `c407159^:prototypes/dioxus-services/src/browser.rs`, retaining
//! bounded late-open cleanup and exact transaction-local compare-and-swap.

use super::*;
mod durability;
pub mod history;
pub mod identity;
pub mod outbox;
use futures_channel::oneshot;
use js_sys::Uint8Array;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use wasm_bindgen::{closure::Closure, JsCast, JsValue};
use web_sys::{Event, IdbDatabase, IdbOpenDbRequest, IdbRequest, IdbTransaction};

const OBJECT_STORE: &str = "images";
const SCHEMA_VERSION: u32 = 1;

fn storage(_: JsValue) -> Error {
    Error::Storage
}

fn bytes(value: JsValue) -> Result<Option<Vec<u8>>, Error> {
    if value.is_undefined() {
        return Ok(None);
    }
    let array = value.dyn_into::<Uint8Array>().map_err(|_| Error::Corrupt)?;
    if array.length() as usize > MAX_IMAGE_BYTES {
        return Err(Error::Bounds);
    }
    Ok(Some(array.to_vec()))
}

thread_local! {
    static PENDING_OPENS: Cell<usize> = const { Cell::new(0) };
}

struct OpenSlot;

impl OpenSlot {
    fn acquire() -> Result<Self, Error> {
        PENDING_OPENS.with(|count| {
            if count.get() >= MAX_PENDING_OPENS {
                return Err(Error::Bounds);
            }
            count.set(count.get() + 1);
            Ok(Self)
        })
    }
}

impl Drop for OpenSlot {
    fn drop(&mut self) {
        PENDING_OPENS.with(|count| count.set(count.get() - 1));
    }
}

// Even a successfully opened database buffered in an unpolled oneshot must
// close if that future is canceled. Dropping only its JS wrapper is insufficient.
struct OpenedDatabase(Option<IdbDatabase>);

impl OpenedDatabase {
    fn take(mut self) -> IdbDatabase {
        self.0.take().expect("owned database")
    }
}

impl Drop for OpenedDatabase {
    fn drop(&mut self) {
        if let Some(database) = self.0.take() {
            database.close();
        }
    }
}

type OpenReply = oneshot::Sender<Result<OpenedDatabase, Error>>;
type EventCallback = Closure<dyn FnMut(Event)>;

struct OpenState {
    request: IdbOpenDbRequest,
    sender: RefCell<Option<OpenReply>>,
    canceled: Cell<bool>,
    finished: Cell<bool>,
    callbacks: RefCell<Vec<EventCallback>>,
    slot: RefCell<Option<OpenSlot>>,
}

impl OpenState {
    fn cancel(&self, error: Error) {
        self.canceled.set(true);
        if let Some(sender) = self.sender.borrow_mut().take() {
            let _ = sender.send(Err(error));
        }
    }

    fn finish(&self, result: Result<IdbDatabase, Error>) {
        if self.finished.replace(true) {
            if let Ok(database) = result {
                database.close();
            }
            return;
        }
        let result = result.map(|database| OpenedDatabase(Some(database)));
        if !self.canceled.get() {
            if let Some(sender) = self.sender.borrow_mut().take() {
                let _ = sender.send(result);
            }
        }
        self.request.set_onsuccess(None);
        self.request.set_onerror(None);
        self.request.set_onblocked(None);
        self.request.set_onupgradeneeded(None);
        self.callbacks.borrow_mut().clear();
        self.slot.borrow_mut().take();
    }
}

struct OpenGuard(Rc<OpenState>);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        if !self.0.finished.get() {
            self.0.cancel(Error::Storage);
        }
    }
}

async fn open_database(name: &str) -> Result<IdbDatabase, Error> {
    let slot = OpenSlot::acquire()?;
    // Resolve the current realm's factory, so the custody worker can own the
    // same transactions as the window. No database handle crosses a worker
    // boundary; missing, throwing or foreign values refuse before open.
    let factory = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("indexedDB"))
        .map_err(storage)?
        .dyn_into::<web_sys::IdbFactory>()
        .map_err(storage)?;
    let request = factory
        .open_with_u32(name, SCHEMA_VERSION)
        .map_err(storage)?;
    let (sender, receiver) = oneshot::channel();
    let state = Rc::new(OpenState {
        request,
        sender: RefCell::new(Some(sender)),
        canceled: Cell::new(false),
        finished: Cell::new(false),
        callbacks: RefCell::new(Vec::new()),
        slot: RefCell::new(Some(slot)),
    });
    let current = state.clone();
    let success = Closure::<dyn FnMut(Event)>::new(move |_| {
        let result = current
            .request
            .result()
            .map_err(storage)
            .and_then(|value| value.dyn_into::<IdbDatabase>().map_err(|_| Error::Storage));
        current.finish(result);
    });
    let current = state.clone();
    let failure = Closure::<dyn FnMut(Event)>::new(move |_| current.finish(Err(Error::Storage)));
    let current = state.clone();
    let blocked = Closure::<dyn FnMut(Event)>::new(move |_| current.cancel(Error::Blocked));
    let current = state.clone();
    let upgrade = Closure::<dyn FnMut(Event)>::new(move |_| {
        let result = current
            .request
            .result()
            .map_err(storage)
            .and_then(|value| value.dyn_into::<IdbDatabase>().map_err(|_| Error::Storage));
        let valid = !current.canceled.get()
            && result.as_ref().is_ok_and(|database| {
                database.object_store_names().contains(OBJECT_STORE)
                    || database.create_object_store(OBJECT_STORE).is_ok()
            });
        if !valid {
            if let Some(transaction) = current.request.transaction() {
                let _ = transaction.abort();
            }
            if let Ok(database) = result {
                database.close();
            }
        }
    });
    state
        .request
        .set_onsuccess(Some(success.as_ref().unchecked_ref()));
    state
        .request
        .set_onerror(Some(failure.as_ref().unchecked_ref()));
    state
        .request
        .set_onblocked(Some(blocked.as_ref().unchecked_ref()));
    state
        .request
        .set_onupgradeneeded(Some(upgrade.as_ref().unchecked_ref()));
    *state.callbacks.borrow_mut() = vec![success, failure, blocked, upgrade];
    let guard = OpenGuard(state);
    let result = receiver.await.map_err(|_| Error::Storage)?;
    drop(guard);
    result.map(OpenedDatabase::take)
}

fn database_name(namespace: Namespace) -> String {
    let mut name = String::from("vhalla-browser-storage-v1-");
    for byte in namespace.0 {
        use std::fmt::Write;
        write!(&mut name, "{byte:02x}").expect("writing a bounded String");
    }
    name
}

struct TxHandlers {
    request: Option<IdbRequest>,
    transaction: IdbTransaction,
    finished: Rc<Cell<bool>>,
    callbacks: Vec<Closure<dyn FnMut(Event)>>,
}

impl Drop for TxHandlers {
    fn drop(&mut self) {
        if !self.finished.get() {
            let _ = self.transaction.abort();
        }
        if let Some(request) = &self.request {
            request.set_onsuccess(None);
        }
        self.transaction.set_oncomplete(None);
        self.transaction.set_onabort(None);
        self.transaction.set_onerror(None);
    }
}

/// One host-owned profile database. Drop closes it; no reset/delete API exists.
///
/// Mutable async methods permit one operation per handle. The adapter must bound
/// the number of live handles/tasks and run domain verification before publishing
/// or using opaque bytes. Independent slots are not a multi-slot transaction.
pub struct IndexedStorage {
    database: IdbDatabase,
    access: Rc<RefCell<Access>>,
    _version_change: Closure<dyn FnMut(Event)>,
}

impl Drop for IndexedStorage {
    fn drop(&mut self) {
        self.database.set_onversionchange(None);
        self.database.close();
    }
}

impl IndexedStorage {
    /// Open a host-selected profile and create missing schema only.
    ///
    /// This never initializes, replaces or repairs an image. At most four opens
    /// may await terminal events, including blocked/canceled opens. Late success
    /// closes its database, and canceled upgrades abort. A permanently blocked
    /// request retains one slot instead of permitting unbounded orphan callbacks.
    pub async fn open(namespace: Namespace) -> Result<Self, Error> {
        let database = open_database(&database_name(namespace)).await?;
        let access = Rc::new(RefCell::new(Access::Ready));
        let current = access.clone();
        let connection = database.clone();
        let version_change = Closure::<dyn FnMut(Event)>::new(move |_| {
            *current.borrow_mut() = Access::NeedsReopen;
            connection.close();
        });
        database.set_onversionchange(Some(version_change.as_ref().unchecked_ref()));
        Ok(Self {
            database,
            access,
            _version_change: version_change,
        })
    }

    /// Whether a canceled/failed publication or schema change requires reopening.
    #[must_use]
    pub fn needs_reopen(&self) -> bool {
        self.access.borrow().ready().is_err()
    }

    /// Read one exact slot after transaction completion. `None` is explicit
    /// absence/eviction, never a newly fabricated empty image. Bytes remain opaque.
    pub async fn load(&mut self, slot: Slot) -> Result<Option<Image>, Error> {
        self.access.borrow().ready()?;
        let result = self.transaction(slot, None, None).await.and_then(|raw| {
            self.access.borrow().ready()?;
            raw.as_deref()
                .map(|raw| Image::from_bytes(slot, raw))
                .transpose()
        });
        if result.is_err() {
            *self.access.borrow_mut() = Access::NeedsReopen;
        }
        result
    }

    /// Replace exactly one slot only if its stored bytes equal `expected`.
    ///
    /// `None` initializes only an absent slot. Passing an exact prior vault image
    /// permits an explicitly authorized vault/password rotation; no unchanged-key
    /// policy is inferred here. Validate signatures/authority and prepare `next`
    /// before this call. There is no awaited verification inside the transaction.
    ///
    /// Only the transaction's `complete` event permits success. Once polled into
    /// publication, this handle becomes unavailable until success; error or dropped
    /// future requires drop/open/load, even if a put may already have committed.
    pub async fn compare_exchange(
        &mut self,
        expected: Option<&Image>,
        next: &Image,
    ) -> Result<(), PublishError> {
        self.access
            .borrow()
            .ready()
            .map_err(PublishError::Rejected)?;
        if expected.is_some_and(|image| image.slot() != next.slot()) {
            return Err(PublishError::Rejected(Error::WrongSlot));
        }
        let expected = expected.map(|image| image.as_bytes().to_vec());
        let candidate = next.as_bytes().to_vec();
        self.access
            .borrow_mut()
            .begin()
            .map_err(PublishError::Rejected)?;
        match self
            .transaction(next.slot(), expected, Some(candidate))
            .await
        {
            Ok(_) => self
                .access
                .borrow_mut()
                .completed()
                .map_err(PublishError::ReopenRequired),
            Err(error) => {
                *self.access.borrow_mut() = Access::NeedsReopen;
                Err(PublishError::ReopenRequired(error))
            }
        }
    }

    async fn transaction(
        &self,
        slot: Slot,
        expected: Option<Vec<u8>>,
        candidate: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let transaction = durability::begin(&self.database, candidate.is_some())?;
        let finished = Rc::new(Cell::new(false));
        // Install ownership before any fallible request setup so every early
        // return/cancellation aborts an unfinished transaction and detaches hooks.
        let mut guard = TxHandlers {
            request: None,
            transaction: transaction.clone(),
            finished: finished.clone(),
            callbacks: Vec::new(),
        };
        let store = transaction.object_store(OBJECT_STORE).map_err(storage)?;
        let request = store.get(&JsValue::from_str(slot.key())).map_err(storage)?;
        guard.request = Some(request.clone());
        let result: Rc<RefCell<Result<Option<Vec<u8>>, Error>>> =
            Rc::new(RefCell::new(Err(Error::Storage)));
        let (sender, receiver) = oneshot::channel();
        let sender = Rc::new(RefCell::new(Some(sender)));
        let tx = transaction.clone();
        let request_copy = request.clone();
        let value = result.clone();
        let read = Closure::<dyn FnMut(Event)>::new(move |_| {
            let update = request_copy
                .result()
                .map_err(storage)
                .and_then(bytes)
                .and_then(|observed| {
                    if let Some(candidate) = &candidate {
                        compare_exact(expected.as_deref(), observed.as_deref())?;
                        store
                            .put_with_key(
                                &Uint8Array::from(candidate.as_slice()),
                                &JsValue::from_str(slot.key()),
                            )
                            .map_err(storage)?;
                        // Queuing put is not publication. Only complete can ack.
                        Ok(None)
                    } else {
                        Ok(observed)
                    }
                });
            let failed = update.is_err();
            *value.borrow_mut() = update;
            if failed {
                let _ = tx.abort();
            }
        });
        let value = result.clone();
        let done = sender.clone();
        let terminal = finished.clone();
        let complete = Closure::<dyn FnMut(Event)>::new(move |_| {
            terminal.set(true);
            if let Some(sender) = done.borrow_mut().take() {
                let result = std::mem::replace(&mut *value.borrow_mut(), Err(Error::Storage));
                let _ = sender.send(result);
            }
        });
        let value = result.clone();
        let done = sender.clone();
        let terminal = finished.clone();
        let abort = Closure::<dyn FnMut(Event)>::new(move |_| {
            terminal.set(true);
            if let Some(sender) = done.borrow_mut().take() {
                let error = value
                    .borrow()
                    .as_ref()
                    .err()
                    .copied()
                    .unwrap_or(Error::Storage);
                let _ = sender.send(Err(error));
            }
        });
        let tx = transaction.clone();
        let value = result;
        let error = Closure::<dyn FnMut(Event)>::new(move |_| {
            // A request error is not a terminal transaction event. Request abort
            // explicitly, retain handlers, and await abort/complete; never report
            // success merely because the initial get and put setup succeeded.
            let was_ok = value.borrow().is_ok();
            if was_ok {
                *value.borrow_mut() = Err(Error::Storage);
            }
            let _ = tx.abort();
        });
        request.set_onsuccess(Some(read.as_ref().unchecked_ref()));
        transaction.set_oncomplete(Some(complete.as_ref().unchecked_ref()));
        transaction.set_onabort(Some(abort.as_ref().unchecked_ref()));
        transaction.set_onerror(Some(error.as_ref().unchecked_ref()));
        guard.callbacks = vec![read, complete, abort, error];
        let result = receiver.await.map_err(|_| Error::Storage)?;
        drop(guard);
        result
    }
}
