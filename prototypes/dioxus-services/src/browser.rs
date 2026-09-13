//! Rust IndexedDB adapter. Runtime qualification must execute in a real browser.
//! One atomic image contains admitted public sources and private reader state.
use super::*;
use futures_channel::oneshot;
use js_sys::Uint8Array;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use vhalla_social::archive::Limits;
use wasm_bindgen::{closure::Closure, JsCast, JsValue};
use web_sys::{
    Event, IdbDatabase, IdbOpenDbRequest, IdbRequest, IdbTransaction, IdbTransactionMode,
};

const OBJECT_STORE: &str = "image";
const KEY: &str = "current";
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

const MAX_PENDING_OPENS: usize = 4;
thread_local! {static PENDING_OPENS:Cell<usize>=const{Cell::new(0)};}
struct OpenSlot;
impl OpenSlot {
    fn acquire() -> Result<Self, Error> {
        PENDING_OPENS.with(|count| {
            if count.get() == MAX_PENDING_OPENS {
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
// A completed open can sit buffered in a oneshot while its receiver is canceled.
// Dropping a JS wrapper does not close IndexedDB, so ownership must stay RAII even
// after the event callback finished and before the awaiting future consumes it.
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
struct OpenState {
    request: IdbOpenDbRequest,
    sender: RefCell<Option<OpenReply>>,
    canceled: Cell<bool>,
    finished: Cell<bool>,
    callbacks: RefCell<Vec<Closure<dyn FnMut(Event)>>>,
    slot: RefCell<Option<OpenSlot>>,
    terminal: RefCell<Option<oneshot::Sender<()>>>,
}
impl OpenState {
    fn cancel(&self) {
        self.canceled.set(true);
        if let Some(sender) = self.sender.borrow_mut().take() {
            let _ = sender.send(Err(Error::Storage));
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
        if let Some(terminal) = self.terminal.borrow_mut().take() {
            let _ = terminal.send(());
        }
    }
}
struct OpenGuard(Rc<OpenState>);
impl Drop for OpenGuard {
    fn drop(&mut self) {
        if !self.0.finished.get() {
            self.0.cancel();
        }
    }
}

// IndexedDB opens cannot be canceled. A bounded self-owned callback state lives
// until the eventual terminal event; canceled/blocked late success closes its DB.
// If a blocker never releases, its slot remains occupied and further opens fail
// at four instead of accumulating callbacks/hidden future database connections.
async fn open_database(name: &str, version: u32) -> Result<IdbDatabase, Error> {
    open_database_observed(name, version, None).await
}
async fn open_database_observed(
    name: &str,
    version: u32,
    terminal: Option<oneshot::Sender<()>>,
) -> Result<IdbDatabase, Error> {
    let slot = OpenSlot::acquire()?;
    let factory = web_sys::window()
        .ok_or(Error::Storage)?
        .indexed_db()
        .map_err(storage)?
        .ok_or(Error::Storage)?;
    let request = factory.open_with_u32(name, version).map_err(storage)?;
    let (sender, receiver) = oneshot::channel();
    let state = Rc::new(OpenState {
        request,
        sender: RefCell::new(Some(sender)),
        canceled: Cell::new(false),
        finished: Cell::new(false),
        callbacks: RefCell::new(Vec::new()),
        slot: RefCell::new(Some(slot)),
        terminal: RefCell::new(terminal),
    });
    let current = state.clone();
    let success = Closure::<dyn FnMut(Event)>::new(move |_| {
        let result = current
            .request
            .result()
            .map_err(storage)
            .and_then(|v| v.dyn_into::<IdbDatabase>().map_err(|_| Error::Storage));
        current.finish(result);
    });
    let current = state.clone();
    let failure = Closure::<dyn FnMut(Event)>::new(move |_| current.finish(Err(Error::Storage)));
    let current = state.clone();
    let blocked = Closure::<dyn FnMut(Event)>::new(move |_| current.cancel());
    let current = state.clone();
    let upgrade = Closure::<dyn FnMut(Event)>::new(move |_| {
        let result = current
            .request
            .result()
            .map_err(storage)
            .and_then(|v| v.dyn_into::<IdbDatabase>().map_err(|_| Error::Storage));
        let valid = if current.canceled.get() {
            false
        } else {
            result.as_ref().is_ok_and(|database| {
                database.object_store_names().contains(OBJECT_STORE)
                    || database.create_object_store(OBJECT_STORE).is_ok()
            })
        };
        if !valid {
            if let Some(tx) = current.request.transaction() {
                let _ = tx.abort();
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
fn database_name(scope: ReaderScope) -> String {
    format!(
        "vhalla-u1-{}",
        scope
            .digest()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}
struct TxHandlers {
    request: IdbRequest,
    transaction: IdbTransaction,
    finished: Rc<Cell<bool>>,
    _callbacks: Vec<Closure<dyn FnMut(Event)>>,
}
impl Drop for TxHandlers {
    fn drop(&mut self) {
        if !self.finished.get() {
            let _ = self.transaction.abort();
        }
        self.request.set_onsuccess(None);
        self.transaction.set_oncomplete(None);
        self.transaction.set_onabort(None);
        self.transaction.set_onerror(None);
    }
}

/// Host-owned database handle; components never receive its name or arbitrary keys.
pub struct IndexedStorage {
    database: IdbDatabase,
    scope: ReaderScope,
    limits: Limits,
}
impl Drop for IndexedStorage {
    fn drop(&mut self) {
        self.database.close();
    }
}
impl IndexedStorage {
    /// Namespace is derived from a locally validated reader. No route/query/remote
    /// string chooses the database. This creates schema only, not a reader image.
    pub async fn open(scope: ReaderScope, limits: Limits) -> Result<Self, Error> {
        let database = open_database(&database_name(scope), 1).await?;
        Ok(Self {
            database,
            scope,
            limits,
        })
    }
    /// Source/signature verification occurs after the read transaction settles.
    /// Missing/evicted data is an error; open never invents an empty reader.
    pub async fn load(&self) -> Result<Image, Error> {
        let raw = self
            .transaction(None, None, false)
            .await?
            .ok_or(Error::MissingSource)?;
        Image::decode(&raw, self.scope, self.limits)
    }
    /// Explicit initial import only. Existing state is never overwritten/reset.
    pub async fn initialize(&self, image: &Image) -> Result<(), Error> {
        let raw = image.encode();
        Image::decode(&raw, self.scope, self.limits)?;
        self.transaction(None, Some(raw), false).await?;
        Ok(())
    }
    async fn publish(&self, previous: &Image, next: &Image, abort: bool) -> Result<(), Error> {
        next.validate_delta(previous)?;
        // Expensive signature validation and projection finish before starting the
        // readwrite transaction. The event callback performs only exact byte CAS
        // and one put; no await yields an auto-committable transaction here.
        let raw = next.encode();
        Image::decode(&raw, self.scope, self.limits)?;
        self.transaction(Some(previous.encode()), Some(raw), abort)
            .await?;
        Ok(())
    }
    async fn transaction(
        &self,
        expected: Option<Vec<u8>>,
        candidate: Option<Vec<u8>>,
        abort: bool,
    ) -> Result<Option<Vec<u8>>, Error> {
        let mode = if candidate.is_some() {
            IdbTransactionMode::Readwrite
        } else {
            IdbTransactionMode::Readonly
        };
        let transaction = self
            .database
            .transaction_with_str_and_mode(OBJECT_STORE, mode)
            .map_err(storage)?;
        let store = transaction.object_store(OBJECT_STORE).map_err(storage)?;
        let request = store.get(&JsValue::from_str(KEY)).map_err(storage)?;
        let result: Rc<RefCell<Result<Option<Vec<u8>>, Error>>> =
            Rc::new(RefCell::new(Err(Error::Storage)));
        let (sender, receiver) = oneshot::channel();
        let sender = Rc::new(RefCell::new(Some(sender)));
        let finished = Rc::new(Cell::new(false));
        let tx = transaction.clone();
        let request_copy = request.clone();
        let value = result.clone();
        let read = Closure::<dyn FnMut(Event)>::new(move |_| {
            let observed = request_copy.result().map_err(storage).and_then(bytes);
            let update = observed.and_then(|observed| {
                if let Some(candidate) = &candidate {
                    if observed != expected {
                        return Err(Error::Stale);
                    }
                    store
                        .put_with_key(
                            &Uint8Array::from(candidate.as_slice()),
                            &JsValue::from_str(KEY),
                        )
                        .map_err(storage)?;
                    if abort {
                        return Err(Error::Storage);
                    }
                    Ok(Some(candidate.clone()))
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
        let finished_copy = finished.clone();
        let complete = Closure::<dyn FnMut(Event)>::new(move |_| {
            finished_copy.set(true);
            if let Some(sender) = done.borrow_mut().take() {
                let _ = sender.send(value.borrow().clone());
            }
        });
        let value = result.clone();
        let done = sender.clone();
        let finished_copy = finished.clone();
        let failure = Closure::<dyn FnMut(Event)>::new(move |_| {
            finished_copy.set(true);
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
        request.set_onsuccess(Some(read.as_ref().unchecked_ref()));
        transaction.set_oncomplete(Some(complete.as_ref().unchecked_ref()));
        transaction.set_onabort(Some(failure.as_ref().unchecked_ref()));
        transaction.set_onerror(Some(failure.as_ref().unchecked_ref()));
        let guard = TxHandlers {
            request,
            transaction,
            finished,
            _callbacks: vec![read, complete, failure],
        };
        let value = receiver.await.map_err(|_| Error::Storage)?;
        drop(guard);
        value
    }
}

pub struct BrowserService<C> {
    storage: IndexedStorage,
    engine: Engine,
    clock: C,
    ready: bool,
}
impl<C: Clock> BrowserService<C> {
    pub async fn open(scope: ReaderScope, limits: Limits, clock: C) -> Result<Self, Error> {
        let storage = IndexedStorage::open(scope, limits).await?;
        let engine = Engine::from_image(storage.load().await?, Persistence::Browser)?;
        Ok(Self {
            storage,
            engine,
            clock,
            ready: true,
        })
    }
}
impl<C: Clock> Service for BrowserService<C> {
    fn project(&mut self, screen: Screen) -> Result<Projection, Error> {
        if !self.ready {
            return Err(Error::Storage);
        }
        self.engine.project(screen, self.clock.now()?)
    }
    fn submit(
        &mut self,
        intent: Intent,
    ) -> Pin<Box<dyn Future<Output = Result<Projection, Error>> + '_>> {
        Box::pin(async move {
            if !self.ready {
                return Err(Error::Storage);
            }
            let now = self.clock.now()?;
            let pending = self.engine.prepare(intent, now)?;
            self.ready = false;
            self.storage
                .publish(&self.engine.image(), &pending.image, false)
                .await?;
            let result = self.engine.confirm(pending, Persistence::Browser, now);
            self.ready = result.is_ok();
            result
        })
    }
}

/// Real-browser qualification entry point for the launcher-owned signed fixture.
/// A fresh namespace must be explicitly supplied; this never deletes an existing DB.
pub async fn qualify(image: Image, now: u64) -> Result<String, Error> {
    let scope = image.scope;
    let limits = image.archive.limits();
    let storage = IndexedStorage::open(scope, limits).await?;
    storage.initialize(&image).await?;
    let mut engine = Engine::from_image(storage.load().await?, Persistence::Browser)?;
    let page = engine.project(Screen::Inbox, now)?;
    let id = page.notifications.first().ok_or(Error::Evidence)?.id;
    let pending = engine.prepare(Intent::acknowledge(page.receipt, vec![id])?, now)?;
    assert_eq!(
        storage.publish(&image, &pending.image, true).await,
        Err(Error::Storage)
    );
    assert_eq!(storage.load().await?.encode(), image.encode());
    storage.publish(&image, &pending.image, false).await?;
    assert_eq!(
        storage.publish(&image, &pending.image, false).await,
        Err(Error::Stale)
    );
    drop(storage);
    let restarted = IndexedStorage::open(scope, limits).await?;
    let saved = restarted.load().await?;
    let mut reopened = Engine::from_image(saved.clone(), Persistence::Browser)?;
    let page = reopened.project(Screen::Inbox, now)?;
    assert_eq!(
        page.notifications
            .iter()
            .filter(|n| n.id == id && n.read == ReadState::Read)
            .count(),
        1
    );
    let mut sibling_profile = scope.profile();
    sibling_profile[0] ^= 1;
    let sibling = ReaderScope::new(
        &image.archive,
        now,
        scope.owner(),
        scope.agent(),
        sibling_profile,
        scope.device(),
    )?;
    let sibling_image = Image {
        scope: sibling,
        archive: image.archive.clone(),
        attention: vhalla_attention::Attention::new(sibling),
        discovery: vhalla_discovery::DiscoveryState::new(sibling.digest()),
    };
    let sibling_store = IndexedStorage::open(sibling, limits).await?;
    sibling_store.initialize(&sibling_image).await?;
    let mut sibling_engine = Engine::from_image(sibling_store.load().await?, Persistence::Browser)?;
    assert!(sibling_engine
        .project(Screen::Inbox, now)?
        .notifications
        .iter()
        .all(|n| n.read == ReadState::Unread));
    // Inject exact test-owned damage without manufacturing valid semantic claims.
    let mut bad = saved.encode();
    let middle = bad.len() / 2;
    bad[middle] ^= 1;
    restarted
        .transaction(Some(saved.encode()), Some(bad), false)
        .await?;
    assert!(matches!(restarted.load().await, Err(Error::Corrupt)));
    drop(restarted);
    qualify_open_cleanup(scope, limits).await?;
    Ok("indexeddb: abort preserved image; exact CAS rejected stale tab; restart retained exact ACK; sibling isolated; corruption rejected; blocked/canceled opens reclaimed; no reset".into())
}

async fn qualify_open_cleanup(scope: ReaderScope, limits: Limits) -> Result<(), Error> {
    use std::task::Poll;
    let held = IndexedStorage::open(scope, limits).await?;
    // The retained v1 handle blocks the attempted v2 upgrade. The failed opener
    // must retain bounded cleanup callbacks until the blocker is released.
    assert!(matches!(
        open_database(&database_name(scope), 2).await,
        Err(Error::Storage)
    ));
    assert_eq!(PENDING_OPENS.with(Cell::get), 1);
    drop(held);
    let reopened = IndexedStorage::open(scope, limits).await?;
    assert_eq!(PENDING_OPENS.with(Cell::get), 0);
    drop(reopened);
    let mut canceled = Box::pin(IndexedStorage::open(scope, limits));
    std::future::poll_fn(|context| {
        assert!(matches!(canceled.as_mut().poll(context), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    drop(canceled);
    let reopened = IndexedStorage::open(scope, limits).await?;
    assert_eq!(PENDING_OPENS.with(Cell::get), 0);
    drop(reopened);
    // Do not poll the open future after its actual onsuccess event. Cancel it
    // while the owned database remains buffered in the oneshot, then prove no
    // orphan v1 connection blocks an actual v2 upgrade of this test-only DB.
    let name = database_name(scope);
    let (terminal, settled) = oneshot::channel();
    let mut buffered = Box::pin(open_database_observed(&name, 1, Some(terminal)));
    std::future::poll_fn(|context| {
        assert!(matches!(buffered.as_mut().poll(context), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    settled.await.map_err(|_| Error::Storage)?;
    drop(buffered);
    let upgraded = open_database(&name, 2).await?;
    upgraded.close();
    Ok(())
}
