//! Explicit bounded sync over a selected same-origin gateway; ciphertext only.
#[path = "delivery_engine.rs"]
pub(super) mod engine;
#[path = "delivery_model.rs"]
mod model;
#[path = "delivery_profile.rs"]
mod profile;
#[path = "delivery_transport.rs"]
mod transport;
use super::{now, Session};
use crate::private_wire::{DeliveryReport, PROFILE};
pub(super) use engine::{Admission, Summary};
use engine::{Engine, Failure, Host, Result, TransportError};
use vhalla_browser_storage::{
    browser::{
        private_delivery::{DeliveryWrite, IndexedDelivery},
        private_rooms::IndexedPrivateStore,
    },
    Namespace,
};
use vhalla_private_kernel::{Context, Kernel};
use vhalla_private_relay::{RelayItem, RelayNamespace};
use wasm_bindgen::JsCast;
use zeroize::Zeroizing;

pub(super) fn canceled() -> bool {
    transport::canceled()
}
pub(super) fn abort() {
    transport::abort();
}
/// The worker-side environment of one delivery engine: this session's kernel
/// and identity revalidation, the profile database and the same-origin fetch.
struct WorkerHost<'a> {
    session: &'a mut Session,
    store: &'a mut IndexedDelivery,
    origin: &'a str,
    mode: profile::Mode,
    namespace: [u8; 32],
    capability: &'a Zeroizing<String>,
}
impl Host for WorkerHost<'_> {
    type Store = IndexedPrivateStore;
    fn now(&self) -> Result<u64> {
        now()
    }
    fn canceled(&self) -> bool {
        transport::canceled()
    }
    fn kernel(&mut self) -> Result<&mut Kernel<IndexedPrivateStore>> {
        self.session.kernel()
    }
    async fn reopen_kernel(&mut self, context: Context) -> Result<()> {
        self.session.reopen_kernel(context).await
    }
    async fn revalidate(&mut self) -> Result<()> {
        self.session.revalidate().await
    }
    async fn load(&mut self) -> Result<Option<Vec<u8>>> {
        self.store.load().await.map_err(|_| Failure::Storage)
    }
    async fn publish(
        &mut self,
        expected: Option<&[u8]>,
        next: &[u8],
        retain: Option<(u64, &[u8])>,
        discard: Option<u64>,
    ) -> Result<()> {
        self.store
            .publish(DeliveryWrite {
                expected,
                next,
                retain,
                discard,
            })
            .await
            .map_err(|_| Failure::Storage)
    }
    async fn load_retained(&mut self, position: u64) -> Result<Option<Vec<u8>>> {
        self.store
            .load_retained(position)
            .await
            .map_err(|_| Failure::Storage)
    }
    async fn exchange(
        &mut self,
        frame: &[u8],
        maximum: usize,
    ) -> core::result::Result<Vec<u8>, TransportError> {
        transport::exchange(
            self.origin,
            self.mode,
            &self.namespace,
            self.capability,
            frame,
            maximum,
        )
        .await
    }
}
pub(super) struct Delivery {
    store: IndexedDelivery,
    engine: Engine,
    origin: String,
    mode: profile::Mode,
    namespace: RelayNamespace,
    capability: Zeroizing<String>,
}
impl Delivery {
    pub async fn connect(
        session: &mut Session,
        context: Context,
        bytes: &[u8],
        create: bool,
    ) -> Result<Self> {
        let selected = profile::select(
            bytes,
            &transport::origin().map_err(|_| Failure::Invalid)?,
            transport::secure_context(),
        )
        .map_err(|_| Failure::Invalid)?;
        let namespace = selected.namespace;
        let initial = selected.initial;
        let bound = selected.binding(context);
        let mut owner = [0; 16];
        js_sys::global()
            .dyn_into::<web_sys::DedicatedWorkerGlobalScope>()
            .map_err(|_| Failure::Invalid)?
            .crypto()
            .map_err(|_| Failure::Invalid)?
            .get_random_values_with_u8_array(&mut owner)
            .map_err(|_| Failure::Invalid)?;
        if owner == [0; 16] {
            return Err(Failure::Invalid);
        }
        let mut store = IndexedDelivery::open(Namespace::new(PROFILE), context)
            .await
            .map_err(|_| Failure::Storage)?;
        let engine = {
            let mut host = WorkerHost {
                session,
                store: &mut store,
                origin: &selected.origin,
                mode: selected.mode,
                namespace: *namespace.as_bytes(),
                capability: &selected.capability,
            };
            Engine::open(&mut host, namespace, bound, owner, initial, create).await?
        };
        Ok(Self {
            store,
            engine,
            origin: selected.origin,
            mode: selected.mode,
            namespace,
            capability: selected.capability,
        })
    }
    fn report(context: Context, s: Summary) -> DeliveryReport {
        DeliveryReport {
            context,
            sent: s.sent,
            cursor: s.cursor,
            fetched: s.fetched,
            deferred: s.deferred,
            retained: s.retained,
            received: s.received,
            attempts: s.attempts,
            wire_bytes: s.wire_bytes,
            retry_at: s.retry_at,
            pending: s.pending,
            stop: s.stop,
            detail: s.detail,
            blocked: s.blocked,
            refused: s.refused,
            admissions: s.admissions,
            review: s.review,
        }
    }
    pub fn status(&self, context: Context) -> DeliveryReport {
        Self::report(context, self.engine.summary(false))
    }
    pub fn admissions(&self) -> Vec<Admission> {
        self.engine.admissions()
    }
    fn host<'a>(&'a mut self, session: &'a mut Session) -> (&'a mut Engine, WorkerHost<'a>) {
        (
            &mut self.engine,
            WorkerHost {
                session,
                store: &mut self.store,
                origin: &self.origin,
                mode: self.mode,
                namespace: *self.namespace.as_bytes(),
                capability: &self.capability,
            },
        )
    }
    pub async fn sync(
        &mut self,
        session: &mut Session,
        context: Context,
    ) -> Result<DeliveryReport> {
        let (engine, mut host) = self.host(session);
        let summary = engine.sync(&mut host).await?;
        Ok(Self::report(context, summary))
    }
    pub async fn retained(&mut self, session: &mut Session, position: u64) -> Result<RelayItem> {
        let (engine, mut host) = self.host(session);
        engine.retained(&mut host, position).await
    }
    pub async fn discard(
        &mut self,
        session: &mut Session,
        context: Context,
        position: u64,
    ) -> Result<DeliveryReport> {
        let (engine, mut host) = self.host(session);
        let summary = engine.discard(&mut host, position).await?;
        Ok(Self::report(context, summary))
    }
}
