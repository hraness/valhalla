//! Explicit bounded sync over a selected local gateway; ciphertext only.
#[path = "delivery_engine.rs"]
pub(super) mod engine;
#[path = "delivery_model.rs"]
mod model;
#[path = "delivery_transport.rs"]
mod transport;
use super::{now, Session};
use crate::private_wire::{DeliveryReport, PROFILE};
pub(super) use engine::{Admission, Summary};
use engine::{Engine, Failure, Host, Result, TransportError};
use sha2::{Digest, Sha256};
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
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    format: u8,
    origin: String,
    namespace: String,
    capability: String,
    initial_cursor: String,
}
fn hex(raw: &str) -> Result<[u8; 32]> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Failure::Invalid);
    }
    let mut out = [0; 32];
    for (i, v) in out.iter_mut().enumerate() {
        *v = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).map_err(|_| Failure::Invalid)?;
    }
    if out == [0; 32] {
        return Err(Failure::Invalid);
    }
    Ok(out)
}
fn binding(
    context: Context,
    profile: &Profile,
    namespace: RelayNamespace,
    initial: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"vhalla/browser-private-delivery-profile/v1\0");
    for b in [
        context.scope.room.as_bytes(),
        context.scope.anchor.as_bytes(),
        context.account.as_bytes(),
        context.device.as_bytes(),
    ] {
        h.update(b);
    }
    h.update(profile.origin.as_bytes());
    h.update([0]);
    h.update(namespace.as_bytes());
    h.update(initial.to_be_bytes());
    h.finalize().into()
}
/// The worker-side environment of one delivery engine: this session's kernel
/// and identity revalidation, the profile database and the same-origin fetch.
struct WorkerHost<'a> {
    session: &'a mut Session,
    store: &'a mut IndexedDelivery,
    origin: &'a str,
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
        if bytes.len() > 4096 {
            return Err(Failure::Invalid);
        }
        let mut p: Profile = serde_json::from_slice(bytes).map_err(|_| Failure::Invalid)?;
        let capability = Zeroizing::new(std::mem::take(&mut p.capability));
        hex(&capability)?;
        if p.format != 1
            || !transport::canonical_origin(&p.origin)
            || transport::origin().map_err(|_| Failure::Invalid)? != p.origin
        {
            return Err(Failure::Invalid);
        }
        let namespace =
            RelayNamespace::from_bytes(hex(&p.namespace)?).map_err(|_| Failure::Invalid)?;
        let initial = p
            .initial_cursor
            .parse::<u64>()
            .map_err(|_| Failure::Invalid)?;
        if initial.to_string() != p.initial_cursor
            || initial > vhalla_private_relay::MAX_RELAY_ITEMS as u64
        {
            return Err(Failure::Invalid);
        }
        let bound = binding(context, &p, namespace, initial);
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
                origin: &p.origin,
                namespace: *namespace.as_bytes(),
                capability: &capability,
            };
            Engine::open(&mut host, namespace, bound, owner, initial, create).await?
        };
        Ok(Self {
            store,
            engine,
            origin: p.origin,
            namespace,
            capability,
        })
    }
    fn report(context: Context, s: Summary) -> DeliveryReport {
        DeliveryReport {
            context,
            sent: s.sent,
            cursor: s.cursor,
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
