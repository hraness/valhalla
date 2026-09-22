//! Explicit bounded sync over a selected local gateway; ciphertext only.
#[path = "delivery_model.rs"]
mod model;
#[path = "delivery_transport.rs"]
mod transport;
use super::{now, Failure, Result, Session};
use crate::private_wire::{DeliveryReport, PROFILE};
use sha2::{Digest, Sha256};
use vhalla_browser_storage::{browser::private_delivery::IndexedDelivery, Namespace};
use vhalla_private_kernel::{Context, MemberAcceptance, OperationId, OutboxKind, Phase};
use vhalla_private_relay::{codec, RelayItem, RelayNamespace};
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
pub(super) struct Delivery {
    store: IndexedDelivery,
    state: model::State,
    raw: Vec<u8>,
    origin: String,
    namespace: RelayNamespace,
    capability: Zeroizing<String>,
}
impl Delivery {
    pub async fn connect(context: Context, bytes: &[u8], create: bool) -> Result<Self> {
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
        let old = store.load().await.map_err(|_| Failure::Storage)?;
        let mut state = match (create, old.as_ref()) {
            (true, None) => model::State::new(bound, owner, initial, now()?),
            (false, Some(raw)) => model::State::decode(raw).map_err(|_| Failure::Storage)?,
            _ => return Err(Failure::State),
        };
        if state.binding != bound || state.initial != initial || now()? < state.wall {
            return Err(Failure::State);
        }
        state.owner = owner;
        let raw = state.encode().map_err(|_| Failure::Storage)?;
        store
            .compare_exchange(old.as_deref(), &raw)
            .await
            .map_err(|_| Failure::Storage)?;
        Ok(Self {
            store,
            state,
            raw,
            origin: p.origin,
            namespace,
            capability,
        })
    }
    async fn save(&mut self) -> Result<()> {
        if canceled() {
            return Err(Failure::State);
        }
        let raw = self.state.encode().map_err(|_| Failure::State)?;
        self.store
            .compare_exchange(Some(&self.raw), &raw)
            .await
            .map_err(|_| Failure::Storage)?;
        self.raw = raw;
        Ok(())
    }
    async fn fence(&mut self) -> Result<()> {
        if canceled() {
            return Err(Failure::State);
        }
        if self
            .store
            .load()
            .await
            .map_err(|_| Failure::Storage)?
            .as_deref()
            != Some(self.raw.as_slice())
        {
            return Err(Failure::State);
        }
        Ok(())
    }
    async fn halt<T>(&mut self) -> Result<T> {
        self.state.stopped = true;
        self.save().await?;
        Err(Failure::Invalid)
    }
    pub fn report(&self, context: Context, review: bool) -> DeliveryReport {
        DeliveryReport {
            context,
            sent: self.state.sent,
            cursor: self.state.cursor,
            retained: self.state.retained,
            received: self.state.received,
            attempts: self.state.attempts,
            retry_at: self.state.retry_at,
            pending: !self.state.pending.is_empty() || !self.state.staged.is_empty(),
            stopped: self.state.stopped,
            review,
        }
    }
    async fn exchange(
        &mut self,
        session: &Session,
        op: u8,
        body: &[u8],
        maximum: usize,
    ) -> Result<Option<Vec<u8>>> {
        self.fence().await?;
        session.revalidate().await?;
        let reserved = self
            .state
            .reserve(now()?, body.len() + 5 + maximum)
            .map_err(|_| Failure::State)?;
        self.save().await?;
        if !reserved {
            return Ok(None);
        }
        let raw = transport::exchange(
            &self.origin,
            self.namespace.as_bytes(),
            &self.capability,
            &codec::frame(op, body),
            maximum,
        )
        .await;
        self.fence().await?;
        session.revalidate().await?;
        let raw = match raw {
            Ok(raw) => raw,
            Err(transport::Error::Retry) => return Ok(None),
            Err(transport::Error::Authorization) => return Err(Failure::State),
            Err(transport::Error::Refused) => return self.halt().await,
        };
        let (status, body) = match codec::decode_frame(&raw, maximum.saturating_sub(4)) {
            Ok(frame) => frame,
            Err(_) => return self.halt().await,
        };
        match codec::decode_status(status, body) {
            Ok(body) => Ok(Some(body)),
            Err(codec::NetError::Denied) => Err(Failure::State),
            Err(
                codec::NetError::Capacity
                | codec::NetError::Unavailable
                | codec::NetError::Connect
                | codec::NetError::Timeout,
            ) => Ok(None),
            Err(_) => self.halt().await,
        }
    }
    async fn own_item(session: &mut Session, item: &RelayItem) -> Result<bool> {
        if item.sequence() > session.kernel()?.status().outbox_head {
            return Ok(false);
        }
        let page = session.kernel()?.outbox(item.sequence() - 1, 1).await?;
        Ok(page
            .records
            .first()
            .and_then(|entry| entry.artifact())
            .is_some_and(|v| {
                v.sequence() == item.sequence()
                    && v.operation() == item.operation()
                    && v.kind() == item.kind()
                    && v.bytes() == item.payload()
            }))
    }
    pub async fn sync(&mut self, session: &mut Session) -> Result<DeliveryReport> {
        self.fence().await?;
        let initial = session.kernel()?.membership().await?.status();
        if initial.quarantined
            || !matches!(
                initial.phase,
                Phase::OwnerGenesis
                    | Phase::OwnerJoined
                    | Phase::MemberJoined
                    | Phase::OwnerAfterRemoval
            )
        {
            return Err(Failure::State);
        }
        let context = initial.context;
        if self.state.stopped {
            return Ok(self.report(context, false));
        }
        // At most two outgoing items per user gesture. Secret bootstrap entries
        // advance only this local enumeration; they never enter network bytes.
        for _ in 0..2 {
            if self.state.pending.is_empty() {
                let page = session.kernel()?.outbox(self.state.sent, 1).await?;
                let Some(entry) = page.records.first() else {
                    break;
                };
                if let Some(artifact) = entry.artifact().filter(|a| {
                    matches!(
                        a.kind(),
                        OutboxKind::Application
                            | OutboxKind::Removal
                            | OutboxKind::OwnerUpdate
                            | OutboxKind::Succession
                            | OutboxKind::ContactRequest
                            | OutboxKind::ContactInvitation
                    )
                }) {
                    self.state.pending = RelayItem::from_artifact(self.namespace, artifact)
                        .and_then(|v| v.encode())
                        .map_err(|_| Failure::Invalid)?;
                } else {
                    self.state.sent = entry.sequence();
                }
                self.save().await?;
                if self.state.pending.is_empty() {
                    continue;
                }
            }
            let item = RelayItem::decode(&self.state.pending).map_err(|_| Failure::Storage)?;
            if item.namespace() != self.namespace || !Self::own_item(session, &item).await? {
                return Err(Failure::State);
            }
            let raw = self.state.pending.clone();
            let Some(reply) = self.exchange(session, codec::OP_PUT, &raw, 46).await? else {
                return Ok(self.report(context, false));
            };
            if codec::decode_receipt(&reply, &item).is_err() {
                return self.halt().await;
            }
            self.state.sent = item.sequence();
            self.state.retained = self.state.retained.checked_add(1).ok_or(Failure::State)?;
            self.state.pending.clear();
            self.state.success();
            self.save().await?;
        }
        if self.state.staged.is_empty() {
            let request = codec::page_request(self.state.cursor, model::PAGE)
                .map_err(|_| Failure::Invalid)?;
            let Some(raw) = self
                .exchange(session, codec::OP_PAGE, &request, codec::MAX_RESPONSE + 4)
                .await?
            else {
                return Ok(self.report(context, false));
            };
            let page = match codec::decode_page(&raw, self.state.cursor, model::PAGE) {
                Ok(page) => page,
                Err(_) => return self.halt().await,
            };
            if page.head < self.state.cursor
                || page
                    .records
                    .iter()
                    .any(|r| r.item.namespace() != self.namespace)
            {
                return self.halt().await;
            }
            self.state.success();
            self.state.staged_after = self.state.cursor;
            self.state.applied = 0;
            if !page.records.is_empty() {
                self.state.staged = raw;
            }
            self.save().await?;
        }
        if self.state.staged.is_empty() {
            return Ok(self.report(context, false));
        }
        let page = codec::decode_page(&self.state.staged, self.state.staged_after, model::PAGE)
            .map_err(|_| Failure::Storage)?;
        for record in page.records.iter().skip(self.state.applied as usize) {
            if record.item.namespace() != self.namespace {
                return Err(Failure::State);
            }
            self.fence().await?;
            session.revalidate().await?;
            let mut review = false;
            if !Self::own_item(session, &record.item).await? {
                match record.item.kind() {
                    OutboxKind::Application => {
                        let message = session
                            .kernel()?
                            .receive(record.item.payload(), now()?)
                            .await?;
                        if !MemberAcceptance::is_receipt(message.body()) {
                            let mut h = Sha256::new();
                            h.update(b"vhalla/browser-member-acceptance-operation/v1\0");
                            h.update(context.device.as_bytes());
                            h.update(record.item.digest());
                            let digest: [u8; 32] = h.finalize().into();
                            let operation = OperationId::from_bytes(
                                digest[..16].try_into().map_err(|_| Failure::Invalid)?,
                            )
                            .map_err(|_| Failure::Invalid)?;
                            session
                                .kernel()?
                                .issue_acceptance(operation, record.item.payload(), now()?)
                                .await?;
                        }
                        self.state.received =
                            self.state.received.checked_add(1).ok_or(Failure::State)?;
                    }
                    OutboxKind::Removal | OutboxKind::OwnerUpdate | OutboxKind::Succession => {
                        session.message = None;
                        session
                            .kernel()?
                            .apply_control(record.item.payload(), now()?)
                            .await?;
                        review = true;
                    }
                    // These canonical encrypted bootstrap artifacts require
                    // dedicated user-selected admission, never generic apply.
                    OutboxKind::ContactRequest | OutboxKind::ContactInvitation => (),
                    _ => return Err(Failure::Invalid),
                }
            }
            self.state.cursor = record.position;
            self.state.applied += 1;
            if self.state.applied as usize == page.records.len() {
                self.state.staged.clear();
                self.state.applied = 0;
                self.state.staged_after = self.state.cursor;
            }
            self.save().await?;
            if review {
                return Ok(self.report(context, true));
            }
        }
        Ok(self.report(context, false))
    }
}
