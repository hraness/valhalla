use zeroize::Zeroizing;

use crate::{
    codec,
    model::{State, Working},
    packets::{Received, Sent},
    storage::{Image, RecordKey, Store, StoreError, StoredRecord},
    *,
};

mod contact;
mod controls;
mod drafts;
mod membership;
mod messages;
#[cfg(feature = "local-qualification")]
mod qualification;
pub mod recovery;
mod renewal;
mod snapshot;
mod succession;
pub use drafts::{MemberDraft, OwnerDraft};
pub use snapshot::MembershipSnapshot;

fn encrypted_base(work: &Working) -> protocol::ControlFloor {
    work.state
        .checkpoint
        .as_ref()
        .map_or(work.state.base, |checkpoint| checkpoint.claims().accepted)
}

/// One private room/device custody session. Operations borrow it exclusively;
/// separate sessions still require the backend's exact atomic image comparison.
/// No prepared state or uncommitted wire/plaintext accessor is exposed.
pub struct Kernel<S: Store> {
    store: S,
    key: StorageKey,
    context: Context,
    image: Image,
    status: Status,
    needs_reopen: bool,
    pending_fault: Option<ForkEvidence>,
}
impl<S: Store> Kernel<S> {
    /// Open only an existing exact room/account/device state with retained custody.
    /// Backend recovery must already have completed explicitly. Missing state does
    /// not authorize initialization, key-only restore or ratchet regeneration.
    pub async fn open(mut store: S, key: &StorageKey, context: Context) -> Result<Self> {
        let image = store
            .load(context)
            .await
            .map_err(store_error)?
            .ok_or(Error::Missing)?;
        let work = decode_work(key, context, &image)?;
        Ok(Self {
            store,
            key: key.duplicate(),
            context,
            image,
            status: work.state.status(),
            needs_reopen: false,
            pending_fault: None,
        })
    }
    /// Last authenticated local status. It does not promise remote delivery or
    /// fresh state after another writer; check needs_reopen before any operation.
    pub fn status(&self) -> Status {
        self.status
    }
    /// A canceled/failed in-flight operation must be reconciled by reopening the
    /// exact original backend and context, not by generating a replacement device.
    pub fn needs_reopen(&self) -> bool {
        self.needs_reopen
    }
    /// End custody and recover the opaque backend handle for explicit close/reopen.
    /// The wrapping key and private state are not returned.
    pub fn into_store(self) -> S {
        self.store
    }

    async fn begin(&mut self) -> Result<Working> {
        if self.needs_reopen {
            return Err(Error::NeedsReopen);
        }
        // Set before the first backend await. Dropped futures cannot make the
        // stale session usable again after an indeterminate write/read outcome.
        self.needs_reopen = true;
        let observed = self
            .store
            .load(self.context)
            .await
            .map_err(store_error)?
            .ok_or(Error::Missing)?;
        if observed != self.image {
            return Err(Error::Conflict);
        }
        decode_work(&self.key, self.context, &observed)
    }
    async fn begin_live(&mut self) -> Result<Working> {
        let work = self.begin().await?;
        if work.state.fault.is_some() {
            self.needs_reopen = false;
            return Err(Error::Quarantined);
        }
        Ok(work)
    }
    async fn publish(&mut self, mut work: Working, records: Vec<StoredRecord>) -> Result<()> {
        if !self.needs_reopen || records.len() > MAX_TRANSACTION_RECORDS {
            return Err(Error::NeedsReopen);
        }
        work.state.revision = work.state.revision.checked_add(1).ok_or(Error::Bounds)?;
        let state = work.capture()?;
        let next = encode_state(&self.key, self.context, &state)?;
        self.store
            .publish(self.context, Some(&self.image), &next, &records)
            .await
            .map_err(store_error)?;
        // A successful backend return alone cannot release any output. Re-read
        // exact committed bytes and authenticate both current state and records.
        let observed = self
            .store
            .load(self.context)
            .await
            .map_err(store_error)?
            .ok_or(Error::Missing)?;
        if observed != next {
            return Err(Error::NeedsReopen);
        }
        let confirmed = decode_work(&self.key, self.context, &observed)?;
        for expected in &records {
            let actual = self
                .store
                .read(self.context, expected.key)
                .await
                .map_err(store_error)?
                .ok_or(Error::Missing)?;
            if actual != *expected {
                return Err(Error::NeedsReopen);
            }
            self.decrypt_record(&actual)?;
        }
        self.image = observed;
        self.status = confirmed.state.status();
        // The operation still owns the latch until its retained output has been
        // decoded. Failure/cancellation of that final read also requires reopen.
        Ok(())
    }
    fn encrypt_record(&self, key: RecordKey, clear: &[u8]) -> Result<StoredRecord> {
        key.validate()?;
        let mut purpose = b"record/".to_vec();
        purpose.extend(key.encode());
        let bytes = codec::seal(
            &self.key,
            self.context,
            &purpose,
            clear,
            MAX_STORED_RECORD_BYTES,
        )?;
        Ok(StoredRecord { key, bytes })
    }
    fn decrypt_record(&self, record: &StoredRecord) -> Result<Zeroizing<Vec<u8>>> {
        record.key.validate()?;
        let mut purpose = b"record/".to_vec();
        purpose.extend(record.key.encode());
        codec::unseal(
            &self.key,
            self.context,
            &purpose,
            &record.bytes,
            MAX_STORED_RECORD_BYTES,
        )
    }
    async fn read_clear(&mut self, key: RecordKey) -> Result<Option<Zeroizing<Vec<u8>>>> {
        key.validate()?;
        match self
            .store
            .read(self.context, key)
            .await
            .map_err(store_error)?
        {
            Some(record) if record.key == key => Ok(Some(self.decrypt_record(&record)?)),
            Some(_) => Err(Error::Scope),
            None => Ok(None),
        }
    }
    async fn retained(
        &mut self,
        operation: OperationId,
        request: [u8; 32],
        kind: OutboxKind,
        head: u64,
    ) -> Result<Option<CommittedOutbox>> {
        let Some(lookup) = self.read_clear(RecordKey::Operation(operation)).await? else {
            return Ok(None);
        };
        let index = decode_index(&lookup)?;
        let mut sent = self.sent_at(index, head).await?;
        if sent.kind == OutboxKind::ContactOffer {
            use zeroize::Zeroize;
            sent.bytes.zeroize();
            return Err(Error::Conflict);
        }
        if sent.operation != operation || sent.request != request || sent.kind != kind {
            return Err(Error::Conflict);
        }
        Ok(Some(sent.committed()?))
    }
    async fn sent_at(&mut self, index: u64, head: u64) -> Result<Sent> {
        if index == 0 || index > head {
            return Err(Error::Encoding);
        }
        let bytes = self
            .read_clear(RecordKey::Outbox(index))
            .await?
            .ok_or(Error::Missing)?;
        let sent = Sent::decode(&bytes)?;
        if sent.sequence != index {
            return Err(Error::Encoding);
        }
        Ok(sent)
    }
    async fn received(&mut self, wire: &[u8], head: u64) -> Result<Option<ReceivedMessage>> {
        let wire_id = wire_hash(wire);
        let Some(lookup) = self.read_clear(RecordKey::Received(wire_id)).await? else {
            return Ok(None);
        };
        let index = decode_index(&lookup)?;
        if index == 0 || index > head {
            return Err(Error::Encoding);
        }
        let bytes = self
            .read_clear(RecordKey::Inbox(index))
            .await?
            .ok_or(Error::Missing)?;
        let received = Received::decode(&bytes)?;
        if received.sequence != index || received.wire != wire {
            return Err(Error::Conflict);
        }
        Ok(Some(received.committed()))
    }
    async fn publish_sent(
        &mut self,
        work: Working,
        operation: OperationId,
        request: [u8; 32],
        kind: OutboxKind,
        bytes: Vec<u8>,
    ) -> Result<CommittedOutbox> {
        self.publish_sent_control(work, operation, request, kind, bytes, None)
            .await
    }
    async fn publish_sent_control(
        &mut self,
        mut work: Working,
        operation: OperationId,
        request: [u8; 32],
        kind: OutboxKind,
        bytes: Vec<u8>,
        control: Option<(&packets::ControlPacket, &[u8])>,
    ) -> Result<CommittedOutbox> {
        let index = work.state.outbox.checked_add(1).ok_or(Error::Bounds)?;
        let sent = Sent {
            sequence: index,
            operation,
            request,
            kind,
            bytes,
        };
        let clear = Zeroizing::new(sent.encode()?);
        let mut records = vec![
            self.encrypt_record(RecordKey::Outbox(index), &clear)?,
            self.encrypt_record(RecordKey::Operation(operation), &index.to_be_bytes())?,
        ];
        if let Some((control, envelope)) = control {
            records.push(
                self.encrypt_record(
                    RecordKey::Control(control.floor()?.sequence()),
                    &transport::RetainedControl::new(
                        control.control.clone(),
                        Some(envelope.to_vec()),
                    )?
                    .encode()?,
                )?,
            );
        }
        work.state.outbox = index;
        self.publish(work, records).await?;
        let retained = self
            .retained(operation, request, kind, index)
            .await?
            .ok_or(Error::Missing)?;
        self.needs_reopen = false;
        Ok(retained)
    }
    async fn publish_received(
        &mut self,
        mut work: Working,
        wire: &[u8],
        sender: protocol::Key,
        body: Vec<u8>,
    ) -> Result<ReceivedMessage> {
        let index = work.state.inbox.checked_add(1).ok_or(Error::Bounds)?;
        let received = Received {
            sequence: index,
            wire: wire.to_vec(),
            sender,
            body,
        };
        let clear = Zeroizing::new(received.encode()?);
        let records = vec![
            self.encrypt_record(RecordKey::Inbox(index), &clear)?,
            self.encrypt_record(RecordKey::Received(wire_hash(wire)), &index.to_be_bytes())?,
        ];
        work.state.inbox = index;
        self.publish(work, records).await?;
        let retained = self.received(wire, index).await?.ok_or(Error::Missing)?;
        self.needs_reopen = false;
        Ok(retained)
    }

    /// Read a bounded immutable local outbox prefix. `after` is an explicit
    /// exclusive cursor; this does not mark remote delivery or delete records.
    pub async fn outbox(&mut self, after: u64, limit: usize) -> Result<OutboxPage> {
        if limit == 0 || limit > MAX_PAGE_RECORDS {
            return Err(Error::Bounds);
        }
        let work = self.begin().await?;
        let head = work.state.outbox;
        if after > head {
            return Err(Error::Bounds);
        }
        let mut records = Vec::new();
        let mut total = 0usize;
        let mut cursor = after;
        while cursor < head && records.len() < limit {
            let next = cursor.checked_add(1).ok_or(Error::Bounds)?;
            let sent = self.sent_at(next, head).await?;
            let size = total.checked_add(sent.bytes.len()).ok_or(Error::Bounds)?;
            if size > MAX_PAGE_BYTES {
                break;
            }
            total = size;
            cursor = next;
            records.push(sent.entry()?);
        }
        if cursor == after && cursor < head {
            return Err(Error::Bounds);
        }
        self.needs_reopen = false;
        Ok(OutboxPage {
            head,
            next: (cursor < head).then_some(cursor),
            records,
        })
    }

    /// Read already committed private inbox history without a network request,
    /// cursor write, or new member authorization. No implicit pruning occurs.
    pub async fn inbox(&mut self, after: u64, limit: usize) -> Result<InboxPage> {
        if limit == 0 || limit > MAX_PAGE_RECORDS {
            return Err(Error::Bounds);
        }
        let work = self.begin().await?;
        let head = work.state.inbox;
        if after > head {
            return Err(Error::Bounds);
        }
        let mut records = Vec::new();
        let mut total = 0usize;
        let mut cursor = after;
        while cursor < head && records.len() < limit {
            let next = cursor.checked_add(1).ok_or(Error::Bounds)?;
            let clear = self
                .read_clear(RecordKey::Inbox(next))
                .await?
                .ok_or(Error::Missing)?;
            let received = Received::decode(&clear)?;
            if received.sequence != next {
                return Err(Error::Encoding);
            }
            let size = total
                .checked_add(received.body.len())
                .ok_or(Error::Bounds)?;
            if size > MAX_PAGE_BYTES {
                break;
            }
            total = size;
            cursor = next;
            records.push(received.committed());
        }
        if cursor == after && cursor < head {
            return Err(Error::Bounds);
        }
        self.needs_reopen = false;
        Ok(InboxPage {
            head,
            next: (cursor < head).then_some(cursor),
            records,
        })
    }
}

async fn initialize<S: Store>(mut store: S, key: &StorageKey, work: Working) -> Result<Kernel<S>> {
    let state = work.capture()?;
    let context = state.context();
    let image = encode_state(key, context, &state)?;
    // Consumed draft and independently retained context/key are essential: a
    // canceled initializer can only reopen this namespace, never mint a fallback.
    store
        .publish(context, None, &image, &[])
        .await
        .map_err(store_error)?;
    let observed = store
        .load(context)
        .await
        .map_err(store_error)?
        .ok_or(Error::Missing)?;
    if observed != image {
        return Err(Error::NeedsReopen);
    }
    let work = decode_work(key, context, &observed)?;
    Ok(Kernel {
        store,
        key: key.duplicate(),
        context,
        image: observed,
        status: work.state.status(),
        needs_reopen: false,
        pending_fault: None,
    })
}
fn encode_state(key: &StorageKey, context: Context, state: &State) -> Result<Image> {
    let clear = Zeroizing::new(state.encode()?);
    Ok(Image(codec::seal(
        key,
        context,
        b"current-state",
        &clear,
        MAX_IMAGE_BYTES,
    )?))
}
fn decode_work(key: &StorageKey, context: Context, image: &Image) -> Result<Working> {
    let clear = codec::unseal(key, context, b"current-state", &image.0, MAX_IMAGE_BYTES)?;
    Working::hydrate(State::decode(&clear, context)?)
}
fn decode_index(bytes: &[u8]) -> Result<u64> {
    let index = u64::from_be_bytes(bytes.try_into().map_err(|_| Error::Encoding)?);
    if index == 0 {
        return Err(Error::Encoding);
    }
    Ok(index)
}
fn store_error(error: StoreError) -> Error {
    match error {
        StoreError::Conflict => Error::Conflict,
        StoreError::Refused => Error::Refused,
        StoreError::Uncertain | StoreError::Corrupt => Error::NeedsReopen,
    }
}
fn wire_hash(bytes: &[u8]) -> [u8; 32] {
    codec::hash(b"vhalla/private-kernel/incoming-wire/v1\0", bytes)
}
