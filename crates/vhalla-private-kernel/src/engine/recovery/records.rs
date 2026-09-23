use super::*;

pub(super) fn first(snapshot: &Snapshot, unit: u64) -> Result<RecordKey> {
    if unit < snapshot.outbox {
        return Ok(RecordKey::Outbox(unit + 1));
    }
    let unit = unit.checked_sub(snapshot.outbox).ok_or(Error::Bounds)?;
    if unit < snapshot.inbox {
        return Ok(RecordKey::Inbox(unit + 1));
    }
    let offset = unit.checked_sub(snapshot.inbox).ok_or(Error::Bounds)?;
    let sequence = snapshot
        .base
        .sequence()
        .checked_add(offset)
        .and_then(|n| n.checked_add(1))
        .ok_or(Error::Bounds)?;
    if sequence > snapshot.floor.sequence() {
        return Err(Error::Bounds);
    }
    Ok(RecordKey::Control(sequence))
}
/// Derive every auxiliary index record a unit must carry. A unit has zero to
/// two secondaries: outbox units index their operation and (for application
/// sends) their ciphertext hash; inbox units index their wire hash and (for a
/// verified member receipt) the sender-side acceptance. Re-deriving the exact
/// expectation keeps archive accounting honest when a unit carries one or
/// three records, instead of assuming one auxiliary per unit.
async fn secondaries<S: Store>(
    store: &mut S,
    key: &StorageKey,
    context: Context,
    record: &StoredRecord,
) -> Result<Vec<RecordKey>> {
    let clear = record_clear(key, context, record)?;
    match record.key() {
        RecordKey::Outbox(index) => {
            let sent = Sent::decode(&clear)?;
            if sent.sequence != index {
                return Err(Error::Encoding);
            }
            let mut keys = vec![RecordKey::Operation(sent.operation)];
            if sent.kind == OutboxKind::Application {
                keys.push(RecordKey::Sent(wire_hash(&sent.bytes)));
            }
            Ok(keys)
        }
        RecordKey::Inbox(index) => {
            let received = Received::decode(&clear)?;
            if received.sequence != index {
                return Err(Error::Encoding);
            }
            let sender = received.sender;
            let body = Zeroizing::new(received.body.clone());
            let mut keys = vec![RecordKey::Received(wire_hash(&received.wire))];
            let Some(claim) = MemberAcceptance::claimed_ciphertext(&body) else {
                return Ok(keys);
            };
            let Some(lookup) = store
                .read(context, RecordKey::Sent(claim))
                .await
                .map_err(store_error)?
            else {
                // A receipt for ciphertext this custody never sent carries no
                // acceptance record: it stays inert content in the archive.
                return Ok(keys);
            };
            if lookup.key() != RecordKey::Sent(claim) {
                return Err(Error::Scope);
            }
            let outbox = decode_index(&record_clear(key, context, &lookup)?)?;
            let original_record = store
                .read(context, RecordKey::Outbox(outbox))
                .await
                .map_err(store_error)?
                .ok_or(Error::Missing)?;
            if original_record.key() != RecordKey::Outbox(outbox) {
                return Err(Error::Scope);
            }
            let sent = Sent::decode(&record_clear(key, context, &original_record)?)?;
            if sent.sequence != outbox || sent.kind != OutboxKind::Application {
                return Ok(keys);
            }
            let original = sent.committed()?;
            let message = ReceivedMessage {
                sequence: received.sequence,
                sender,
                body: body.to_vec(),
            };
            if let Ok(Some(_)) = MemberAcceptance::verify(context, &original, &message) {
                keys.push(RecordKey::Acceptance {
                    outbox,
                    recipient: sender,
                });
            }
            Ok(keys)
        }
        RecordKey::Control(_) => Ok(Vec::new()),
        _ => Err(Error::Encoding),
    }
}
pub(super) async fn load<S: Store>(
    store: &mut S,
    key: &StorageKey,
    context: Context,
    snapshot: &Snapshot,
    unit: u64,
    prior: ControlFloor,
) -> Result<(Vec<StoredRecord>, ControlFloor)> {
    let first_key = first(snapshot, unit)?;
    let first = store
        .read(context, first_key)
        .await
        .map_err(store_error)?
        .ok_or(Error::Missing)?;
    if first.key() != first_key {
        return Err(Error::Scope);
    }
    let mut records = vec![first];
    for secondary in secondaries(store, key, context, &records[0]).await? {
        let record = store
            .read(context, secondary)
            .await
            .map_err(store_error)?
            .ok_or(Error::Missing)?;
        if record.key() != secondary {
            return Err(Error::Scope);
        }
        records.push(record);
    }
    let next = check(store, key, context, snapshot, unit, prior, &records).await?;
    Ok((records, next))
}
pub(super) async fn check<S: Store>(
    store: &mut S,
    key: &StorageKey,
    context: Context,
    snapshot: &Snapshot,
    unit: u64,
    prior: ControlFloor,
    records: &[StoredRecord],
) -> Result<ControlFloor> {
    let first_key = first(snapshot, unit)?;
    let record = records.first().ok_or(Error::Missing)?;
    if record.key() != first_key {
        return Err(Error::Scope);
    }
    let expected = secondaries(store, key, context, record).await?;
    if expected.is_empty() {
        if records.len() != 1 {
            return Err(Error::Encoding);
        }
        let clear = record_clear(key, context, record)?;
        let retained = transport::RetainedControl::decode(&clear)?;
        let claims = retained.control.claims();
        let floor = retained.floor()?;
        if first_key != RecordKey::Control(floor.sequence())
            || claims.scope != context.scope
            || claims.owner_device != snapshot.owner_at(floor.sequence())
            || claims.parent != prior
        {
            return Err(Error::Policy);
        }
        if floor.sequence() == snapshot.floor.sequence() && floor != snapshot.floor {
            return Err(Error::Conflict);
        }
        Ok(floor)
    } else {
        if records.len() != expected.len() + 1 {
            return Err(Error::Encoding);
        }
        let index = match first_key {
            RecordKey::Outbox(n) | RecordKey::Inbox(n) => n,
            _ => return Err(Error::Encoding),
        };
        for (record, key_expected) in records[1..].iter().zip(expected.iter()) {
            if record.key() != *key_expected {
                return Err(Error::Encoding);
            }
            let clear = record_clear(key, context, record)?;
            if decode_index(&clear)? != index {
                return Err(Error::Conflict);
            }
        }
        Ok(prior)
    }
}
pub(super) fn bytes(records: &[StoredRecord]) -> Result<u64> {
    records.iter().try_fold(0u64, |n, r| {
        n.checked_add(r.as_bytes().len() as u64)
            .ok_or(Error::Bounds)
    })
}
pub(super) fn payload(unit: u64, records: &[StoredRecord]) -> Result<Zeroizing<Vec<u8>>> {
    let mut w = codec::Writer::new(&[1], MAX_ARCHIVE_PAGE_BYTES - 256)?;
    w.u64(unit)?;
    w.byte(u8::try_from(records.len()).map_err(|_| Error::Bounds)?)?;
    for record in records {
        frame::put_record(&mut w, record)?;
    }
    Ok(Zeroizing::new(w.finish()))
}
pub(super) fn decode(raw: &[u8]) -> Result<(u64, Vec<StoredRecord>)> {
    let mut r = codec::Reader::new(raw, &[1], MAX_ARCHIVE_PAGE_BYTES)?;
    let unit = r.u64()?;
    let count = usize::from(r.byte()?);
    if !(1..=MAX_TRANSACTION_RECORDS).contains(&count) {
        return Err(Error::Bounds);
    }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(frame::read_record(&mut r)?);
    }
    r.end()?;
    Ok((unit, records))
}
