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
fn second(key: &StorageKey, context: Context, record: &StoredRecord) -> Result<Option<RecordKey>> {
    let clear = record_clear(key, context, record)?;
    Ok(match record.key() {
        RecordKey::Outbox(index) => {
            let sent = Sent::decode(&clear)?;
            if sent.sequence != index {
                return Err(Error::Encoding);
            }
            Some(RecordKey::Operation(sent.operation))
        }
        RecordKey::Inbox(index) => {
            let mut received = Received::decode(&clear)?;
            // The decoded plaintext copy is immediately guarded, including all errors.
            let _body = Zeroizing::new(std::mem::take(&mut received.body));
            if received.sequence != index {
                return Err(Error::Encoding);
            }
            Some(RecordKey::Received(wire_hash(&received.wire)))
        }
        RecordKey::Control(_) => None,
        _ => return Err(Error::Encoding),
    })
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
    if let Some(second) = second(key, context, &records[0])? {
        let record = store
            .read(context, second)
            .await
            .map_err(store_error)?
            .ok_or(Error::Missing)?;
        if record.key() != second {
            return Err(Error::Scope);
        }
        records.push(record);
    }
    let next = check(key, context, snapshot, unit, prior, &records)?;
    Ok((records, next))
}
pub(super) fn check(
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
    match second(key, context, record)? {
        Some(index_key) => {
            if records.len() != 2 || records[1].key() != index_key {
                return Err(Error::Encoding);
            }
            let clear = record_clear(key, context, &records[1])?;
            let expected = match first_key {
                RecordKey::Outbox(n) | RecordKey::Inbox(n) => n,
                _ => return Err(Error::Encoding),
            };
            if decode_index(&clear)? != expected {
                return Err(Error::Conflict);
            }
            Ok(prior)
        }
        None => {
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
        }
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
