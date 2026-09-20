//! Canonical opaque private-room storage framing. This authenticates no MLS,
//! plaintext, ownership, current policy or hardware durability. Kernel AEAD is
//! required after every load; local checksums only detect mismatched evidence.
use crate::Error;
use sha2::{Digest, Sha256};
use vhalla_private_kernel::{
    storage::{Image, RecordKey, StoredRecord},
    Context, MAX_IMAGE_BYTES, MAX_STORED_RECORD_BYTES,
};

const FORMAT: &[u8; 8] = b"VHPIF001";
const STATE: &[u8; 8] = b"VHPIS001";
const MARKER: &[u8; 8] = b"VHPIM001";
pub(crate) const FORMAT_BYTES: usize = 184;
pub(crate) use vhalla_private_kernel::MAX_TRANSACTION_RECORDS;
pub(crate) const STATE_OVERHEAD: usize = 196;
pub(crate) const MAX_MARKER_BYTES: usize = 238;

/// Immutable local budgets. Exhaustion never authorizes pruning or a reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// At most one million immutable records, counting every index record too.
    pub max_records: u64,
    /// Encrypted record payload bytes; browser/metadata overhead is additional.
    pub max_record_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_records: 100_000,
            max_record_bytes: 256 * 1024 * 1024,
        }
    }
}
impl Limits {
    pub(crate) fn check(self) -> Result<(), Error> {
        if !(1..=1_000_000).contains(&self.max_records)
            || !(40..=8 * 1024 * 1024 * 1024).contains(&self.max_record_bytes)
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
}

pub(crate) fn context_bytes(context: Context) -> [u8; 128] {
    let mut out = [0; 128];
    for (chunk, field) in out.as_chunks_mut::<32>().0.iter_mut().zip([
        context.scope.room.as_bytes(),
        context.scope.anchor.as_bytes(),
        context.account.as_bytes(),
        context.device.as_bytes(),
    ]) {
        chunk.copy_from_slice(field);
    }
    out
}
fn hex(raw: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(raw.len() * 2);
    for byte in raw {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
pub(crate) fn prefix(context: Context) -> String {
    format!("private-rooms/v1/{}/", hex(&context_bytes(context)))
}
pub(crate) fn record_keys(context: Context, key: RecordKey) -> Result<(String, String), Error> {
    key.validate().map_err(|_| Error::Corrupt)?;
    let base = prefix(context);
    let key = hex(&key.encode());
    Ok((
        format!("{base}record/{key}"),
        format!("{base}published/{key}"),
    ))
}
fn checksum(domain: &[u8], raw: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(raw);
    hash.finalize().into()
}
fn append_checksum(domain: &[u8], raw: &mut Vec<u8>) {
    raw.extend(checksum(domain, raw));
}
fn checked<'a>(
    domain: &[u8],
    raw: &'a [u8],
    minimum: usize,
    maximum: usize,
) -> Result<&'a [u8], Error> {
    if !(minimum..=maximum).contains(&raw.len()) {
        return Err(Error::Corrupt);
    }
    let end = raw.len() - 32;
    if checksum(domain, &raw[..end]) != raw[end..] {
        return Err(Error::Corrupt);
    }
    Ok(&raw[..end])
}
fn number(raw: &[u8]) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        raw.try_into().map_err(|_| Error::Corrupt)?,
    ))
}

pub(crate) fn format_frame(context: Context, limits: Limits) -> Result<Vec<u8>, Error> {
    limits.check()?;
    let mut raw = FORMAT.to_vec();
    raw.extend(context_bytes(context));
    raw.extend(limits.max_records.to_be_bytes());
    raw.extend(limits.max_record_bytes.to_be_bytes());
    append_checksum(b"vhalla/private-idb/format/v1\0", &mut raw);
    Ok(raw)
}
pub(crate) fn parse_format(context: Context, raw: &[u8]) -> Result<Limits, Error> {
    let body = checked(
        b"vhalla/private-idb/format/v1\0",
        raw,
        FORMAT_BYTES,
        FORMAT_BYTES,
    )?;
    if &body[..8] != FORMAT || body[8..136] != context_bytes(context) {
        return Err(Error::Corrupt);
    }
    let limits = Limits {
        max_records: number(&body[136..144])?,
        max_record_bytes: number(&body[144..152])?,
    };
    limits.check().map_err(|_| Error::Corrupt)?;
    Ok(limits)
}

#[derive(Clone)]
pub(crate) struct State {
    pub(crate) generation: u64,
    pub(crate) records: u64,
    pub(crate) bytes: u64,
    pub(crate) image: Image,
}
impl State {
    fn check(&self, limits: Limits) -> Result<(), Error> {
        if self.generation == 0
            || self.records > limits.max_records
            || self.bytes > limits.max_record_bytes
            || (self.records == 0) != (self.bytes == 0)
            || self.bytes < self.records.checked_mul(40).ok_or(Error::Corrupt)?
            || self.bytes
                > self
                    .records
                    .checked_mul(MAX_STORED_RECORD_BYTES as u64)
                    .ok_or(Error::Corrupt)?
        {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    pub(crate) fn encode(&self, context: Context) -> Vec<u8> {
        let mut raw = STATE.to_vec();
        raw.extend(context_bytes(context));
        raw.extend(self.generation.to_be_bytes());
        raw.extend(self.records.to_be_bytes());
        raw.extend(self.bytes.to_be_bytes());
        raw.extend((self.image.as_bytes().len() as u32).to_be_bytes());
        raw.extend(self.image.as_bytes());
        append_checksum(b"vhalla/private-idb/state/v1\0", &mut raw);
        raw
    }
    pub(crate) fn decode(context: Context, limits: Limits, raw: &[u8]) -> Result<Self, Error> {
        let body = checked(
            b"vhalla/private-idb/state/v1\0",
            raw,
            STATE_OVERHEAD + 40,
            STATE_OVERHEAD + MAX_IMAGE_BYTES,
        )?;
        if &body[..8] != STATE || body[8..136] != context_bytes(context) {
            return Err(Error::Corrupt);
        }
        let length =
            u32::from_be_bytes(body[160..164].try_into().map_err(|_| Error::Corrupt)?) as usize;
        if !(40..=MAX_IMAGE_BYTES).contains(&length) || body.len() != 164 + length {
            return Err(Error::Corrupt);
        }
        let state = Self {
            generation: number(&body[136..144])?,
            records: number(&body[144..152])?,
            bytes: number(&body[152..160])?,
            image: Image::from_bytes(&body[164..]).map_err(|_| Error::Corrupt)?,
        };
        state.check(limits)?;
        Ok(state)
    }
}

pub(crate) fn marker(context: Context, record: &StoredRecord) -> Vec<u8> {
    let key = record.key().encode();
    let mut raw = MARKER.to_vec();
    raw.extend(context_bytes(context));
    raw.push(key.len() as u8);
    raw.extend(key);
    raw.extend((record.as_bytes().len() as u32).to_be_bytes());
    raw.extend(checksum(
        b"vhalla/private-idb/payload/v1\0",
        record.as_bytes(),
    ));
    append_checksum(b"vhalla/private-idb/marker/v1\0", &mut raw);
    raw
}
pub(crate) fn pair(
    context: Context,
    key: RecordKey,
    raw: Option<Vec<u8>>,
    proof: Option<Vec<u8>>,
) -> Result<Option<StoredRecord>, Error> {
    match (raw, proof) {
        (None, None) => Ok(None),
        (Some(raw), Some(proof)) => {
            checked(
                b"vhalla/private-idb/marker/v1\0",
                &proof,
                214,
                MAX_MARKER_BYTES,
            )?;
            let record = StoredRecord::from_bytes(key, &raw).map_err(|_| Error::Corrupt)?;
            if marker(context, &record) != proof {
                return Err(Error::Corrupt);
            }
            Ok(Some(record))
        }
        _ => Err(Error::Corrupt),
    }
}

pub(crate) fn validate_records(records: &[StoredRecord]) -> Result<(), Error> {
    if records.len() > MAX_TRANSACTION_RECORDS {
        return Err(Error::Bounds);
    }
    for (i, record) in records.iter().enumerate() {
        record.key().validate().map_err(|_| Error::Corrupt)?;
        if records[i + 1..]
            .iter()
            .any(|other| other.key() == record.key())
        {
            return Err(Error::Bounds);
        }
    }
    Ok(())
}

// Every offered collision is checked before the transaction queues any writes.
pub(crate) fn prepare(
    limits: Limits,
    observed: Option<&State>,
    expected: Option<&Image>,
    next: &Image,
    records: &[StoredRecord],
    retained: &[Option<StoredRecord>],
) -> Result<State, Error> {
    validate_records(records)?;
    if records.len() != retained.len() {
        return Err(Error::Bounds);
    }
    if observed.map(|state| state.image.as_bytes()) != expected.map(Image::as_bytes) {
        return Err(Error::Stale);
    }
    let (mut count, mut bytes, generation) = observed.map_or((0, 0, 0), |state| {
        (state.records, state.bytes, state.generation)
    });
    for (record, old) in records.iter().zip(retained) {
        // Retries reconcile retained reads; publication only appends new keys.
        if old.is_some() {
            return Err(Error::Stale);
        }
        count = count.checked_add(1).ok_or(Error::Bounds)?;
        bytes = bytes
            .checked_add(record.as_bytes().len() as u64)
            .ok_or(Error::Bounds)?;
    }
    if count > limits.max_records || bytes > limits.max_record_bytes {
        return Err(Error::Bounds);
    }
    let state = State {
        generation: generation.checked_add(1).ok_or(Error::Bounds)?,
        records: count,
        bytes,
        image: next.clone(),
    };
    state.check(limits)?;
    Ok(state)
}

#[cfg(test)]
mod tests;
