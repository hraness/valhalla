use super::*;
use crate::codec::{Reader, Writer};
use hkdf::Hkdf;
use sha2::Sha256;

const MAGIC: &[u8] = b"VHPRARC1";
const PREFIX: usize = 8 + 128 + 32 + 8 + 32 + 4;
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Header {
    pub revision: u64,
    pub records: u64,
    pub bytes: u64,
    pub image_len: u32,
    pub image_hash: [u8; 32],
    pub state_hash: [u8; 32],
}
impl Header {
    pub fn put(self, w: &mut Writer) -> Result<()> {
        w.u64(self.revision)?;
        w.u64(self.records)?;
        w.u64(self.bytes)?;
        w.put(&self.image_len.to_be_bytes())?;
        w.put(&self.image_hash)?;
        w.put(&self.state_hash)
    }
    pub fn read(r: &mut Reader<'_>) -> Result<Self> {
        let value = Self {
            revision: r.u64()?,
            records: r.u64()?,
            bytes: r.u64()?,
            image_len: u32::from_be_bytes(r.array()?),
            image_hash: r.array()?,
            state_hash: r.array()?,
        };
        if !(40..=MAX_IMAGE_BYTES).contains(&(value.image_len as usize))
            || value.image_hash == [0; 32]
            || value.state_hash == [0; 32]
            || value.bytes < value.records.checked_mul(40).ok_or(Error::Bounds)?
            || value.bytes
                > value
                    .records
                    .checked_mul(MAX_STORED_RECORD_BYTES as u64)
                    .ok_or(Error::Bounds)?
        {
            return Err(Error::Bounds);
        }
        Ok(value)
    }
}
pub(super) struct Page {
    pub id: [u8; 32],
    pub index: u64,
    pub previous: [u8; 32],
    pub payload: Zeroizing<Vec<u8>>,
}
fn archive_key(
    key: &StorageKey,
    context: Context,
    id: [u8; 32],
    purpose: &[u8],
) -> Result<StorageKey> {
    if id == [0; 32] {
        return Err(Error::Encoding);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(&id), &*key.0);
    let mut secret = Zeroizing::new([0; 32]);
    hkdf.expand_multi_info(
        &[
            b"vhalla/private-archive/key/v1\0",
            &context.encode(),
            purpose,
        ],
        secret.as_mut(),
    )
    .map_err(|_| Error::Bounds)?;
    Ok(StorageKey(secret))
}
impl Page {
    fn prefix(&self, context: Context, encrypted_len: usize) -> Result<Vec<u8>> {
        let mut w = Writer::new(MAGIC, PREFIX)?;
        w.put(&context.encode())?;
        w.put(&self.id)?;
        w.u64(self.index)?;
        w.put(&self.previous)?;
        w.put(
            &u32::try_from(encrypted_len)
                .map_err(|_| Error::Bounds)?
                .to_be_bytes(),
        )?;
        Ok(w.finish())
    }
    pub fn seal(&self, key: &StorageKey, context: Context) -> Result<ArchivePage> {
        if self.payload.len() > MAX_ARCHIVE_PAGE_BYTES - PREFIX - 40 {
            return Err(Error::Bounds);
        }
        let mut out = self.prefix(context, self.payload.len() + 40)?;
        let mut purpose = b"archive-page/v1\0".to_vec();
        purpose.extend_from_slice(&out);
        let encrypted = codec::seal(
            &archive_key(key, context, self.id, b"page")?,
            context,
            &purpose,
            &self.payload,
            MAX_ARCHIVE_PAGE_BYTES - PREFIX,
        )?;
        out.extend(encrypted);
        Ok(ArchivePage(out))
    }
    pub fn open(key: &StorageKey, context: Context, id: [u8; 32], raw: &[u8]) -> Result<Self> {
        if raw.len() < PREFIX + 40 || raw.len() > MAX_ARCHIVE_PAGE_BYTES {
            return Err(Error::Bounds);
        }
        let mut r = Reader::new(raw, MAGIC, MAX_ARCHIVE_PAGE_BYTES)?;
        if r.take(128)? != context.encode() || r.array::<32>()? != id {
            return Err(Error::Scope);
        }
        let index = r.u64()?;
        let previous = r.array()?;
        if index == 0 && previous != [0; 32] {
            return Err(Error::Encoding);
        }
        let len = u32::from_be_bytes(r.array()?) as usize;
        if !(40..=MAX_ARCHIVE_PAGE_BYTES - PREFIX).contains(&len) {
            return Err(Error::Bounds);
        }
        let encrypted = r.take(len)?;
        r.end()?;
        let mut purpose = b"archive-page/v1\0".to_vec();
        purpose.extend_from_slice(&raw[..PREFIX]);
        let payload = codec::unseal(
            &archive_key(key, context, id, b"page")?,
            context,
            &purpose,
            encrypted,
            MAX_ARCHIVE_PAGE_BYTES - PREFIX,
        )?;
        Ok(Self {
            id,
            index,
            previous,
            payload,
        })
    }
}

pub(super) fn put_record(w: &mut Writer, record: &StoredRecord) -> Result<()> {
    w.blob(&record.key().encode(), 64)?;
    w.blob(record.as_bytes(), MAX_STORED_RECORD_BYTES)
}
pub(super) fn read_record(r: &mut Reader<'_>) -> Result<StoredRecord> {
    let mut key = Reader { rest: r.blob(64)? };
    let key_value = match key.byte()? {
        1 => RecordKey::Outbox(key.u64()?),
        2 => RecordKey::Inbox(key.u64()?),
        3 => RecordKey::Operation(OperationId::from_bytes(key.array()?)?),
        4 => RecordKey::Received(key.array()?),
        5 => RecordKey::Control(key.u64()?),
        6 => RecordKey::Sent(key.array()?),
        7 => RecordKey::Acceptance {
            outbox: key.u64()?,
            recipient: protocol::Key::from_bytes(key.array()?)?,
        },
        _ => return Err(Error::Encoding),
    };
    key.end()?;
    StoredRecord::from_bytes(key_value, r.blob(MAX_STORED_RECORD_BYTES)?)
}

// Closed storage purposes: none can be chosen from untrusted frame magic or
// exposed as a generic sealer. The same context/ID cannot cross these roles.
pub(super) fn receiving_key(
    key: &StorageKey,
    context: Context,
    id: [u8; 32],
) -> Result<StorageKey> {
    archive_key(key, context, id, b"receiving")
}
pub(super) fn read_only_key(
    key: &StorageKey,
    context: Context,
    id: [u8; 32],
) -> Result<StorageKey> {
    archive_key(key, context, id, b"read-only")
}
