//! Exact opaque delivery snapshots. No credentials, plaintext, network or reset.
use super::{
    history::{bounded, transaction},
    IndexedStorage,
};
use crate::{Access, Error, Namespace};
use vhalla_private_kernel::Context;

/// One page plus one pending ciphertext and bounded controller metadata.
pub const MAX_DELIVERY_BYTES: usize = 5 * 1024 * 1024;
/// One retained relay-delivered bootstrap item: a complete canonical relay
/// item frame, bounded by the largest stored artifact plus its framing.
pub const MAX_RETAINED_BYTES: usize = vhalla_private_kernel::MAX_STORED_RECORD_BYTES + 128;

/// One atomic delivery publication: the exact image compare-and-swap plus at
/// most one retained bootstrap item added and one discarded in the same
/// IndexedDB transaction. Retained items are never repaired or enumerated
/// without the image index that names them.
#[derive(Clone, Copy, Default)]
pub struct DeliveryWrite<'a> {
    /// Exact previously observed image, or None only for absent-image creation.
    pub expected: Option<&'a [u8]>,
    /// Complete next image.
    pub next: &'a [u8],
    /// Mailbox position and exact bytes of one bootstrap item to retain.
    pub retain: Option<(u64, &'a [u8])>,
    /// Mailbox position of one retained bootstrap item to discard.
    pub discard: Option<u64>,
}

/// A full-context delivery image sharing the selected profile database.
pub struct IndexedDelivery {
    inner: IndexedStorage,
    key: String,
    prefix: String,
}
impl IndexedDelivery {
    /// Open only an existing profile database. Creation of a delivery image is
    /// a separate exact absent-image compare-and-swap, never inferred by open.
    pub async fn open(namespace: Namespace, context: Context) -> Result<Self, Error> {
        let prefix = crate::private_rooms::prefix(context);
        Ok(Self {
            inner: IndexedStorage::open_existing(namespace).await?,
            key: format!("{prefix}delivery-v1"),
            prefix,
        })
    }
    fn retained_key(&self, position: u64) -> String {
        format!("{}delivery-v1/retained/{position:020}", self.prefix)
    }
    /// Read one bounded image. Missing state is reported, never repaired.
    pub async fn load(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.read(self.key.clone(), MAX_DELIVERY_BYTES).await
    }
    /// Read one retained bootstrap item by its exact mailbox position. Absence
    /// is reported; the caller compares the bytes against its image index.
    pub async fn load_retained(&mut self, position: u64) -> Result<Option<Vec<u8>>, Error> {
        self.read(self.retained_key(position), MAX_RETAINED_BYTES)
            .await
    }
    async fn read(&mut self, key: String, maximum: usize) -> Result<Option<Vec<u8>>, Error> {
        self.inner.access.borrow().ready()?;
        let result = transaction(&self.inner.database, false, move |tx| {
            tx.read(&key.into(), move |tx, value| {
                *tx.result.borrow_mut() = Some(bounded(value, maximum));
                Ok(())
            })
        })
        .await
        .and_then(|value| {
            self.inner.access.borrow().ready()?;
            Ok(value)
        });
        if result.is_err() {
            *self.inner.access.borrow_mut() = Access::NeedsReopen;
        }
        result
    }
    /// Publish only over the exact previously observed image. A stale tab,
    /// canceled transaction or uncertain completion invalidates this handle.
    pub async fn compare_exchange(
        &mut self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), Error> {
        self.publish(DeliveryWrite {
            expected,
            next,
            retain: None,
            discard: None,
        })
        .await
    }
    /// Publish the image and its retained-item changes in one strict-durability
    /// transaction; nothing is written when the observed image differs.
    pub async fn publish(&mut self, write: DeliveryWrite<'_>) -> Result<(), Error> {
        if write.next.is_empty()
            || write.next.len() > MAX_DELIVERY_BYTES
            || write.expected.is_some_and(|v| v.len() > MAX_DELIVERY_BYTES)
            || write
                .retain
                .is_some_and(|(_, v)| v.is_empty() || v.len() > MAX_RETAINED_BYTES)
            || write
                .retain
                .zip(write.discard)
                .is_some_and(|((a, _), b)| a == b)
        {
            return Err(Error::Bounds);
        }
        self.inner.access.borrow_mut().begin()?;
        let expected = write.expected.map(<[u8]>::to_vec);
        let next = write.next.to_vec();
        let retain = write
            .retain
            .map(|(position, bytes)| (self.retained_key(position), bytes.to_vec()));
        let discard = write.discard.map(|position| self.retained_key(position));
        let key = self.key.clone();
        let result = transaction(&self.inner.database, true, move |tx| {
            let read_key = key.clone();
            tx.read(&read_key.into(), move |tx, value| {
                if bounded(value, MAX_DELIVERY_BYTES)? != expected {
                    return Err(Error::Stale);
                }
                if let Some((key, bytes)) = &retain {
                    tx.put(key, bytes)?;
                }
                if let Some(key) = &discard {
                    tx.delete(key)?;
                }
                tx.put(&key, &next)?;
                *tx.result.borrow_mut() = Some(Ok(()));
                Ok(())
            })
        })
        .await;
        match result {
            Ok(()) => self.inner.access.borrow_mut().completed(),
            Err(e) => {
                *self.inner.access.borrow_mut() = Access::NeedsReopen;
                Err(e)
            }
        }
    }
}
