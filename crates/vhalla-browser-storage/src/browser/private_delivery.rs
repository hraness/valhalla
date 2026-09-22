//! Exact opaque delivery snapshots. No credentials, plaintext, network or reset.
use super::{
    history::{bounded, transaction},
    IndexedStorage,
};
use crate::{Access, Error, Namespace};
use vhalla_private_kernel::Context;

/// One page plus one pending ciphertext and bounded controller metadata.
pub const MAX_DELIVERY_BYTES: usize = 5 * 1024 * 1024;

/// A full-context delivery image sharing the selected profile database.
pub struct IndexedDelivery {
    inner: IndexedStorage,
    key: String,
}
impl IndexedDelivery {
    /// Open only an existing profile database. Creation of a delivery image is
    /// a separate exact absent-image compare-and-swap, never inferred by open.
    pub async fn open(namespace: Namespace, context: Context) -> Result<Self, Error> {
        Ok(Self {
            inner: IndexedStorage::open_existing(namespace).await?,
            key: format!("{}delivery-v1", crate::private_rooms::prefix(context)),
        })
    }
    /// Read one bounded image. Missing state is reported, never repaired.
    pub async fn load(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.inner.access.borrow().ready()?;
        let key = self.key.clone();
        let result = transaction(&self.inner.database, false, move |tx| {
            tx.read(&key.into(), |tx, value| {
                *tx.result.borrow_mut() = Some(bounded(value, MAX_DELIVERY_BYTES));
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
        if next.is_empty()
            || next.len() > MAX_DELIVERY_BYTES
            || expected.is_some_and(|v| v.len() > MAX_DELIVERY_BYTES)
        {
            return Err(Error::Bounds);
        }
        self.inner.access.borrow_mut().begin()?;
        let expected = expected.map(<[u8]>::to_vec);
        let next = next.to_vec();
        let key = self.key.clone();
        let result = transaction(&self.inner.database, true, move |tx| {
            let read_key = key.clone();
            tx.read(&read_key.into(), move |tx, value| {
                if bounded(value, MAX_DELIVERY_BYTES)? != expected {
                    return Err(Error::Stale);
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
