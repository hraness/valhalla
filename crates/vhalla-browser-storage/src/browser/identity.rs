//! Atomic vault/provenance publication. No plaintext secrets enter this layer.

use super::{
    history::{bounded, transaction, Transaction},
    IndexedStorage,
};
use crate::{
    identity::{
        compare_identity, created, replaced, revalidated, IdentitySnapshot, BIRTH_BYTES, BIRTH_KEY,
    },
    Access, Error, Image, PublishError, Slot, MAX_IMAGE_BYTES,
};
use std::rc::Rc;
use wasm_bindgen::JsValue;

pub(super) fn read_identity<T: 'static>(
    state: &Rc<Transaction<T>>,
    callback: impl FnOnce(&Rc<Transaction<T>>, IdentitySnapshot) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    state.read(
        &JsValue::from_str(Slot::Vault.key()),
        move |state, value| {
            let vault = bounded(value, MAX_IMAGE_BYTES)?;
            state.read(&JsValue::from_str(BIRTH_KEY), move |state, value| {
                let birth = bounded(value, BIRTH_BYTES)?;
                let observed = IdentitySnapshot::decode(vault.as_deref(), birth.as_deref())?;
                callback(state, observed)
            })
        },
    )
}

impl IndexedStorage {
    /// Read the encrypted vault and local creation metadata as one snapshot.
    /// Missing provenance means imported/legacy state, never fresh authority.
    /// Malformed or mismatching provenance fails closed without modifying data.
    pub async fn load_identity(&mut self) -> Result<IdentitySnapshot, Error> {
        self.access.borrow().ready()?;
        let result = transaction(&self.database, false, |state| {
            read_identity(state, |state, observed| {
                *state.result.borrow_mut() = Some(Ok(observed));
                Ok(())
            })
        })
        .await
        .and_then(|observed| {
            self.access.borrow().ready()?;
            Ok(observed)
        });
        if result.is_err() {
            *self.access.borrow_mut() = Access::NeedsReopen;
        }
        result
    }

    /// Revalidate an already authenticated, unchanged vault without writing.
    ///
    /// Reads and compares the exact existing vault/provenance pair in one readonly
    /// transaction. This permits unlock and export when reads remain available but
    /// writes fail, including storage pressure. The caller must have authenticated
    /// this exact encrypted vault in its key worker. No absent identity is accepted.
    /// Cancellation, mismatch, or failed completion requires drop/open/revalidation.
    pub async fn revalidate_identity(
        &mut self,
        expected: &IdentitySnapshot,
    ) -> Result<IdentitySnapshot, Error> {
        // Use the same conservative operation latch as publication: cancellation
        // cannot leave a handle that appears to have authenticated successfully.
        self.access.borrow_mut().begin()?;
        let expected = expected.clone();
        let result = transaction(&self.database, false, move |state| {
            read_identity(state, move |state, observed| {
                *state.result.borrow_mut() = Some(Ok(revalidated(&expected, &observed)?));
                Ok(())
            })
        })
        .await;
        match result {
            Ok(snapshot) => {
                self.access.borrow_mut().completed()?;
                Ok(snapshot)
            }
            Err(error) => {
                *self.access.borrow_mut() = Access::NeedsReopen;
                Err(error)
            }
        }
    }

    /// Publish a genuinely newly generated key and its creation metadata together.
    ///
    /// The trusted caller must use its CSPRNG new-key path, never a backup/import.
    /// Both stored keys must be absent. Only transaction completion acknowledges
    /// local creation; an uncertain outcome requires reopening and reconciliation.
    pub async fn create_local_identity(
        &mut self,
        next: &Image,
    ) -> Result<IdentitySnapshot, PublishError> {
        let next = created(next).map_err(PublishError::Rejected)?;
        self.publish_identity(IdentitySnapshot::empty(), next, true)
            .await
    }

    /// Exact pair CAS for authentication, same-key password change, or key import.
    ///
    /// Import into an empty profile creates no provenance. An existing identity
    /// can only retain its key, preserving its provenance or its absence exactly.
    /// Never call `create_local_identity` to restore a key or repair missing data.
    pub async fn replace_identity(
        &mut self,
        expected: &IdentitySnapshot,
        next: &Image,
    ) -> Result<IdentitySnapshot, PublishError> {
        let next = replaced(expected, next).map_err(PublishError::Rejected)?;
        self.publish_identity(expected.clone(), next, false).await
    }

    async fn publish_identity(
        &mut self,
        expected: IdentitySnapshot,
        next: IdentitySnapshot,
        create: bool,
    ) -> Result<IdentitySnapshot, PublishError> {
        self.access
            .borrow_mut()
            .begin()
            .map_err(PublishError::Rejected)?;
        let result = transaction(&self.database, true, move |state| {
            read_identity(state, move |state, observed| {
                compare_identity(&expected, &observed)?;
                let vault = next.vault().ok_or(Error::Corrupt)?;
                if create {
                    state.add(Slot::Vault.key(), vault.as_bytes())?;
                    state.add(BIRTH_KEY, &next.birth_bytes().ok_or(Error::Corrupt)?)?;
                } else {
                    // Birth is immutable, including absence. The exact pair CAS
                    // ensures a changed provenance record cannot be overlooked.
                    state.put(Slot::Vault.key(), vault.as_bytes())?;
                }
                *state.result.borrow_mut() = Some(Ok(next));
                Ok(())
            })
        })
        .await;
        match result {
            Ok(snapshot) => {
                self.access
                    .borrow_mut()
                    .completed()
                    .map_err(PublishError::ReopenRequired)?;
                Ok(snapshot)
            }
            Err(error) => {
                *self.access.borrow_mut() = Access::NeedsReopen;
                Err(PublishError::ReopenRequired(error))
            }
        }
    }
}
