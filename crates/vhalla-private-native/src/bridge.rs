//! Native binding of the private kernel's encrypted atomic-store contract.
//!
//! Opening/recovery is explicit. The async trait methods perform one synchronous
//! bounded native operation without yielding midway or invoking callbacks. They
//! must run on an appropriate native worker, not a UI event loop. MLS, storage
//! secrets, ciphertext release and plaintext release remain owned by the kernel.

use std::path::Path;
use vhalla_private_kernel::{
    storage::{Image, RecordKey, Store, StoreError, StoredRecord},
    Context, MAX_TRANSACTION_RECORDS,
};

use crate::private_rooms::{self as native, Limits, NativePrivateStore};

const _: () = assert!(native::MAX_TRANSACTION_RECORDS == MAX_TRANSACTION_RECORDS);

/// One exclusive native kernel store; never clones a live custody handle.
pub struct KernelStore(NativePrivateStore);

impl KernelStore {
    /// Create only a never-used private directory for the exact typed context.
    /// This creates an empty encrypted namespace, not a room or membership grant.
    pub fn create_new(
        path: impl AsRef<Path>,
        context: Context,
        limits: Limits,
    ) -> Result<Self, StoreError> {
        NativePrivateStore::create_new(path, native_context(context)?, limits)
            .map(Self)
            .map_err(store_error)
    }

    /// Explicitly recover and resync an existing exact-context native store.
    /// The kernel must then open and authenticate the existing encrypted image.
    pub fn open(path: impl AsRef<Path>, context: Context) -> Result<Self, StoreError> {
        NativePrivateStore::open(path, native_context(context)?)
            .map(Self)
            .map_err(store_error)
    }
}

impl Store for KernelStore {
    async fn load(&mut self, context: Context) -> Result<Option<Image>, StoreError> {
        self.0
            .load(native_context(context)?)
            .map_err(store_error)?
            .map(|bytes| Image::from_bytes(&bytes).map_err(|_| StoreError::Corrupt))
            .transpose()
    }

    async fn read(
        &mut self,
        context: Context,
        key: RecordKey,
    ) -> Result<Option<StoredRecord>, StoreError> {
        self.0
            .read(native_context(context)?, native_key(key)?)
            .map_err(store_error)?
            .map(|bytes| StoredRecord::from_bytes(key, &bytes).map_err(|_| StoreError::Corrupt))
            .transpose()
    }

    async fn publish(
        &mut self,
        context: Context,
        expected: Option<&Image>,
        next: &Image,
        records: &[StoredRecord],
    ) -> Result<(), StoreError> {
        if records.len() > MAX_TRANSACTION_RECORDS {
            return Err(StoreError::Refused);
        }
        let records = records
            .iter()
            .map(|record| {
                native::Record::new(native_key(record.key())?, record.as_bytes())
                    .map_err(store_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.0
            .publish(
                native_context(context)?,
                expected.map(Image::as_bytes),
                next.as_bytes(),
                &records,
            )
            .map_err(store_error)
    }
}

fn native_context(context: Context) -> Result<native::Context, StoreError> {
    native::Context::new(
        *context.scope.room.as_bytes(),
        *context.scope.anchor.as_bytes(),
        *context.account.as_bytes(),
        *context.device.as_bytes(),
    )
    .map_err(store_error)
}

fn native_key(key: RecordKey) -> Result<native::RecordKey, StoreError> {
    key.validate().map_err(|_| StoreError::Refused)?;
    Ok(match key {
        RecordKey::Outbox(n) => native::RecordKey::Outbox(n),
        RecordKey::Inbox(n) => native::RecordKey::Inbox(n),
        RecordKey::Operation(op) => native::RecordKey::Operation(*op.as_bytes()),
        RecordKey::Received(hash) => native::RecordKey::Received(hash),
        RecordKey::Control(n) => native::RecordKey::Control(n),
    })
}

fn store_error(error: native::Error) -> StoreError {
    match error {
        native::Error::Conflict => StoreError::Conflict,
        native::Error::Refused => StoreError::Refused,
        native::Error::Uncertain => StoreError::Uncertain,
        native::Error::Corrupt => StoreError::Corrupt,
    }
}
