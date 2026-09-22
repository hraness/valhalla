//! Staged opaque private-room IndexedDB backend. No MLS, plaintext or network API.
//! Kernel authentication follows every read. Namespace custody is explicit;
//! coherent deletion/rollback of both payload and publication marker is outside
//! the trusted-origin model. A restored/cloned identity never gains fresh state.
use super::{
    history::{bounded, transaction, Transaction},
    IndexedStorage,
};
pub use crate::private_rooms::Limits;
use crate::{
    private_rooms::{self as model, State},
    Access, Error, Namespace,
};
use std::rc::Rc;
use vhalla_private_kernel::{
    storage::{Image, RecordKey, Store, StoreError, StoredRecord},
    Context, MAX_IMAGE_BYTES, MAX_STORED_RECORD_BYTES,
};
use wasm_bindgen::JsCast;
use web_sys::IdbKeyRange;

fn error(error: Error) -> StoreError {
    match error {
        Error::Stale => StoreError::Conflict,
        Error::Bounds => StoreError::Refused,
        Error::Corrupt | Error::WrongScope | Error::WrongSlot => StoreError::Corrupt,
        _ => StoreError::Uncertain,
    }
}

/// One explicitly created private context, sharing the profile's images store.
/// No automatic initialization, migration, deletion, pruning or public export.
pub struct IndexedPrivateStore {
    inner: IndexedStorage,
    context: Context,
    limits: Limits,
}
impl IndexedPrivateStore {
    /// Open an exact reserved archive destination or initialize a wholly absent
    /// prefix atomically. Errors are never interpreted as absence; orphan or
    /// conflicting evidence is preserved. Call only after archive reservation.
    pub async fn open_or_create_archive(
        reservation: super::private_archives::ReservedArchive,
    ) -> Result<Self, StoreError> {
        let namespace = reservation.namespace;
        let context = reservation.context;
        let limits = Limits {
            max_records: crate::private_archives::SNAPSHOT_RECORDS,
            max_record_bytes: crate::private_archives::SNAPSHOT_BYTES,
        };
        let frame = model::format_frame(context, limits).map_err(error)?;
        let mut out = Self {
            inner: IndexedStorage::open(namespace).await.map_err(error)?,
            context,
            limits,
        };
        out.run(true, move |tx| {
            tx.read(
                &format!("{}format", model::prefix(context)).into(),
                move |tx, value| match bounded(value, model::FORMAT_BYTES)? {
                    Some(_) => read_meta(tx, context, Some(limits), |tx, _, _| {
                        *tx.result.borrow_mut() = Some(Ok(()));
                        Ok(())
                    }),
                    None => pristine(tx, context, false, move |tx| {
                        tx.add(&format!("{}format", model::prefix(context)), &frame)?;
                        *tx.result.borrow_mut() = Some(Ok(()));
                        Ok(())
                    }),
                },
            )
        })
        .await?;
        Ok(out)
    }
    /// Create only a wholly absent full-context prefix. This is local custody
    /// setup, never authorization to start a new MLS device after lost history.
    pub async fn create_new(
        namespace: Namespace,
        context: Context,
        limits: Limits,
    ) -> Result<Self, StoreError> {
        let frame = model::format_frame(context, limits).map_err(error)?;
        let mut out = Self {
            inner: IndexedStorage::open(namespace).await.map_err(error)?,
            context,
            limits,
        };
        out.run(true, move |tx| {
            pristine(tx, context, false, move |tx| {
                tx.add(&format!("{}format", model::prefix(context)), &frame)?;
                *tx.result.borrow_mut() = Some(Ok(()));
                Ok(())
            })
        })
        .await?;
        Ok(out)
    }
    /// Open existing custody only. A missing FORMAT/image half, malformed data,
    /// or orphan key refuses; open never repairs or initializes the scope.
    pub async fn open(namespace: Namespace, context: Context) -> Result<Self, StoreError> {
        let mut inner = IndexedStorage::open_existing(namespace)
            .await
            .map_err(error)?;
        let limits = run(&mut inner, false, move |tx| {
            read_meta(tx, context, None, |tx, limits, _| {
                *tx.result.borrow_mut() = Some(Ok(limits));
                Ok(())
            })
        })
        .await?;
        Ok(Self {
            inner,
            context,
            limits,
        })
    }
    /// Any canceled/failed transaction requires a new handle and reconciliation.
    pub fn needs_reopen(&self) -> bool {
        self.inner.needs_reopen()
    }
    fn matches(&self, context: Context) -> Result<(), StoreError> {
        if context != self.context {
            return Err(StoreError::Refused);
        }
        self.inner.access.borrow().ready().map_err(error)
    }
    async fn run<T: 'static>(
        &mut self,
        write: bool,
        setup: impl FnOnce(&Rc<Transaction<T>>) -> Result<(), Error>,
    ) -> Result<T, StoreError> {
        run(&mut self.inner, write, setup).await
    }
}

async fn run<T: 'static>(
    inner: &mut IndexedStorage,
    write: bool,
    setup: impl FnOnce(&Rc<Transaction<T>>) -> Result<(), Error>,
) -> Result<T, StoreError> {
    // A dropped future, including a canceled read, leaves this latch set. The
    // existing transaction guard aborts/detaches but never invents completion.
    inner.access.borrow_mut().begin().map_err(error)?;
    match transaction(&inner.database, write, setup).await {
        Ok(value) => {
            inner.access.borrow_mut().completed().map_err(error)?;
            Ok(value)
        }
        Err(failure) => {
            *inner.access.borrow_mut() = Access::NeedsReopen;
            Err(error(failure))
        }
    }
}

impl Store for IndexedPrivateStore {
    async fn load(&mut self, context: Context) -> Result<Option<Image>, StoreError> {
        self.matches(context)?;
        let limits = self.limits;
        self.run(false, move |tx| {
            read_meta(tx, context, Some(limits), |tx, _, state| {
                *tx.result.borrow_mut() = Some(Ok(state.map(|state| state.image)));
                Ok(())
            })
        })
        .await
    }
    async fn read(
        &mut self,
        context: Context,
        key: RecordKey,
    ) -> Result<Option<StoredRecord>, StoreError> {
        self.matches(context)?;
        key.validate().map_err(|_| StoreError::Refused)?;
        let limits = self.limits;
        self.run(false, move |tx| {
            read_meta(tx, context, Some(limits), move |tx, _, state| {
                // A pristine FORMAT has already passed the bounded whole-prefix check.
                if state.is_none() {
                    *tx.result.borrow_mut() = Some(Ok(None));
                    return Ok(());
                }
                read_pair(tx, context, key, |tx, record| {
                    *tx.result.borrow_mut() = Some(Ok(record));
                    Ok(())
                })
            })
        })
        .await
    }
    async fn publish(
        &mut self,
        context: Context,
        expected: Option<&Image>,
        next: &Image,
        records: &[StoredRecord],
    ) -> Result<(), StoreError> {
        self.matches(context)?;
        model::validate_records(records).map_err(|_| StoreError::Refused)?;
        let expected = expected.cloned();
        let next = next.clone();
        let records = records.to_vec();
        let limits = self.limits;
        self.run(true, move |tx| {
            read_meta(tx, context, Some(limits), move |tx, _, state| {
                read_offered(
                    tx,
                    context,
                    records,
                    Vec::new(),
                    move |tx, records, retained| {
                        let after = model::prepare(
                            limits,
                            state.as_ref(),
                            expected.as_ref(),
                            &next,
                            &records,
                            &retained,
                        )?;
                        for record in &records {
                            let (data, proof) = model::record_keys(context, record.key())?;
                            tx.add(&data, record.as_bytes())?;
                            tx.add(&proof, &model::marker(context, record))?;
                        }
                        tx.put(
                            &format!("{}state", model::prefix(context)),
                            &after.encode(context),
                        )?;
                        *tx.result.borrow_mut() = Some(Ok(()));
                        Ok(())
                    },
                )
            })
        })
        .await
    }
}

// One bounded first-key query sees all keys under the exact prefix, including
// unknown Unicode suffixes. FORMAT itself is the only allowed pristine key.
fn pristine<T: 'static>(
    tx: &Rc<Transaction<T>>,
    context: Context,
    existing: bool,
    done: impl FnOnce(&Rc<Transaction<T>>) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    let start = model::prefix(context);
    let end = format!("{}0", &start[..start.len() - 1]); // '/' followed by any suffix is below '0'.
    let range = IdbKeyRange::bound_with_lower_open_and_upper_open(
        &start.clone().into(),
        &end.into(),
        false,
        true,
    )
    .map_err(super::storage)?;
    let request = tx
        .store
        .get_all_keys_with_key_and_limit(&range, if existing { 2 } else { 1 })
        .map_err(super::storage)?;
    tx.handle(request, move |tx, value| {
        let keys = value
            .dyn_into::<js_sys::Array>()
            .map_err(|_| Error::Corrupt)?;
        if !existing {
            if keys.length() != 0 {
                return Err(Error::Stale);
            }
        } else {
            if keys.length() != 1 {
                return Err(Error::Corrupt);
            }
            let format = format!("{start}format");
            let raw = keys.get(0);
            let key = raw.dyn_ref::<js_sys::JsString>().ok_or(Error::Corrupt)?;
            if key.length() as usize != format.len() || raw.as_string().as_deref() != Some(&format)
            {
                return Err(Error::Corrupt);
            }
        }
        done(tx)
    });
    Ok(())
}

fn read_meta<T: 'static>(
    tx: &Rc<Transaction<T>>,
    context: Context,
    expected: Option<Limits>,
    done: impl FnOnce(&Rc<Transaction<T>>, Limits, Option<State>) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    tx.read(
        &format!("{}format", model::prefix(context)).into(),
        move |tx, value| {
            let raw = bounded(value, model::FORMAT_BYTES)
                .map_err(|_| Error::Corrupt)?
                .ok_or(Error::Corrupt)?;
            let limits = model::parse_format(context, &raw)?;
            if expected.is_some_and(|expected| expected != limits) {
                return Err(Error::Corrupt);
            }
            tx.read(
                &format!("{}state", model::prefix(context)).into(),
                move |tx, value| {
                    if let Some(raw) = bounded(value, MAX_IMAGE_BYTES + model::STATE_OVERHEAD)
                        .map_err(|_| Error::Corrupt)?
                    {
                        let state = State::decode(context, limits, &raw)?;
                        done(tx, limits, Some(state))
                    } else {
                        pristine(tx, context, true, move |tx| done(tx, limits, None))
                    }
                },
            )
        },
    )
}

fn read_pair<T: 'static>(
    tx: &Rc<Transaction<T>>,
    context: Context,
    key: RecordKey,
    done: impl FnOnce(&Rc<Transaction<T>>, Option<StoredRecord>) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    let (data, proof) = model::record_keys(context, key)?;
    tx.read(&data.into(), move |tx, value| {
        let data = bounded(value, MAX_STORED_RECORD_BYTES).map_err(|_| Error::Corrupt)?;
        tx.read(&proof.into(), move |tx, value| {
            let proof = bounded(value, model::MAX_MARKER_BYTES).map_err(|_| Error::Corrupt)?;
            done(tx, model::pair(context, key, data, proof)?)
        })
    })
}
fn read_offered<T: 'static>(
    tx: &Rc<Transaction<T>>,
    context: Context,
    records: Vec<StoredRecord>,
    mut retained: Vec<Option<StoredRecord>>,
    done: impl FnOnce(
            &Rc<Transaction<T>>,
            Vec<StoredRecord>,
            Vec<Option<StoredRecord>>,
        ) -> Result<(), Error>
        + 'static,
) -> Result<(), Error> {
    if retained.len() == records.len() {
        return done(tx, records, retained);
    }
    read_pair(
        tx,
        context,
        records[retained.len()].key(),
        move |tx, record| {
            retained.push(record);
            read_offered(tx, context, records, retained, done)
        },
    )
}

#[cfg(feature = "qualification")]
pub mod qualification;

impl vhalla_private_kernel::storage::ArchiveStore for IndexedPrivateStore {
    async fn accounting(
        &mut self,
        context: Context,
    ) -> Result<vhalla_private_kernel::storage::Accounting, StoreError> {
        self.matches(context)?;
        let limits = self.limits;
        self.run(false, move |tx| {
            read_meta(tx, context, Some(limits), |tx, limits, state| {
                let (image, records, bytes) =
                    state.map_or((None, 0, 0), |s| (Some(s.image), s.records, s.bytes));
                *tx.result.borrow_mut() = Some(Ok(vhalla_private_kernel::storage::Accounting {
                    image,
                    records,
                    bytes,
                    max_records: limits.max_records,
                    max_bytes: limits.max_record_bytes,
                }));
                Ok(())
            })
        })
        .await
    }
}
