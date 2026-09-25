//! Exact opaque delivery snapshots. No credentials, plaintext, network or reset.
use super::{
    history::{bounded, transaction, Transaction},
    IndexedStorage,
};
use crate::private_rooms::{self as model, DeliveryGeneration};
use crate::{Access, Error, Namespace};
use std::rc::Rc;
use vhalla_private_kernel::{storage::Image, Context, MAX_IMAGE_BYTES};

pub(super) fn read_generation<T: 'static>(
    tx: &Rc<Transaction<T>>,
    context: Context,
    done: impl FnOnce(&Rc<Transaction<T>>, Option<DeliveryGeneration>) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    tx.read(
        &model::delivery_selector_key(context).into(),
        move |tx, value| {
            let generation = bounded(value, DeliveryGeneration::BYTES)?
                .map(|raw| DeliveryGeneration::decode(&raw))
                .transpose()?;
            tx.read(
                &format!("{}format", model::prefix(context)).into(),
                move |tx, value| {
                    let raw = bounded(value, model::FORMAT_BYTES)?.ok_or(Error::Corrupt)?;
                    model::parse_format(context, &raw)?;
                    if model::guarded_format(&raw) != generation.is_some() {
                        return Err(Error::Corrupt);
                    }
                    done(tx, generation)
                },
            )
        },
    )
}

pub(super) fn check_generation<T: 'static>(
    tx: &Rc<Transaction<T>>,
    context: Context,
    expected: Option<DeliveryGeneration>,
    writing: bool,
    done: impl FnOnce(&Rc<Transaction<T>>) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    read_generation(tx, context, move |tx, observed| {
        if observed != expected || (writing && observed.is_some_and(|g| g.paused)) {
            return Err(Error::Stale);
        }
        done(tx)
    })
}

/// One page, pending application/control ciphertext, and bounded metadata.
pub const MAX_DELIVERY_BYTES: usize = 5 * 1024 * 1024;
/// One retained relay-delivered bootstrap or deferred item: a canonical relay
/// item frame, bounded by the largest stored artifact plus its framing.
pub const MAX_RETAINED_BYTES: usize = vhalla_private_kernel::MAX_STORED_RECORD_BYTES + 128;

/// One atomic delivery publication: the exact image compare-and-swap plus at
/// most one exact retained item added and one discarded in the same
/// IndexedDB transaction. Retained items are never repaired or enumerated
/// without the image index that names them.
#[derive(Clone, Copy, Default)]
pub struct DeliveryWrite<'a> {
    /// Exact previously observed image, or None only for absent-image creation.
    pub expected: Option<&'a [u8]>,
    /// Complete next image.
    pub next: &'a [u8],
    /// Mailbox position and exact bytes of one bootstrap or deferred item to retain.
    pub retain: Option<(u64, &'a [u8])>,
    /// Mailbox position of one resolved deferred or explicitly discarded bootstrap item.
    pub discard: Option<u64>,
}

/// A full-context delivery image sharing the selected profile database.
pub struct IndexedDelivery {
    inner: IndexedStorage,
    context: Context,
    generation: Option<DeliveryGeneration>,
    key: String,
    prefix: String,
}
impl IndexedDelivery {
    /// Open only an existing profile database. Creation of a delivery image is
    /// a separate exact absent-image compare-and-swap, never inferred by open.
    pub async fn open(namespace: Namespace, context: Context) -> Result<Self, Error> {
        let prefix = crate::private_rooms::prefix(context);
        let inner = IndexedStorage::open_existing(namespace).await?;
        let generation = transaction(&inner.database, false, move |tx| {
            read_generation(tx, context, |tx, generation| {
                *tx.result.borrow_mut() = Some(Ok(generation));
                Ok(())
            })
        })
        .await?;
        Ok(Self {
            inner,
            context,
            generation,
            key: Self::image_key(&prefix, generation.map_or(0, |g| g.generation)),
            prefix,
        })
    }
    /// Current durable selector; None is the unchanged legacy generation zero.
    pub fn generation(&self) -> Option<DeliveryGeneration> {
        self.generation
    }
    fn image_key(prefix: &str, generation: u64) -> String {
        if generation == 0 {
            format!("{prefix}delivery-v1")
        } else {
            format!("{prefix}delivery-generations-v1/{generation:02}/image")
        }
    }
    fn retained_key(&self, position: u64) -> String {
        format!("{}/retained/{position:020}", self.key)
    }
    /// Read one bounded image. Missing state is reported, never repaired.
    pub async fn load(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.read(self.key.clone(), MAX_DELIVERY_BYTES).await
    }
    /// Read one retained item by its exact mailbox position. Absence
    /// is reported; the caller compares the bytes against its image index.
    pub async fn load_retained(&mut self, position: u64) -> Result<Option<Vec<u8>>, Error> {
        self.read(self.retained_key(position), MAX_RETAINED_BYTES)
            .await
    }
    async fn read(&mut self, key: String, maximum: usize) -> Result<Option<Vec<u8>>, Error> {
        self.inner.access.borrow().ready()?;
        let context = self.context;
        let generation = self.generation;
        let result = transaction(&self.inner.database, false, move |tx| {
            check_generation(tx, context, generation, false, move |tx| {
                tx.read(&key.into(), move |tx, value| {
                    *tx.result.borrow_mut() = Some(bounded(value, maximum));
                    Ok(())
                })
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
    /// Read the exact private receipt retained by this generation's pause.
    pub async fn pause_receipt(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let selected = self.generation.filter(|g| g.paused).ok_or(Error::Stale)?;
        self.read(self.receipt_key(selected.generation), 1024).await
    }
    fn receipt_key(&self, generation: u64) -> String {
        format!(
            "{}delivery-generations-v1/{generation:02}/pause",
            self.prefix
        )
    }
    fn valid_image(raw: &[u8]) -> bool {
        !raw.is_empty() && raw.len() <= MAX_DELIVERY_BYTES
    }
    fn completed(&mut self, result: Result<(), Error>) -> Result<(), Error> {
        match result {
            Ok(()) => self.inner.access.borrow_mut().completed(),
            Err(e) => {
                *self.inner.access.borrow_mut() = Access::NeedsReopen;
                Err(e)
            }
        }
    }
    /// Atomically pause delivery and kernel mutation only over the exact
    /// authenticated kernel image and complete drained delivery image. The
    /// private FORMAT upgrade makes old applications reject further writes.
    /// Neither kernel bytes nor historical records are rewritten.
    pub async fn pause(
        &mut self,
        expected: &[u8],
        next: &[u8],
        kernel: &Image,
        selected: DeliveryGeneration,
        receipt: &[u8],
    ) -> Result<(), Error> {
        selected.validate()?;
        if !selected.paused
            || selected.generation != self.generation.map_or(0, |g| g.generation)
            || self.generation.is_some_and(|g| {
                g.paused || g.binding != selected.binding || g.namespace != selected.namespace
            })
            || !Self::valid_image(expected)
            || !Self::valid_image(next)
            || receipt.is_empty()
            || receipt.len() > 1024
        {
            return Err(Error::Bounds);
        }
        self.inner.access.borrow_mut().begin()?;
        let context = self.context;
        let generation = self.generation;
        let key = self.key.clone();
        let receipt_key = self.receipt_key(selected.generation);
        let expected = expected.to_vec();
        let next = next.to_vec();
        let kernel = kernel.clone();
        let receipt = receipt.to_vec();
        let selector = selected.encode()?;
        let result = transaction(&self.inner.database, true, move |tx| {
            check_generation(tx, context, generation, true, move |tx| {
                tx.read(&key.clone().into(), move |tx, observed| {
                    if bounded(observed, MAX_DELIVERY_BYTES)?.as_deref() != Some(&expected) {
                        return Err(Error::Stale);
                    }
                    let format_key = format!("{}format", model::prefix(context));
                    tx.read(&format_key.clone().into(), move |tx, value| {
                        let raw = bounded(value, model::FORMAT_BYTES)?.ok_or(Error::Corrupt)?;
                        let limits = model::parse_format(context, &raw)?;
                        tx.read(
                            &format!("{}state", model::prefix(context)).into(),
                            move |tx, value| {
                                let raw = bounded(value, MAX_IMAGE_BYTES + model::STATE_OVERHEAD)?
                                    .ok_or(Error::Corrupt)?;
                                if model::State::decode(context, limits, &raw)?.image != kernel {
                                    return Err(Error::Stale);
                                }
                                tx.put(
                                    &format_key,
                                    &model::guarded_format_frame(context, limits)?,
                                )?;
                                tx.add(&receipt_key, &receipt)?;
                                tx.put(&key, &next)?;
                                tx.put(&model::delivery_selector_key(context), &selector)?;
                                *tx.result.borrow_mut() = Some(Ok(()));
                                Ok(())
                            },
                        )
                    })
                })
            })
        })
        .await;
        self.completed(result)?;
        self.generation = Some(selected);
        Ok(())
    }
    /// Record the exact reviewed successor intent while leaving all ordinary
    /// mutations paused. This never changes the selected generation or receipt.
    pub async fn publish_paused(&mut self, expected: &[u8], next: &[u8]) -> Result<(), Error> {
        let generation = self.generation.filter(|g| g.paused).ok_or(Error::Stale)?;
        if !Self::valid_image(expected) || !Self::valid_image(next) {
            return Err(Error::Bounds);
        }
        self.inner.access.borrow_mut().begin()?;
        let context = self.context;
        let key = self.key.clone();
        let expected = expected.to_vec();
        let next = next.to_vec();
        let result = transaction(&self.inner.database, true, move |tx| {
            check_generation(tx, context, Some(generation), false, move |tx| {
                tx.read(&key.clone().into(), move |tx, observed| {
                    if bounded(observed, MAX_DELIVERY_BYTES)?.as_deref() != Some(&expected) {
                        return Err(Error::Stale);
                    }
                    tx.put(&key, &next)?;
                    *tx.result.borrow_mut() = Some(Ok(()));
                    Ok(())
                })
            })
        })
        .await;
        self.completed(result)
    }
    /// Publish an immutable predecessor archive, fresh successor image and
    /// active selector in one transaction. Old retained keys remain untouched;
    /// no position can alias a predecessor ciphertext after the selection.
    pub async fn select_successor(
        &mut self,
        expected: &[u8],
        next: &[u8],
        selected: DeliveryGeneration,
    ) -> Result<(), Error> {
        let previous = self.generation.filter(|g| g.paused).ok_or(Error::Stale)?;
        selected.validate()?;
        if selected.paused
            || selected.generation != previous.generation + 1
            || selected.transition != previous.transition
            || selected.namespace == previous.namespace
            || selected.binding == previous.binding
            || !Self::valid_image(expected)
            || !Self::valid_image(next)
        {
            return Err(Error::Bounds);
        }
        self.inner.access.borrow_mut().begin()?;
        let context = self.context;
        let key = self.key.clone();
        let next_key = Self::image_key(&self.prefix, selected.generation);
        let published_key = next_key.clone();
        let archive = format!(
            "{}delivery-generations-v1/{:02}/archive",
            self.prefix, previous.generation
        );
        let expected = expected.to_vec();
        let next = next.to_vec();
        let selector = selected.encode()?;
        let result = transaction(&self.inner.database, true, move |tx| {
            check_generation(tx, context, Some(previous), false, move |tx| {
                tx.read(&key.clone().into(), move |tx, observed| {
                    if bounded(observed, MAX_DELIVERY_BYTES)?.as_deref() != Some(&expected) {
                        return Err(Error::Stale);
                    }
                    tx.add(&archive, &expected)?;
                    tx.add(&next_key, &next)?;
                    tx.put(&model::delivery_selector_key(context), &selector)?;
                    *tx.result.borrow_mut() = Some(Ok(()));
                    Ok(())
                })
            })
        })
        .await;
        self.completed(result)?;
        self.generation = Some(selected);
        self.key = published_key;
        Ok(())
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
        let context = self.context;
        let generation = self.generation;
        let result = transaction(&self.inner.database, true, move |tx| {
            check_generation(tx, context, generation, true, move |tx| {
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
