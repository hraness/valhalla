//! Transactional global archive reservations, before destination creation.
use super::{
    history::{bounded, transaction},
    IndexedStorage,
};
use crate::{private_archives as model, Access, Error, Namespace};
use vhalla_private_kernel::{recovery::ArchiveSource, Context};

/// Successful durable catalog reservation. Only this module can mint one.
pub struct ReservedArchive {
    pub(crate) namespace: Namespace,
    pub(crate) context: Context,
}

/// Reserve one authenticated snapshot under the origin-wide cap. Transactional
/// read/modify/write serializes concurrent workers. A canceled/uncertain result
/// must be retried with the same source; committed reservations are never erased.
pub async fn reserve(source: &ArchiveSource) -> Result<ReservedArchive, Error> {
    let namespace = model::source_namespace(source);
    let catalog = IndexedStorage::open(model::catalog_namespace()).await?;
    catalog.access.borrow_mut().begin()?;
    let result = transaction(&catalog.database, true, move |tx| {
        tx.read(&"archive-reservations".into(), move |tx, value| {
            let raw = bounded(value, model::MAX_CATALOG_BYTES)?;
            let next = model::reserve(raw.as_deref(), namespace)?;
            if raw.as_deref() != Some(next.as_slice()) {
                tx.put("archive-reservations", &next)?;
            }
            *tx.result.borrow_mut() = Some(Ok(namespace));
            Ok(())
        })
    })
    .await;
    match result {
        Ok(namespace) => {
            catalog.access.borrow_mut().completed()?;
            Ok(ReservedArchive {
                namespace,
                context: source.context(),
            })
        }
        Err(error) => {
            *catalog.access.borrow_mut() = Access::NeedsReopen;
            Err(error)
        }
    }
}
