//! Bounded synthetic fixture access, excluded unless continuity-qualification is enabled.
//! These deliberate corruption helpers are never linked by the product build.
use super::*;

/// Exact bounded physical bytes, including absent keys. No decoded-proof shortcut.
pub type RawImage = Vec<Option<Vec<u8>>>;

/// Capture the fixture's v1 author, history and one preexisting delivery receipt.
/// The caller must use a new synthetic namespace with at most 33 source events.
pub async fn source_image(
    outbox: &mut IndexedOutbox,
    scope: &SessionScope,
    events: u8,
) -> Result<RawImage, Error> {
    if events > 33 {
        return Err(Error::Bounds);
    }
    let a = crate::outbox::prefix(scope.author());
    let h = crate::history::prefix(scope.history());
    let d = crate::outbox::delivery::prefix(scope.author(), scope.peer());
    let mut keys = vec![
        format!("{a}head"),
        format!("{a}pending"),
        format!("{a}receipt-revision"),
        format!("{h}head"),
        format!("{h}bootstrap"),
        format!("{d}head"),
        format!("{d}receipt/0000000000000001"),
        format!("{d}receipt/0000000000000002"),
    ];
    keys.extend((1..=u64::from(events) + 1).map(|n| format!("{a}outbox/{n:016x}")));
    image(outbox, keys).await
}

/// Capture FORMAT, STATE and the bounded fixture's expected receipts plus one
/// unallocated successor. This does not enumerate arbitrary database history.
pub async fn receipt_image(
    outbox: &mut IndexedOutbox,
    scope: &SessionScope,
    records: u8,
) -> Result<RawImage, Error> {
    if records > 12 {
        return Err(Error::Bounds);
    }
    let p = codec::prefix(scope);
    let mut keys = vec![format!("{p}format"), format!("{p}state")];
    keys.extend((1..=u64::from(records) + 1).map(|n| format!("{p}receipt/{n:016x}")));
    image(outbox, keys).await
}

async fn image(outbox: &mut IndexedOutbox, keys: Vec<String>) -> Result<RawImage, Error> {
    outbox
        .read(move |tx| read_next(tx, keys.into_iter(), Vec::new()))
        .await
}
fn read_next(
    tx: &Rc<Transaction<RawImage>>,
    mut keys: std::vec::IntoIter<String>,
    mut values: RawImage,
) -> Result<(), Error> {
    let Some(key) = keys.next() else {
        *tx.result.borrow_mut() = Some(Ok(values));
        return Ok(());
    };
    tx.read(&key.into(), move |tx, raw| {
        values.push(bounded(raw, MAX_STATE_BYTES.max(MAX_RECORD_BYTES))?);
        read_next(tx, keys, values)
    })
}

/// Closed corruption locations for test-owned data only.
pub enum Damage {
    /// Replace the first actual signed outbox frame with different valid bytes.
    FirstSourceFrame(Vec<u8>),
    /// Remove the existing author head without recreating the author.
    MissingAuthorHead,
    /// Remove FORMAT while retaining the receipt STATE and immutable evidence.
    MissingReceiptFormat,
}
/// Inject one named synthetic fault in a real strict transaction. Never repairs
/// the corruption afterward; fixtures retain each damaged namespace as evidence.
pub async fn damage(
    outbox: &mut IndexedOutbox,
    scope: &SessionScope,
    damage: Damage,
) -> Result<(), PublishError> {
    let (key, value) = match damage {
        Damage::FirstSourceFrame(bytes) => {
            if bytes.len() > MAX_EVENT_BYTES {
                return Err(PublishError::Rejected(Error::Bounds));
            }
            (
                format!(
                    "{}outbox/0000000000000001",
                    crate::outbox::prefix(scope.author())
                ),
                Some(bytes),
            )
        }
        Damage::MissingAuthorHead => (
            format!("{}head", crate::outbox::prefix(scope.author())),
            None,
        ),
        Damage::MissingReceiptFormat => (format!("{}format", codec::prefix(scope)), None),
    };
    outbox
        .write(move |tx| {
            if let Some(bytes) = value {
                tx.put(&key, &bytes)?;
            } else {
                tx.store
                    .delete(&key.into())
                    .map_err(super::super::super::storage)?;
            }
            *tx.result.borrow_mut() = Some(Ok(()));
            Ok(())
        })
        .await
}
