//! Receipt-only continuity prefix inside the SAME author/history database.
//! Publication rechecks actual source and exact metadata in one strict transaction.
#[cfg(feature = "continuity-qualification")]
pub mod qualification;

use super::super::history::{bounded, Transaction};
use super::IndexedOutbox;
use crate::outbox::continuity::{
    codec, ContinuityEvidenceRecord, Limits, Publication, RecordRef, SessionScope, Snapshot,
    SourceCheck, MAX_RECORD_BYTES, MAX_STATE_BYTES,
};
use crate::{
    history::HistoryHead,
    outbox::{AuthorHead, AUTHOR_HEAD_BYTES},
    Error, PublishError,
};
use std::{cell::RefCell, rc::Rc};
use vhalla_room_activity::MAX_EVENT_BYTES;
use wasm_bindgen::JsValue;
use web_sys::IdbKeyRange;

impl IndexedOutbox {
    /// Explicit new receipt session only. Requires an existing author/history
    /// and an entirely unused versioned prefix; never initializes an author or
    /// treats a lost receipt session as fresh. No signing/network side effects.
    pub async fn create_continuity(
        &mut self,
        scope: SessionScope,
        limits: Limits,
    ) -> Result<Snapshot, PublishError> {
        let snapshot = Snapshot::fresh(scope.clone(), limits).map_err(PublishError::Rejected)?;
        let returned = snapshot.clone();
        self.write(move |tx| {
            let start = codec::prefix(&scope);
            let range = IdbKeyRange::bound(
                &JsValue::from_str(&start),
                &JsValue::from_str(&format!("{start}\u{ffff}")),
            )
            .map_err(super::super::storage)?;
            let request = tx.store.get_key(&range).map_err(super::super::storage)?;
            tx.handle(request, move |tx, value| {
                if !value.is_undefined() {
                    return Err(Error::Stale);
                }
                read_source(tx, scope, Vec::new(), move |tx| {
                    tx.add(&format!("{start}format"), &snapshot.format())?;
                    tx.add(&format!("{start}state"), &snapshot.encode())?;
                    *tx.result.borrow_mut() = Some(Ok(()));
                    Ok(())
                })
            });
            Ok(())
        })
        .await?;
        Ok(returned)
    }
    /// Read and reauthenticate an existing exact receipt prefix and bounded
    /// referenced local source. Missing prior state refuses; reads never repair.
    pub async fn load_continuity(
        &mut self,
        scope: SessionScope,
        limits: Limits,
    ) -> Result<Snapshot, Error> {
        self.read(move |tx| {
            read_session(tx, scope, limits, |tx, snapshot| {
                *tx.result.borrow_mut() = Some(Ok(snapshot));
                Ok(())
            })
        })
        .await
    }
    /// Atomically CAS the receipt state, compare every actual local outbox frame,
    /// add the original signed response, and publish the new head. Access latches
    /// before await; abort/cancellation/uncertainty requires explicit reopen.
    pub async fn publish_continuity(
        &mut self,
        change: Publication,
    ) -> Result<Snapshot, PublishError> {
        let scope = change.before.scope().clone();
        let limits = change.before.limits();
        let answer = Rc::new(RefCell::new(None));
        let result = answer.clone();
        self.write(move |tx| {
            read_session(tx, scope.clone(), limits, move |tx, observed| {
                if observed != change.before {
                    return Err(Error::Stale);
                }
                let checks = change.sources.clone();
                read_source(tx, scope.clone(), checks, move |tx| {
                    let start = codec::prefix(&scope);
                    if let Some(record) = change.record() {
                        tx.add(
                            &format!("{start}receipt/{:016x}", record.reference().index()),
                            &record.encode(),
                        )?;
                    }
                    tx.put(&format!("{start}state"), &change.after.encode())?;
                    *result.borrow_mut() = Some(change.after);
                    *tx.result.borrow_mut() = Some(Ok(()));
                    Ok(())
                })
            })
        })
        .await?;
        let result = answer.borrow_mut().take();
        result.ok_or_else(|| {
            *self.inner.access.borrow_mut() = crate::Access::NeedsReopen;
            PublishError::ReopenRequired(Error::Corrupt)
        })
    }
    /// Direct indexed original response. None means beyond the retained record
    /// count; missing published records are corruption, never absent evidence.
    pub async fn continuity_record(
        &mut self,
        scope: SessionScope,
        limits: Limits,
        index: u64,
    ) -> Result<Option<ContinuityEvidenceRecord>, Error> {
        if index == 0 {
            return Err(Error::Bounds);
        }
        self.read(move |tx| {
            read_session(tx, scope.clone(), limits, move |tx, snapshot| {
                if index > snapshot.record_count() {
                    *tx.result.borrow_mut() = Some(Ok(None));
                    return Ok(());
                }
                read_record(tx, scope.clone(), index, move |tx, record| {
                    let checks = record.sources()?;
                    read_source(tx, scope, checks, move |tx| {
                        *tx.result.borrow_mut() = Some(Ok(Some(record)));
                        Ok(())
                    })
                })
            })
        })
        .await
    }
}
fn read_session<T: 'static>(
    tx: &Rc<Transaction<T>>,
    scope: SessionScope,
    limits: Limits,
    callback: impl FnOnce(&Rc<Transaction<T>>, Snapshot) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    limits.check()?;
    let start = codec::prefix(&scope);
    tx.read(
        &JsValue::from_str(&format!("{start}format")),
        move |tx, value| {
            let raw = bounded(value, codec::MAX_FORMAT)?.ok_or(Error::RecoveryRequired)?;
            codec::check_format(&raw, &scope, limits)?;
            tx.read(
                &JsValue::from_str(&format!("{start}state")),
                move |tx, value| {
                    let raw = bounded(value, MAX_STATE_BYTES)?.ok_or(Error::Corrupt)?;
                    let snapshot = Snapshot::decode(&raw)?;
                    if snapshot.scope() != &scope || snapshot.limits() != limits {
                        return Err(Error::WrongScope);
                    }
                    let refs = snapshot.references();
                    read_references(tx, scope.clone(), refs, Vec::new(), move |tx, records| {
                        let checks = snapshot.validate_records(|index| {
                            records
                                .iter()
                                .find(|r| r.reference().index() == index)
                                .cloned()
                                .ok_or(Error::Corrupt)
                        })?;
                        read_source(tx, scope, checks, move |tx| callback(tx, snapshot))
                    })
                },
            )
        },
    )
}
fn read_references<T: 'static>(
    tx: &Rc<Transaction<T>>,
    scope: SessionScope,
    mut refs: Vec<RecordRef>,
    mut records: Vec<ContinuityEvidenceRecord>,
    callback: impl FnOnce(&Rc<Transaction<T>>, Vec<ContinuityEvidenceRecord>) -> Result<(), Error>
        + 'static,
) -> Result<(), Error> {
    let Some(reference) = refs.pop() else {
        return callback(tx, records);
    };
    read_record(tx, scope.clone(), reference.index(), move |tx, record| {
        if record.reference() != reference {
            return Err(Error::Corrupt);
        }
        records.push(record);
        read_references(tx, scope, refs, records, callback)
    })
}
fn read_record<T: 'static>(
    tx: &Rc<Transaction<T>>,
    scope: SessionScope,
    index: u64,
    callback: impl FnOnce(&Rc<Transaction<T>>, ContinuityEvidenceRecord) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    tx.read(
        &JsValue::from_str(&format!("{}receipt/{index:016x}", codec::prefix(&scope))),
        move |tx, value| {
            let raw = bounded(value, MAX_RECORD_BYTES)?.ok_or(Error::Corrupt)?;
            let record = ContinuityEvidenceRecord::decode(&raw)?;
            if record.scope() != &scope || record.reference().index() != index {
                return Err(Error::WrongScope);
            }
            callback(tx, record)
        },
    )
}
fn read_source<T: 'static>(
    tx: &Rc<Transaction<T>>,
    scope: SessionScope,
    checks: Vec<SourceCheck>,
    callback: impl FnOnce(&Rc<Transaction<T>>) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    let start = crate::outbox::prefix(scope.author());
    tx.read(
        &JsValue::from_str(&format!("{start}head")),
        move |tx, value| {
            let raw = bounded(value, AUTHOR_HEAD_BYTES)?.ok_or(Error::RecoveryRequired)?;
            let head = AuthorHead::decode(&raw)?;
            if head.scope() != scope.author() {
                return Err(Error::WrongScope);
            }
            tx.read(
                &JsValue::from_str(&format!("{}head", crate::history::prefix(scope.history()))),
                move |tx, value| {
                    let raw = bounded(value, 248)?.ok_or(Error::RecoveryRequired)?;
                    if HistoryHead::decode(&raw)?.scope() != scope.history() {
                        return Err(Error::WrongScope);
                    }
                    read_source_next(tx, scope, head, checks, callback)
                },
            )
        },
    )
}
fn read_source_next<T: 'static>(
    tx: &Rc<Transaction<T>>,
    scope: SessionScope,
    head: AuthorHead,
    mut checks: Vec<SourceCheck>,
    callback: impl FnOnce(&Rc<Transaction<T>>) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    let Some(check) = checks.pop() else {
        return callback(tx);
    };
    let key = format!(
        "{}outbox/{:016x}",
        crate::outbox::prefix(scope.author()),
        check.position.sequence()
    );
    tx.read(&JsValue::from_str(&key), move |tx, value| {
        let raw = bounded(value, MAX_EVENT_BYTES)?.ok_or(Error::Corrupt)?;
        check.check(&scope, head, &raw)?;
        read_source_next(tx, scope, head, checks, callback)
    })
}
