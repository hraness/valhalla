//! Immutable per-peer local acceptance evidence. Outbox bytes are never removed.
use super::super::history::{bounded, Transaction};
use super::IndexedOutbox;
use crate::outbox::delivery::{
    advance, prefix, DeliveryHead, DeliveryRecord, DELIVERY_HEAD_BYTES, MAX_DELIVERY_RECORD_BYTES,
};
use crate::outbox::{AuthorHead, AuthorScope, AUTHOR_HEAD_BYTES};
use crate::{Access, Error, PublishError};
use std::{cell::Cell, rc::Rc};
use vhalla_public_protocol::activity::{ActivityRequest, ActivityResponseProof};
use vhalla_room_activity::{VerifiedEvent, MAX_EVENT_BYTES};
use wasm_bindgen::JsValue;
use web_sys::IdbKeyRange;

impl IndexedOutbox {
    /// Load this exact peer's contiguous author delivery floor, reauthenticating
    /// its retained proof and binding it to the complete signed local outbox event.
    /// None means no retained peer acknowledgment, never global non-delivery.
    pub async fn load_delivery(
        &mut self,
        scope: AuthorScope,
        peer: [u8; 32],
    ) -> Result<Option<DeliveryHead>, Error> {
        self.read(move |state| {
            read_state(state, scope, peer, |state, record| {
                *state.result.borrow_mut() = Some(Ok(record.map(|r| r.head())));
                Ok(())
            })
        })
        .await
    }

    /// Retain original request/proof/body and monotonically acknowledge one more
    /// contiguous local author event at one full peer. No outbox bytes are deleted.
    ///
    /// Independently verifies the peer proof before publication; the transaction
    /// rechecks the exact current peer floor and stored signed event bytes. Only
    /// completion permits success. An exact retry of the latest acknowledged event
    /// returns the original floor/proof without replacing its cursor or evidence.
    pub async fn record_delivery(
        &mut self,
        scope: AuthorScope,
        peer: [u8; 32],
        expected: Option<&DeliveryHead>,
        request: &ActivityRequest,
        proof: &ActivityResponseProof,
        receipt_bytes: &[u8],
    ) -> Result<DeliveryHead, PublishError> {
        let candidate = DeliveryRecord::new(scope, peer, request, proof, receipt_bytes)
            .map_err(PublishError::Rejected)?;
        if expected.is_some_and(|h| h.scope() != scope || h.peer() != peer) {
            return Err(PublishError::Rejected(Error::WrongScope));
        }
        let expected = expected.copied();
        let answer = Rc::new(Cell::new(None));
        let committed = answer.clone();
        self.write(move |state| {
            read_state(state, scope, peer, move |state, prior| {
                let observed = prior.map(|r| r.head());
                read_local_event(state, candidate, move |state, candidate, event| {
                    if advance(expected.as_ref(), observed.as_ref(), &candidate, &event)? {
                        let start = prefix(scope, peer);
                        state.add(
                            &format!("{start}receipt/{:016x}", candidate.head().sequence()),
                            candidate.as_bytes(),
                        )?;
                        state.put(&format!("{start}head"), &candidate.head().encode())?;
                        let revision_key =
                            format!("{}receipt-revision", crate::outbox::prefix(scope));
                        state.read(&JsValue::from_str(&revision_key), move |state, value| {
                            let prior = bounded(value, 8)?
                                .map(|v| {
                                    v.try_into()
                                        .map(u64::from_be_bytes)
                                        .map_err(|_| Error::Corrupt)
                                })
                                .transpose()?
                                .unwrap_or(0);
                            let next_revision = prior.checked_add(1).ok_or(Error::Bounds)?;
                            state.put(&revision_key, &next_revision.to_be_bytes())?;
                            committed.set(Some(candidate.head()));
                            *state.result.borrow_mut() = Some(Ok(()));
                            Ok(())
                        })
                    } else {
                        committed.set(Some(observed.ok_or(Error::Corrupt)?));
                        *state.result.borrow_mut() = Some(Ok(()));
                        Ok(())
                    }
                })
            })
        })
        .await?;
        match answer.get() {
            Some(head) => Ok(head),
            None => {
                *self.inner.access.borrow_mut() = Access::NeedsReopen;
                Err(PublishError::ReopenRequired(Error::Corrupt))
            }
        }
    }

    /// Read one retained original proof for offline display, never beyond this
    /// peer's observed author floor. Missing published receipts are corruption.
    /// This verifies local retained evidence, not the peer's present availability.
    pub async fn load_delivery_receipt(
        &mut self,
        scope: AuthorScope,
        peer: [u8; 32],
        sequence: u64,
    ) -> Result<Option<DeliveryRecord>, Error> {
        if sequence == 0 {
            return Err(Error::Bounds);
        }
        self.read(move |state| {
            read_state(state, scope, peer, move |state, latest| {
                let Some(latest) = latest else {
                    *state.result.borrow_mut() = Some(Ok(None));
                    return Ok(());
                };
                if sequence > latest.head().sequence() {
                    *state.result.borrow_mut() = Some(Ok(None));
                    return Ok(());
                }
                if sequence == latest.head().sequence() {
                    *state.result.borrow_mut() = Some(Ok(Some(latest)));
                    return Ok(());
                }
                read_record(state, scope, peer, sequence, |state, record| {
                    *state.result.borrow_mut() = Some(Ok(Some(record)));
                    Ok(())
                })
            })
        })
        .await
    }
}

fn read_state<T: 'static>(
    state: &Rc<Transaction<T>>,
    scope: AuthorScope,
    peer: [u8; 32],
    callback: impl FnOnce(&Rc<Transaction<T>>, Option<DeliveryRecord>) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    let start = prefix(scope, peer);
    state.read(
        &JsValue::from_str(&format!("{start}head")),
        move |state, value| {
            let raw = bounded(value, DELIVERY_HEAD_BYTES)?;
            let Some(raw) = raw else {
                // A lost head with surviving receipts is partial state, not a fresh
                // peer cursor. Refuse resetting that namespace to sequence one.
                let range = IdbKeyRange::bound(
                    &JsValue::from_str(&start),
                    &JsValue::from_str(&format!("{start}\u{ffff}")),
                )
                .map_err(super::super::storage)?;
                let request = state.store.get_key(&range).map_err(super::super::storage)?;
                state.handle(request, move |state, value| {
                    if !value.is_undefined() {
                        return Err(Error::Corrupt);
                    }
                    callback(state, None)
                });
                return Ok(());
            };
            let head = DeliveryHead::decode(&raw)?;
            if head.scope() != scope || head.peer() != peer {
                return Err(Error::WrongScope);
            }
            read_record(state, scope, peer, head.sequence(), move |state, record| {
                if record.head() != head {
                    return Err(Error::Corrupt);
                }
                callback(state, Some(record))
            })
        },
    )
}

fn read_record<T: 'static>(
    state: &Rc<Transaction<T>>,
    scope: AuthorScope,
    peer: [u8; 32],
    sequence: u64,
    callback: impl FnOnce(&Rc<Transaction<T>>, DeliveryRecord) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    let key = format!("{}receipt/{sequence:016x}", prefix(scope, peer));
    state.read(&JsValue::from_str(&key), move |state, value| {
        let raw = bounded(value, MAX_DELIVERY_RECORD_BYTES)?.ok_or(Error::Corrupt)?;
        let record = DeliveryRecord::decode(&raw)?;
        if record.head().scope() != scope
            || record.head().peer() != peer
            || record.head().sequence() != sequence
        {
            return Err(Error::WrongScope);
        }
        read_local_event(state, record, move |state, record, _| {
            callback(state, record)
        })
    })
}

fn read_local_event<T: 'static>(
    state: &Rc<Transaction<T>>,
    record: DeliveryRecord,
    callback: impl FnOnce(&Rc<Transaction<T>>, DeliveryRecord, VerifiedEvent) -> Result<(), Error>
        + 'static,
) -> Result<(), Error> {
    let start = crate::outbox::prefix(record.head().scope());
    state.read(
        &JsValue::from_str(&format!("{start}head")),
        move |state, value| {
            let raw = bounded(value, AUTHOR_HEAD_BYTES)?.ok_or(Error::Corrupt)?;
            let head = AuthorHead::decode(&raw)?;
            if head.scope() != record.head().scope() || head.sequence() < record.head().sequence() {
                return Err(Error::Corrupt);
            }
            let key = format!("{start}outbox/{:016x}", record.head().sequence());
            state.read(&JsValue::from_str(&key), move |state, value| {
                let raw = bounded(value, MAX_EVENT_BYTES)?.ok_or(Error::Corrupt)?;
                let event = record.check_event(&raw)?;
                if event.claims().sequence == head.sequence() && event.id() != head.event_id() {
                    return Err(Error::Corrupt);
                }
                callback(state, record, event)
            })
        },
    )
}
