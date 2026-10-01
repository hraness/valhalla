//! Bounded metadata for completed local operations, distinct from remote frames.

use crate::{codec::*, *};
use sha2::{Digest as _, Sha256};

/// Exact kind of a completed local operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    /// One public text event was committed locally.
    Event,
    /// One owner policy was committed locally.
    Policy,
}

/// Authenticated immutable local completion metadata, without message content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationEntry {
    /// Local journal position of the completion, not a room-wide sequence.
    pub cursor: u64,
    /// Exact caller-selected local operation.
    pub operation: [u8; 16],
    /// Completed event or owner-policy operation.
    pub kind: OperationKind,
    /// SHA-256 of the entire exact signed frame, including its signature.
    pub frame_hash: [u8; 32],
}

/// One bounded local scan. Entries prove neither admission nor remote delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationPage {
    /// Fixed local journal tip observed for this call.
    pub tip: u64,
    /// Continue from this cursor, even when the filtered page was empty.
    pub next: Option<u64>,
    /// Completed local operations in ascending local cursor order.
    pub operations: Vec<OperationEntry>,
}

impl RoomSession {
    /// Inspect at most 128 local records and return at most 32 completions.
    /// Pending reservations remain in [`Status`]; author-key equality never
    /// turns a remotely observed signature into a locally queued operation.
    pub fn operations(&mut self, after: u64, limit: usize) -> Result<OperationPage> {
        self.ready()?;
        if limit == 0 || limit > vhalla_direct_store::MAX_PAGE_RECORDS {
            return Err(Error::Bounds);
        }
        let result = self.operations_inner(after, limit);
        if result.as_ref().is_err_and(|error| *error != Error::Bounds) {
            self.poisoned = true;
        }
        result
    }

    fn operations_inner(&mut self, after: u64, limit: usize) -> Result<OperationPage> {
        if self.store.load()?.as_deref() != Some(self.image_bytes.as_slice()) {
            return Err(Error::Corrupt);
        }
        let tip = self.store.accounting()?.tip;
        if after > tip {
            return Err(Error::Bounds);
        }
        let mut cursor = after;
        let mut scanned = 0;
        let mut operations = Vec::new();
        while cursor < tip && scanned < MAX_FILTER_SCAN && operations.len() < limit {
            let page = self.store.page(
                cursor,
                (MAX_FILTER_SCAN - scanned).min(vhalla_direct_store::MAX_PAGE_RECORDS),
            )?;
            if page.tip != tip || page.records.is_empty() {
                return Err(Error::Corrupt);
            }
            for entry in page.records {
                cursor = entry.cursor;
                scanned += 1;
                if entry.key[0] == COMPLETION {
                    if entry.data.len() != 49 {
                        return Err(Error::Corrupt);
                    }
                    let operation = array(&entry.data[1..17])?;
                    let reserved = self.reservation(operation)?.ok_or(Error::Corrupt)?;
                    if entry.key != operation_key(COMPLETION, operation)
                        || entry.data[0] != reserved.kind
                    {
                        return Err(Error::Corrupt);
                    }
                    let bytes = self.completed_bytes(&reserved)?.ok_or(Error::Corrupt)?;
                    let (kind, id) = match reserved.kind {
                        EVENT => (
                            OperationKind::Event,
                            *self.event_raw(&bytes)?.id().as_bytes(),
                        ),
                        POLICY => (
                            OperationKind::Policy,
                            *self.policy_raw(&bytes)?.id().as_bytes(),
                        ),
                        _ => return Err(Error::Corrupt),
                    };
                    if entry.data[17..] != id {
                        return Err(Error::Corrupt);
                    }
                    operations.push(OperationEntry {
                        cursor,
                        operation,
                        kind,
                        frame_hash: Sha256::digest(&bytes).into(),
                    });
                }
                if scanned == MAX_FILTER_SCAN || operations.len() == limit {
                    break;
                }
            }
        }
        self.ready()?;
        Ok(OperationPage {
            tip,
            next: (cursor < tip).then_some(cursor),
            operations,
        })
    }
}

#[cfg(test)]
#[path = "operations_tests.rs"]
mod tests;
