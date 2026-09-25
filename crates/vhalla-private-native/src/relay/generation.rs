//! Explicit mailbox format migration and permanent generation fences.
use super::*;
use sha2::{Digest, Sha256};

/// Durable retention boundary selected by the trusted operator. Every field is
/// opaque relay metadata; this record contains no room or member identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationFence {
    transition: [u8; 32],
    predecessor: RelayNamespace,
    successor: RelayNamespace,
    head: u64,
    items: [u8; 32],
}
impl GenerationFence {
    /// Random operator-selected transition identity.
    pub fn transition(&self) -> [u8; 32] {
        self.transition
    }
    /// Exact fenced namespace.
    pub fn predecessor(&self) -> RelayNamespace {
        self.predecessor
    }
    /// Exact independently selected successor namespace.
    pub fn successor(&self) -> RelayNamespace {
        self.successor
    }
    /// Fixed last retained mailbox position.
    pub fn head(&self) -> u64 {
        self.head
    }
    /// Commitment to ordered positions and their exact canonical item digests.
    pub fn items_commitment(&self) -> [u8; 32] {
        self.items
    }
    /// Commitment to the complete fence, suitable for a private host intent.
    pub fn commitment(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private/relay-generation-fence/v1\0");
        hash.update(self.transition);
        hash.update(self.predecessor.as_bytes());
        hash.update(self.successor.as_bytes());
        hash.update(self.head.to_be_bytes());
        hash.update(self.items);
        hash.finalize().into()
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum MaintenanceFault {
    BeforeCommit,
    AfterCommit,
}

impl FileStore {
    pub(super) fn live(&self) -> Result<()> {
        if self.needs_reopen {
            Err(Error::Storage)
        } else {
            Ok(())
        }
    }

    /// A storage failure or uncertain maintenance publication requires closing
    /// this handle and reopening the exact original mailbox.
    pub fn needs_reopen(&self) -> bool {
        self.needs_reopen
    }

    /// Return the current terminal head and ordered ciphertext commitment while
    /// holding mailbox custody. This read neither migrates nor fences the store.
    ///
    /// The commitment is SHA-256 over the exact bytes
    /// `b"vhalla/private/relay-generation-items/v1\0"`, the 32-byte namespace,
    /// each contiguous position's big-endian `u64` followed by its canonical
    /// 32-byte item digest, then the terminal head as a big-endian `u64` (zero
    /// for an empty mailbox). Invalid items and gaps refuse. Controllers may
    /// compute the same value from complete, validated PAGE records; it attests
    /// only retention and never proves that a private controller has drained.
    pub fn retained_head(&self) -> Result<(u64, [u8; 32])> {
        self.live()?;
        self.item_commitment()
    }

    /// Explicitly migrate format 2 to 3 under lifetime mailbox custody. No item,
    /// namespace, quota or TLS charge changes. Old binaries reject format 3.
    /// An interrupted SQLite transaction reopens wholly before or after upgrade.
    pub fn upgrade_generation_format(&mut self) -> Result<()> {
        self.live()?;
        if self.format == 3 {
            self.generation_fence()?;
            return Ok(());
        }
        self.validate()?;
        self.maintenance(|store| {
            store.conn.execute_batch(
                "CREATE TABLE meta_v3 (id INTEGER PRIMARY KEY CHECK(id=1), format INTEGER NOT NULL CHECK(format=3), namespace BLOB NOT NULL, max_items INTEGER NOT NULL, max_bytes INTEGER NOT NULL);
                 INSERT INTO meta_v3 SELECT id,3,namespace,max_items,max_bytes FROM meta;
                 DROP TABLE meta;
                 ALTER TABLE meta_v3 RENAME TO meta;
                 CREATE TABLE generation_state (id INTEGER PRIMARY KEY CHECK(id=1), transition BLOB, successor BLOB, head INTEGER, items BLOB,
                   CHECK((transition IS NULL AND successor IS NULL AND head IS NULL AND items IS NULL) OR
                         (transition IS NOT NULL AND length(transition)=32 AND transition!=zeroblob(32) AND
                          successor IS NOT NULL AND length(successor)=32 AND successor!=zeroblob(32) AND
                          head IS NOT NULL AND head>=0 AND items IS NOT NULL AND length(items)=32)));
                 INSERT INTO generation_state VALUES(1,NULL,NULL,NULL,NULL);"
            ).map_err(|_| Error::Storage)
        })?;
        self.format = 3;
        let result = self.validate();
        if result.is_err() {
            self.needs_reopen = true;
        }
        result
    }

    /// Permanently refuse new items only if the agreed terminal head still
    /// matches. Controllers must separately prove their private drain and pause.
    /// Exact repetition reconciles the original fence; substitution conflicts.
    pub fn fence(
        &mut self,
        transition: [u8; 32],
        successor: RelayNamespace,
        expected_head: u64,
    ) -> Result<GenerationFence> {
        self.live()?;
        if self.format != 3
            || transition == [0; 32]
            || successor == self.namespace
            || expected_head > MAX_RELAY_ITEMS as u64
        {
            return Err(Error::Bounds);
        }
        if let Some(prior) = self.generation_fence()? {
            return if prior.transition == transition
                && prior.successor == successor
                && prior.head == expected_head
            {
                Ok(prior)
            } else {
                Err(Error::Conflict)
            };
        }
        self.maintenance(|store| {
            let (head, items) = store.item_commitment()?;
            if head != expected_head { return Err(Error::Conflict); }
            let fence = GenerationFence { transition, predecessor: store.namespace, successor, head, items };
            let changed = store.conn.execute(
                "UPDATE generation_state SET transition=?1,successor=?2,head=?3,items=?4 WHERE id=1 AND transition IS NULL",
                params![transition.as_slice(), successor.as_bytes().as_slice(), head as i64, items.as_slice()],
            ).map_err(|_| Error::Storage)?;
            if changed != 1 { return Err(Error::Storage); }
            Ok(fence)
        })
    }

    /// Read and check the complete retained fence against actual immutable items.
    pub fn generation_fence(&self) -> Result<Option<GenerationFence>> {
        self.live()?;
        if self.format == 2 {
            return Ok(None);
        }
        type Row = (
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<i64>,
            Option<Vec<u8>>,
        );
        let (transition, successor, head, items): Row = self
            .conn
            .query_row(
                "SELECT transition,successor,head,items FROM generation_state WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|_| Error::Storage)?;
        let (transition, successor, head, items) = match (transition, successor, head, items) {
            (None, None, None, None) => return Ok(None),
            (Some(transition), Some(successor), Some(head), Some(items)) => {
                (transition, successor, head, items)
            }
            _ => return Err(Error::Storage),
        };
        let transition: [u8; 32] = transition.try_into().map_err(|_| Error::Storage)?;
        let successor =
            RelayNamespace::from_bytes(successor.try_into().map_err(|_| Error::Storage)?)
                .map_err(|_| Error::Storage)?;
        let head = u64::try_from(head).map_err(|_| Error::Storage)?;
        let items: [u8; 32] = items.try_into().map_err(|_| Error::Storage)?;
        if transition == [0; 32]
            || successor == self.namespace
            || self.item_commitment()? != (head, items)
        {
            return Err(Error::Storage);
        }
        Ok(Some(GenerationFence {
            transition,
            predecessor: self.namespace,
            successor,
            head,
            items,
        }))
    }

    pub(super) fn fenced(&self) -> Result<bool> {
        self.live()?;
        if self.format == 2 {
            return Ok(false);
        }
        self.conn
            .query_row(
                "SELECT transition IS NOT NULL FROM generation_state WHERE id=1",
                [],
                |r| r.get(0),
            )
            .map_err(|_| Error::Storage)
    }

    fn item_commitment(&self) -> Result<(u64, [u8; 32])> {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private/relay-generation-items/v1\0");
        hash.update(self.namespace.as_bytes());
        let mut statement = self.conn.prepare("SELECT position,sequence,operation,kind,payload,digest FROM items ORDER BY position")
            .map_err(|_| Error::Storage)?;
        let rows = statement
            .query_map([], |row| decode_row(row, self.namespace))
            .map_err(|_| Error::Storage)?;
        let mut head = 0;
        for row in rows {
            let row = row.map_err(|_| Error::Storage)?;
            if row.position != head + 1 || row.position > MAX_RELAY_ITEMS as u64 {
                return Err(Error::Storage);
            }
            head = row.position;
            hash.update(head.to_be_bytes());
            hash.update(row.item.digest());
        }
        hash.update(head.to_be_bytes());
        Ok((head, hash.finalize().into()))
    }

    /// All maintenance uses SQLite's rollback transaction and one post-commit
    /// barrier. Even a known rollback after storage failure requires reopen;
    /// callers never continue through a possibly damaged maintenance handle.
    pub(super) fn maintenance<T>(
        &mut self,
        operation: impl FnOnce(&Self) -> Result<T>,
    ) -> Result<T> {
        self.live()?;
        #[cfg(test)]
        let fault = self.maintenance_fault.take();
        if self.conn.execute_batch("BEGIN IMMEDIATE").is_err() {
            self.needs_reopen = true;
            return Err(Error::Storage);
        }
        let outcome = operation(self);
        #[cfg(test)]
        let outcome = if fault == Some(MaintenanceFault::BeforeCommit) {
            Err(Error::Storage)
        } else {
            outcome
        };
        let value = match outcome {
            Ok(value) => value,
            Err(error) => {
                if self.conn.execute_batch("ROLLBACK").is_err() || error == Error::Storage {
                    self.needs_reopen = true;
                    return Err(Error::Storage);
                }
                return Err(error);
            }
        };
        if self.conn.execute_batch("COMMIT").is_err() {
            let _ = self.conn.execute_batch("ROLLBACK");
            self.needs_reopen = true;
            return Err(Error::Storage);
        }
        #[cfg(test)]
        if fault == Some(MaintenanceFault::AfterCommit) {
            self.needs_reopen = true;
            return Err(Error::Storage);
        }
        if self.sync().is_err() {
            self.needs_reopen = true;
            return Err(Error::Storage);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
