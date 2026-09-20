use super::*;
use crate::{
    model::FaultEvidence as StoredFault,
    packets::ControlPacket,
    protocol::{ControlFloor, SignedOwnerControl, VerifiedOwnerControl},
};

impl<S: Store> Kernel<S> {
    /// Compare a canonical signed owner claim with already-known history only.
    /// This also detects conflicting unsupported transition kinds. It never
    /// accepts a future floor, admits a device, or processes MLS ciphertext.
    pub async fn observe_owner_control(&mut self, raw: &[u8], now: u64) -> Result<Status> {
        let control = SignedOwnerControl::decode(raw)?.verify()?;
        let work = self.begin_live().await?;
        match self.reconcile_control(work, &control, now).await? {
            None => Ok(self.status),
            Some(_) => Err(Error::Missing),
        }
    }
    /// Read the first durable fork proof. It never clears quarantine or grants
    /// owner succession. Missing evidence means no locally retained proof only.
    pub async fn fork_evidence(&mut self) -> Result<Option<ForkEvidence>> {
        let work = self.begin().await?;
        let evidence = if let Some(fault) = &work.state.fault {
            let (accepted_proof, accepted_from_checkpoint) =
                self.accepted_proof(&work, fault.accepted).await?;
            Some(ForkEvidence {
                accepted: fault.accepted,
                conflicting: fault.conflicting.signed().clone(),
                accepted_proof,
                accepted_from_checkpoint,
            })
        } else {
            None
        };
        self.needs_reopen = false;
        Ok(evidence)
    }

    /// An observation whose quarantine write failed remains available in this
    /// latched custodian for explicit preservation/reconciliation. It is not a
    /// claim that the observation will survive losing this process.
    pub fn pending_fork_evidence(&self) -> Option<&ForkEvidence> {
        self.pending_fault.as_ref()
    }

    async fn control_at(&mut self, sequence: u64) -> Result<ControlPacket> {
        let raw = self
            .read_clear(RecordKey::Control(sequence))
            .await?
            .ok_or(Error::Missing)?;
        let packet = ControlPacket::decode(&raw)?;
        if packet.floor()?.sequence() != sequence
            || packet.control.claims().scope != self.context.scope
        {
            return Err(Error::Scope);
        }
        Ok(packet)
    }

    async fn accepted_proof(
        &mut self,
        work: &Working,
        floor: ControlFloor,
    ) -> Result<(Vec<u8>, bool)> {
        if floor == work.state.base {
            let checkpoint = work.state.checkpoint.as_ref().ok_or(Error::Missing)?;
            if floor.sequence() == 0 || checkpoint.claims().parent != floor {
                return Err(Error::Policy);
            }
            Ok((checkpoint.encode()?, true))
        } else {
            let packet = self.control_at(floor.sequence()).await?;
            if packet.floor()? != floor
                || packet.control.claims().owner_device != work.state.owner.claims().device
            {
                return Err(Error::Policy);
            }
            Ok((packet.control.signed().encode(), false))
        }
    }

    /// Export only this device's independently retained control suffix. The exact
    /// floor cursor prevents an accidental gap or a cursor from a different fork.
    pub async fn controls(&mut self, after: ControlFloor, limit: usize) -> Result<ControlPage> {
        if limit == 0 || limit > MAX_PAGE_RECORDS {
            return Err(Error::Bounds);
        }
        let work = self.begin().await?;
        let base = work.state.base;
        let head = work.state.floor;
        if after.sequence() < base.sequence() {
            return Err(Error::Missing);
        }
        if after.sequence() > head.sequence() {
            return Err(Error::Bounds);
        }
        let accepted = if after.sequence() == base.sequence() {
            base
        } else {
            self.control_at(after.sequence()).await?.floor()?
        };
        if accepted != after {
            return Err(Error::Conflict);
        }
        let mut cursor = after;
        let mut records = Vec::new();
        let mut total = 0usize;
        while cursor.sequence() < head.sequence() && records.len() < limit {
            let packet = self.control_at(cursor.next_sequence()?).await?;
            if packet.control.claims().owner_device != work.state.owner.claims().device
                || packet.control.claims().parent != cursor
            {
                return Err(Error::Policy);
            }
            let bytes = packet.encode()?;
            let size = total.checked_add(bytes.len()).ok_or(Error::Bounds)?;
            if size > MAX_PAGE_BYTES {
                break;
            }
            total = size;
            cursor = packet.floor()?;
            records.push(CommittedControl {
                floor: cursor,
                bytes,
            });
        }
        if cursor == after && cursor.sequence() < head.sequence() {
            return Err(Error::Bounds);
        }
        if cursor.sequence() == head.sequence() && cursor != head {
            return Err(Error::Conflict);
        }
        self.needs_reopen = false;
        Ok(ControlPage {
            base,
            head,
            next: (cursor != head).then_some(cursor),
            records,
        })
    }

    /// Classify only valid pinned-owner signatures at known local sequences.
    /// Unknown history and foreign signatures cannot manufacture a durable fault.
    pub(super) async fn reconcile_control(
        &mut self,
        mut work: Working,
        control: &VerifiedOwnerControl,
        now: u64,
    ) -> Result<Option<Working>> {
        let c = control.claims();
        if c.scope != self.context.scope || c.owner_device != work.state.owner.claims().device {
            return Err(Error::Policy);
        }
        if now < work.state.clock {
            return Err(Error::Time);
        }
        let sequence = c.sequence()?;
        if sequence > work.state.floor.sequence() {
            return Ok(Some(work));
        }
        if sequence < work.state.base.sequence() {
            return Err(Error::Missing);
        }
        let accepted = if sequence == work.state.base.sequence() {
            work.state.base
        } else {
            self.control_at(sequence).await?.floor()?
        };
        if accepted.id() == Some(control.id()) {
            self.needs_reopen = false;
            return Ok(None);
        }
        let (accepted_proof, accepted_from_checkpoint) =
            self.accepted_proof(&work, accepted).await?;
        self.pending_fault = Some(ForkEvidence {
            accepted,
            conflicting: control.signed().clone(),
            accepted_proof,
            accepted_from_checkpoint,
        });
        work.state.fault = Some(StoredFault {
            accepted,
            conflicting: control.clone(),
        });
        work.state.clock = now;
        self.publish(work, Vec::new()).await?;
        self.pending_fault = None;
        self.needs_reopen = false;
        Err(Error::Quarantined)
    }
}
