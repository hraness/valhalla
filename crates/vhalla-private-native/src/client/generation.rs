//! Private controller evidence for a drained mailbox transition.
//!
//! These are cooperating-owner custody records, not peer signatures or relay
//! authorization. They contain private context and must not enter public logs.

use super::{Error, Result};
use crate::relay::{delivery::LedgerSnapshot, RelayNamespace, MAX_RELAY_ITEMS};
use sha2::{Digest, Sha256};
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
    storage::StoreError,
    Context,
};

const MAGIC: &[u8; 9] = b"VHCDRAIN\x01";
/// Exact canonical controller receipt length; no trailing extension is admitted.
pub const NATIVE_RECEIPT_BYTES: usize = 650;
/// Exact encoding length of a browser shared-accounting receipt.
pub const BROWSER_RECEIPT_BYTES: usize = 546;
/// Finite retained generations. Exhaustion refuses without replacing evidence.
pub const MAX_GENERATIONS: u64 = 16;
/// Maximum cumulative canonical bytes authorized for each delivery stream.
pub const MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;

fn refused() -> Error {
    Error::Storage(StoreError::Refused)
}

/// Cumulative browser counters as actually recorded by its shared delivery image.
/// No per-stream spend, outages or resumes are inferred from these values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserSharedAccounting {
    /// Every reserved transport attempt, across all generations.
    pub attempts: u64,
    /// Cumulative reserved then reconciled transport bytes.
    pub wire_bytes: u64,
    /// Cumulative successfully retained outgoing items.
    pub retained: u64,
    /// Cumulative locally accepted incoming items.
    pub received: u64,
    /// Cumulative refused incoming items.
    pub refused_total: u64,
    /// Explicit finite authorized lifetime byte ceiling.
    pub total_byte_ceiling: u64,
    /// Explicit finite authorized lifetime attempt ceiling.
    pub total_attempt_ceiling: u64,
    /// Commitment to the exact seven preceding counters.
    pub commitment: [u8; 32],
}
impl BrowserSharedAccounting {
    /// Canonical accounting commitment shared with the browser implementation.
    pub fn computed_commitment(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private/controller-browser-accounting/v1\0");
        for field in self.fields() {
            hash.update(field.to_be_bytes());
        }
        hash.finalize().into()
    }
    fn fields(&self) -> [u64; 7] {
        [
            self.attempts,
            self.wire_bytes,
            self.retained,
            self.received,
            self.refused_total,
            self.total_byte_ceiling,
            self.total_attempt_ceiling,
        ]
    }
}
/// Counter semantics are explicit; native and browser histories cannot substitute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Accounting {
    /// Native persists independent ordinary and encrypted-control queue ledgers.
    NativeSplit {
        /// Complete ordinary-outbox queue ledger, including inherited spend.
        normal: LedgerSnapshot,
        /// Complete encrypted-control queue ledger, including inherited spend.
        controls: LedgerSnapshot,
        /// Explicit finite ordinary queue byte ceiling.
        normal_total_byte_ceiling: u64,
        /// Explicit finite control queue byte ceiling.
        control_total_byte_ceiling: u64,
    },
    /// Browser legacy images persist one shared transport allowance.
    BrowserShared(BrowserSharedAccounting),
}

/// Complete private pause evidence, produced under kernel and delivery custody.
/// All integer fields encode as big-endian u64. Construction and encoding both
/// validate the cross-field contract; callers cannot make a malformed record
/// authoritative by supplying a plausible digest or terminal head alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerPauseReceipt {
    /// Exact room, anchor, account and device, in that canonical order.
    pub context: Context,
    /// Stable hash of context and the original profile binding.
    pub controller_id: [u8; 32],
    /// First-generation profile binding, retained throughout the lineage.
    pub original_profile_binding: [u8; 32],
    /// Explicit operator-selected nonzero transition identity.
    pub transition: [u8; 32],
    /// Predecessor generation, starting at zero.
    pub generation: u64,
    /// Exact predecessor mailbox namespace.
    pub namespace: [u8; 32],
    /// Exact predecessor endpoint and TLS-pin commitment.
    pub endpoint: [u8; 32],
    /// Complete immutable predecessor profile binding.
    pub profile_binding: [u8; 32],
    /// Common drained mailbox head; a host fence must match it exactly.
    pub terminal_head: u64,
    /// Ordered mailbox item commitment, using the relay generation domain.
    pub items_commitment: [u8; 32],
    /// Kernel-authenticated complete outbox head.
    pub outbox_head: u64,
    /// Kernel-authenticated encrypted-control head.
    pub control_head: u64,
    /// Commitment to the exact authenticated encrypted native/kernel image.
    pub image_commitment: [u8; 32],
    /// Real counter mode, preserved across generation transitions.
    pub accounting: Accounting,
    /// Previous generation's receipt commitment; zero only at generation zero.
    pub prior_ledger_commitment: [u8; 32],
}

/// Stable controller identity without exposing private context to the relay.
pub fn controller_id(context: Context, original_profile_binding: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"vhalla/private/controller-id/v1\0");
    context_hash(&mut hash, context);
    hash.update(original_profile_binding);
    hash.finalize().into()
}

fn context_hash(hash: &mut Sha256, context: Context) {
    for field in [
        context.scope.room.as_bytes(),
        context.scope.anchor.as_bytes(),
        context.account.as_bytes(),
        context.device.as_bytes(),
    ] {
        hash.update(field);
    }
}

impl ControllerPauseReceipt {
    /// Check all fixed-format and cross-field bounds without a network request.
    pub fn validate(&self) -> Result<()> {
        if self.generation >= MAX_GENERATIONS
            || self.transition == [0; 32]
            || self.original_profile_binding == [0; 32]
            || self.profile_binding == [0; 32]
            || self.endpoint == [0; 32]
            || self.items_commitment == [0; 32]
            || self.image_commitment == [0; 32]
            || self.controller_id != controller_id(self.context, self.original_profile_binding)
            || RelayNamespace::from_bytes(self.namespace).is_err()
            || self.terminal_head > MAX_RELAY_ITEMS as u64
            || (self.generation == 0) != (self.prior_ledger_commitment == [0; 32])
            || (self.generation == 0 && self.original_profile_binding != self.profile_binding)
        {
            return Err(refused());
        }
        match self.accounting {
            Accounting::NativeSplit {
                normal,
                controls,
                normal_total_byte_ceiling,
                control_total_byte_ceiling,
            } => {
                if normal.outgoing != self.outbox_head
                    || normal.applied != self.terminal_head
                    || controls.outgoing != self.control_head
                    || controls.applied != 0
                {
                    return Err(refused());
                }
                for (ledger, ceiling) in [
                    (normal, normal_total_byte_ceiling),
                    (controls, control_total_byte_ceiling),
                ] {
                    if !(1..=MAX_TOTAL_BYTES).contains(&ceiling)
                        || ledger.canonical_bytes > ceiling
                        || ledger.retained_jobs > MAX_GENERATIONS * MAX_RELAY_ITEMS as u64
                        || ledger.commitment == [0; 32]
                    {
                        return Err(refused());
                    }
                }
            }
            Accounting::BrowserShared(value) => {
                if !(1..=MAX_TOTAL_BYTES).contains(&value.total_byte_ceiling)
                    || !(1..=MAX_GENERATIONS * 4096).contains(&value.total_attempt_ceiling)
                    || value.wire_bytes > value.total_byte_ceiling
                    || value.attempts > value.total_attempt_ceiling
                    || value.commitment != value.computed_commitment()
                {
                    return Err(refused());
                }
            }
        }
        Ok(())
    }

    /// Canonical bounded private encoding. Invalid in-memory records refuse.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(NATIVE_RECEIPT_BYTES);
        out.extend(MAGIC);
        for field in [
            self.context.scope.room.as_bytes(),
            self.context.scope.anchor.as_bytes(),
            self.context.account.as_bytes(),
            self.context.device.as_bytes(),
            &self.controller_id,
            &self.original_profile_binding,
            &self.transition,
        ] {
            out.extend(field);
        }
        out.extend(self.generation.to_be_bytes());
        out.extend(self.namespace);
        out.extend(self.endpoint);
        out.extend(self.profile_binding);
        out.extend(self.terminal_head.to_be_bytes());
        out.extend(self.items_commitment);
        out.extend(self.outbox_head.to_be_bytes());
        out.extend(self.control_head.to_be_bytes());
        out.extend(self.image_commitment);
        match self.accounting {
            Accounting::NativeSplit {
                normal,
                controls,
                normal_total_byte_ceiling,
                control_total_byte_ceiling,
            } => {
                out.push(0);
                for ledger in [normal, controls] {
                    for field in [
                        ledger.outgoing,
                        ledger.applied,
                        ledger.retained_jobs,
                        ledger.canonical_bytes,
                        ledger.charged_attempts,
                        ledger.outages,
                        ledger.resumes,
                    ] {
                        out.extend(field.to_be_bytes());
                    }
                    out.extend(ledger.commitment);
                }
                out.extend(normal_total_byte_ceiling.to_be_bytes());
                out.extend(control_total_byte_ceiling.to_be_bytes());
            }
            Accounting::BrowserShared(value) => {
                out.push(1);
                for field in value.fields() {
                    out.extend(field.to_be_bytes());
                }
                out.extend(value.commitment);
            }
        }
        out.extend(self.prior_ledger_commitment);
        debug_assert!(matches!(
            out.len(),
            NATIVE_RECEIPT_BYTES | BROWSER_RECEIPT_BYTES
        ));
        Ok(out)
    }

    /// Decode only the exact canonical version. Extra/truncated bytes refuse.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if !matches!(raw.len(), NATIVE_RECEIPT_BYTES | BROWSER_RECEIPT_BYTES)
            || &raw[..MAGIC.len()] != MAGIC
        {
            return Err(refused());
        }
        let mut r = Reader(&raw[MAGIC.len()..]);
        let context = Context {
            scope: PrivateRoomScope {
                room: RoomId::from_bytes(r.array()?).map_err(|_| refused())?,
                anchor: AnchorId::from_bytes(r.array()?).map_err(|_| refused())?,
            },
            account: Key::from_bytes(r.array()?).map_err(|_| refused())?,
            device: Key::from_bytes(r.array()?).map_err(|_| refused())?,
        };
        let value = Self {
            context,
            controller_id: r.array()?,
            original_profile_binding: r.array()?,
            transition: r.array()?,
            generation: r.number()?,
            namespace: r.array()?,
            endpoint: r.array()?,
            profile_binding: r.array()?,
            terminal_head: r.number()?,
            items_commitment: r.array()?,
            outbox_head: r.number()?,
            control_head: r.number()?,
            image_commitment: r.array()?,
            accounting: r.accounting()?,
            prior_ledger_commitment: r.array()?,
        };
        if !r.0.is_empty() {
            return Err(refused());
        }
        value.validate()?;
        Ok(value)
    }

    /// Domain-separated commitment to every canonical private receipt field.
    pub fn commitment(&self) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private/controller-pause-receipt/v1\0");
        hash.update(self.encode()?);
        Ok(hash.finalize().into())
    }
}

/// Exclusive account and store custody after authenticated kernel inspection.
/// Moving into maintenance destroys private kernel state without unlocking its
/// store. This value cannot author messages or return a live kernel handle.
pub struct ControllerMaintenance {
    store: crate::bridge::KernelStore,
    _identity: vhalla_identity::Identity,
    status: vhalla_private_kernel::Status,
}

impl super::RoomSession {
    /// Transfer the still-locked store to explicit delivery maintenance.
    pub fn into_delivery_maintenance(mut self) -> Result<ControllerMaintenance> {
        let status = self.status()?;
        let custody = self.custody.take().ok_or(Error::Locked)?;
        Ok(ControllerMaintenance {
            store: custody.kernel.into_store(),
            _identity: custody.identity,
            status,
        })
    }

    /// Reauthenticate an already committed receive without authoring a receipt.
    pub async fn retained_received(
        &mut self,
        raw: &[u8],
    ) -> Result<Option<vhalla_private_kernel::ReceivedMessage>> {
        Ok(self.live_mut()?.kernel.retained_received(raw).await?)
    }

    /// Reauthenticate an already committed control without applying it again.
    pub async fn retained_control(&mut self, raw: &[u8]) -> Result<bool> {
        Ok(self.live_mut()?.kernel.retained_control(raw).await?)
    }

    /// Exact authenticated local-send lookup, used to reconcile retained echoes.
    pub async fn original(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<vhalla_private_kernel::CommittedOutbox>> {
        Ok(self.live_mut()?.kernel.original(digest).await?)
    }

    /// Read the authenticated receipt index without creating another acceptance.
    pub async fn acceptances(
        &mut self,
        sequence: u64,
    ) -> Result<Vec<vhalla_private_kernel::MemberAcceptance>> {
        Ok(self.live_mut()?.kernel.acceptances(sequence).await?)
    }
}

impl ControllerMaintenance {
    /// Hash the exact encrypted image authenticated before the custody transfer.
    pub fn image_commitment(&mut self) -> Result<[u8; 32]> {
        Ok(self.store.image_commitment(self.status.context)?)
    }

    /// Pause every native store publisher for this exact authenticated boundary.
    /// Caller-owned transport/queue custody supplies the rest of the receipt.
    pub fn pause(&mut self, receipt: &ControllerPauseReceipt) -> Result<()> {
        receipt.validate()?;
        if receipt.context != self.status.context
            || receipt.outbox_head != self.status.outbox_head
            || receipt.control_head != self.status.control_floor.sequence()
            || receipt.image_commitment != self.image_commitment()?
        {
            return Err(refused());
        }
        self.store.pause_delivery(
            receipt.context,
            receipt.generation,
            receipt.image_commitment,
            &receipt.encode()?,
        )?;
        Ok(())
    }

    /// Resume publication only after the caller durably selected the exact
    /// successor. This does not renew a grant, create ratchets or change history.
    pub fn select_successor(
        &mut self,
        receipt: &ControllerPauseReceipt,
        successor_binding: [u8; 32],
    ) -> Result<()> {
        receipt.validate()?;
        if receipt.context != self.status.context
            || receipt.image_commitment != self.image_commitment()?
        {
            return Err(refused());
        }
        self.store.select_delivery_successor(
            receipt.context,
            receipt.generation,
            &receipt.encode()?,
            successor_binding,
        )?;
        Ok(())
    }
}

struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, tail) = self.0.split_at_checked(N).ok_or_else(refused)?;
        self.0 = tail;
        head.try_into().map_err(|_| refused())
    }
    fn number(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn accounting(&mut self) -> Result<Accounting> {
        match self.array::<1>()?[0] {
            0 => Ok(Accounting::NativeSplit {
                normal: self.ledger()?,
                controls: self.ledger()?,
                normal_total_byte_ceiling: self.number()?,
                control_total_byte_ceiling: self.number()?,
            }),
            1 => Ok(Accounting::BrowserShared(BrowserSharedAccounting {
                attempts: self.number()?,
                wire_bytes: self.number()?,
                retained: self.number()?,
                received: self.number()?,
                refused_total: self.number()?,
                total_byte_ceiling: self.number()?,
                total_attempt_ceiling: self.number()?,
                commitment: self.array()?,
            })),
            _ => Err(refused()),
        }
    }
    fn ledger(&mut self) -> Result<LedgerSnapshot> {
        Ok(LedgerSnapshot {
            outgoing: self.number()?,
            applied: self.number()?,
            retained_jobs: self.number()?,
            canonical_bytes: self.number()?,
            charged_attempts: self.number()?,
            outages: self.number()?,
            resumes: self.number()?,
            commitment: self.array()?,
        })
    }
}

#[cfg(test)]
mod tests;
