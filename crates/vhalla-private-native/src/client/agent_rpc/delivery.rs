//! Trusted metadata updates checked against this session's actual retained wire.
use super::{hex, queued, Error, RpcSession};
use crate::{
    agent::QueuedStatus,
    relay::{
        delivery::{JobState, JobStatus},
        net::NetError,
        RelayItem, RelayNamespace, MAX_RELAY_ITEMS,
    },
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use vhalla_private_kernel::{
    CommittedOutbox, MemberAcceptance, OperationId, OutboxEntry, OutboxKind, MAX_MEMBERS,
};

pub(super) struct DeliveryView {
    operation: OperationId,
    relay: Option<JobStatus>,
    acceptances: BTreeMap<[u8; 32], MemberAcceptance>,
}

impl RpcSession {
    /// Host-only update from durable delivery custody. Reload the exact local
    /// output and match the canonical relay digest, namespace and operation;
    /// caller-provided sequence metadata alone is never enough. This changes no
    /// grant and is never an MCP method. At most 4096 metadata entries are held.
    pub async fn update_delivery(
        &mut self,
        namespace: RelayNamespace,
        status: &JobStatus,
    ) -> Result<(), Error> {
        if self.delivery_namespace.is_some_and(|old| old != namespace)
            || status.sequence == 0
            || status.attempts > 100
            || (status.state == JobState::Retained) != status.position.is_some()
            || status.position == Some(0)
            || (status.state == JobState::Retained && status.uncertain)
            || (status.state == JobState::Uncertain && !status.uncertain)
        {
            return Err(Error::Authority);
        }
        let original = self.original(status.sequence).await?;
        let item = RelayItem::from_artifact(namespace, &original).map_err(|_| Error::Authority)?;
        if original.operation() != status.operation || item.digest() != status.id {
            return Err(Error::Authority);
        }
        let changed = {
            let view = self.delivery_view(status.sequence, status.operation)?;
            if let Some(old) = &view.relay {
                if old.id != status.id
                    || old.attempts > status.attempts
                    || (old.uncertain && !status.uncertain && status.state != JobState::Retained)
                    || (old.state == JobState::Retained
                        && (status.state != JobState::Retained || old.position != status.position))
                    || (old.state == JobState::Stopped && status.state != JobState::Stopped)
                {
                    return Err(Error::Authority);
                }
            }
            let changed = view.relay.as_ref() != Some(status);
            if changed {
                view.relay = Some(status.clone());
            }
            changed
        };
        // Restore verified member claims from the kernel's durable acceptance
        // index, so a relaunched host reports the same evidence without
        // re-walking retained inbox content through this session. Only
        // application records can carry member receipts; relayed admission
        // artifacts never index acceptances.
        if original.kind() == OutboxKind::Application
            && self
                .deliveries
                .get(&status.sequence)
                .is_some_and(|view| view.acceptances.is_empty())
        {
            let proofs = self
                .session
                .acceptances(status.sequence)
                .await
                .map_err(|_| Error::Authority)?;
            for proof in proofs {
                let recipient = *proof.recipient().as_bytes();
                let inserted = {
                    let view = self.delivery_view(status.sequence, status.operation)?;
                    match view.acceptances.get(&recipient) {
                        Some(old) if *old != proof => return Err(Error::Authority),
                        Some(_) => false,
                        None if view.acceptances.len() < MAX_MEMBERS => {
                            view.acceptances.insert(recipient, proof);
                            true
                        }
                        None => return Err(Error::Bounds),
                    }
                };
                if inserted {
                    self.delivery_version = self.delivery_version.wrapping_add(1);
                }
            }
        }
        if changed {
            self.delivery_version = self.delivery_version.wrapping_add(1);
        }
        self.delivery_namespace = Some(namespace);
        Ok(())
    }

    /// Host-only already-verified member claim. Recheck exact local context and
    /// original ciphertext, retain distinct recipients separately from relay
    /// retention, and refuse conflicting claims instead of replacing evidence.
    /// A claim is not proof of honest disk state, human reading or current roster.
    pub async fn record_member_acceptance(
        &mut self,
        sequence: u64,
        proof: MemberAcceptance,
    ) -> Result<(), Error> {
        let original = self.original(sequence).await?;
        if !proof.matches_original(self.launch.context(), &original) {
            return Err(Error::Authority);
        }
        let view = self.delivery_view(sequence, original.operation())?;
        let recipient = *proof.recipient().as_bytes();
        if let Some(old) = view.acceptances.get(&recipient) {
            return if *old == proof {
                Ok(())
            } else {
                Err(Error::Authority)
            };
        }
        if view.acceptances.len() >= MAX_MEMBERS {
            return Err(Error::Bounds);
        }
        view.acceptances.insert(recipient, proof);
        self.delivery_version = self.delivery_version.wrapping_add(1);
        Ok(())
    }

    async fn original(&mut self, sequence: u64) -> Result<CommittedOutbox, Error> {
        let after = sequence.checked_sub(1).ok_or(Error::Bounds)?;
        let page = self
            .session
            .outbox(after, 1)
            .await
            .map_err(|_| Error::Authority)?;
        match page.records.into_iter().next() {
            Some(OutboxEntry::Artifact(original)) if original.sequence() == sequence => {
                Ok(original)
            }
            _ => Err(Error::Authority),
        }
    }
    fn delivery_view(
        &mut self,
        sequence: u64,
        operation: OperationId,
    ) -> Result<&mut DeliveryView, Error> {
        if !self.deliveries.contains_key(&sequence) && self.deliveries.len() >= MAX_RELAY_ITEMS {
            return Err(Error::Bounds);
        }
        let entry = self
            .deliveries
            .entry(sequence)
            .or_insert_with(|| DeliveryView {
                operation,
                relay: None,
                acceptances: BTreeMap::new(),
            });
        if entry.operation != operation {
            return Err(Error::Authority);
        }
        Ok(entry)
    }
    pub(super) fn queued_with_delivery(&self, status: QueuedStatus) -> Value {
        let mut value = queued(status);
        if let Some(view) = self
            .deliveries
            .get(&status.sequence)
            .filter(|view| view.operation == status.operation)
        {
            if let Some(relay) = &view.relay {
                // A refused TCP connect means the endpoint did not accept the
                // attempt: nothing reached the relay. Report it distinctly from
                // `uncertain`, which is reserved for attempts that may have
                // retained bytes remotely.
                let state = match relay.state {
                    JobState::Pending => "pending",
                    JobState::Uncertain if relay.last_error == Some(NetError::Connect) => {
                        "unreachable"
                    }
                    JobState::Uncertain => "uncertain",
                    JobState::Retained => "retained",
                    JobState::Stopped => "stopped",
                };
                value["relay"] = json!({"state":state,"attempts":relay.attempts,"uncertain":relay.uncertain,"position":relay.position.map(|p|p.to_string()),"next_due":relay.next_due.to_string(),"last_error":relay.last_error.map(net_error),"evidence":"durable local delivery journal; relay retention is not member acceptance"});
            }
            value["member_acceptances"]=json!(view.acceptances.values().map(|proof|json!({"recipient":hex(proof.recipient().as_bytes()),"received_sequence":proof.received_sequence().to_string(),"evidence":"device-signed durable-reception claim; not human reading or current membership"})).collect::<Vec<_>>());
        }
        value
    }
}
fn net_error(e: NetError) -> &'static str {
    match e {
        NetError::Connect => "connect",
        NetError::Timeout => "timeout",
        NetError::Denied => "denied",
        NetError::Conflict => "conflict",
        NetError::Capacity => "capacity",
        NetError::Bounds => "bounds",
        NetError::Scope => "scope",
        NetError::Malformed => "malformed",
        NetError::Unavailable => "unavailable",
    }
}
