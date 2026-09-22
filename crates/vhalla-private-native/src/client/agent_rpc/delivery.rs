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
    CommittedOutbox, MemberAcceptance, OperationId, OutboxEntry, MAX_MEMBERS,
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
        view.relay = Some(status.clone());
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
                value["relay"] = json!({"state":match relay.state{JobState::Pending=>"pending",JobState::Uncertain=>"uncertain",JobState::Retained=>"retained",JobState::Stopped=>"stopped"},"attempts":relay.attempts,"uncertain":relay.uncertain,"position":relay.position.map(|p|p.to_string()),"next_due":relay.next_due.to_string(),"last_error":relay.last_error.map(net_error),"evidence":"durable local delivery journal; relay retention is not member acceptance"});
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
