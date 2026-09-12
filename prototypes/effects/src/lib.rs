//! Throwaway reference for Valhalla's local authority and history seams.
//! This crate intentionally has no network, crypto, filesystem, or model dependency.

use std::collections::{HashMap, VecDeque};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EventId(u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerId(u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PolicyEpoch(u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Operation {
    ReadWorkspace,
    WriteWorkspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    pub operation: Operation,
    pub resource: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteRequest {
    pub event: EventId,
    pub author: PeerId,
    pub requested: Scope,
    pub argument: Vec<u8>,
}

/// A proposal remains inert until a local policy produces this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedEffect {
    request: RemoteRequest,
    capability: EffectCapability,
}

/// Deliberately no `Deserialize` or public constructor. Real code also binds
/// audience, expiry, nonce, and a cryptographic owner signature here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectCapability {
    scope: Scope,
    audience: PeerId,
    epoch: PolicyEpoch,
    max_uses: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Denied {
    WrongAudience,
    ScopeMismatch,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalPolicy {
    owner: PeerId,
    epoch: PolicyEpoch,
    read_resource: Option<u32>,
    write_resource: Option<u32>,
}

impl LocalPolicy {
    pub fn read_only(owner: PeerId, epoch: PolicyEpoch, resource: u32) -> Self {
        Self {
            owner,
            epoch,
            read_resource: Some(resource),
            write_resource: None,
        }
    }

    /// This is the only constructor path for an effect capability.
    pub fn authorize(&self, request: RemoteRequest) -> Result<AuthorizedEffect, Denied> {
        let allowed = match request.requested.operation {
            Operation::ReadWorkspace => self.read_resource == Some(request.requested.resource),
            Operation::WriteWorkspace => self.write_resource == Some(request.requested.resource),
        };
        if !allowed {
            return Err(Denied::ScopeMismatch);
        }
        Ok(AuthorizedEffect {
            capability: EffectCapability {
                scope: request.requested,
                audience: self.owner,
                epoch: self.epoch,
                max_uses: 1,
            },
            request,
        })
    }
}

impl AuthorizedEffect {
    pub fn consume(
        &mut self,
        caller: PeerId,
        epoch: PolicyEpoch,
    ) -> Result<ExecutedEffect, Denied> {
        if self.capability.audience != caller {
            return Err(Denied::WrongAudience);
        }
        if self.capability.epoch != epoch {
            return Err(Denied::Exhausted);
        }
        if self.capability.max_uses == 0 {
            return Err(Denied::Exhausted);
        }
        self.capability.max_uses -= 1;
        Ok(ExecutedEffect {
            event: self.request.event,
            scope: self.capability.scope,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutedEffect {
    pub event: EventId,
    pub scope: Scope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Visibility {
    Public,
    Private,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryEvent {
    pub id: EventId,
    pub visibility: Visibility,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum HistoryError {
    TooLarge,
    Duplicate,
}

/// A bounded append-only view. It does not promise durable replication or
/// encryption; those are separate protocol decisions.
pub struct BoundedHistory {
    max_events: usize,
    max_bytes: usize,
    bytes: usize,
    seen: HashMap<EventId, ()>,
    events: VecDeque<HistoryEvent>,
}

impl BoundedHistory {
    pub fn new(max_events: usize, max_bytes: usize) -> Self {
        Self {
            max_events,
            max_bytes,
            bytes: 0,
            seen: HashMap::new(),
            events: VecDeque::new(),
        }
    }

    pub fn append(&mut self, event: HistoryEvent) -> Result<(), HistoryError> {
        if event.bytes.len() > self.max_bytes {
            return Err(HistoryError::TooLarge);
        }
        if self.seen.contains_key(&event.id) {
            return Err(HistoryError::Duplicate);
        }
        while self.events.len() >= self.max_events
            || self.bytes + event.bytes.len() > self.max_bytes
        {
            if let Some(old) = self.events.pop_front() {
                self.bytes -= old.bytes.len();
                self.seen.remove(&old.id);
            } else {
                return Err(HistoryError::TooLarge);
            }
        }
        self.bytes += event.bytes.len();
        self.seen.insert(event.id, ());
        self.events.push_back(event);
        Ok(())
    }

    pub fn events(&self) -> impl Iterator<Item = &HistoryEvent> {
        self.events.iter()
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation: Operation) -> RemoteRequest {
        RemoteRequest {
            event: EventId(1),
            author: PeerId(99),
            requested: Scope {
                operation,
                resource: 7,
            },
            argument: b"hostile prose".to_vec(),
        }
    }

    #[test]
    fn remote_request_is_inert_until_local_policy_authorizes() {
        let policy = LocalPolicy::read_only(PeerId(1), PolicyEpoch(3), 7);
        assert_eq!(
            policy.authorize(request(Operation::WriteWorkspace)),
            Err(Denied::ScopeMismatch)
        );
        let mut authorized = policy.authorize(request(Operation::ReadWorkspace)).unwrap();
        assert_eq!(
            authorized.consume(PeerId(2), PolicyEpoch(3)),
            Err(Denied::WrongAudience)
        );
        assert!(authorized.consume(PeerId(1), PolicyEpoch(2)).is_err());
        assert!(authorized.consume(PeerId(1), PolicyEpoch(3)).is_ok());
        assert_eq!(
            authorized.consume(PeerId(1), PolicyEpoch(3)),
            Err(Denied::Exhausted)
        );
    }

    #[test]
    fn history_deduplicates_and_evicts_within_bound() {
        let mut h = BoundedHistory::new(2, 8);
        h.append(HistoryEvent {
            id: EventId(1),
            visibility: Visibility::Public,
            bytes: b"1234".to_vec(),
        })
        .unwrap();
        assert_eq!(
            h.append(HistoryEvent {
                id: EventId(1),
                visibility: Visibility::Public,
                bytes: b"1234".to_vec()
            }),
            Err(HistoryError::Duplicate)
        );
        h.append(HistoryEvent {
            id: EventId(2),
            visibility: Visibility::Private,
            bytes: b"5678".to_vec(),
        })
        .unwrap();
        h.append(HistoryEvent {
            id: EventId(3),
            visibility: Visibility::Public,
            bytes: b"ab".to_vec(),
        })
        .unwrap();
        let ids: Vec<_> = h.events().map(|event| event.id).collect();
        assert_eq!(ids, vec![EventId(2), EventId(3)]);
        assert_eq!(h.bytes(), 6);
    }
}
