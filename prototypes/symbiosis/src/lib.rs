//! Reference model for typed symbiotic contracts and bounded signaling.
//!
//! A contract is an explicit obligation between two peers. Messages are
//! deduplicated by ID, scoped to the contract, and admitted through a bounded
//! queue. Expiry ends the obligation; it never transfers ownership.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Peer(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContractId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MessageId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractState {
    Active,
    Fulfilled,
    Cancelled,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Contract {
    pub id: ContractId,
    pub provider: Peer,
    pub consumer: Peer,
    pub input_kind: u16,
    pub output_kind: u16,
    pub expires_at: u64,
    pub state: ContractState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signal {
    pub id: MessageId,
    pub contract: ContractId,
    pub sender: Peer,
    pub sequence: u64,
    pub kind: u16,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    DuplicateContract,
    InvalidContract,
    UnknownContract,
    WrongParticipant,
    WrongSignalKind,
    Expired,
    NotActive,
    DuplicateSignal,
    StaleSequence,
    TooLarge,
    QueueFull,
}

pub struct Exchange {
    now: u64,
    max_queue: usize,
    max_signal_bytes: usize,
    seen_limit: usize,
    contracts: BTreeMap<ContractId, Contract>,
    seen_signals: BTreeSet<MessageId>,
    last_sequence: BTreeMap<(ContractId, Peer), u64>,
    queue: VecDeque<Signal>,
}

impl Exchange {
    pub fn new(now: u64, max_queue: usize) -> Self {
        Self {
            now,
            max_signal_bytes: max_queue.max(1).saturating_mul(1024),
            seen_limit: max_queue.max(1).saturating_mul(4),
            max_queue,
            contracts: BTreeMap::new(),
            seen_signals: BTreeSet::new(),
            last_sequence: BTreeMap::new(),
            queue: VecDeque::new(),
        }
    }

    pub fn propose(&mut self, contract: Contract) -> Result<(), Error> {
        if self.contracts.contains_key(&contract.id) {
            return Err(Error::DuplicateContract);
        }
        if contract.provider == contract.consumer || contract.state != ContractState::Active {
            return Err(Error::InvalidContract);
        }
        if contract.expires_at <= self.now {
            return Err(Error::Expired);
        }
        self.contracts.insert(contract.id, contract);
        Ok(())
    }

    pub fn advance(&mut self, now: u64) -> bool {
        if now < self.now {
            return false;
        }
        self.now = now;
        for contract in self.contracts.values_mut() {
            if contract.state == ContractState::Active && contract.expires_at <= now {
                contract.state = ContractState::Expired;
            }
        }
        true
    }

    pub fn signal(&mut self, signal: Signal) -> Result<(), Error> {
        let contract = self
            .contracts
            .get(&signal.contract)
            .ok_or(Error::UnknownContract)?;
        if contract.state != ContractState::Active {
            return Err(Error::NotActive);
        }
        if self.now >= contract.expires_at {
            return Err(Error::Expired);
        }
        if signal.sender != contract.provider && signal.sender != contract.consumer {
            return Err(Error::WrongParticipant);
        }
        let expected_kind = if signal.sender == contract.provider {
            contract.output_kind
        } else {
            contract.input_kind
        };
        if signal.kind != expected_kind {
            return Err(Error::WrongSignalKind);
        }
        if self.seen_signals.contains(&signal.id) {
            return Err(Error::DuplicateSignal);
        }
        if signal.bytes.len() > self.max_signal_bytes {
            return Err(Error::TooLarge);
        }
        if self
            .last_sequence
            .get(&(signal.contract, signal.sender))
            .is_some_and(|last| signal.sequence <= *last)
        {
            return Err(Error::StaleSequence);
        }
        if self.queue.len() >= self.max_queue {
            return Err(Error::QueueFull);
        }
        if self.seen_signals.len() >= self.seen_limit {
            if let Some(oldest) = self.seen_signals.iter().next().copied() {
                self.seen_signals.remove(&oldest);
            }
        }
        self.seen_signals.insert(signal.id);
        self.last_sequence
            .insert((signal.contract, signal.sender), signal.sequence);
        self.queue.push_back(signal);
        Ok(())
    }

    pub fn receive(&mut self) -> Option<Signal> {
        while let Some(signal) = self.queue.pop_front() {
            let active = self
                .contracts
                .get(&signal.contract)
                .is_some_and(|contract| {
                    contract.state == ContractState::Active && self.now < contract.expires_at
                });
            if active {
                return Some(signal);
            }
        }
        None
    }

    pub fn fulfill(&mut self, id: ContractId, actor: Peer) -> Result<(), Error> {
        let contract = self.contracts.get_mut(&id).ok_or(Error::UnknownContract)?;
        if contract.state != ContractState::Active {
            return Err(Error::NotActive);
        }
        if actor != contract.provider && actor != contract.consumer {
            return Err(Error::WrongParticipant);
        }
        contract.state = ContractState::Fulfilled;
        Ok(())
    }

    pub fn cancel(&mut self, id: ContractId, actor: Peer) -> Result<(), Error> {
        let contract = self.contracts.get_mut(&id).ok_or(Error::UnknownContract)?;
        if actor != contract.provider && actor != contract.consumer {
            return Err(Error::WrongParticipant);
        }
        if contract.state != ContractState::Active {
            return Err(Error::NotActive);
        }
        contract.state = ContractState::Cancelled;
        Ok(())
    }

    pub fn contract(&self, id: ContractId) -> Option<&Contract> {
        self.contracts.get(&id)
    }

    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    pub fn state_digest(&self) -> u64 {
        let mut hash = 0xcbf29ce484222325u64;
        for contract in self.contracts.values() {
            for byte in contract.id.0.to_be_bytes() {
                hash = hash
                    .wrapping_mul(0x100000001b3)
                    .wrapping_add(u64::from(byte));
            }
            hash = hash
                .wrapping_mul(0x100000001b3)
                .wrapping_add(contract.state as u64);
        }
        for id in &self.seen_signals {
            for byte in id.0.to_be_bytes() {
                hash = hash
                    .wrapping_mul(0x100000001b3)
                    .wrapping_add(u64::from(byte));
            }
        }
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn contract() -> Contract {
        Contract {
            id: ContractId(1),
            provider: Peer(1),
            consumer: Peer(2),
            input_kind: 10,
            output_kind: 11,
            expires_at: 20,
            state: ContractState::Active,
        }
    }

    #[test]
    fn signals_are_typed_scoped_and_bounded() {
        let mut exchange = Exchange::new(5, 1);
        exchange.propose(contract()).unwrap();
        assert_eq!(
            exchange.signal(Signal {
                id: MessageId(1),
                contract: ContractId(1),
                sender: Peer(1),
                sequence: 0,
                kind: 11,
                bytes: vec![],
            }),
            Ok(())
        );
        assert_eq!(
            exchange.signal(Signal {
                id: MessageId(2),
                contract: ContractId(1),
                sender: Peer(1),
                sequence: 1,
                kind: 11,
                bytes: vec![],
            }),
            Err(Error::QueueFull)
        );
        assert_eq!(exchange.receive().unwrap().id, MessageId(1));
    }

    #[test]
    fn duplicate_and_cross_contract_signals_do_not_create_obligations() {
        let mut exchange = Exchange::new(5, 4);
        exchange.propose(contract()).unwrap();
        let signal = Signal {
            id: MessageId(7),
            contract: ContractId(1),
            sender: Peer(2),
            sequence: 0,
            kind: 10,
            bytes: vec![],
        };
        exchange.signal(signal.clone()).unwrap();
        assert_eq!(exchange.signal(signal), Err(Error::DuplicateSignal));
        assert_eq!(
            exchange.signal(Signal {
                id: MessageId(8),
                contract: ContractId(99),
                sender: Peer(2),
                sequence: 0,
                kind: 10,
                bytes: vec![],
            }),
            Err(Error::UnknownContract)
        );
    }

    #[test]
    fn expiry_ends_obligation_without_transferring_ownership() {
        let mut exchange = Exchange::new(5, 4);
        exchange.propose(contract()).unwrap();
        exchange.advance(20);
        assert_eq!(
            exchange.contract(ContractId(1)).unwrap().state,
            ContractState::Expired
        );
        assert_eq!(
            exchange.fulfill(ContractId(1), Peer(2)),
            Err(Error::NotActive)
        );
        assert_eq!(exchange.contract(ContractId(1)).unwrap().provider, Peer(1));
    }

    #[test]
    fn delayed_signal_is_dropped_after_contract_expiry() {
        let mut exchange = Exchange::new(5, 4);
        exchange.propose(contract()).unwrap();
        exchange
            .signal(Signal {
                id: MessageId(9),
                contract: ContractId(1),
                sender: Peer(2),
                sequence: 0,
                kind: 10,
                bytes: vec![],
            })
            .unwrap();
        assert!(exchange.advance(20));
        assert!(exchange.receive().is_none());
    }

    #[test]
    fn deterministic_state_digest_is_replayable() {
        let mut left = Exchange::new(5, 4);
        let mut right = Exchange::new(5, 4);
        left.propose(contract()).unwrap();
        right.propose(contract()).unwrap();
        let signal = Signal {
            id: MessageId(1),
            contract: ContractId(1),
            sender: Peer(2),
            sequence: 0,
            kind: 10,
            bytes: vec![1, 2],
        };
        left.signal(signal.clone()).unwrap();
        right.signal(signal).unwrap();
        assert_eq!(left.state_digest(), right.state_digest());
    }

    #[derive(Clone, Debug)]
    enum Action {
        Propose(u8),
        Signal(u8, u8),
        Advance(u8),
        Receive,
        Cancel,
        Fulfill,
    }

    fn action_strategy() -> impl Strategy<Value = Action> {
        prop_oneof![
            any::<u8>().prop_map(Action::Propose),
            (any::<u8>(), any::<u8>()).prop_map(|(id, seq)| Action::Signal(id, seq)),
            any::<u8>().prop_map(Action::Advance),
            Just(Action::Receive),
            Just(Action::Cancel),
            Just(Action::Fulfill),
        ]
    }

    proptest! {
        #[test]
        fn arbitrary_contract_schedule_preserves_queue_and_sequence_bounds(
            actions in prop::collection::vec(action_strategy(), 0..96)
        ) {
            let mut exchange = Exchange::new(0, 4);
            let mut next_contract = 1u64;
            for action in actions {
                match action {
                    Action::Propose(raw) if next_contract < 8 => {
                        let id = ContractId(next_contract);
                        next_contract += 1;
                        let expiry = 5 + u64::from(raw % 20);
                        let _ = exchange.propose(Contract { id, provider: Peer(1), consumer: Peer(2),
                            input_kind: 10, output_kind: 11, expires_at: expiry, state: ContractState::Active });
                    }
                    Action::Signal(raw, seq) => {
                        let id = ContractId(1 + u64::from(raw % 7));
                        let _ = exchange.signal(Signal { id: MessageId(u64::from(raw)), contract: id,
                            sender: Peer(1), sequence: u64::from(seq), kind: 11, bytes: vec![raw] });
                    }
                    Action::Advance(raw) => { let _ = exchange.advance(u64::from(raw % 32)); }
                    Action::Receive => { let _ = exchange.receive(); }
                    Action::Cancel => { let _ = exchange.cancel(ContractId(1), Peer(1)); }
                    Action::Fulfill => { let _ = exchange.fulfill(ContractId(1), Peer(1)); }
                    Action::Propose(_) => {}
                }
                prop_assert!(exchange.queue_len() <= 4);
                prop_assert!(exchange.last_sequence.len() <= exchange.contracts.len().saturating_mul(2));
                let scoped_sequences = exchange.last_sequence.keys().all(|(id, peer)| {
                    exchange.contracts.contains_key(id) && (*peer == Peer(1) || *peer == Peer(2))
                });
                prop_assert!(scoped_sequences);
            }
        }
    }
}
