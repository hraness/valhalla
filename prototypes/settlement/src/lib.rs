//! Disposable voucher, quorum-finality, and light-client prototype.
//!
//! It tests the smallest value layer Valhalla could add without making chat or
//! games depend on a global blockchain. Cryptographic signatures and durable
//! storage are intentionally injected concerns; this models state transitions.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Id(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Validator(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Voucher {
    pub id: Id,
    pub owner: Id,
    pub amount: u64,
    pub parents: Vec<Id>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    MissingParent,
    AlreadySpent,
    AmountMismatch,
    UnknownOwner,
}

#[derive(Default)]
pub struct VoucherLedger {
    live: BTreeMap<Id, Voucher>,
    spent: BTreeSet<Id>,
    owners: BTreeSet<Id>,
}

impl VoucherLedger {
    pub fn register_owner(&mut self, owner: Id) {
        self.owners.insert(owner);
    }

    pub fn issue(&mut self, voucher: Voucher) -> Result<(), Reject> {
        if !self.owners.contains(&voucher.owner) {
            return Err(Reject::UnknownOwner);
        }
        if voucher
            .parents
            .iter()
            .any(|parent| self.spent.contains(parent))
        {
            return Err(Reject::AlreadySpent);
        }
        if !voucher
            .parents
            .iter()
            .all(|parent| self.live.contains_key(parent))
        {
            return Err(Reject::MissingParent);
        }
        let parent_amount = voucher
            .parents
            .iter()
            .map(|parent| self.live.get(parent).expect("checked above").amount)
            .sum::<u64>();
        if !voucher.parents.is_empty() && voucher.amount > parent_amount {
            return Err(Reject::AmountMismatch);
        }
        for parent in &voucher.parents {
            self.live.remove(parent);
            self.spent.insert(*parent);
        }
        self.live.insert(voucher.id, voucher);
        Ok(())
    }

    pub fn balance(&self, owner: Id) -> u64 {
        self.live
            .values()
            .filter(|voucher| voucher.owner == owner)
            .map(|voucher| voucher.amount)
            .sum()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub height: u64,
    pub state_root: Id,
    pub approvals: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalityError {
    InsufficientQuorum,
    Reorg,
}

pub struct Finality {
    threshold: usize,
    latest: Option<Checkpoint>,
}

impl Finality {
    pub fn new(threshold: usize) -> Self {
        Self {
            threshold,
            latest: None,
        }
    }

    pub fn accept(&mut self, checkpoint: Checkpoint) -> Result<(), FinalityError> {
        if checkpoint.approvals < self.threshold {
            return Err(FinalityError::InsufficientQuorum);
        }
        if self
            .latest
            .is_some_and(|latest| checkpoint.height < latest.height)
        {
            return Err(FinalityError::Reorg);
        }
        if self.latest.is_some_and(|latest| {
            checkpoint.height == latest.height && checkpoint.state_root != latest.state_root
        }) {
            return Err(FinalityError::Reorg);
        }
        self.latest = Some(checkpoint);
        Ok(())
    }

    pub fn latest(&self) -> Option<Checkpoint> {
        self.latest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub height: u64,
    pub parent: Id,
    pub state_root: Id,
    pub quorum: usize,
}

#[derive(Default)]
pub struct LightClient {
    head: Option<Header>,
}

impl LightClient {
    pub fn accept(&mut self, header: Header, required_quorum: usize) -> Result<(), FinalityError> {
        if header.quorum < required_quorum {
            return Err(FinalityError::InsufficientQuorum);
        }
        if let Some(head) = self.head {
            if header.height != head.height + 1 || header.parent != head.state_root {
                return Err(FinalityError::Reorg);
            }
        }
        self.head = Some(header);
        Ok(())
    }

    pub fn head(&self) -> Option<Header> {
        self.head
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vouchers_are_single_spend_and_amount_bounded() {
        let mut ledger = VoucherLedger::default();
        ledger.register_owner(Id(1));
        ledger.register_owner(Id(2));
        ledger
            .issue(Voucher {
                id: Id(10),
                owner: Id(1),
                amount: 100,
                parents: vec![],
            })
            .unwrap();
        ledger
            .issue(Voucher {
                id: Id(11),
                owner: Id(2),
                amount: 60,
                parents: vec![Id(10)],
            })
            .unwrap();
        assert_eq!(ledger.balance(Id(2)), 60);
        assert_eq!(
            ledger.issue(Voucher {
                id: Id(12),
                owner: Id(2),
                amount: 60,
                parents: vec![Id(10)]
            }),
            Err(Reject::AlreadySpent)
        );
        assert_eq!(
            ledger.issue(Voucher {
                id: Id(13),
                owner: Id(2),
                amount: 50,
                parents: vec![Id(11)]
            }),
            Ok(())
        );
    }

    #[test]
    fn quorum_finality_rejects_conflicts_and_old_checkpoints() {
        let mut finality = Finality::new(2);
        assert_eq!(
            finality.accept(Checkpoint {
                height: 1,
                state_root: Id(1),
                approvals: 1
            }),
            Err(FinalityError::InsufficientQuorum)
        );
        finality
            .accept(Checkpoint {
                height: 1,
                state_root: Id(1),
                approvals: 2,
            })
            .unwrap();
        assert_eq!(
            finality.accept(Checkpoint {
                height: 1,
                state_root: Id(2),
                approvals: 3
            }),
            Err(FinalityError::Reorg)
        );
        assert_eq!(
            finality.accept(Checkpoint {
                height: 0,
                state_root: Id(0),
                approvals: 3
            }),
            Err(FinalityError::Reorg)
        );
    }

    #[test]
    fn light_client_only_follows_contiguous_quorum_headers() {
        let mut client = LightClient::default();
        client
            .accept(
                Header {
                    height: 0,
                    parent: Id(0),
                    state_root: Id(9),
                    quorum: 2,
                },
                2,
            )
            .unwrap();
        assert_eq!(
            client.accept(
                Header {
                    height: 2,
                    parent: Id(9),
                    state_root: Id(10),
                    quorum: 2
                },
                2
            ),
            Err(FinalityError::Reorg)
        );
        client
            .accept(
                Header {
                    height: 1,
                    parent: Id(9),
                    state_root: Id(10),
                    quorum: 2,
                },
                2,
            )
            .unwrap();
        assert_eq!(client.head().unwrap().state_root, Id(10));
    }
}
