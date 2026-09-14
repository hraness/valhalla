#![no_std]
#![forbid(unsafe_code)]
//! Throwaway bounded peer hint protocol. Hints carry no admitted text or authority.
extern crate alloc;
use alloc::{collections::BTreeSet, vec::Vec};

pub const MAX_PEERS: usize = 4;
pub const MAX_HINTS: usize = 32;
pub const MAX_RESPONSE_BYTES: usize = 5 + MAX_HINTS * 64;
pub type Id = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hint {
    pub post: Id,
    pub revision: Id,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Budget,
    Malformed,
    Peer,
}

pub fn encode(hints: &[Hint]) -> Result<Vec<u8>, Error> {
    if hints.len() > MAX_HINTS || hints.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Error::Malformed);
    }
    let mut out = Vec::with_capacity(5 + hints.len() * 64);
    out.extend_from_slice(b"VHQ1");
    out.push(hints.len() as u8);
    for hint in hints {
        out.extend_from_slice(&hint.post);
        out.extend_from_slice(&hint.revision);
    }
    Ok(out)
}

fn decode(raw: &[u8]) -> Result<Vec<Hint>, Error> {
    if raw.len() < 5 || raw.len() > MAX_RESPONSE_BYTES || &raw[..4] != b"VHQ1" {
        return Err(Error::Malformed);
    }
    let count = usize::from(raw[4]);
    if count > MAX_HINTS || raw.len() != 5 + count * 64 {
        return Err(Error::Malformed);
    }
    let mut out = Vec::with_capacity(count);
    for bytes in raw[5..].as_chunks::<64>().0 {
        let mut post = [0; 32];
        let mut revision = [0; 32];
        post.copy_from_slice(&bytes[..32]);
        revision.copy_from_slice(&bytes[32..]);
        out.push(Hint { post, revision });
    }
    if out.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Error::Malformed);
    }
    Ok(out)
}

/// Explicitly selected providers only. A response can never assert completeness.
pub struct Round {
    peers: BTreeSet<Id>,
    attempted: BTreeSet<Id>,
    hints: BTreeSet<Hint>,
    hint_credit: usize,
    byte_credit: usize,
}

impl Round {
    pub fn new(peers: &[Id]) -> Result<Self, Error> {
        if peers.len() > MAX_PEERS {
            return Err(Error::Peer);
        }
        let unique: BTreeSet<_> = peers.iter().copied().collect();
        if unique.len() != peers.len() {
            return Err(Error::Peer);
        }
        Ok(Self {
            peers: unique,
            attempted: BTreeSet::new(),
            hints: BTreeSet::new(),
            hint_credit: MAX_PEERS * MAX_HINTS,
            byte_credit: MAX_PEERS * MAX_RESPONSE_BYTES,
        })
    }

    /// One bounded response/failure per selected peer. Failed attempts count.
    pub fn response(&mut self, peer: Id, raw: Option<&[u8]>) -> Result<(), Error> {
        if !self.peers.contains(&peer) || !self.attempted.insert(peer) {
            return Err(Error::Peer);
        }
        let Some(raw) = raw else {
            return Ok(());
        };
        // The adapter must enforce frame bounds before allocating incoming bytes.
        if raw.len() > MAX_RESPONSE_BYTES || raw.len() > self.byte_credit {
            return Err(Error::Budget);
        }
        self.byte_credit -= raw.len();
        let decoded = decode(raw)?;
        if decoded.len() > self.hint_credit {
            return Err(Error::Budget);
        }
        self.hint_credit -= decoded.len(); // duplicates consume work too
        self.hints.extend(decoded);
        Ok(())
    }

    pub fn hints(&self) -> impl Iterator<Item = &Hint> {
        self.hints.iter()
    }
    pub fn finished(&self) -> bool {
        self.attempted.len() == self.peers.len()
    }
}

/// Discovery has no access to the archive's independent control reserve.
pub struct FetchBudget {
    data: usize,
    control: usize,
}
impl FetchBudget {
    pub fn new(data: usize, control: usize) -> Self {
        Self { data, control }
    }
    pub fn candidate_attempt(&mut self) -> Result<(), Error> {
        if self.data == 0 {
            return Err(Error::Budget);
        }
        self.data -= 1;
        Ok(())
    }
    pub fn control_attempt(&mut self) -> Result<(), Error> {
        if self.control == 0 {
            return Err(Error::Budget);
        }
        self.control -= 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    fn hint(n: u8) -> Hint {
        Hint {
            post: [n; 32],
            revision: [n.wrapping_add(1); 32],
        }
    }

    #[test]
    fn errors_duplicates_and_timeouts_finish_without_search_completeness() {
        let mut round = Round::new(&[[1; 32], [2; 32], [3; 32], [4; 32]]).unwrap();
        let raw = encode(&[hint(1)]).unwrap();
        round.response([1; 32], Some(&raw)).unwrap();
        round.response([2; 32], Some(&raw)).unwrap();
        assert_eq!(
            round.response([3; 32], Some(b"poison")),
            Err(Error::Malformed)
        );
        round.response([4; 32], None).unwrap();
        assert!(round.finished());
        assert_eq!(round.hints().count(), 1);
        assert_eq!(round.response([3; 32], Some(&raw)), Err(Error::Peer));
    }

    #[test]
    fn content_flood_cannot_spend_reserved_control_credit() {
        let mut budget = FetchBudget::new(2, 1);
        for _ in 0..2 {
            budget.candidate_attempt().unwrap();
        }
        for _ in 0..100 {
            assert_eq!(budget.candidate_attempt(), Err(Error::Budget));
        }
        budget.control_attempt().unwrap();
        assert_eq!(budget.control_attempt(), Err(Error::Budget));
    }

    #[test]
    fn omitted_or_poisoned_hint_is_only_an_untrusted_reference() {
        let mut round = Round::new(&[[1; 32]]).unwrap();
        round
            .response([1; 32], Some(&encode(&[hint(99)]).unwrap()))
            .unwrap();
        let local_verified_revisions = BTreeSet::<Hint>::new();
        assert_eq!(
            round
                .hints()
                .filter(|id| local_verified_revisions.contains(id))
                .count(),
            0
        );
    }

    proptest! {
        #[test]
        fn canonical_encoding_and_union_ignore_provider_order(ids in prop::collection::btree_set(any::<u8>(), 0..=MAX_HINTS), reverse in any::<bool>()) {
            let hints: Vec<_> = ids.into_iter().map(hint).collect();
            let raw = encode(&hints).unwrap();
            prop_assert_eq!(decode(&raw).unwrap(), hints.clone());
            let mut round = Round::new(&[[1;32],[2;32]]).unwrap();
            let peers = if reverse { [[2;32],[1;32]] } else { [[1;32],[2;32]] };
            for peer in peers { round.response(peer, Some(&raw)).unwrap(); }
            prop_assert_eq!(round.hints().copied().collect::<Vec<_>>(), hints);
        }
        #[test]
        fn arbitrary_response_is_bounded_and_attempt_consumed(raw in prop::collection::vec(any::<u8>(), 0..MAX_RESPONSE_BYTES+100)) {
            let mut round = Round::new(&[[1;32]]).unwrap();
            let _ = round.response([1;32], Some(&raw));
            prop_assert!(round.finished());
            prop_assert!(round.hints().count() <= MAX_HINTS);
            prop_assert_eq!(round.response([1;32], Some(&raw)), Err(Error::Peer));
        }
        #[test]
        fn noncanonical_order_is_rejected(a in any::<u8>()) {
            prop_assert_eq!(encode(&[hint(a),hint(a)]), Err(Error::Malformed));
        }
    }
}
