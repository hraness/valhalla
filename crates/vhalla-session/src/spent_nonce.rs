//! Bounded, single-use invitation nonce tracking.
//!
//! Verification and spending are deliberately separate operations: callers
//! first verify an [`Invitation`](crate::Invitation), then consume its nonce
//! at the local authorization boundary. The guard has no clock, storage, or
//! network behavior. Its explicit capacity is a hard admission bound; once it
//! is full, a new nonce is rejected without changing state.

use alloc::collections::BTreeSet;

/// A bounded set of invitation nonces that have already been consumed.
///
/// The guard is move-only by default and requires exclusive `&mut self` access
/// for consumption. This makes the check-and-insert operation atomic within a
/// caller's event loop: no successful path can observe a nonce as unused and
/// then race another insertion. If a shared concurrent guard is needed, the
/// caller must place this value behind its own platform lock.
#[derive(Debug, Default)]
pub struct SpentInvitationNonces {
    capacity: usize,
    spent: BTreeSet<[u8; 32]>,
}

/// Failure to consume an invitation nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpendError {
    /// The all-zero value is reserved and cannot be consumed.
    Malformed,
    /// This nonce was consumed previously.
    AlreadySpent,
    /// The explicit guard capacity is exhausted. State is unchanged.
    Capacity,
}

impl SpentInvitationNonces {
    /// Create an empty guard with a hard maximum number of distinct nonces.
    ///
    /// A capacity of zero is valid and creates a deny-all guard. Capacity is
    /// not rounded or expanded internally, and no allocation occurs here.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            spent: BTreeSet::new(),
        }
    }

    /// Return the configured maximum number of distinct consumed nonces.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Return the number of distinct nonces currently consumed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spent.len()
    }

    /// Return whether no nonce has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }

    /// Check whether a nonce is already spent without changing state.
    #[must_use]
    pub fn contains(&self, nonce: &[u8; 32]) -> bool {
        self.spent.contains(nonce)
    }

    /// Atomically consume one nonce.
    ///
    /// Duplicate consumption and capacity overflow are rejected before any
    /// mutation. In particular, a full guard never evicts an older nonce and
    /// never admits a new one.
    pub fn consume(&mut self, nonce: [u8; 32]) -> Result<(), SpendError> {
        if nonce == [0; 32] {
            return Err(SpendError::Malformed);
        }
        if self.spent.contains(&nonce) {
            return Err(SpendError::AlreadySpent);
        }
        if self.spent.len() >= self.capacity {
            return Err(SpendError::Capacity);
        }
        // The capacity check above ensures the set cannot grow beyond the
        // caller-declared bound. BTreeSet insertion is the sole mutation.
        self.spent.insert(nonce);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{SpendError, SpentInvitationNonces};
    use alloc::format;
    use alloc::string::ToString;
    use hegel::generators as gs;
    use hegel::TestCase;

    /// Guard consumption under Hegel's interleaved draw model: each nonce is
    /// drawn inside the loop while the spent set mutates across steps.
    #[hegel::test]
    fn consume_is_idempotently_rejected_and_never_exceeds_capacity(tc: TestCase) {
        let capacity = tc.draw(gs::integers::<usize>().max_value(31));
        let steps = tc.draw(gs::integers::<usize>().max_value(95));
        let mut guard = SpentInvitationNonces::new(capacity);
        for _ in 0..steps {
            let nonce: [u8; 32] = tc.draw(gs::arrays(gs::integers::<u8>()));
            let before_len = guard.len();
            let already = guard.contains(&nonce);
            let result = guard.consume(nonce);
            assert!(guard.len() <= capacity);
            if nonce == [0; 32] {
                assert_eq!(result, Err(SpendError::Malformed));
                assert_eq!(guard.len(), before_len);
            } else if already {
                assert_eq!(result, Err(SpendError::AlreadySpent));
                assert_eq!(guard.len(), before_len);
            } else if before_len >= capacity {
                assert_eq!(result, Err(SpendError::Capacity));
                assert_eq!(guard.len(), before_len);
                assert!(!guard.contains(&nonce));
            } else {
                assert_eq!(result, Ok(()));
                assert_eq!(guard.len(), before_len + 1);
                assert!(guard.contains(&nonce));
            }
        }
    }

    #[test]
    fn full_guard_preserves_existing_nonce_and_rejects_new_nonce() {
        let mut guard = SpentInvitationNonces::new(1);
        let first = [1; 32];
        let second = [2; 32];
        assert_eq!(guard.consume(first), Ok(()));
        assert_eq!(guard.consume(second), Err(SpendError::Capacity));
        assert_eq!(guard.consume(first), Err(SpendError::AlreadySpent));
        assert_eq!(guard.len(), 1);
        assert!(guard.contains(&first));
        assert!(!guard.contains(&second));
    }

    #[test]
    fn zero_nonce_is_rejected_without_using_capacity() {
        let mut guard = SpentInvitationNonces::new(1);
        assert_eq!(guard.consume([0; 32]), Err(SpendError::Malformed));
        assert_eq!(guard.len(), 0);
        assert_eq!(guard.consume([7; 32]), Ok(()));
        assert_eq!(guard.consume([0; 32]), Err(SpendError::Malformed));
        assert_eq!(guard.len(), 1);
    }
}
