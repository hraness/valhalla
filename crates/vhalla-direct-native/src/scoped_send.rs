//! Agent sends may use only the exact policy and author that were authorized.

use crate::{codec::EVENT, Error, OperationOutcome, RoomSession};
use vhalla_direct_room::{PolicyPosition, UnsignedEvent};

impl RoomSession {
    /// Send or retry only within an exact current policy and local author scope.
    ///
    /// A retained operation also has to belong to this policy and author before
    /// any signature or completion is attempted. In particular, a new grant
    /// cannot finish an older-policy reservation or retrieve an older-policy
    /// completion by choosing its operation ID. The trusted [`Self::send`]
    /// recovery API intentionally retains its historical retry behavior.
    ///
    /// Changed current authority returns [`Error::ReadOnly`]. A retained
    /// operation from a different scope or of another kind returns
    /// [`Error::OperationConflict`] without changing its durable state.
    pub fn send_scoped(
        &mut self,
        expected: PolicyPosition,
        author: [u8; 32],
        operation: [u8; 16],
        text: &str,
        created_at: u64,
    ) -> crate::Result<OperationOutcome> {
        let status = self.status()?;
        if status.policy != expected
            || status.author != author
            || status.pending_policy.is_some()
            || status.owner_forked
            || status.capacity_fenced
            || status.author_custody_lost
            || status.owner_custody_lost
        {
            return Err(Error::ReadOnly);
        }
        if let Some(reservation) = self.reservation(operation)? {
            if reservation.kind != EVENT {
                return Err(Error::OperationConflict);
            }
            let unsigned = UnsignedEvent::decode(&reservation.unsigned)?;
            if unsigned.claims().policy != expected.id || unsigned.claims().author != author {
                return Err(Error::OperationConflict);
            }
        }
        self.send(operation, text, created_at)
    }
}

#[cfg(test)]
#[path = "scoped_send_tests.rs"]
mod tests;
