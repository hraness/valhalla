//! Borrowed trusted-host reads over the daemon's existing room custody.
//!
//! These typed methods are not agent tools or permission to publish retained
//! ciphertext. They share the room controller and expose no key or kernel.

use super::{Result, RoomSession};
use vhalla_private_kernel::{CommittedOutbox, OperationId};

impl RoomSession {
    /// Return only an already committed send matching the complete original
    /// operation, epoch, roster and body. A changed membership does not recreate
    /// the old draft or authorize publication to a new roster. Missing retained
    /// output is not permission to reset an operation or signing state.
    pub async fn retained_send(
        &mut self,
        operation: OperationId,
        epoch: u64,
        roster: [u8; 32],
        body: &[u8],
    ) -> Result<Option<CommittedOutbox>> {
        Ok(self
            .live_mut()?
            .kernel
            .retained_send(operation, epoch, roster, body)
            .await?)
    }
}
