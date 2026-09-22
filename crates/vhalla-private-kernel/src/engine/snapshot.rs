use super::*;
use crate::protocol::{SignedDeviceEnrollment, SignedOwnerSuccession, SignedRoomAnchor};

/// Authenticated, bounded local membership view for a trusted room controller.
/// This is the last accepted state, not a claim of global freshness. In pending,
/// removed or quarantined phases it must not be presented as permission to send.
/// Account/device identifiers and enrollment times are private room metadata.
pub struct MembershipSnapshot {
    status: Status,
    anchor: SignedRoomAnchor,
    local: SignedDeviceEnrollment,
    owner: SignedDeviceEnrollment,
    successions: Vec<SignedOwnerSuccession>,
    members: Vec<SignedDeviceEnrollment>,
}
impl MembershipSnapshot {
    pub(super) fn from_state(state: &State) -> Self {
        Self {
            status: state.status(),
            anchor: state.anchor.signed().clone(),
            local: state.local.signed().clone(),
            owner: state.owner.signed().clone(),
            successions: state
                .successions
                .iter()
                .map(|grant| grant.signed().clone())
                .collect(),
            members: state.roster.iter().map(|e| e.signed().clone()).collect(),
        }
    }
    /// Exact accepted context, epoch, roster commitment and lifecycle state.
    pub const fn status(&self) -> Status {
        self.status
    }
    /// Account-signed room anchor, for an explicitly confidential invitation path.
    pub fn anchor(&self) -> &SignedRoomAnchor {
        &self.anchor
    }
    /// This device's enrollment; it may be expired or no longer a member.
    pub fn local(&self) -> &SignedDeviceEnrollment {
        &self.local
    }
    /// Exact anchored owner's latest locally accepted enrollment.
    pub fn owner(&self) -> &SignedDeviceEnrollment {
        &self.owner
    }
    /// Complete accepted account-authorized handoff chain, in ascending control
    /// order. Together with `anchor` it proves `owner`; supply it unchanged to
    /// `MemberDraft::new_succeeded`. Empty while the anchor device leads.
    pub fn successions(&self) -> &[SignedOwnerSuccession] {
        &self.successions
    }
    /// At most sixteen enrolled devices in the last locally accepted roster.
    /// Display complete account/device keys and validity before authorizing a
    /// release; a matching account alone does not confer owner powers.
    pub fn members(&self) -> &[SignedDeviceEnrollment] {
        &self.members
    }
}

impl<S: Store> Kernel<S> {
    /// Authenticate the exact retained image before exposing its membership.
    /// Read-only inspection remains available after removal or fork quarantine.
    /// A stale writer, failed read or canceled await requires exact-store reopen.
    pub async fn membership(&mut self) -> Result<MembershipSnapshot> {
        let work = self.begin().await?;
        let snapshot = MembershipSnapshot {
            status: work.state.status(),
            anchor: work.state.anchor.signed().clone(),
            local: work.state.local.signed().clone(),
            owner: work.state.owner.signed().clone(),
            successions: work
                .state
                .successions
                .iter()
                .map(|grant| grant.signed().clone())
                .collect(),
            members: work
                .state
                .roster
                .iter()
                .map(|e| e.signed().clone())
                .collect(),
        };
        self.needs_reopen = false;
        Ok(snapshot)
    }
}
