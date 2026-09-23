//! Local-qualification evidence fabrication only. This module is compiled only
//! by the browser acceptance build and is never part of a production artifact.
//! It grants no authority: the output is fork evidence material, not a usable
//! control, and no retained state is modified.
use super::*;
use crate::protocol::{ControlChange, UnsignedOwnerControl};
use openmls_traits::signatures::Signer;

impl<S: Store> Kernel<S> {
    /// Produce a divergent control validly signed by this owner device at an
    /// already retained floor: the same claims with a different change body,
    /// exactly the equivocation `observe_owner_control` quarantines on. Only an
    /// owner-device session can sign it; a member signer never verifies as the
    /// owner. The retained floor, image and latch are unchanged.
    pub async fn qualification_divergent_control(&mut self, sequence: u64) -> Result<Vec<u8>> {
        let work = self.begin().await?;
        if !work.state.owner_role() {
            return Err(Error::Policy);
        }
        let mut claims = self.control_at(sequence).await?.control.claims().clone();
        claims.change = ControlChange::Membership {
            additions: Vec::new(),
            removals: vec![work.state.owner.claims().device],
        };
        let unsigned = UnsignedOwnerControl::new(claims)?;
        let signature: [u8; 64] = work
            .signer()?
            .sign(&unsigned.signing_bytes())
            .map_err(|_| Error::Mls)?
            .try_into()
            .map_err(|_| Error::Mls)?;
        let signed = unsigned.attach(signature)?;
        Ok(signed.encode())
    }
}
