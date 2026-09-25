//! One-use owner action review bound to the exact accepted membership.
use crate::private_wire::{OwnerConsent, Request};
use vhalla_private_kernel::{
    protocol::{Key, Validity},
    storage::Store,
    Error, Kernel,
};

#[derive(Default)]
pub(crate) struct OwnerActions(Option<OwnerConsent>);
impl OwnerActions {
    pub fn before(&mut self, request: &Request) {
        if !matches!(request, Request::Remove { .. } | Request::Succeed { .. }) {
            self.0 = None;
        }
    }
    pub async fn review<S: Store>(
        &mut self,
        kernel: &mut Kernel<S>,
        target: Key,
        succession: bool,
        now: impl FnOnce() -> Result<u64, Error>,
    ) -> Result<OwnerConsent, Error> {
        self.0 = None;
        let view = kernel.membership().await?;
        let now = now()?;
        let status = view.status();
        let owner = view.owner().claims();
        if status.quarantined
            || status.context.account != owner.account
            || status.context.device != owner.device
        {
            return Err(Error::Policy);
        }
        owner.validity.check_at(now)?;
        let target = view
            .members()
            .iter()
            .find(|member| member.claims().device == target)
            .ok_or(Error::Policy)?
            .clone();
        let claim = target.claims();
        if claim.device == owner.device || (succession && claim.account != owner.account) {
            return Err(Error::Policy);
        }
        if succession {
            claim.validity.check_at(now)?;
        }
        let end = now
            .checked_add(300)
            .ok_or(Error::Time)?
            .min(owner.validity.expires_at());
        let end = if succession {
            end.min(claim.validity.expires_at())
        } else {
            end
        };
        let consent = OwnerConsent {
            status,
            target,
            succession,
            validity: Validity::new(now, end)?,
        };
        self.0 = Some(consent.clone());
        Ok(consent)
    }
    pub async fn confirm<S: Store>(
        &mut self,
        kernel: &mut Kernel<S>,
        target: Key,
        succession: bool,
        now: impl FnOnce() -> Result<u64, Error>,
    ) -> Result<OwnerConsent, Error> {
        let consent = self.0.take().ok_or(Error::Policy)?;
        let view = kernel.membership().await?;
        consent.validity.check_at(now()?)?;
        if consent.status != view.status()
            || consent.target.claims().device != target
            || consent.succession != succession
            || !view.members().contains(&consent.target)
        {
            return Err(Error::Policy);
        }
        Ok(consent)
    }
}
