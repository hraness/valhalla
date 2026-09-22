use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use super::*;
use crate::Error;
use crate::{model::SUITE, protocol::*};

struct Material {
    provider: OpenMlsRustCrypto,
    device: Key,
}
impl Material {
    fn new() -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signer =
            SignatureKeyPair::new(SUITE.signature_algorithm()).map_err(|_| Error::Entropy)?;
        let device = Key::from_bytes(signer.to_public_vec().try_into().map_err(|_| Error::Mls)?)?;
        signer.store(provider.storage()).map_err(|_| Error::Mls)?;
        Ok(Self { provider, device })
    }
}

/// Move-only unpublished owner device. Only public typed account-signing requests
/// are exposed; consuming creation persists the device before any MLS output.
pub struct OwnerDraft {
    material: Material,
    enrollment: UnsignedDeviceEnrollment,
    anchor: UnsignedRoomAnchor,
}
impl OwnerDraft {
    /// Generate a fresh room and MLS device using operating-system entropy.
    pub fn new(account: Key, validity: Validity) -> Result<Self> {
        let material = Material::new()?;
        let enrollment = UnsignedDeviceEnrollment::new(DeviceEnrollmentClaims {
            account,
            device: material.device,
            validity,
        })?;
        let anchor = UnsignedRoomAnchor::new(RoomAnchorClaims {
            room: RoomId::from_bytes(codec::random()?)?,
            owner_account: account,
            owner_device: material.device,
        })?;
        Ok(Self {
            material,
            enrollment,
            anchor,
        })
    }
    /// Exact public request to sign with the independently held account key.
    pub fn enrollment_request(&self) -> &UnsignedDeviceEnrollment {
        &self.enrollment
    }
    /// Exact public room-anchor request to sign with the same account key.
    pub fn anchor_request(&self) -> &UnsignedRoomAnchor {
        &self.anchor
    }
    /// Authenticate and retain this context before consuming creation. An
    /// uncertain initializer must reopen this exact context and storage key.
    pub fn context(&self, anchor: &SignedRoomAnchor) -> Result<Context> {
        if anchor.claims() != self.anchor.claims() {
            return Err(Error::Scope);
        }
        let anchor = anchor.verify()?;
        Ok(Context {
            scope: anchor.scope(),
            account: anchor.claims().owner_account,
            device: self.material.device,
        })
    }
    /// Atomically create only an unused backend namespace. This never restores
    /// from an account key or silently replaces an existing ratchet.
    pub async fn create<S: Store>(
        self,
        store: S,
        key: &StorageKey,
        enrollment: SignedDeviceEnrollment,
        anchor: SignedRoomAnchor,
        now: u64,
    ) -> Result<Kernel<S>> {
        self.context(&anchor)?;
        if enrollment.claims() != self.enrollment.claims() {
            return Err(Error::Scope);
        }
        let local = enrollment.verify()?;
        local.claims().validity.check_at(now)?;
        let state = initial(
            Phase::OwnerGenesis,
            anchor.verify()?,
            local.clone(),
            local,
            Vec::new(),
            now,
        )?;
        let work = Working {
            state,
            provider: self.material.provider,
        };
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(4, 32))
            .build();
        MlsGroup::new_with_group_id(
            &work.provider,
            &work.signer()?,
            &config,
            GroupId::from_slice(work.state.context().scope.room.as_bytes()),
            work.credential(),
        )
        .map_err(|_| Error::Mls)?;
        initialize(store, key, work).await
    }
}

/// Move-only fresh joining device bound to an independently selected anchor and
/// owner enrollment. Account authentication alone does not authorize room entry.
pub struct MemberDraft {
    material: Material,
    enrollment: UnsignedDeviceEnrollment,
    anchor: VerifiedRoomAnchor,
    owner: VerifiedDeviceEnrollment,
    successions: Vec<VerifiedOwnerSuccession>,
    clock: u64,
}
impl MemberDraft {
    /// Generate a fresh device only for an explicitly selected private scope.
    /// Never use this constructor as key-only recovery of a previous device.
    pub fn new(
        scope: PrivateRoomScope,
        anchor: SignedRoomAnchor,
        owner: SignedDeviceEnrollment,
        account: Key,
        validity: Validity,
        now: u64,
    ) -> Result<Self> {
        Self::checked(scope, anchor, owner, Vec::new(), account, validity, now)
    }
    /// Fresh device for a room whose owner authority already moved: the exact
    /// retained grant chain must prove the selected owner against the anchor.
    /// Supplying an empty or unrelated chain refuses; it never downgrades to
    /// the anchor's original device.
    pub fn new_succeeded(
        scope: PrivateRoomScope,
        anchor: SignedRoomAnchor,
        owner: SignedDeviceEnrollment,
        successions: Vec<SignedOwnerSuccession>,
        account: Key,
        validity: Validity,
        now: u64,
    ) -> Result<Self> {
        let grants = successions
            .iter()
            .map(|grant| grant.verify().map_err(Error::from))
            .collect::<Result<Vec<_>>>()?;
        Self::checked(scope, anchor, owner, grants, account, validity, now)
    }
    fn checked(
        scope: PrivateRoomScope,
        anchor: SignedRoomAnchor,
        owner: SignedDeviceEnrollment,
        successions: Vec<VerifiedOwnerSuccession>,
        account: Key,
        validity: Validity,
        now: u64,
    ) -> Result<Self> {
        let anchor = anchor.verify()?;
        let owner = owner.verify()?;
        if anchor.scope() != scope
            || anchor.claims().owner_account != owner.claims().account
            || crate::model::check_succession_chain(&anchor, &successions)? != owner.claims().device
        {
            return Err(Error::Scope);
        }
        owner.claims().validity.check_at(now)?;
        validity.check_at(now)?;
        let material = Material::new()?;
        if material.device == owner.claims().device {
            return Err(Error::Policy);
        }
        let enrollment = UnsignedDeviceEnrollment::new(DeviceEnrollmentClaims {
            account,
            device: material.device,
            validity,
        })?;
        Ok(Self {
            material,
            enrollment,
            anchor,
            owner,
            successions,
            clock: now,
        })
    }
    /// Exact public enrollment request for the separately held account key.
    pub fn enrollment_request(&self) -> &UnsignedDeviceEnrollment {
        &self.enrollment
    }
    /// Retain this exact context before consuming initialization.
    pub fn context(&self) -> Context {
        Context {
            scope: self.anchor.scope(),
            account: self.enrollment.claims().account,
            device: self.material.device,
        }
    }
    /// Persist a fresh device before generating or releasing its one KeyPackage.
    /// It remains outside the room until a verified owner Welcome is committed.
    pub async fn initialize<S: Store>(
        self,
        store: S,
        key: &StorageKey,
        enrollment: SignedDeviceEnrollment,
        now: u64,
    ) -> Result<Kernel<S>> {
        if now < self.clock {
            return Err(Error::Time);
        }
        if enrollment.claims() != self.enrollment.claims() {
            return Err(Error::Scope);
        }
        let local = enrollment.verify()?;
        local.claims().validity.check_at(now)?;
        self.owner.claims().validity.check_at(now)?;
        let state = initial(
            Phase::AwaitingWelcome,
            self.anchor,
            local,
            self.owner,
            self.successions,
            now,
        )?;
        initialize(
            store,
            key,
            Working {
                state,
                provider: self.material.provider,
            },
        )
        .await
    }
}
#[allow(clippy::too_many_arguments)]
fn initial(
    phase: Phase,
    anchor: VerifiedRoomAnchor,
    local: VerifiedDeviceEnrollment,
    owner: VerifiedDeviceEnrollment,
    successions: Vec<VerifiedOwnerSuccession>,
    now: u64,
) -> Result<State> {
    Ok(State {
        revision: 0,
        phase,
        epoch: 0,
        clock: now,
        floor: ControlFloor::new(0, None)?,
        outbox: 0,
        inbox: 0,
        anchor,
        local,
        roster: vec![owner.clone()],
        successions,
        owner,
        base: ControlFloor::new(0, None)?,
        checkpoint: None,
        fault: None,
        key_package: None,
        joined: None,
        records: Vec::new(),
        offers: Vec::new(),
        contact: None,
    })
}
