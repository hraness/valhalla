use crate::*;

/// Account-attributed creation context. No local trust or membership is implied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomAnchorClaims {
    /// Fresh full private room ID; generate independently of public directories.
    pub room: RoomId,
    /// Claimed room owner account and exact signing key.
    pub owner_account: Key,
    /// Initially designated control device; enrollment must be checked separately.
    pub owner_device: Key,
}
impl Record for RoomAnchorClaims {
    const KIND: u8 = 1;
    fn signer(&self) -> Key {
        self.owner_account
    }
    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.extend(self.room.0);
        out.extend(self.owner_account.0);
        out.extend(self.owner_device.0);
        out.extend(CIPHERSUITE.to_be_bytes());
        out.push(MEMBERSHIP_POLICY);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let claims = Self {
            room: RoomId::from_bytes(r.array()?)?,
            owner_account: r.key()?,
            owner_device: r.key()?,
        };
        if u16::from_be_bytes(r.array()?) != CIPHERSUITE || r.byte()? != MEMBERSHIP_POLICY {
            return Err(Error::Protocol);
        }
        Ok(claims)
    }
}
signed_record!(
    RoomAnchorClaims,
    UnsignedRoomAnchor,
    SignedRoomAnchor,
    VerifiedRoomAnchor,
    AnchorId,
    b"vhalla/private-room/anchor-id/v1\0"
);
impl VerifiedRoomAnchor {
    /// Exact context of these authenticated bytes, not an independently trusted pin.
    pub fn scope(&self) -> PrivateRoomScope {
        PrivateRoomScope {
            room: self.claims().room,
            anchor: self.id(),
        }
    }
}

/// Account assertion binding a device key during an explicit validity interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceEnrollmentClaims {
    /// Account making and signing the assertion.
    pub account: Key,
    /// Exact device MLS signature key; no secret or endpoint is carried.
    pub device: Key,
    /// Signed interval; the caller must enforce it using its trusted clock.
    pub validity: Validity,
}
impl Record for DeviceEnrollmentClaims {
    const KIND: u8 = 2;
    fn signer(&self) -> Key {
        self.account
    }
    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.extend(self.account.0);
        out.extend(self.device.0);
        put_validity(out, self.validity);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            account: r.key()?,
            device: r.key()?,
            validity: r.validity()?,
        })
    }
}
signed_record!(
    DeviceEnrollmentClaims,
    UnsignedDeviceEnrollment,
    SignedDeviceEnrollment,
    VerifiedDeviceEnrollment,
    EnrollmentId,
    b"vhalla/private-room/enrollment-id/v1\0"
);

/// Device-signed invitation claims. Only retained policy can authorize its issuer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationClaims {
    /// Full independently selected private room and signed anchor.
    pub scope: PrivateRoomScope,
    /// Claimed current owner control device; verification alone does not grant it.
    pub owner_device: Key,
    /// Exact intended recipient account.
    pub recipient_account: Key,
    /// Exact intended recipient MLS device signature key.
    pub recipient_device: Key,
    /// Hash of exact recipient KeyPackage bytes, whose MLS validity is separate.
    pub key_package: KeyPackageDigest,
    /// Caller-generated one-use nonce; durable consumption is mandatory externally.
    pub nonce: Nonce,
    /// Signed interval checked externally against a trustworthy clock.
    pub validity: Validity,
    /// Exact required control floor; no automatic rebase or currentness claim.
    pub floor: ControlFloor,
}
impl Record for InvitationClaims {
    const KIND: u8 = 3;
    fn signer(&self) -> Key {
        self.owner_device
    }
    fn validate(&self) -> Result<(), Error> {
        self.floor.next_sequence()?;
        Ok(())
    }
    fn write(&self, out: &mut Vec<u8>) {
        put_scope(out, self.scope);
        out.extend(self.owner_device.0);
        out.extend(self.recipient_account.0);
        out.extend(self.recipient_device.0);
        out.extend(self.key_package.0);
        out.extend(self.nonce.0);
        put_validity(out, self.validity);
        put_floor(out, self.floor);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            scope: r.scope()?,
            owner_device: r.key()?,
            recipient_account: r.key()?,
            recipient_device: r.key()?,
            key_package: KeyPackageDigest::from_bytes(r.array()?)?,
            nonce: Nonce::from_bytes(r.array()?)?,
            validity: r.validity()?,
            floor: r.floor()?,
        })
    }
}
signed_record!(
    InvitationClaims,
    UnsignedInvitation,
    SignedInvitation,
    VerifiedInvitation,
    InvitationId,
    b"vhalla/private-room/invitation-id/v1\0"
);

/// Complete exact artifact and identity binding for one intended addition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Addition {
    /// Exact signed owner-device invitation required by this addition.
    pub invitation: InvitationId,
    /// Full account bound by that invitation and a verified enrollment.
    pub account: Key,
    /// Full MLS device key; defines canonical addition ordering.
    pub device: Key,
    /// Exact KeyPackage commitment for this recipient.
    pub key_package: KeyPackageDigest,
    /// Exact MLS-wrapped Welcome commitment, possibly shared by several additions.
    pub welcome: WelcomeDigest,
}
impl Addition {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend(self.invitation.0);
        out.extend(self.account.0);
        out.extend(self.device.0);
        out.extend(self.key_package.0);
        out.extend(self.welcome.0);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            invitation: InvitationId::from_bytes(r.array()?)?,
            account: r.key()?,
            device: r.key()?,
            key_package: KeyPackageDigest::from_bytes(r.array()?)?,
            welcome: WelcomeDigest::from_bytes(r.array()?)?,
        })
    }
}

/// Closed version-one control vocabulary; real MLS proposals must match exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlChange {
    /// At least one membership change, canonically sorted by full device key.
    Membership {
        /// Strictly increasing device keys; no repeated invitation or KeyPackage.
        additions: Vec<Addition>,
        /// Strictly increasing device keys; cannot also occur in additions.
        removals: Vec<Key>,
    },
    /// Explicit owner leaf update with no membership changes. Does not authorize
    /// an owner/device handoff; the adapter must inspect the staged MLS update.
    OwnerUpdate,
    /// Anchor-authorized owner-device handoff. The carrying control is still
    /// predecessor-signed; the grant is verified on decode but authorizes
    /// nothing until the kernel pins it to the retained floor and roster.
    Succession {
        /// Complete account-signed grant bound to this exact control sequence.
        grant: Box<SignedOwnerSuccession>,
    },
}
impl ControlChange {
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::OwnerUpdate => Ok(()),
            Self::Succession { grant } => grant.verify().map(|_| ()),
            Self::Membership {
                additions,
                removals,
            } => {
                if additions.len() > MAX_CHANGES
                    || removals.len() > MAX_CHANGES
                    || additions.len() + removals.len() > MAX_CHANGES
                {
                    return Err(Error::Bounds);
                }
                if additions.is_empty() && removals.is_empty() {
                    return Err(Error::Membership);
                }
                if additions.windows(2).any(|w| w[0].device >= w[1].device)
                    || removals.windows(2).any(|w| w[0] >= w[1])
                {
                    return Err(Error::Membership);
                }
                for (index, add) in additions.iter().enumerate() {
                    if removals.contains(&add.device)
                        || additions[..index].iter().any(|prior| {
                            prior.invitation == add.invitation
                                || prior.key_package == add.key_package
                        })
                    {
                        return Err(Error::Membership);
                    }
                }
                Ok(())
            }
        }
    }
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::OwnerUpdate => out.extend([1, 0, 0]),
            Self::Succession { grant } => {
                out.extend([2, 0, 0]);
                let raw = grant.encode();
                out.extend((raw.len() as u32).to_be_bytes());
                out.extend(raw);
            }
            Self::Membership {
                additions,
                removals,
            } => {
                out.extend([0, additions.len() as u8, removals.len() as u8]);
                for addition in additions {
                    addition.write(out);
                }
                for key in removals {
                    out.extend(key.0);
                }
            }
        }
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let kind = r.byte()?;
        let additions = usize::from(r.byte()?);
        let removals = usize::from(r.byte()?);
        // Fixed count limits precede multiplication, allocation and iteration.
        if additions > MAX_CHANGES || removals > MAX_CHANGES || additions + removals > MAX_CHANGES {
            return Err(Error::Bounds);
        }
        match kind {
            1 if additions == 0 && removals == 0 => Ok(Self::OwnerUpdate),
            2 if additions == 0 && removals == 0 => Ok(Self::Succession {
                grant: Box::new(SignedOwnerSuccession::decode(r.blob(MAX_RECORD_BYTES)?)?),
            }),
            0 => {
                if r.0.len() < additions * 160 + removals * 32 + 64 {
                    return Err(Error::Encoding);
                }
                let mut added = Vec::with_capacity(additions);
                for _ in 0..additions {
                    added.push(Addition::read(r)?);
                }
                let mut removed = Vec::with_capacity(removals);
                for _ in 0..removals {
                    removed.push(r.key()?);
                }
                Ok(Self::Membership {
                    additions: added,
                    removals: removed,
                })
            }
            1 | 2 => Err(Error::Membership),
            _ => Err(Error::Protocol),
        }
    }
}

/// Attributed proposed control transition, requiring independent retained-state
/// ordering and owner-device authorization before any MLS merge or persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerControlClaims {
    /// Exact private room and signed anchor.
    pub scope: PrivateRoomScope,
    /// Claimed current control device and signature key.
    pub owner_device: Key,
    /// Exact claimed predecessor, absent only at genesis.
    pub parent: ControlFloor,
    /// Expected MLS epoch before this transition.
    pub prior_epoch: u64,
    /// Must be exactly the checked next MLS epoch.
    pub next_epoch: u64,
    /// Commitment to the exact MLS-wrapped Commit bytes.
    pub commit: CommitDigest,
    /// Bounded canonical membership delta or explicit owner update.
    pub change: ControlChange,
}
impl OwnerControlClaims {
    /// Checked control sequence, exactly predecessor plus one.
    pub fn sequence(&self) -> Result<u64, Error> {
        self.parent.next_sequence()
    }
}
impl Record for OwnerControlClaims {
    const KIND: u8 = 4;
    fn signer(&self) -> Key {
        self.owner_device
    }
    fn validate(&self) -> Result<(), Error> {
        self.parent.next_sequence()?;
        if self.prior_epoch.checked_add(1) != Some(self.next_epoch) {
            return Err(Error::Sequence);
        }
        self.change.validate()
    }
    fn write(&self, out: &mut Vec<u8>) {
        put_scope(out, self.scope);
        out.extend(self.owner_device.0);
        put_floor(out, self.parent);
        out.extend(self.prior_epoch.to_be_bytes());
        out.extend(self.next_epoch.to_be_bytes());
        out.extend(self.commit.0);
        self.change.write(out);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            scope: r.scope()?,
            owner_device: r.key()?,
            parent: r.floor()?,
            prior_epoch: r.u64()?,
            next_epoch: r.u64()?,
            commit: CommitDigest::from_bytes(r.array()?)?,
            change: ControlChange::read(r)?,
        })
    }
}
signed_record!(
    OwnerControlClaims,
    UnsignedOwnerControl,
    SignedOwnerControl,
    VerifiedOwnerControl,
    ControlId,
    b"vhalla/private-room/control-id/v1\0"
);

/// Account-signed owner authority handoff to a second enrolled owner device.
///
/// The grant alone authorizes nothing and changes no MLS state: a member applies
/// it only inside the exact next predecessor-signed control, after the kernel
/// pins the scope, claimed account, predecessor, retained floor, rostered
/// successor enrollment and caller clock. It never upgrades the anchor and can
/// never add a member, remove a device or rewrite an earlier control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSuccessionClaims {
    /// Exact private room and signed anchor.
    pub scope: PrivateRoomScope,
    /// Claimed owner account and signature key; must equal the anchored account.
    pub account: Key,
    /// Owner device whose sole control authority ends at this grant's control.
    pub predecessor: Key,
    /// Complete enrolled successor already admitted as an ordinary member.
    pub successor: SignedDeviceEnrollment,
    /// Exact sequence of the control carrying this grant. Later controls must
    /// be signed by the successor; the grant cannot replay at another floor.
    pub sequence: u64,
    /// Signed apply window; the caller checks it against a trustworthy clock.
    pub validity: Validity,
}
impl Record for OwnerSuccessionClaims {
    const KIND: u8 = 5;
    fn signer(&self) -> Key {
        self.account
    }
    fn validate(&self) -> Result<(), Error> {
        // The embedded account/device grant must be authentic on its own; an
        // outer account signature can never hide an invalid nested enrollment.
        let successor = self.successor.verify()?;
        if self.sequence == 0 {
            return Err(Error::Sequence);
        }
        if successor.claims().account != self.account
            || successor.claims().device == self.predecessor
        {
            return Err(Error::Membership);
        }
        Ok(())
    }
    fn write(&self, out: &mut Vec<u8>) {
        put_scope(out, self.scope);
        out.extend(self.account.0);
        out.extend(self.predecessor.0);
        let enrollment = self.successor.encode();
        out.extend((enrollment.len() as u32).to_be_bytes());
        out.extend(enrollment);
        out.extend(self.sequence.to_be_bytes());
        put_validity(out, self.validity);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            scope: r.scope()?,
            account: r.key()?,
            predecessor: r.key()?,
            successor: SignedDeviceEnrollment::decode(r.blob(MAX_RECORD_BYTES)?)?,
            sequence: r.u64()?,
            validity: r.validity()?,
        })
    }
}
signed_record!(
    OwnerSuccessionClaims,
    UnsignedOwnerSuccession,
    SignedOwnerSuccession,
    VerifiedOwnerSuccession,
    SuccessionId,
    b"vhalla/private-room/succession-id/v1\0"
);
