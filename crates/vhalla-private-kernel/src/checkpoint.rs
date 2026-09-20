//! Bounded owner-signed roster endorsement for a genuinely fresh joining device.
//!
//! A checkpoint verifies signature and canonical bindings only. The kernel must
//! independently pin the owner/anchor, match the exact invitation and real MLS
//! Commit/Welcome/GroupContext, check enrollment validity and inspect the staged
//! roster. Existing members cannot use it to skip their retained control floor.
//! The roster and invitation bindings are private metadata, not public exports.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::{
    codec::{Reader, Writer},
    protocol::{
        AnchorId, CommitDigest, ControlFloor, ControlId, InvitationId, Key, PrivateRoomScope,
        RoomId, SignedDeviceEnrollment, VerifiedDeviceEnrollment, WelcomeDigest,
    },
    Error, Result, MAX_MEMBERS,
};

pub(crate) const MAX_CHECKPOINT_BYTES: usize = 4096;
const MAGIC: &[u8] = b"VHPKROSTER\x01";
const DOMAIN: &[u8] = b"vhalla/private-kernel/roster-checkpoint/v1\0";
const SIGNATURE_BYTES: usize = 64;
// The protocol v1 enrollment is a fixed 6-byte prefix/kind, two full keys,
// a 16-byte validity interval and a 64-byte signature. Reuse its encoder; this
// limit rejects an impossible declared nested allocation before decoding it.
const ENROLLMENT_BYTES: usize = 150;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CheckpointClaims {
    pub(crate) scope: PrivateRoomScope,
    pub(crate) owner: Key,
    pub(crate) invitation: InvitationId,
    pub(crate) parent: ControlFloor,
    pub(crate) accepted: ControlFloor,
    pub(crate) epoch: u64,
    pub(crate) commit: CommitDigest,
    pub(crate) welcome: WelcomeDigest,
    /// Digest of the exact serialized staged MLS GroupContext, checked by caller.
    pub(crate) group_context: [u8; 32],
    /// Strictly verified account enrollments in increasing full device-key order.
    pub(crate) roster: Vec<VerifiedDeviceEnrollment>,
}
impl CheckpointClaims {
    fn validate(&self) -> Result<()> {
        if self.roster.is_empty() || self.roster.len() > MAX_MEMBERS {
            return Err(Error::Bounds);
        }
        if self.accepted.sequence() != self.parent.next_sequence()?
            || self.epoch != self.accepted.sequence()
            || self.group_context == [0; 32]
        {
            return Err(Error::Encoding);
        }
        let mut previous = None;
        let mut owner_present = false;
        for enrollment in &self.roster {
            let device = enrollment.claims().device;
            if previous.is_some_and(|prior| prior >= device) {
                return Err(Error::Encoding);
            }
            previous = Some(device);
            owner_present |= device == self.owner;
        }
        if !owner_present {
            return Err(Error::Policy);
        }
        Ok(())
    }
    fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut w = Writer::new(MAGIC, MAX_CHECKPOINT_BYTES - SIGNATURE_BYTES)?;
        w.put(self.scope.room.as_bytes())?;
        w.put(self.scope.anchor.as_bytes())?;
        w.put(self.owner.as_bytes())?;
        w.put(self.invitation.as_bytes())?;
        put_floor(&mut w, self.parent)?;
        put_floor(&mut w, self.accepted)?;
        w.u64(self.epoch)?;
        w.put(self.commit.as_bytes())?;
        w.put(self.welcome.as_bytes())?;
        w.put(&self.group_context)?;
        w.byte(u8::try_from(self.roster.len()).map_err(|_| Error::Bounds)?)?;
        for enrollment in &self.roster {
            // VerifiedDeviceEnrollment has private construction; no caller can
            // supply an unchecked signature through this constructor.
            w.blob(&enrollment.signed().encode(), ENROLLMENT_BYTES)?;
        }
        Ok(w.finish())
    }
}

/// Prepared attribution bytes only; this does not grant membership or authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnsignedCheckpoint {
    claims: CheckpointClaims,
}
impl UnsignedCheckpoint {
    pub(crate) fn new(claims: CheckpointClaims) -> Result<Self> {
        claims.unsigned_bytes()?;
        Ok(Self { claims })
    }
    pub(crate) fn signing_bytes(&self) -> Result<Vec<u8>> {
        signing_bytes(&self.claims)
    }
    /// Only a strict signature from the exact claimed owner device can attach.
    /// The current owner's authority is a separate stateful kernel check.
    pub(crate) fn attach(&self, signature: [u8; 64]) -> Result<Checkpoint> {
        verify(&self.claims, signature)?;
        Ok(Checkpoint {
            claims: self.claims.clone(),
            signature,
        })
    }
}

/// Strictly signed canonical checkpoint, with no unchecked public constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Checkpoint {
    claims: CheckpointClaims,
    signature: [u8; 64],
}
impl Checkpoint {
    pub(crate) fn claims(&self) -> &CheckpointClaims {
        &self.claims
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut raw = self.claims.unsigned_bytes()?;
        raw.extend(self.signature);
        Ok(raw)
    }
    pub(crate) fn decode(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw, MAGIC, MAX_CHECKPOINT_BYTES)?;
        let scope = PrivateRoomScope {
            room: RoomId::from_bytes(r.array()?)?,
            anchor: AnchorId::from_bytes(r.array()?)?,
        };
        let owner = Key::from_bytes(r.array()?)?;
        let invitation = InvitationId::from_bytes(r.array()?)?;
        let parent = floor(&mut r)?;
        let accepted = floor(&mut r)?;
        let epoch = r.u64()?;
        let commit = CommitDigest::from_bytes(r.array()?)?;
        let welcome = WelcomeDigest::from_bytes(r.array()?)?;
        let group_context = r.array()?;
        let count = usize::from(r.byte()?);
        if count == 0 || count > MAX_MEMBERS {
            return Err(Error::Bounds);
        }
        let mut roster = Vec::with_capacity(count);
        for _ in 0..count {
            let enrollment = SignedDeviceEnrollment::decode(r.blob(ENROLLMENT_BYTES)?)?.verify()?;
            roster.push(enrollment);
        }
        let signature = r.array()?;
        r.end()?;
        let claims = CheckpointClaims {
            scope,
            owner,
            invitation,
            parent,
            accepted,
            epoch,
            commit,
            welcome,
            group_context,
            roster,
        };
        verify(&claims, signature)?;
        Ok(Self { claims, signature })
    }
}

fn signing_bytes(claims: &CheckpointClaims) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(claims.unsigned_bytes()?);
    Ok(bytes)
}
fn verify(claims: &CheckpointClaims, signature: [u8; 64]) -> Result<()> {
    let key =
        VerifyingKey::from_bytes(claims.owner.as_bytes()).map_err(|_| Error::Authentication)?;
    if key.is_weak() {
        return Err(Error::Authentication);
    }
    key.verify_strict(&signing_bytes(claims)?, &Signature::from_bytes(&signature))
        .map_err(|_| Error::Authentication)
}
fn put_floor(w: &mut Writer, floor: ControlFloor) -> Result<()> {
    w.u64(floor.sequence())?;
    match floor.id() {
        Some(id) => w.put(id.as_bytes()),
        None => w.put(&[0; 32]),
    }
}
fn floor(r: &mut Reader<'_>) -> Result<ControlFloor> {
    let sequence = r.u64()?;
    let id: [u8; 32] = r.array()?;
    let id = if sequence == 0 && id == [0; 32] {
        None
    } else {
        Some(ControlId::from_bytes(id)?)
    };
    Ok(ControlFloor::new(sequence, id)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{DeviceEnrollmentClaims, UnsignedDeviceEnrollment, Validity};
    use ed25519_dalek::{Signer, SigningKey};

    fn key(signer: &SigningKey) -> Key {
        Key::from_bytes(signer.verifying_key().to_bytes()).unwrap()
    }
    fn fixture(count: usize) -> (SigningKey, CheckpointClaims) {
        let owner = SigningKey::from_bytes(&[201; 32]);
        let mut roster = Vec::new();
        for i in 0..count {
            let account = SigningKey::from_bytes(&[101 + i as u8; 32]);
            let device = SigningKey::from_bytes(&[201 + i as u8; 32]);
            roster.push(
                UnsignedDeviceEnrollment::new(DeviceEnrollmentClaims {
                    account: key(&account),
                    device: key(&device),
                    validity: Validity::new(10, 20).unwrap(),
                })
                .unwrap()
                .sign(&account)
                .unwrap()
                .verify()
                .unwrap(),
            );
        }
        roster.sort_by_key(|enrollment| enrollment.claims().device);
        let claims = CheckpointClaims {
            scope: PrivateRoomScope {
                room: RoomId::from_bytes([1; 32]).unwrap(),
                anchor: AnchorId::from_bytes([2; 32]).unwrap(),
            },
            owner: key(&owner),
            invitation: InvitationId::from_bytes([3; 32]).unwrap(),
            parent: ControlFloor::new(0, None).unwrap(),
            accepted: ControlFloor::new(1, Some(ControlId::from_bytes([4; 32]).unwrap())).unwrap(),
            epoch: 1,
            commit: CommitDigest::of_bytes(b"actual Commit is checked by kernel").unwrap(),
            welcome: WelcomeDigest::of_bytes(b"actual Welcome is checked by kernel").unwrap(),
            group_context: [5; 32],
            roster,
        };
        (owner, claims)
    }
    fn sign(owner: &SigningKey, claims: CheckpointClaims) -> Checkpoint {
        let unsigned = UnsignedCheckpoint::new(claims).unwrap();
        unsigned
            .attach(owner.sign(&unsigned.signing_bytes().unwrap()).to_bytes())
            .unwrap()
    }
    fn resign(owner: &SigningKey, raw: &mut [u8]) {
        let end = raw.len() - SIGNATURE_BYTES;
        let mut preimage = DOMAIN.to_vec();
        preimage.extend(&raw[..end]);
        raw[end..].copy_from_slice(&owner.sign(&preimage).to_bytes());
    }
    const COUNT_OFFSET: usize = 11 + 4 * 32 + 2 * 40 + 8 + 3 * 32;

    #[test]
    fn checkpoint_roundtrip_at_genesis_later_floor_and_sixteen_member_bound() {
        for count in [1, 2, MAX_MEMBERS] {
            let (owner, mut claims) = fixture(count);
            for parent in [0, 17, u64::MAX - 1] {
                claims.parent = ControlFloor::new(
                    parent,
                    (parent != 0).then(|| ControlId::from_bytes([9; 32]).unwrap()),
                )
                .unwrap();
                claims.accepted =
                    ControlFloor::new(parent + 1, Some(ControlId::from_bytes([4; 32]).unwrap()))
                        .unwrap();
                claims.epoch = parent + 1;
                let checkpoint = sign(&owner, claims.clone());
                let raw = checkpoint.encode().unwrap();
                assert_eq!(
                    raw.len(),
                    COUNT_OFFSET + 1 + count * (4 + ENROLLMENT_BYTES) + 64
                );
                assert!(raw.len() <= MAX_CHECKPOINT_BYTES);
                let restored = Checkpoint::decode(&raw).unwrap();
                assert_eq!(&claims, restored.claims());
                assert_eq!(raw, restored.encode().unwrap());
            }
        }
    }

    #[test]
    fn checkpoint_every_byte_truncation_and_domain_tamper_refuse() {
        let (owner, claims) = fixture(2);
        let checkpoint = sign(&owner, claims.clone());
        let raw = checkpoint.encode().unwrap();
        for i in 0..raw.len() {
            let mut changed = raw.clone();
            changed[i] ^= 1;
            assert!(Checkpoint::decode(&changed).is_err(), "tamper byte {i}");
            assert!(Checkpoint::decode(&raw[..i]).is_err(), "truncation {i}");
        }
        let unsigned = UnsignedCheckpoint::new(claims).unwrap();
        assert!(unsigned
            .attach(owner.sign(&raw[..raw.len() - 64]).to_bytes())
            .is_err());
        let foreign = SigningKey::from_bytes(&[77; 32]);
        assert!(unsigned
            .attach(foreign.sign(&unsigned.signing_bytes().unwrap()).to_bytes())
            .is_err());
        let mut trailing = raw;
        trailing.push(0);
        assert!(Checkpoint::decode(&trailing).is_err());
    }

    #[test]
    fn checkpoint_refuses_invalid_roster_owner_floor_epoch_and_context() {
        let (_, claims) = fixture(2);
        let mut invalid = Vec::new();
        let mut c = claims.clone();
        c.roster.clear();
        invalid.push(c);
        let (_, c) = fixture(MAX_MEMBERS + 1);
        invalid.push(c);
        let mut c = claims.clone();
        c.roster.reverse();
        invalid.push(c);
        let mut c = claims.clone();
        c.roster.push(c.roster[0].clone());
        c.roster.sort_by_key(|e| e.claims().device);
        invalid.push(c);
        let mut c = claims.clone();
        c.owner = key(&SigningKey::from_bytes(&[99; 32]));
        invalid.push(c);
        let mut c = claims.clone();
        c.epoch = 2;
        invalid.push(c);
        let mut c = claims.clone();
        c.group_context = [0; 32];
        invalid.push(c);
        let mut c = claims.clone();
        c.accepted = ControlFloor::new(2, Some(ControlId::from_bytes([4; 32]).unwrap())).unwrap();
        c.epoch = 2;
        invalid.push(c);
        let mut c = claims;
        c.parent =
            ControlFloor::new(u64::MAX, Some(ControlId::from_bytes([9; 32]).unwrap())).unwrap();
        invalid.push(c);
        for c in invalid {
            assert!(UnsignedCheckpoint::new(c).is_err());
        }
    }

    #[test]
    fn checkpoint_owner_signature_cannot_hide_invalid_nested_enrollment_or_framing() {
        let (owner, claims) = fixture(2);
        let raw = sign(&owner, claims).encode().unwrap();
        let mut changed = raw.clone();
        // Correctly re-sign the whole checkpoint after corrupting an account's
        // enrollment signature. Outer owner authority cannot fabricate enrollment.
        changed[COUNT_OFFSET + 1 + 4 + ENROLLMENT_BYTES - 1] ^= 1;
        resign(&owner, &mut changed);
        assert!(Checkpoint::decode(&changed).is_err());
        for (offset, value) in [(COUNT_OFFSET, 0), (COUNT_OFFSET, 17), (COUNT_OFFSET, 255)] {
            let mut changed = raw.clone();
            changed[offset] = value;
            resign(&owner, &mut changed);
            assert!(Checkpoint::decode(&changed).is_err());
        }
        let mut changed = raw.clone();
        changed[COUNT_OFFSET + 1..COUNT_OFFSET + 5].copy_from_slice(&u32::MAX.to_be_bytes());
        resign(&owner, &mut changed);
        assert!(Checkpoint::decode(&changed).is_err());
        let mut changed = raw.clone();
        let owner_offset = MAGIC.len() + 64;
        changed[owner_offset..owner_offset + 32].fill(0);
        changed[owner_offset] = 1; // small-order identity point
        assert!(Checkpoint::decode(&changed).is_err());
        let mut changed = raw;
        changed.resize(MAX_CHECKPOINT_BYTES + 1, 0);
        assert!(matches!(Checkpoint::decode(&changed), Err(Error::Bounds)));
    }

    #[test]
    fn checkpoint_noncanonical_genesis_floor_is_rejected_even_with_valid_owner_signature() {
        let (owner, claims) = fixture(2);
        let raw = sign(&owner, claims).encode().unwrap();
        let parent = MAGIC.len() + 4 * 32;
        let mut nonzero_genesis_id = raw.clone();
        nonzero_genesis_id[parent + 8] = 1;
        resign(&owner, &mut nonzero_genesis_id);
        assert!(Checkpoint::decode(&nonzero_genesis_id).is_err());
        let mut missing_id = raw;
        missing_id[parent..parent + 8].copy_from_slice(&1u64.to_be_bytes());
        resign(&owner, &mut missing_id);
        assert!(Checkpoint::decode(&missing_id).is_err());
    }
}
