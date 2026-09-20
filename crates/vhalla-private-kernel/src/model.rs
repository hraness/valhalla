use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use crate::{
    codec::{Reader, Writer},
    protocol::*,
    Context, Error, Phase, Result, Status, MAX_MEMBERS, MAX_STATE_BYTES,
};

pub(crate) const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const MAX_PROVIDER_RECORDS: usize = 256;
// No automatic migration from the preserved two-device qualification image.
const MAGIC: &[u8] = b"VHPKSTATE\x02";
const FAULT_RESERVE: usize = MAX_RECORD_BYTES + 64;

pub(crate) struct State {
    pub(crate) revision: u64,
    pub(crate) phase: Phase,
    pub(crate) epoch: u64,
    pub(crate) clock: u64,
    pub(crate) floor: ControlFloor,
    pub(crate) outbox: u64,
    pub(crate) inbox: u64,
    pub(crate) anchor: VerifiedRoomAnchor,
    pub(crate) local: VerifiedDeviceEnrollment,
    pub(crate) owner: VerifiedDeviceEnrollment,
    pub(crate) roster: Vec<VerifiedDeviceEnrollment>,
    pub(crate) base: ControlFloor,
    pub(crate) checkpoint: Option<crate::checkpoint::Checkpoint>,
    pub(crate) fault: Option<FaultEvidence>,
    pub(crate) key_package: Option<KeyPackageDigest>,
    pub(crate) joined: Option<[u8; 32]>,
    pub(crate) records: Vec<(Vec<u8>, Vec<u8>)>,
}
impl State {
    pub(crate) fn context(&self) -> Context {
        Context {
            scope: self.anchor.scope(),
            account: self.local.claims().account,
            device: self.local.claims().device,
        }
    }
    pub(crate) fn status(&self) -> Status {
        Status {
            context: self.context(),
            phase: self.phase,
            epoch: self.epoch,
            control_sequence: self.floor.sequence(),
            control_floor: self.floor,
            outbox_head: self.outbox,
            inbox_head: self.inbox,
            history_base: self.base,
            roster: self.roster_digest(),
            members: self.roster.len(),
            quarantined: self.fault.is_some(),
        }
    }
    pub(crate) fn validate(&self, context: Context) -> Result<()> {
        if self.context() != context
            || self.anchor.claims().owner_account != self.owner.claims().account
            || self.anchor.claims().owner_device != self.owner.claims().device
        {
            return Err(Error::Scope);
        }
        let is_owner = matches!(
            self.phase,
            Phase::OwnerGenesis | Phase::OwnerJoined | Phase::OwnerAfterRemoval
        );
        if is_owner != (context.device == self.owner.claims().device) {
            return Err(Error::Policy);
        }
        if is_owner && self.local.signed() != self.owner.signed() {
            return Err(Error::Policy);
        }
        if self.epoch != self.floor.sequence() || self.base.sequence() > self.floor.sequence() {
            return Err(Error::Policy);
        }
        check_roster(&self.roster)?;
        let owner = self
            .roster
            .iter()
            .find(|e| e.claims().device == self.owner.claims().device)
            .ok_or(Error::Policy)?;
        if owner.signed() != self.owner.signed() {
            return Err(Error::Policy);
        }
        let local = self
            .roster
            .iter()
            .find(|e| e.claims().device == context.device);
        match self.phase {
            Phase::AwaitingWelcome => {
                if self.epoch != 0
                    || self.roster.len() != 1
                    || local.is_some()
                    || self.checkpoint.is_some()
                {
                    return Err(Error::Policy);
                }
            }
            Phase::Removed => {
                if self.epoch == 0 || local.is_some() {
                    return Err(Error::Policy);
                }
            }
            _ => {
                if local.is_none_or(|e| e.signed() != self.local.signed()) {
                    return Err(Error::Policy);
                }
                if self.phase == Phase::OwnerGenesis && (self.epoch != 0 || self.roster.len() != 1)
                {
                    return Err(Error::Policy);
                }
                if self.phase == Phase::OwnerAfterRemoval
                    && (self.epoch == 0 || self.roster.len() != 1)
                {
                    return Err(Error::Policy);
                }
                if matches!(self.phase, Phase::OwnerJoined | Phase::MemberJoined)
                    && (self.epoch == 0 || self.roster.len() < 2)
                {
                    return Err(Error::Policy);
                }
            }
        }
        if is_owner && (self.base.sequence() != 0 || self.checkpoint.is_some()) {
            return Err(Error::Policy);
        }
        if let Some(checkpoint) = &self.checkpoint {
            let c = checkpoint.claims();
            if c.scope != context.scope
                || c.owner != self.owner.claims().device
                || c.parent != self.base
                || c.accepted.sequence() > self.floor.sequence()
                || !c.roster.iter().any(|e| e.signed() == self.local.signed())
            {
                return Err(Error::Policy);
            }
        } else if matches!(self.phase, Phase::MemberJoined | Phase::Removed) {
            return Err(Error::Policy);
        }
        if let Some(fault) = &self.fault {
            let c = fault.conflicting.claims();
            if c.scope != context.scope
                || c.owner_device != self.owner.claims().device
                || c.sequence()? != fault.accepted.sequence()
                || fault.accepted.sequence() > self.floor.sequence()
                || fault.accepted.id() == Some(fault.conflicting.id())
            {
                return Err(Error::Policy);
            }
        }
        if is_owner && (self.key_package.is_some() || self.joined.is_some()) {
            return Err(Error::Policy);
        }
        if matches!(self.phase, Phase::MemberJoined | Phase::Removed)
            && (self.key_package.is_none() || self.joined.is_none())
        {
            return Err(Error::Policy);
        }
        if self.records.len() > MAX_PROVIDER_RECORDS {
            return Err(Error::Bounds);
        }
        let mut total = 0usize;
        let mut previous: Option<&[u8]> = None;
        for (key, value) in &self.records {
            if key.is_empty()
                || key.len() > 4096
                || value.len() > MAX_STATE_BYTES
                || previous.is_some_and(|p| p >= key.as_slice())
            {
                return Err(Error::Encoding);
            }
            total = total
                .checked_add(key.len())
                .and_then(|n| n.checked_add(value.len()))
                .ok_or(Error::Bounds)?;
            if total > MAX_STATE_BYTES {
                return Err(Error::Bounds);
            }
            previous = Some(key);
        }
        Ok(())
    }
    pub(crate) fn roster_digest(&self) -> [u8; 32] {
        let mut raw = Vec::with_capacity(self.roster.len() * 150 + 64);
        raw.extend(self.context().scope.room.as_bytes());
        raw.extend(self.context().scope.anchor.as_bytes());
        for member in &self.roster {
            raw.extend(member.signed().encode());
        }
        crate::codec::hash(b"vhalla/private-kernel/roster/v1\0", &raw)
    }
    pub(crate) fn owner_role(&self) -> bool {
        self.local.claims().device == self.owner.claims().device
    }
    pub(crate) fn set_membership_phase(&mut self) {
        self.phase = if self.owner_role() {
            if self.roster.len() == 1 {
                Phase::OwnerAfterRemoval
            } else {
                Phase::OwnerJoined
            }
        } else if self
            .roster
            .iter()
            .any(|e| e.claims().device == self.local.claims().device)
        {
            Phase::MemberJoined
        } else {
            Phase::Removed
        };
    }
    pub(crate) fn check_time(&self, now: u64) -> Result<()> {
        if now < self.clock {
            return Err(Error::Time);
        }
        self.local.claims().validity.check_at(now)?;
        self.owner.claims().validity.check_at(now)?;
        Ok(())
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate(self.context())?;
        // Leave bounded space for the first proven owner conflict. This reserves
        // encoding capacity, not physical disk or browser persistence.
        let limit = if self.fault.is_some() {
            MAX_STATE_BYTES
        } else {
            MAX_STATE_BYTES - FAULT_RESERVE
        };
        let mut w = Writer::new(MAGIC, limit)?;
        w.u64(self.revision)?;
        w.byte(phase_byte(self.phase))?;
        w.u64(self.epoch)?;
        w.u64(self.clock)?;
        w.u64(self.floor.sequence())?;
        w.put(
            self.floor
                .id()
                .as_ref()
                .map_or(&[0; 32], |id| id.as_bytes()),
        )?;
        w.u64(self.outbox)?;
        w.u64(self.inbox)?;
        w.blob(&self.anchor.signed().encode(), MAX_RECORD_BYTES)?;
        w.blob(&self.local.signed().encode(), MAX_RECORD_BYTES)?;
        w.blob(&self.owner.signed().encode(), MAX_RECORD_BYTES)?;
        w.byte(u8::try_from(self.roster.len()).map_err(|_| Error::Bounds)?)?;
        for member in &self.roster {
            w.blob(&member.signed().encode(), MAX_RECORD_BYTES)?;
        }
        put_floor(&mut w, self.base)?;
        if let Some(checkpoint) = &self.checkpoint {
            w.byte(1)?;
            w.blob(&checkpoint.encode()?, MAX_RECORD_BYTES)?;
        } else {
            w.byte(0)?;
        }
        if let Some(fault) = &self.fault {
            w.byte(1)?;
            put_floor(&mut w, fault.accepted)?;
            w.blob(&fault.conflicting.signed().encode(), MAX_RECORD_BYTES)?;
        } else {
            w.byte(0)?;
        }
        if let Some(package) = self.key_package {
            w.byte(1)?;
            w.put(package.as_bytes())?;
        } else {
            w.byte(0)?;
        }
        if let Some(joined) = self.joined {
            w.byte(1)?;
            w.put(&joined)?;
        } else {
            w.byte(0)?;
        }
        w.put(
            &u16::try_from(self.records.len())
                .map_err(|_| Error::Bounds)?
                .to_be_bytes(),
        )?;
        for (key, value) in &self.records {
            w.blob(key, 4096)?;
            w.blob(value, MAX_STATE_BYTES)?;
        }
        Ok(w.finish())
    }
    pub(crate) fn decode(raw: &[u8], context: Context) -> Result<Self> {
        let mut r = Reader::new(raw, MAGIC, MAX_STATE_BYTES)?;
        let revision = r.u64()?;
        let phase = decode_phase(r.byte()?)?;
        let epoch = r.u64()?;
        let clock = r.u64()?;
        let sequence = r.u64()?;
        let id = r.array()?;
        let floor = ControlFloor::new(
            sequence,
            if id == [0; 32] {
                None
            } else {
                Some(ControlId::from_bytes(id)?)
            },
        )?;
        let outbox = r.u64()?;
        let inbox = r.u64()?;
        let anchor = SignedRoomAnchor::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?;
        let local = SignedDeviceEnrollment::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?;
        let owner = SignedDeviceEnrollment::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?;
        let count = usize::from(r.byte()?);
        if count == 0 || count > MAX_MEMBERS {
            return Err(Error::Bounds);
        }
        let mut roster = Vec::with_capacity(count);
        for _ in 0..count {
            roster.push(SignedDeviceEnrollment::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?);
        }
        check_roster(&roster)?;
        let base = read_floor(&mut r)?;
        let checkpoint = match r.byte()? {
            0 => None,
            1 => Some(crate::checkpoint::Checkpoint::decode(
                r.blob(MAX_RECORD_BYTES)?,
            )?),
            _ => return Err(Error::Encoding),
        };
        let fault = match r.byte()? {
            0 => None,
            1 => Some(FaultEvidence {
                accepted: read_floor(&mut r)?,
                conflicting: SignedOwnerControl::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?,
            }),
            _ => return Err(Error::Encoding),
        };
        let key_package = match r.byte()? {
            0 => None,
            1 => Some(KeyPackageDigest::from_bytes(r.array()?)?),
            _ => return Err(Error::Encoding),
        };
        let joined = match r.byte()? {
            0 => None,
            1 => Some(r.array()?),
            _ => return Err(Error::Encoding),
        };
        let count = usize::from(u16::from_be_bytes(r.array()?));
        if count > MAX_PROVIDER_RECORDS {
            return Err(Error::Bounds);
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let key = r.blob(4096)?;
            let value = r.blob(MAX_STATE_BYTES)?;
            if key.is_empty()
                || records
                    .last()
                    .is_some_and(|(prior, _): &(Vec<u8>, Vec<u8>)| prior.as_slice() >= key)
            {
                return Err(Error::Encoding);
            }
            records.push((key.to_vec(), value.to_vec()));
        }
        r.end()?;
        let state = Self {
            revision,
            phase,
            epoch,
            clock,
            floor,
            outbox,
            inbox,
            anchor,
            local,
            owner,
            roster,
            base,
            checkpoint,
            fault,
            key_package,
            joined,
            records,
        };
        state.validate(context)?;
        Ok(state)
    }
}

pub(crate) struct Working {
    pub(crate) state: State,
    pub(crate) provider: OpenMlsRustCrypto,
}
impl Working {
    pub(crate) fn hydrate(mut state: State) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        provider
            .storage()
            .values
            .write()
            .map_err(|_| Error::Mls)?
            .extend(std::mem::take(&mut state.records));
        let work = Self { state, provider };
        if work.signer()?.to_public_vec() != work.state.local.claims().device.as_bytes() {
            return Err(Error::Scope);
        }
        if work.state.phase != Phase::AwaitingWelcome {
            work.check_group(&work.group()?)?;
        }
        Ok(work)
    }
    pub(crate) fn signer(&self) -> Result<SignatureKeyPair> {
        SignatureKeyPair::read(
            self.provider.storage(),
            self.state.local.claims().device.as_bytes(),
            SUITE.signature_algorithm(),
        )
        .ok_or(Error::Missing)
    }
    pub(crate) fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.state.local.signed().encode()).into(),
            signature_key: self.state.local.claims().device.as_bytes().to_vec().into(),
        }
    }
    pub(crate) fn group(&self) -> Result<MlsGroup> {
        if self.state.phase == Phase::AwaitingWelcome {
            return Err(Error::Policy);
        }
        MlsGroup::load(
            self.provider.storage(),
            &GroupId::from_slice(self.state.context().scope.room.as_bytes()),
        )
        .map_err(|_| Error::Mls)?
        .ok_or(Error::Missing)
    }
    pub(crate) fn check_group(&self, group: &MlsGroup) -> Result<()> {
        if group.group_id().as_slice() != self.state.context().scope.room.as_bytes()
            || group.ciphersuite() != SUITE
            || group.epoch().as_u64() != self.state.epoch
        {
            return Err(Error::Scope);
        }
        if group.pending_proposals().next().is_some() || group.pending_commit().is_some() {
            return Err(Error::Policy);
        }
        if group.is_active() == (self.state.phase == Phase::Removed) {
            return Err(Error::Policy);
        }
        let expected = self.expected_members()?;
        check_members(group.members(), &expected)?;
        if group.is_active() {
            let local = group
                .members()
                .find(|m| m.index == group.own_leaf_index())
                .ok_or(Error::Policy)?;
            check_credential(&local.credential, &local.signature_key, &self.state.local)?;
        }
        Ok(())
    }
    pub(crate) fn expected_members(&self) -> Result<Vec<&VerifiedDeviceEnrollment>> {
        Ok(self.state.roster.iter().collect())
    }
    pub(crate) fn capture(mut self) -> Result<State> {
        if self.state.phase != Phase::AwaitingWelcome {
            self.check_group(&self.group()?)?;
        }
        let map = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| Error::Mls)?;
        if map.len() > MAX_PROVIDER_RECORDS {
            return Err(Error::Bounds);
        }
        let mut total = 0usize;
        for (key, value) in map.iter() {
            if key.is_empty() || key.len() > 4096 || value.len() > MAX_STATE_BYTES {
                return Err(Error::Bounds);
            }
            total = total
                .checked_add(key.len())
                .and_then(|n| n.checked_add(value.len()))
                .ok_or(Error::Bounds)?;
            if total > MAX_STATE_BYTES {
                return Err(Error::Bounds);
            }
        }
        self.state.records = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        self.state.records.sort_by(|a, b| a.0.cmp(&b.0));
        self.state.validate(self.state.context())?;
        Ok(self.state)
    }
}

pub(crate) fn check_credential(
    credential: &Credential,
    signature_key: &[u8],
    enrollment: &VerifiedDeviceEnrollment,
) -> Result<()> {
    if credential.credential_type() != CredentialType::Basic
        || signature_key != enrollment.claims().device.as_bytes()
    {
        return Err(Error::Policy);
    }
    let basic = BasicCredential::try_from(credential.clone()).map_err(|_| Error::Policy)?;
    if basic.identity() != enrollment.signed().encode() {
        return Err(Error::Policy);
    }
    Ok(())
}
pub(crate) fn check_members(
    members: impl Iterator<Item = Member>,
    expected: &[&VerifiedDeviceEnrollment],
) -> Result<()> {
    let mut seen = Vec::new();
    for member in members {
        if seen.len() >= expected.len() {
            return Err(Error::Policy);
        }
        let index = expected
            .iter()
            .position(|e| e.claims().device.as_bytes() == member.signature_key.as_slice())
            .ok_or(Error::Policy)?;
        if seen.contains(&index) {
            return Err(Error::Policy);
        }
        check_credential(&member.credential, &member.signature_key, expected[index])?;
        seen.push(index);
    }
    if seen.len() != expected.len() {
        return Err(Error::Policy);
    }
    Ok(())
}
pub(crate) fn app_aad(context: Context) -> Vec<u8> {
    let mut out = b"vhalla/private-kernel/mls-context/v1\0".to_vec();
    out.extend(context.scope.room.as_bytes());
    out.extend(context.scope.anchor.as_bytes());
    out
}
fn phase_byte(phase: Phase) -> u8 {
    match phase {
        Phase::OwnerGenesis => 0,
        Phase::AwaitingWelcome => 1,
        Phase::OwnerJoined => 2,
        Phase::MemberJoined => 3,
        Phase::OwnerAfterRemoval => 4,
        Phase::Removed => 5,
    }
}
fn decode_phase(value: u8) -> Result<Phase> {
    match value {
        0 => Ok(Phase::OwnerGenesis),
        1 => Ok(Phase::AwaitingWelcome),
        2 => Ok(Phase::OwnerJoined),
        3 => Ok(Phase::MemberJoined),
        4 => Ok(Phase::OwnerAfterRemoval),
        5 => Ok(Phase::Removed),
        _ => Err(Error::Encoding),
    }
}

pub(crate) struct FaultEvidence {
    pub(crate) accepted: ControlFloor,
    pub(crate) conflicting: VerifiedOwnerControl,
}
pub(crate) fn check_roster(roster: &[VerifiedDeviceEnrollment]) -> Result<()> {
    if roster.is_empty() || roster.len() > MAX_MEMBERS {
        return Err(Error::Bounds);
    }
    for pair in roster.windows(2) {
        if pair[0].claims().device >= pair[1].claims().device {
            return Err(Error::Policy);
        }
    }
    Ok(())
}
pub(crate) fn put_floor(w: &mut Writer, floor: ControlFloor) -> Result<()> {
    w.u64(floor.sequence())?;
    w.put(floor.id().as_ref().map_or(&[0; 32], |id| id.as_bytes()))
}
pub(crate) fn read_floor(r: &mut Reader<'_>) -> Result<ControlFloor> {
    let seq = r.u64()?;
    let id = r.array()?;
    Ok(ControlFloor::new(
        seq,
        if id == [0; 32] {
            None
        } else {
            Some(ControlId::from_bytes(id)?)
        },
    )?)
}
