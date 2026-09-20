//! Canonical independently pinned genesis and validator configuration.
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use vhalla_core::RealmId;
use vhalla_rooms::registry::{DirectoryPolicy, MAX_OWNERS};
use vhalla_rooms::DirectoryId;
use vhalla_rooms_consensus::Genesis;
use vhalla_rooms_node::{PublicKey, RoomValidator, RoomValidatorSet};
use vhalla_social::archive::{Archive, Limits, MAX_SNAPSHOT_BYTES};
use vhalla_social::OwnerId;

use crate::Error;

const MAGIC: &[u8; 5] = b"VHPB\x01";
const CONFIG_DOMAIN: &[u8] = b"vhalla/public-bootstrap/v1\0";
const ORIGIN_DOMAIN: &[u8] = b"vhalla/public-network-origin/v1\0";

/// Maximum complete replacement validator sets in a pinned bootstrap.
pub const MAX_VALIDATOR_SETS: usize = 64;
/// Maximum validators in each set, matching the certificate consumer.
pub const MAX_VALIDATORS: usize = 64;
/// Maximum canonical bootstrap frame, including the existing archive ceiling.
pub const MAX_BOOTSTRAP_BYTES: usize = 5
    + 16
    + 32
    + 30
    + 28
    + 2
    + MAX_OWNERS * 32
    + 1
    + MAX_VALIDATOR_SETS * (8 + 1 + MAX_VALIDATORS * 40)
    + 4
    + MAX_SNAPSHOT_BYTES;

/// An unsigned validator configuration entry; constructing it grants no trust.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Validator {
    /// Full Ed25519 consensus identity, not a discovered peer's assertion.
    pub public_key: [u8; 32],
    /// Positive voting power.
    pub power: u64,
}

/// A complete validator replacement at one future consensus height.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorActivation {
    /// Inclusive activation height; the first activation must be height 1.
    pub from: u64,
    /// One to 64 unique identities; canonical encoding orders full keys.
    pub validators: Vec<Validator>,
}

/// Immutable validated configuration with two distinct content commitments.
///
/// pin() binds the complete configuration and exact signed genesis snapshot.
/// network_id() binds immutable genesis and only the initial validator set, so
/// appending a trusted future rotation does not rename the network. Neither
/// commitment is automatically trusted merely because a server supplies it.
#[derive(Clone)]
pub struct Bootstrap {
    pub(crate) pin: [u8; 32],
    pub(crate) network: [u8; 32],
    pub(crate) genesis: Genesis,
    pub(crate) schedule: Vec<(u64, RoomValidatorSet)>,
}

impl Bootstrap {
    /// Build canonical configuration from an already admitted genesis source.
    ///
    /// Equivalent eligible/member orderings normalize to the same commitment.
    /// Duplicate validator identities and activation heights are rejected.
    /// Archive realm and resource limits must exactly match the genesis fields.
    pub fn from_genesis(
        mut genesis: Genesis,
        mut activations: Vec<ValidatorActivation>,
    ) -> Result<Self, Error> {
        genesis.limits.check().map_err(|_| Error::Bootstrap)?;
        genesis.policy.validate().map_err(|_| Error::Bootstrap)?;
        if genesis.archive.realm() != genesis.realm
            || genesis.archive.limits() != genesis.limits
            || genesis.eligible.len() > MAX_OWNERS
        {
            return Err(Error::Bootstrap);
        }
        genesis.eligible.sort_unstable();
        genesis.eligible.dedup();
        if activations.is_empty() || activations.len() > MAX_VALIDATOR_SETS {
            return Err(Error::Bounds);
        }
        activations.sort_by_key(|activation| activation.from);
        if activations[0].from != 1
            || activations
                .windows(2)
                .any(|pair| pair[0].from >= pair[1].from)
        {
            return Err(Error::Validators);
        }
        let mut schedule = Vec::with_capacity(activations.len());
        for activation in activations {
            schedule.push((activation.from, checked_set(activation.validators)?));
        }
        // Registry construction confirms this is the same supported genesis
        // application contract; no caller-supplied frontier is admitted.
        genesis.registry().map_err(|_| Error::Bootstrap)?;
        let mut out = Self {
            pin: [0; 32],
            network: [0; 32],
            genesis,
            schedule,
        };
        out.pin = digest(CONFIG_DOMAIN, &out.encode());
        out.network = digest(ORIGIN_DOMAIN, &out.encode_schedule(&out.schedule[..1]));
        Ok(out)
    }

    /// Decode a bounded canonical frame under an independently retained pin.
    ///
    /// The content pin is checked BEFORE signature-heavy archive admission.
    /// Never obtain expected_pin solely from the same untrusted response.
    pub fn decode(raw: &[u8], expected_pin: [u8; 32]) -> Result<Self, Error> {
        if raw.len() > MAX_BOOTSTRAP_BYTES {
            return Err(Error::Bounds);
        }
        if digest(CONFIG_DOMAIN, raw) != expected_pin {
            return Err(Error::BootstrapPin);
        }
        let mut input = Reader(raw);
        if input.take(5)? != MAGIC {
            return Err(Error::Encoding);
        }
        let realm = RealmId(u128::from_be_bytes(input.array()?));
        let directory = DirectoryId::from_bytes(input.array()?);
        let policy = DirectoryPolicy {
            base_cost: input.u64()?,
            window_seconds: input.u64()?,
            max_in_window: u16::from_be_bytes(input.array()?),
            support_epoch_seconds: input.u64()?,
            max_lifetime_rooms: input.u32()?,
        };
        let limits = Limits {
            records: input.usize32()?,
            control_reserve: input.usize32()?,
            data_per_owner: input.usize32()?,
            data_per_writer: input.usize32()?,
            control_per_owner: input.usize32()?,
            pending: input.usize32()?,
            pending_per_signer: input.usize32()?,
        };
        policy.validate().map_err(|_| Error::Bootstrap)?;
        limits.check().map_err(|_| Error::Bootstrap)?;
        let count = usize::from(u16::from_be_bytes(input.array()?));
        if count > MAX_OWNERS {
            return Err(Error::Bounds);
        }
        let mut eligible = Vec::with_capacity(count);
        for _ in 0..count {
            let owner = OwnerId::from_bytes(input.array()?);
            if eligible.last().is_some_and(|last| *last >= owner) {
                return Err(Error::Encoding);
            }
            eligible.push(owner);
        }
        let count = usize::from(input.array::<1>()?[0]);
        if count == 0 || count > MAX_VALIDATOR_SETS {
            return Err(Error::Bounds);
        }
        let mut activations: Vec<ValidatorActivation> = Vec::with_capacity(count);
        for _ in 0..count {
            let from = input.u64()?;
            if (activations.is_empty() && from != 1)
                || activations.last().is_some_and(|last| last.from >= from)
            {
                return Err(Error::Validators);
            }
            let count = usize::from(input.array::<1>()?[0]);
            if count == 0 || count > MAX_VALIDATORS {
                return Err(Error::Bounds);
            }
            let mut validators: Vec<Validator> = Vec::with_capacity(count);
            for _ in 0..count {
                let public_key = input.array()?;
                let power = input.u64()?;
                if validators
                    .last()
                    .is_some_and(|last| last.public_key >= public_key)
                {
                    return Err(Error::Encoding);
                }
                validators.push(Validator { public_key, power });
            }
            // Check cheap configuration bounds and key identity before any
            // expensive signed genesis snapshot admission.
            checked_set(validators.clone())?;
            activations.push(ValidatorActivation { from, validators });
        }
        let length = input.usize32()?;
        if length > MAX_SNAPSHOT_BYTES {
            return Err(Error::Bounds);
        }
        let snapshot = input.take(length)?;
        if !input.0.is_empty() {
            return Err(Error::Encoding);
        }
        let archive =
            Archive::from_snapshot(realm, limits, snapshot).map_err(|_| Error::Bootstrap)?;
        let genesis = Genesis {
            directory,
            realm,
            policy,
            eligible,
            limits,
            archive,
        };
        let out = Self::from_genesis(genesis, activations)?;
        if out.encode() != raw || out.pin != expected_pin {
            return Err(Error::Encoding);
        }
        Ok(out)
    }

    /// Exact canonical bootstrap bytes, including the complete genesis archive.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_schedule(&self.schedule)
    }

    /// Exact full-configuration content pin, including future activations.
    pub const fn pin(&self) -> [u8; 32] {
        self.pin
    }

    /// Stable immutable-origin identity used by peer advertisements.
    pub const fn network_id(&self) -> [u8; 32] {
        self.network
    }

    /// Borrow the validated genesis; no mutable references escape.
    pub const fn genesis(&self) -> &Genesis {
        &self.genesis
    }

    fn encode_schedule(&self, schedule: &[(u64, RoomValidatorSet)]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(MAGIC);
        raw.extend_from_slice(&self.genesis.realm.0.to_be_bytes());
        raw.extend_from_slice(self.genesis.directory.as_bytes());
        let policy = self.genesis.policy;
        raw.extend_from_slice(&policy.base_cost.to_be_bytes());
        raw.extend_from_slice(&policy.window_seconds.to_be_bytes());
        raw.extend_from_slice(&policy.max_in_window.to_be_bytes());
        raw.extend_from_slice(&policy.support_epoch_seconds.to_be_bytes());
        raw.extend_from_slice(&policy.max_lifetime_rooms.to_be_bytes());
        let limits = self.genesis.limits;
        for limit in [
            limits.records,
            limits.control_reserve,
            limits.data_per_owner,
            limits.data_per_writer,
            limits.control_per_owner,
            limits.pending,
            limits.pending_per_signer,
        ] {
            raw.extend_from_slice(&(limit as u32).to_be_bytes());
        }
        raw.extend_from_slice(&(self.genesis.eligible.len() as u16).to_be_bytes());
        for owner in &self.genesis.eligible {
            raw.extend_from_slice(owner.as_bytes());
        }
        raw.push(schedule.len() as u8);
        for (from, set) in schedule {
            raw.extend_from_slice(&from.to_be_bytes());
            raw.push(set.validators.len() as u8);
            let mut validators: Vec<_> = set.validators.iter().collect();
            validators.sort_by_key(|validator| *validator.public_key.as_bytes());
            for validator in validators {
                raw.extend_from_slice(validator.public_key.as_bytes());
                raw.extend_from_slice(&validator.power.to_be_bytes());
            }
        }
        let snapshot = self.genesis.archive.snapshot();
        raw.extend_from_slice(&(snapshot.len() as u32).to_be_bytes());
        raw.extend_from_slice(&snapshot);
        raw
    }
}

fn checked_set(validators: Vec<Validator>) -> Result<RoomValidatorSet, Error> {
    if validators.is_empty() || validators.len() > MAX_VALIDATORS {
        return Err(Error::Bounds);
    }
    let mut keys = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut total = 0u64;
    let mut members = Vec::with_capacity(validators.len());
    for validator in validators {
        let key = VerifyingKey::from_bytes(&validator.public_key).map_err(|_| Error::Validators)?;
        if key.is_weak() || validator.power == 0 || !keys.insert(validator.public_key) {
            return Err(Error::Validators);
        }
        total = total
            .checked_add(validator.power)
            .filter(|total| *total <= u64::MAX / 3)
            .ok_or(Error::Validators)?;
        let public_key =
            PublicKey::from_bytes(validator.public_key).map_err(|_| Error::Validators)?;
        let member = RoomValidator::new(public_key, validator.power);
        if !addresses.insert(member.address) {
            return Err(Error::Validators);
        }
        members.push(member);
    }
    // All engine invariants are checked above, including duplicate full keys
    // AND derived addresses. This supported constructor only orders the set.
    Ok(RoomValidatorSet::new(members))
}

fn digest(domain: &[u8], raw: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(raw);
    hash.finalize().into()
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], Error> {
        let bytes = self.0.get(..size).ok_or(Error::Encoding)?;
        self.0 = &self.0[size..];
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn usize32(&mut self) -> Result<usize, Error> {
        usize::try_from(self.u32()?).map_err(|_| Error::Bounds)
    }
}
