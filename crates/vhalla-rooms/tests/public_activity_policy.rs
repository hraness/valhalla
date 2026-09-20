//! Public posting is an explicit certified room revision, never a gateway claim.
mod common;
use common::*;
use ed25519_dalek::SigningKey;
use vhalla_rooms::{
    registry::{Applied, Registry, RegistryError},
    Denial, Description, RoomGenesisId, RoomRecordId, RoomUpdate, SignedRecord, UpdateAction,
    VerifiedRecord, PUBLIC_ACTIVITY_VERSION,
};
use vhalla_social::{archive::Archive, control::ControlView, Body, ControlAction};

const NETWORK: [u8; 32] = [7; 32];

struct Fixture {
    archive: Archive,
    creator: Owner,
    registry: Registry,
    genesis: RoomGenesisId,
    create: RoomRecordId,
}
impl Fixture {
    fn new() -> Self {
        let mut archive = Archive::new(REALM, limits()).unwrap();
        let creator = beneficiary(&mut archive, 4);
        let (mut pool, mut registry) = sources(&mut archive, 90, 1);
        let head = grant_create(&mut registry, &archive, &creator, 100);
        award_one(&mut registry, &mut archive, &mut pool[0], &creator, 200);
        let create = creation(&creator, head, head, "public-room", 1, 1, 13);
        let Applied::Created(genesis) = apply(&mut registry, &archive, &create, 300).unwrap()
        else {
            panic!("expected newly created room");
        };
        Self {
            archive,
            creator,
            registry,
            genesis,
            create: create.id(),
        }
    }
    fn update(&self, previous: RoomRecordId, nonce: u8, action: UpdateAction) -> RoomUpdate {
        RoomUpdate {
            directory: DIRECTORY,
            realm: REALM,
            genesis: self.genesis,
            previous,
            owner: self.creator.id,
            social_control: self.creator.head,
            controller_key: self.creator.key.verifying_key().to_bytes(),
            expires_at: 1_000_000,
            nonce: [nonce; 32],
            action,
        }
    }
    fn policy(&self, previous: RoomRecordId, enabled: bool, nonce: u8) -> VerifiedRecord {
        self.update(
            previous,
            nonce,
            UpdateAction::SetPublicActivityPolicy {
                network: NETWORK,
                enabled,
            },
        )
        .sign_with_key(&self.creator.key)
        .unwrap()
        .verify()
        .unwrap()
    }
    fn apply(&mut self, record: &VerifiedRecord, now: u64) -> Result<Applied, RegistryError> {
        self.registry
            .apply(record, &ControlView::new(&self.archive, now), now)
    }
    fn allows(&self, policy: RoomRecordId) -> bool {
        self.registry
            .room_by_genesis(self.genesis)
            .unwrap()
            .allows_public_activity(&NETWORK, policy)
    }
}
fn from_hex(raw: &str) -> Vec<u8> {
    raw.as_bytes()
        .chunks_exact(2)
        .map(|bytes| u8::from_str_radix(core::str::from_utf8(bytes).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn public_policy_absence_preserves_legacy_snapshot_bytes_and_digest() {
    // Frozen v1 encoding of the pre-policy empty registry under common::policy.
    // The header, payload and digest remain byte-identical for old states.
    let legacy = from_hex("5652534e0000000105050505050505050505050505050505050505050505050505050505050505050000000000000000000000000000004d000000000000000100000000000151800001000000000001518000000008000000000000000000000000000000000000000000000000000000000000000000000000000000008793263f8ec32d37dfdad2cdbf766f1fd72e51036d5ba65400de30e07deb15e1");
    let registry = Registry::new(DIRECTORY, REALM, policy(), &[]).unwrap();
    assert_eq!(registry.snapshot(), legacy);
    assert_eq!(
        registry.digest().as_slice(),
        from_hex("8793263f8ec32d37dfdad2cdbf766f1fd72e51036d5ba65400de30e07deb15e1")
    );
    assert_eq!(Registry::restore(&legacy).unwrap().snapshot(), legacy);
    let f = Fixture::new();
    let snapshot = f.registry.snapshot();
    assert_eq!(&snapshot[..8], b"VRSN\0\0\0\x01");
    let room = f.registry.room_by_genesis(f.genesis).unwrap();
    assert!(
        room.public_activity_policy().is_none(),
        "initial_settings confers no posting permission"
    );
    assert!(!room.allows_public_activity(&NETWORK, f.create));
    let restored = Registry::restore(&snapshot).unwrap();
    assert_eq!(restored.snapshot(), snapshot);
    assert_eq!(restored.digest(), f.registry.digest());
    assert!(restored
        .room_by_genesis(f.genesis)
        .unwrap()
        .public_activity_policy()
        .is_none());
}

#[test]
fn public_policy_open_close_and_archive_follow_exact_room_history() {
    let mut f = Fixture::new();
    let before = f.registry.digest();
    let open = f.policy(f.create, true, 14);
    assert_eq!(f.apply(&open, 400), Ok(Applied::Updated(open.id())));
    assert_ne!(f.registry.digest(), before);
    let active = f
        .registry
        .room_by_genesis(f.genesis)
        .unwrap()
        .public_activity_policy()
        .unwrap();
    assert_eq!(active.record, open.id());
    assert_eq!(active.network, NETWORK);
    assert!(active.enabled && f.allows(open.id()));
    assert!(!f.allows(f.create));
    assert!(!f
        .registry
        .room_by_genesis(f.genesis)
        .unwrap()
        .allows_public_activity(&[8; 32], open.id()));
    assert_eq!(f.registry.source_proof(open.id()).unwrap(), open.encode());
    let snapshot = f.registry.snapshot();
    assert_eq!(f.apply(&open, 400), Err(RegistryError::StaleRevision));
    assert_eq!(
        f.registry.snapshot(),
        snapshot,
        "replay never appends or changes policy"
    );
    let describe = f
        .update(
            open.id(),
            15,
            UpdateAction::Describe(Description::new("updated text").unwrap()),
        )
        .sign_with_key(&f.creator.key)
        .unwrap()
        .verify()
        .unwrap();
    assert!(f.apply(&describe, 401).is_ok());
    assert!(
        f.allows(open.id()),
        "an unrelated description revision preserves the policy reference"
    );
    let stale = f.policy(open.id(), false, 16);
    let before = f.registry.snapshot();
    assert_eq!(f.apply(&stale, 402), Err(RegistryError::StaleRevision));
    assert_eq!(f.registry.snapshot(), before);
    let close = f.policy(describe.id(), false, 17);
    assert!(f.apply(&close, 402).is_ok());
    assert!(!f.allows(open.id()) && !f.allows(close.id()));
    assert_eq!(
        f.registry
            .room_by_genesis(f.genesis)
            .unwrap()
            .public_activity_policy()
            .unwrap()
            .record,
        close.id()
    );
    let reopen = f.policy(close.id(), true, 18);
    assert!(f.apply(&reopen, 403).is_ok());
    assert!(f.allows(reopen.id()) && !f.allows(open.id()));
    let archive = f
        .update(reopen.id(), 19, UpdateAction::Archive)
        .sign_with_key(&f.creator.key)
        .unwrap()
        .verify()
        .unwrap();
    assert!(f.apply(&archive, 404).is_ok());
    assert!(
        !f.allows(reopen.id()),
        "archival overrides the retained open revision"
    );
    let after_archive = f.policy(archive.id(), true, 20);
    let before = f.registry.snapshot();
    assert_eq!(f.apply(&after_archive, 405), Err(RegistryError::Archived));
    assert_eq!(f.registry.snapshot(), before);
    assert!(f.registry.source_proof(open.id()).is_some());
    assert!(f.registry.source_proof(close.id()).is_some());
}

#[test]
fn public_policy_snapshots_are_explicitly_versioned_and_restore_the_exact_policy() {
    let mut f = Fixture::new();
    let mut mislabeled_legacy = f.registry.snapshot();
    mislabeled_legacy[7] = 2;
    assert!(Registry::restore(&mislabeled_legacy).is_err());
    let open = f.policy(f.create, true, 14);
    f.apply(&open, 400).unwrap();
    for record in [open.clone(), f.policy(open.id(), false, 15)] {
        if record.id() != open.id() {
            f.apply(&record, 401).unwrap();
        }
        let snapshot = f.registry.snapshot();
        assert_eq!(&snapshot[..8], b"VRSN\0\0\0\x02");
        let restored = Registry::restore(&snapshot).unwrap();
        assert_eq!(restored.snapshot(), snapshot);
        assert_eq!(restored.digest(), f.registry.digest());
        assert_eq!(
            restored
                .room_by_genesis(f.genesis)
                .unwrap()
                .public_activity_policy(),
            f.registry
                .room_by_genesis(f.genesis)
                .unwrap()
                .public_activity_policy()
        );
        assert_eq!(restored.source_proof(record.id()).unwrap(), record.encode());
        let mut downgraded = snapshot;
        downgraded[7] = 1;
        assert!(Registry::restore(&downgraded).is_err());
    }
}

#[test]
fn public_policy_foreign_owner_and_stale_controller_cannot_change_admission() {
    let mut f = Fixture::new();
    let foreign = owner(&mut f.archive, 17);
    let mut stolen = f.update(
        f.create,
        14,
        UpdateAction::SetPublicActivityPolicy {
            network: NETWORK,
            enabled: true,
        },
    );
    stolen.owner = foreign.id;
    stolen.social_control = foreign.head;
    stolen.controller_key = foreign.key.verifying_key().to_bytes();
    let stolen = stolen
        .sign_with_key(&foreign.key)
        .unwrap()
        .verify()
        .unwrap();
    let before = f.registry.snapshot();
    assert_eq!(f.apply(&stolen, 400), Err(RegistryError::OwnerMismatch));
    assert_eq!(f.registry.snapshot(), before);
    let open = f.policy(f.create, true, 15);
    f.apply(&open, 400).unwrap();
    let stale = f.policy(open.id(), false, 16);
    let old_key = f.creator.key.clone();
    let next_key = SigningKey::from_bytes(&[201; 32]);
    let rotation = sign(
        Body::Control {
            owner: f.creator.id,
            previous: f.creator.head,
            action: ControlAction::Rotate {
                new_key: next_key.verifying_key().to_bytes(),
            },
        },
        &old_key,
        Some(&next_key),
    );
    ingest(&mut f.archive, &rotation);
    let before = f.registry.snapshot();
    assert_eq!(
        f.apply(&stale, 401),
        Err(RegistryError::Authority(Denial::StaleSocialBasis))
    );
    assert_eq!(f.registry.snapshot(), before);
    assert!(
        f.allows(open.id()),
        "controller rotation does not rewrite admitted policy history"
    );
    f.creator.head = rotation.id();
    let forged = f.policy(open.id(), false, 17); // current basis, still the old key
    assert_eq!(
        f.apply(&forged, 401),
        Err(RegistryError::Authority(Denial::ControllerKey))
    );
    assert_eq!(f.registry.snapshot(), before);
    f.creator.key = next_key;
    let close = f.policy(open.id(), false, 18);
    assert!(f.apply(&close, 401).is_ok());
    assert!(!f.allows(open.id()));
}

#[test]
fn public_policy_wire_version_network_and_switch_are_canonical_and_signed() {
    let f = Fixture::new();
    let record = f.policy(f.create, true, 14);
    let bytes = record.encode();
    const ACTION: usize = 8 + 32 * 7 + 16 + 8;
    assert_eq!(bytes[ACTION], 2);
    assert_eq!(bytes[ACTION + 1], PUBLIC_ACTIVITY_VERSION);
    assert_eq!(&bytes[ACTION + 2..ACTION + 34], &NETWORK);
    assert_eq!(bytes[ACTION + 34], 1);
    let decoded = SignedRecord::decode(&bytes).unwrap().verify().unwrap();
    assert_eq!(decoded.encode(), bytes);
    assert_eq!(decoded.id(), record.id());
    for version in [0, 2, u8::MAX] {
        let mut bad = bytes.clone();
        bad[ACTION + 1] = version;
        assert_eq!(
            SignedRecord::decode(&bad).unwrap_err(),
            vhalla_rooms::Error::Encoding
        );
    }
    for enabled in [2, u8::MAX] {
        let mut bad = bytes.clone();
        bad[ACTION + 34] = enabled;
        assert_eq!(
            SignedRecord::decode(&bad).unwrap_err(),
            vhalla_rooms::Error::Encoding
        );
    }
    for position in [ACTION + 2, ACTION + 34] {
        let mut tampered = bytes.clone();
        tampered[position] ^= 1;
        assert_eq!(
            SignedRecord::decode(&tampered)
                .unwrap()
                .verify()
                .unwrap_err(),
            vhalla_rooms::Error::Signature
        );
    }
    let zero_network = f.update(
        f.create,
        15,
        UpdateAction::SetPublicActivityPolicy {
            network: [0; 32],
            enabled: false,
        },
    );
    assert_eq!(
        zero_network.sign_with_key(&f.creator.key).unwrap_err(),
        vhalla_rooms::Error::Bounds
    );
    let mut zero_bytes = bytes;
    zero_bytes[ACTION + 2..ACTION + 34].fill(0);
    assert_eq!(
        SignedRecord::decode(&zero_bytes).unwrap_err(),
        vhalla_rooms::Error::Bounds
    );
}
