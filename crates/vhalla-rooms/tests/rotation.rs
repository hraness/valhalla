//! Committed validator-schedule regressions: `Registry::apply_rotation`
//! admission bounds, the append-only activation order, digest binding and
//! the `VRSN3` snapshot layout including strict restore re-validation.
mod common;
use common::*;
use vhalla_rooms::registry::{RegistryError, ValidatorMember, MAX_ROTATIONS, MAX_VALIDATORS};
use vhalla_social::archive::Archive;

/// A deterministic Ed25519 public key: validator members must be
/// canonical points, so raw digest bytes will not do.
fn member_key(seed: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    ed25519_dalek::SigningKey::from_bytes(&bytes)
        .verifying_key()
        .to_bytes()
}

fn member(seed: u8, power: u64) -> ValidatorMember {
    ValidatorMember {
        key: member_key(seed),
        power,
    }
}

#[test]
fn apply_rotation_commits_digest_bound_schedule() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let (_, mut registry) = sources(&mut archive, 10, 2);
    let digest = registry.digest();
    let before = registry.clone();
    registry
        .apply_rotation(30, &[member(1, 5), member(2, 3)], 100)
        .unwrap();
    let schedule = registry.validator_schedule();
    assert_eq!(schedule.len(), 1);
    let set = &schedule[&30];
    // Stored order is canonical key order, not argument order.
    assert!(set.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(set.iter().all(|m| m.power > 0));
    assert_ne!(registry.digest(), digest);
    assert!(registry.is_extension_of(&before));
    assert!(!before.is_extension_of(&registry));
    // A second rotation at a higher activation appends; earlier entries
    // are immutable.
    registry.apply_rotation(60, &[member(3, 7)], 200).unwrap();
    assert_eq!(registry.validator_schedule().len(), 2);
    assert!(registry.is_extension_of(&before));
}

#[test]
fn apply_rotation_rejects_each_bound() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let (_, mut registry) = sources(&mut archive, 20, 2);
    // Empty and oversized sets.
    assert_eq!(
        registry.apply_rotation(10, &[], 1),
        Err(RegistryError::Capacity)
    );
    let oversized: Vec<ValidatorMember> =
        (0..=MAX_VALIDATORS as u8).map(|s| member(s, 1)).collect();
    assert_eq!(
        registry.apply_rotation(10, &oversized, 1),
        Err(RegistryError::Capacity)
    );
    // Zero power and duplicate keys.
    assert_eq!(
        registry.apply_rotation(10, &[member(1, 0)], 1),
        Err(RegistryError::Bounds)
    );
    assert_eq!(
        registry.apply_rotation(10, &[member(1, 2), member(1, 3)], 1),
        Err(RegistryError::Bounds)
    );
    // A key that is not a canonical Ed25519 point ([0x02;32] does not
    // decompress — checked against the same verifier the node uses).
    let mut bad = member(9, 1);
    bad.key = [0x02; 32];
    assert!(ed25519_dalek::VerifyingKey::from_bytes(&bad.key).is_err());
    assert_eq!(
        registry.apply_rotation(10, &[bad], 1),
        Err(RegistryError::Bounds)
    );
    // Total power overflow and the quorum-safety bound.
    let heavy: Vec<ValidatorMember> = vec![member(1, u64::MAX / 3), member(2, u64::MAX / 3)];
    assert_eq!(
        registry.apply_rotation(10, &heavy, 1),
        Err(RegistryError::Cost)
    );
    // Nothing committed through the rejections.
    assert!(registry.validator_schedule().is_empty());

    registry.apply_rotation(50, &[member(1, 1)], 10).unwrap();
    // Reused activation and non-increasing activations are both closed.
    assert_eq!(
        registry.apply_rotation(50, &[member(2, 1)], 20),
        Err(RegistryError::Bounds)
    );
    assert_eq!(
        registry.apply_rotation(30, &[member(2, 1)], 20),
        Err(RegistryError::Bounds)
    );
    // The clock bound applies to rotations like every other transition.
    assert_eq!(
        registry.apply_rotation(80, &[member(2, 1)], 5),
        Err(RegistryError::Clock)
    );
    // Rotation count capacity.
    let mut full = sources(&mut archive, 30, 2).1;
    for i in 0..MAX_ROTATIONS as u64 {
        full.apply_rotation(10 + i * 10, &[member(1, 1)], i * 10 + 1)
            .unwrap();
    }
    assert_eq!(
        full.apply_rotation(10_000, &[member(2, 1)], 100_000),
        Err(RegistryError::Capacity)
    );
}

#[test]
fn snapshot_v3_round_trip_preserves_schedule() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let (_, mut registry) = sources(&mut archive, 40, 2);
    registry
        .apply_rotation(25, &[member(1, 5), member(2, 3), member(3, 1)], 100)
        .unwrap();
    let snapshot = registry.snapshot();
    // The v3 magic marks the schedule-bearing layout.
    assert_eq!(&snapshot[..8], b"VRSN\0\0\0\x03");
    let restored = vhalla_rooms::Registry::restore(&snapshot).unwrap();
    assert_eq!(restored.digest(), registry.digest());
    assert_eq!(restored.snapshot(), snapshot);
    assert_eq!(restored.validator_schedule(), registry.validator_schedule());
    // And the restored schedule still applies in commit order.
    let mut restored = restored;
    restored.apply_rotation(50, &[member(4, 2)], 200).unwrap();
    assert_eq!(restored.validator_schedule().len(), 2);
}

#[test]
fn never_rotated_snapshot_keeps_v1_layout() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let (_, registry) = sources(&mut archive, 50, 2);
    let snapshot = registry.snapshot();
    assert_eq!(&snapshot[..8], b"VRSN\0\0\0\x01");
    let restored = vhalla_rooms::Registry::restore(&snapshot).unwrap();
    assert!(restored.validator_schedule().is_empty());
    assert_eq!(restored.snapshot(), snapshot);
}

#[test]
fn restore_rejects_corrupt_schedule() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let (_, mut registry) = sources(&mut archive, 60, 2);
    registry
        .apply_rotation(25, &[member(1, 5), member(2, 3)], 100)
        .unwrap();
    let snapshot = registry.snapshot();

    // Any member-byte corruption breaks the checksum over the payload.
    let mut corrupt = snapshot.clone();
    let member_byte = corrupt.len() - 32 - 8;
    corrupt[member_byte] ^= 0x01;
    assert!(matches!(
        vhalla_rooms::Registry::restore(&corrupt),
        Err(RegistryError::Corrupt)
    ));

    // A v3 frame claiming a zero-length member set is refused: an empty
    // committed set would wedge every node's validator view.
    let mut framed = snapshot.clone();
    // The schedule tail is count(4) + per-entry (from 8 + count 4 +
    // 2 members * 40) = 4 + 8 + 4 + 80 = 96 bytes before the checksum.
    let set_count = framed.len() - 32 - 84;
    framed[set_count..set_count + 4].copy_from_slice(&0u32.to_be_bytes());
    let end = framed.len() - 32;
    use sha2::{Digest, Sha256};
    let mut checksum = Sha256::new();
    checksum.update(b"vhalla/rooms/registry-snapshot/v1\0");
    checksum.update(&framed[8..end]);
    framed[end..].copy_from_slice(&checksum.finalize());
    assert!(matches!(
        vhalla_rooms::Registry::restore(&framed),
        Err(RegistryError::Corrupt)
    ));
}
