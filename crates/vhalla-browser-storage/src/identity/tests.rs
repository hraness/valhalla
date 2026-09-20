use super::*;
use crate::{Access, PublishError};

fn vault(variant: u8) -> Image {
    // Storage checks framing, not passwords. Mutating nonce/ciphertext produces
    // distinct exact-CAS images for the same key without another expensive KDF.
    let hex = include_str!("../../../vhalla-browser-vault/vectors/v1-envelope.hex").trim();
    let mut raw: Vec<u8> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect();
    raw[30] ^= variant;
    Image::new(Slot::Vault, &[&raw]).unwrap()
}

#[test]
fn provenance_codec_rejects_partial_corrupt_and_mismatching_pairs() {
    let snapshot = created(&vault(0)).unwrap();
    let raw = snapshot.birth_bytes().unwrap();
    let public = vault_public(snapshot.vault().unwrap()).unwrap();
    let reread =
        IdentitySnapshot::decode(Some(snapshot.vault().unwrap().as_bytes()), Some(&raw)).unwrap();
    assert!(snapshot == reread);
    assert_eq!(reread.local_creation(public).unwrap().public_key(), public);
    for length in 0..BIRTH_BYTES {
        assert_eq!(LocalCreation::decode(&raw[..length]), Err(Error::Corrupt));
    }
    let mut extra = raw.to_vec();
    extra.push(0);
    assert_eq!(LocalCreation::decode(&extra), Err(Error::Corrupt));
    let mut version = raw;
    version[7] ^= 1;
    assert_eq!(LocalCreation::decode(&version), Err(Error::Corrupt));
    assert!(matches!(
        IdentitySnapshot::decode(None, Some(&raw)),
        Err(Error::Corrupt)
    ));
    let mut wrong = raw;
    wrong[8] ^= 1;
    assert!(matches!(
        IdentitySnapshot::decode(Some(snapshot.vault().unwrap().as_bytes()), Some(&wrong)),
        Err(Error::Corrupt)
    ));
    let legacy =
        IdentitySnapshot::decode(Some(snapshot.vault().unwrap().as_bytes()), None).unwrap();
    assert_eq!(legacy.local_creation(public), Err(Error::RecoveryRequired));
    assert_eq!(snapshot.local_creation([0; 32]), Err(Error::WrongScope));
}

#[test]
fn replacement_preserves_birth_or_its_absence_and_never_changes_identity() {
    let original = vault(0);
    let rotated = vault(1);
    let born = created(&original).unwrap();
    let replacement = replaced(&born, &rotated).unwrap();
    assert_eq!(replacement.birth_bytes(), born.birth_bytes());
    assert_eq!(replacement.vault().unwrap().as_bytes(), rotated.as_bytes());
    let imported = replaced(&IdentitySnapshot::empty(), &original).unwrap();
    assert!(imported.birth.is_none());
    assert!(replaced(&imported, &rotated).unwrap().birth.is_none());
    let foreign = include_str!("../../../vhalla-browser-vault/vectors/v1-wrong-public.hex").trim();
    let foreign: Vec<u8> = foreign
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect();
    let foreign = Image::new(Slot::Vault, &[&foreign]).unwrap();
    assert!(matches!(replaced(&born, &foreign), Err(Error::WrongScope)));
    assert!(matches!(
        replaced(&imported, &foreign),
        Err(Error::WrongScope)
    ));
}

#[derive(Clone, Copy)]
enum Outcome {
    Complete,
    Abort,
    CancelBeforeCommit,
    CancelAfterCommit,
}

// Native event model shares the actual pair-CAS, candidate preparation and
// access latch. Atomic pair assignment models an IDB transaction, not its engine.
struct Handle(Access);
impl Handle {
    fn new() -> Self {
        Self(Access::Ready)
    }
    fn publish(
        &mut self,
        disk: &mut IdentitySnapshot,
        expected: &IdentitySnapshot,
        candidate: &Image,
        create: bool,
        outcome: Outcome,
    ) -> Option<Result<(), PublishError>> {
        self.0.begin().ok()?;
        if let Err(error) = compare_identity(expected, disk) {
            self.0 = Access::NeedsReopen;
            return Some(Err(PublishError::ReopenRequired(error)));
        }
        let next = if create {
            created(candidate)
        } else {
            replaced(expected, candidate)
        }
        .unwrap();
        match outcome {
            Outcome::Abort => {
                self.0 = Access::NeedsReopen;
                return Some(Err(PublishError::ReopenRequired(Error::Storage)));
            }
            Outcome::CancelBeforeCommit => return None,
            Outcome::Complete | Outcome::CancelAfterCommit => *disk = next,
        }
        if matches!(outcome, Outcome::CancelAfterCommit) {
            return None;
        }
        Some(self.0.completed().map_err(PublishError::ReopenRequired))
    }
}

#[test]
fn competing_creation_restore_and_pair_changes_never_grant_new_birth() {
    let mut disk = IdentitySnapshot::empty();
    let expected = disk.clone();
    assert_eq!(
        Handle::new().publish(&mut disk, &expected, &vault(0), false, Outcome::Complete),
        Some(Ok(()))
    );
    let restored = disk.clone();
    assert_eq!(
        Handle::new().publish(&mut disk, &expected, &vault(1), true, Outcome::Complete),
        Some(Err(PublishError::ReopenRequired(Error::Stale)))
    );
    assert!(disk == restored);
    assert!(disk.birth.is_none());
    let birth = created(&vault(0)).unwrap();
    assert_eq!(
        compare_identity(&restored, &birth),
        Err(Error::Stale),
        "equal vault bytes do not hide changed provenance"
    );

    let mut created_disk = IdentitySnapshot::empty();
    assert_eq!(
        Handle::new().publish(
            &mut created_disk,
            &expected,
            &vault(0),
            true,
            Outcome::Complete
        ),
        Some(Ok(()))
    );
    let winning = created_disk.clone();
    assert_eq!(
        Handle::new().publish(
            &mut created_disk,
            &expected,
            &vault(1),
            true,
            Outcome::Complete
        ),
        Some(Err(PublishError::ReopenRequired(Error::Stale)))
    );
    assert!(created_disk == winning);
}

#[test]
fn interrupted_creation_requires_reconciliation_and_preserves_atomic_pair() {
    for outcome in [
        Outcome::Abort,
        Outcome::CancelBeforeCommit,
        Outcome::CancelAfterCommit,
    ] {
        let mut disk = IdentitySnapshot::empty();
        let expected = disk.clone();
        let mut handle = Handle::new();
        assert_ne!(
            handle.publish(&mut disk, &expected, &vault(0), true, outcome),
            Some(Ok(()))
        );
        assert_eq!(handle.0.ready(), Err(Error::NeedsReopen));
        if matches!(outcome, Outcome::CancelAfterCommit) {
            assert!(disk == created(&vault(0)).unwrap());
            assert_eq!(compare_identity(&expected, &disk), Err(Error::Stale));
        } else {
            assert!(disk == expected);
        }
        let reopened = IdentitySnapshot::decode(
            disk.vault().map(Image::as_bytes),
            disk.birth_bytes().as_ref().map(|b| &b[..]),
        )
        .unwrap();
        assert!(reopened == disk);
    }
}

#[test]
fn author_initialization_checks_exact_birth_vault_key_and_absent_namespace() {
    let born = created(&vault(0)).unwrap();
    let public = vault_public(born.vault().unwrap()).unwrap();
    assert_eq!(fresh_author_check(&born, &born, public, false), Ok(()));
    assert_eq!(
        fresh_author_check(&born, &born, public, true),
        Err(Error::Stale)
    );
    assert_eq!(
        fresh_author_check(&born, &born, [0; 32], false),
        Err(Error::WrongScope)
    );
    let imported = replaced(&IdentitySnapshot::empty(), &vault(0)).unwrap();
    assert_eq!(
        fresh_author_check(&imported, &imported, public, false),
        Err(Error::RecoveryRequired)
    );
    assert_eq!(
        fresh_author_check(&born, &imported, public, false),
        Err(Error::Stale)
    );
    let newer = replaced(&born, &vault(1)).unwrap();
    assert_eq!(
        fresh_author_check(&born, &newer, public, false),
        Err(Error::Stale)
    );
    assert_eq!(fresh_author_check(&newer, &newer, public, false), Ok(()));
}
