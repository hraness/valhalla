use super::*;
use std::collections::BTreeMap;

fn checkpoint(value: &[u8]) -> Image {
    Image::new(Slot::Checkpoint, &[value]).unwrap()
}

fn vault() -> Image {
    let hex = include_str!("../../vhalla-browser-vault/vectors/v1-envelope.hex").trim();
    let raw: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    Image::new(Slot::Vault, &[&raw]).unwrap()
}

#[test]
fn canonical_slots_preserve_exact_bytes_without_claiming_domain_verification() {
    let checkpoint =
        Image::new(Slot::Checkpoint, &[b"not a signed record", b"opaque proof"]).unwrap();
    let decoded = Image::from_bytes(Slot::Checkpoint, checkpoint.as_bytes()).unwrap();
    assert_eq!(decoded.as_bytes(), checkpoint.as_bytes());
    assert_eq!(
        decoded.records().collect::<Vec<_>>(),
        [&b"not a signed record"[..], &b"opaque proof"[..]]
    );
    assert!(matches!(
        Image::from_bytes(Slot::Outbox, checkpoint.as_bytes()),
        Err(Error::WrongSlot)
    ));
    let vault = vault();
    assert_eq!(vault.records().len(), 1);
    assert_eq!(vault.records().next().unwrap().len(), ENVELOPE_BYTES);
    assert!(matches!(
        Image::new(Slot::Vault, &[b"a plaintext seed or password"]),
        Err(Error::Corrupt)
    ));
    assert!(matches!(Image::new(Slot::Vault, &[]), Err(Error::Corrupt)));
    assert!(Image::new(Slot::Outbox, &[]).is_ok());
}

#[test]
fn malformed_lengths_versions_counts_and_trailing_bytes_are_rejected() {
    let image = checkpoint(b"opaque");
    for length in 0..image.as_bytes().len() {
        assert!(Image::from_bytes(Slot::Checkpoint, &image.as_bytes()[..length]).is_err());
    }
    let mut extra = image.as_bytes().to_vec();
    extra.push(0);
    assert!(matches!(
        Image::from_bytes(Slot::Checkpoint, &extra),
        Err(Error::Corrupt)
    ));
    let mut version = image.as_bytes().to_vec();
    version[7] = 2;
    assert!(matches!(
        Image::from_bytes(Slot::Checkpoint, &version),
        Err(Error::Corrupt)
    ));
    let mut count = image.as_bytes().to_vec();
    count[9..11].copy_from_slice(&((MAX_IMAGE_RECORDS + 1) as u16).to_be_bytes());
    assert!(matches!(
        Image::from_bytes(Slot::Checkpoint, &count),
        Err(Error::Bounds)
    ));
    let mut length = image.as_bytes().to_vec();
    length[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        Image::from_bytes(Slot::Checkpoint, &length),
        Err(Error::Bounds)
    ));
    let oversized = vec![0; MAX_IMAGE_BYTES + 1];
    assert!(matches!(
        Image::from_bytes(Slot::Checkpoint, &oversized),
        Err(Error::Bounds)
    ));
    assert!(matches!(
        Image::new(Slot::Outbox, &[&vec![0; MAX_RECORD_BYTES + 1]]),
        Err(Error::Bounds)
    ));
    let part = vec![0; MAX_RECORD_BYTES];
    assert!(matches!(
        Image::new(Slot::Checkpoint, &[&part, &part]),
        Err(Error::Bounds)
    ));
    let records = vec![&b"x"[..]; MAX_IMAGE_RECORDS];
    assert_eq!(
        Image::new(Slot::Checkpoint, &records)
            .unwrap()
            .records()
            .len(),
        MAX_IMAGE_RECORDS
    );
    let records = vec![&b"x"[..]; MAX_IMAGE_RECORDS + 1];
    assert!(matches!(
        Image::new(Slot::Checkpoint, &records),
        Err(Error::Bounds)
    ));
}

// This native event model shares the real CAS predicate and publication latch.
// It does not emulate IndexedDB or prove browser callback/resource lifetimes.
#[derive(Clone, Copy)]
enum EventPath {
    Complete,
    AbortBeforeCommit,
    CancelBeforeCommit,
    CancelAfterCommit,
    VersionChangeAfterCommit,
}

struct ModelHandle(Access);

impl ModelHandle {
    fn open() -> Self {
        Self(Access::Ready)
    }

    fn publish(
        &mut self,
        saved: &mut BTreeMap<u8, Vec<u8>>,
        previous: Option<&Image>,
        next: &Image,
        path: EventPath,
    ) -> Option<Result<(), PublishError>> {
        if let Err(error) = self.0.ready() {
            return Some(Err(PublishError::Rejected(error)));
        }
        if previous.is_some_and(|image| image.slot() != next.slot()) {
            return Some(Err(PublishError::Rejected(Error::WrongSlot)));
        }
        self.0.begin().unwrap();
        if let Err(error) = compare_exact(
            previous.map(Image::as_bytes),
            saved.get(&next.slot().tag()).map(Vec::as_slice),
        ) {
            self.0 = Access::NeedsReopen;
            return Some(Err(PublishError::ReopenRequired(error)));
        }
        if matches!(path, EventPath::AbortBeforeCommit) {
            self.0 = Access::NeedsReopen;
            return Some(Err(PublishError::ReopenRequired(Error::Storage)));
        }
        if matches!(path, EventPath::CancelBeforeCommit) {
            return None;
        }
        saved.insert(next.slot().tag(), next.as_bytes().to_vec());
        if matches!(path, EventPath::CancelAfterCommit) {
            return None;
        }
        if matches!(path, EventPath::VersionChangeAfterCommit) {
            self.0 = Access::NeedsReopen;
        }
        Some(self.0.completed().map_err(PublishError::ReopenRequired))
    }
}

#[test]
fn competing_writers_and_duplicate_initialization_never_overwrite_the_winner() {
    let mut saved = BTreeMap::new();
    let first = checkpoint(b"initial checkpoint");
    let next = checkpoint(b"next checkpoint");
    let stale_candidate = checkpoint(b"stale candidate");
    let mut alice = ModelHandle::open();
    let mut bob = ModelHandle::open();
    assert_eq!(
        alice.publish(&mut saved, None, &first, EventPath::Complete),
        Some(Ok(()))
    );
    assert_eq!(
        alice.publish(&mut saved, Some(&first), &next, EventPath::Complete),
        Some(Ok(()))
    );
    assert_eq!(
        bob.publish(
            &mut saved,
            Some(&first),
            &stale_candidate,
            EventPath::Complete
        ),
        Some(Err(PublishError::ReopenRequired(Error::Stale)))
    );
    assert_eq!(saved[&Slot::Checkpoint.tag()], next.as_bytes());
    assert_eq!(
        bob.publish(&mut saved, None, &first, EventPath::Complete),
        Some(Err(PublishError::Rejected(Error::NeedsReopen)))
    );
    let mut reopened = ModelHandle::open();
    assert_eq!(
        reopened.publish(&mut saved, None, &first, EventPath::Complete),
        Some(Err(PublishError::ReopenRequired(Error::Stale)))
    );
    assert_eq!(saved[&Slot::Checkpoint.tag()], next.as_bytes());
}

#[test]
fn cancellation_and_abort_require_reopen_even_when_storage_may_have_changed() {
    let first = checkpoint(b"old");
    let next = checkpoint(b"new");
    for path in [
        EventPath::AbortBeforeCommit,
        EventPath::CancelBeforeCommit,
        EventPath::CancelAfterCommit,
        EventPath::VersionChangeAfterCommit,
    ] {
        let mut saved = BTreeMap::from([(Slot::Checkpoint.tag(), first.as_bytes().to_vec())]);
        let mut handle = ModelHandle::open();
        let outcome = handle.publish(&mut saved, Some(&first), &next, path);
        assert_ne!(outcome, Some(Ok(())));
        assert_eq!(handle.0.ready(), Err(Error::NeedsReopen));
        let recovered =
            Image::from_bytes(Slot::Checkpoint, &saved[&Slot::Checkpoint.tag()]).unwrap();
        let expected = if matches!(
            path,
            EventPath::CancelAfterCommit | EventPath::VersionChangeAfterCommit
        ) {
            &next
        } else {
            &first
        };
        assert_eq!(recovered.as_bytes(), expected.as_bytes());
        // A fresh handle uses the actual recovered bytes, never a presumed rollback.
        let mut reopened = ModelHandle::open();
        assert_eq!(
            reopened.publish(&mut saved, Some(&recovered), &next, EventPath::Complete),
            Some(Ok(()))
        );
    }
}

#[test]
fn independent_slots_and_explicit_vault_replacement_use_exact_cas() {
    let mut saved = BTreeMap::new();
    let old_vault = vault();
    let mut changed_bytes = old_vault.records().next().unwrap().to_vec();
    // This is deliberately only a structurally valid opaque encrypted envelope.
    // The domain must authenticate/authorize a real rotated vault before storage.
    changed_bytes[21] ^= 1;
    let replacement = Image::new(Slot::Vault, &[&changed_bytes]).unwrap();
    let checkpoint = checkpoint(b"independent checkpoint");
    let outbox = Image::new(Slot::Outbox, &[b"opaque signed submission"]).unwrap();
    let mut handle = ModelHandle::open();
    for image in [&old_vault, &checkpoint, &outbox] {
        assert_eq!(
            handle.publish(&mut saved, None, image, EventPath::Complete),
            Some(Ok(()))
        );
    }
    assert_eq!(
        handle.publish(
            &mut saved,
            Some(&old_vault),
            &replacement,
            EventPath::Complete
        ),
        Some(Ok(()))
    );
    assert_eq!(saved[&Slot::Vault.tag()], replacement.as_bytes());
    assert_eq!(saved[&Slot::Checkpoint.tag()], checkpoint.as_bytes());
    assert_eq!(saved[&Slot::Outbox.tag()], outbox.as_bytes());
    assert_eq!(
        handle.publish(
            &mut saved,
            Some(&checkpoint),
            &replacement,
            EventPath::Complete
        ),
        Some(Err(PublishError::Rejected(Error::WrongSlot)))
    );
    assert_eq!(handle.0.ready(), Ok(()));
}
