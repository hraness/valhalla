use super::*;
use crate::common;
use ed25519_dalek::SigningKey;
use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};
use vhalla_room_activity::{Content, EventClaims, EventId, Text, UnsignedEvent};
use vhalla_rooms::{Applied, RoomRecordId, RoomUpdate, UpdateAction};
use vhalla_social::{archive::Archive, control::ControlView};

const NETWORK: [u8; 32] = [7; 32];
fn limits() -> Limits {
    Limits {
        max_events: 20_000,
        max_history_bytes: 64 * 1024 * 1024,
    }
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-room-activity-store-{}-{}",
            std::process::id(),
            hex(&random)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("store")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Fixture {
    archive: Archive,
    owner: common::Owner,
    registry: vhalla_rooms::Registry,
    scope: RoomScope,
    head: RoomRecordId,
    policy: RoomRecordId,
    key: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let mut archive = Archive::new(common::REALM, common::limits()).unwrap();
        let owner = common::beneficiary(&mut archive, 4);
        let (mut pool, mut registry) = common::sources(&mut archive, 90, 1);
        let head = common::grant_create(&mut registry, &archive, &owner, 100);
        common::award_one(&mut registry, &mut archive, &mut pool[0], &owner, 200);
        let create = common::creation(&owner, head, head, "stored-room", 1, 1, 13);
        let Applied::Created(room) = common::apply(&mut registry, &archive, &create, 300).unwrap()
        else {
            panic!("room creation")
        };
        let mut f = Self {
            archive,
            owner,
            registry,
            scope: RoomScope {
                network: NETWORK,
                realm: common::REALM,
                directory: common::DIRECTORY,
                room,
            },
            head: create.id(),
            policy: create.id(),
            key: SigningKey::from_bytes(&[42; 32]),
        };
        f.set_policy(true);
        f
    }
    fn set_policy(&mut self, enabled: bool) {
        let record = RoomUpdate {
            directory: self.scope.directory,
            realm: self.scope.realm,
            genesis: self.scope.room,
            previous: self.head,
            owner: self.owner.id,
            social_control: self.owner.head,
            controller_key: self.owner.key.verifying_key().to_bytes(),
            expires_at: common::EXPIRES,
            nonce: *self.head.as_bytes(),
            action: UpdateAction::SetPublicActivityPolicy {
                network: NETWORK,
                enabled,
            },
        }
        .sign_with_key(&self.owner.key)
        .unwrap()
        .verify()
        .unwrap();
        assert_eq!(
            self.registry
                .apply(&record, &ControlView::new(&self.archive, 400), 400),
            Ok(Applied::Updated(record.id()))
        );
        self.head = record.id();
        self.policy = record.id();
    }
    fn context(&self) -> AdmissionContext<'_> {
        AdmissionContext::new(NETWORK, &self.registry).unwrap()
    }
    fn author(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    fn event(&self, sequence: u64, previous: EventId, text: &str) -> VerifiedEvent {
        UnsignedEvent::new(EventClaims {
            scope: self.scope,
            policy: self.policy,
            author: self.author(),
            sequence,
            previous,
            created_at: 0,
            content: Content::Text(Text::new(text).unwrap()),
        })
        .unwrap()
        .sign_with_key(&self.key)
        .unwrap()
        .verify()
        .unwrap()
    }
}
fn append(store: &mut Store, event: VerifiedEvent, f: &Fixture) -> StoredEvent {
    let expected = store.author_head(event.claims().author).unwrap();
    let context = f.context();
    store
        .append(event, expected, &context, *context.registry_digest())
        .unwrap()
}

#[test]
fn durable_restart_exact_retry_and_revocation_preserve_author_floor() {
    let temp = Temp::new();
    let mut f = Fixture::new();
    let mut store = Store::create(temp.path(), f.scope, limits()).unwrap();
    let first = f.event(1, EventId::ZERO, "retained before revocation");
    let receipt = append(&mut store, first.clone(), &f);
    assert!(!receipt.reconciled());
    let pin = store.pin();
    let head = store.author_head(f.author()).unwrap();
    drop(store);
    f.set_policy(false);
    let mut store = Store::open(temp.path(), f.scope, limits(), Some(pin)).unwrap();
    assert_eq!(store.author_head(f.author()).unwrap(), head);
    let context = f.context();
    let repeated = store
        .append(first.clone(), None, &context, *context.registry_digest())
        .unwrap();
    assert!(repeated.reconciled());
    assert_eq!(repeated.cursor(), 1);
    assert_eq!(store.pin(), pin);
    let denied = f.event(2, first.id(), "closed room");
    assert!(matches!(
        store.append(denied, head, &context, *context.registry_digest()),
        Err(Error::Activity(vhalla_room_activity::Error::Policy))
    ));
    f.set_policy(true);
    let second = append(&mut store, f.event(2, first.id(), "reopened"), &f);
    assert_eq!(second.event().claims().sequence, 2);
    let page = store.read_page(0, MAX_PAGE).unwrap();
    assert_eq!(page.records().len(), 2);
    assert_eq!(page.records()[0].event().encode(), first.encode());
}

#[test]
fn forks_gaps_stale_heads_and_wrong_registry_basis_never_write_intent() {
    let temp = Temp::new();
    let f = Fixture::new();
    let mut store = Store::create(temp.path(), f.scope, limits()).unwrap();
    let context = f.context();
    let first = f.event(1, EventId::ZERO, "first");
    let gap = f.event(2, first.id(), "gap");
    assert!(matches!(
        store.append(gap, None, &context, *context.registry_digest()),
        Err(Error::Activity(vhalla_room_activity::Error::Gap))
    ));
    assert!(matches!(
        store.append(first.clone(), None, &context, [3; 32]),
        Err(Error::Conflict)
    ));
    assert!(!store.recovery_required().unwrap());
    assert_eq!(store.pin(), Pin::EMPTY);
    append(&mut store, first.clone(), &f);
    let pin = store.pin();
    let head = store.author_head(f.author()).unwrap();
    assert!(matches!(
        store.append(
            f.event(1, EventId::ZERO, "fork"),
            head,
            &context,
            *context.registry_digest()
        ),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        store.append(
            f.event(2, first.id(), "next"),
            None,
            &context,
            *context.registry_digest()
        ),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        store.append(
            f.event(2, EventId::from_bytes([3; 32]), "wrong previous"),
            head,
            &context,
            *context.registry_digest()
        ),
        Err(Error::Activity(vhalla_room_activity::Error::Fork))
    ));
    assert_eq!(store.pin(), pin);
    assert!(!store.recovery_required().unwrap());
}

#[test]
fn each_publication_interruption_recovers_exact_old_admission_once() {
    for step in [
        Step::IntentWritten,
        Step::IntentDurable,
        Step::RecoveryIntentSynced,
        Step::RecordPublished,
        Step::SequenceIndexed,
        Step::AuthorTempDurable,
        Step::AuthorHeadPublished,
        Step::HeadTempDurable,
        Step::HeadPublished,
        Step::DirectorySynced,
        Step::IntentRemoved,
    ] {
        let temp = Temp::new();
        let mut f = Fixture::new();
        let event = f.event(1, EventId::ZERO, "durable intent");
        let context = f.context();
        let mut store = Store::create(temp.path(), f.scope, limits()).unwrap();
        store.fault = Some(step);
        assert!(
            matches!(
                store.append(event.clone(), None, &context, *context.registry_digest()),
                Err(Error::Indeterminate(_))
            ),
            "{step:?}"
        );
        drop(store);
        f.set_policy(false);
        let mut store = Store::open(temp.path(), f.scope, limits(), None).unwrap();
        if store.recovery_required().unwrap() {
            assert!(matches!(
                store.read_page(0, 1),
                Err(Error::RecoveryRequired)
            ));
            let recovered = store.recover().unwrap().unwrap();
            assert_eq!(recovered.event().encode(), event.encode());
            assert!(recovered.reconciled());
        }
        assert_eq!(store.pin().count(), 1);
        assert!(store.recover().unwrap().is_none());
        let context = f.context();
        let retry = store
            .append(event.clone(), None, &context, *context.registry_digest())
            .unwrap();
        assert_eq!(retry.cursor(), 1);
        assert!(retry.reconciled());
        let page = store.read_page(0, 64).unwrap();
        assert_eq!(page.records().len(), 1);
        assert_eq!(page.records()[0].event().encode(), event.encode());
    }
}

#[test]
fn torn_intent_and_unknown_temporaries_fail_closed_without_cleanup() {
    let temp = Temp::new();
    let f = Fixture::new();
    let mut store = Store::create(temp.path(), f.scope, limits()).unwrap();
    store.fault = Some(Step::IntentCreated);
    let context = f.context();
    assert!(matches!(
        store.append(
            f.event(1, EventId::ZERO, "not admitted"),
            None,
            &context,
            *context.registry_digest()
        ),
        Err(Error::Indeterminate(_))
    ));
    drop(store);
    assert!(matches!(
        Store::open(temp.path(), f.scope, limits(), None),
        Err(Error::Corrupt)
    ));
    assert_eq!(
        fs::read(temp.path().join(INTENT)).unwrap(),
        Vec::<u8>::new()
    );
    let temp = Temp::new();
    let store = Store::create(temp.path(), f.scope, limits()).unwrap();
    drop(store);
    write_new(&temp.path().join(HEAD_TEMP), b"unknown").unwrap();
    assert!(matches!(
        Store::open(temp.path(), f.scope, limits(), None),
        Err(Error::RecoveryRequired)
    ));
    assert_eq!(fs::read(temp.path().join(HEAD_TEMP)).unwrap(), b"unknown");
}

#[test]
fn exact_unpublished_prefix_recovers_but_committed_corruption_is_not_rewritten() {
    let temp = Temp::new();
    let f = Fixture::new();
    let context = f.context();
    let event = f.event(1, EventId::ZERO, "prefix recovery");
    let mut store = Store::create(temp.path(), f.scope, limits()).unwrap();
    store.fault = Some(Step::IntentDurable);
    assert!(store
        .append(event.clone(), None, &context, *context.registry_digest())
        .is_err());
    let intent = store.validate_intent().unwrap();
    let raw = intent.record.encode();
    write_new(&store.record_path(1), &raw[..17]).unwrap();
    drop(store);
    let mut store = Store::open(temp.path(), f.scope, limits(), None).unwrap();
    store.recover().unwrap();
    assert_eq!(
        store.read_page(0, 1).unwrap().records()[0].event().encode(),
        event.encode()
    );
    let path = store.record_path(1);
    let uid = store.uid;
    drop(store);
    let file = open(&path, uid, MAX_RECORD_BYTES).unwrap();
    file.set_len(17).unwrap();
    file.sync_all().unwrap();
    assert!(Store::open(temp.path(), f.scope, limits(), None).is_err());
    assert_eq!(fs::metadata(path).unwrap().len(), 17);
}

#[test]
fn duplicate_checks_full_key_scope_sequence_record_and_head_indexes() {
    for damage in 0..4 {
        let temp = Temp::new();
        let f = Fixture::new();
        let mut store = Store::create(temp.path(), f.scope, limits()).unwrap();
        let event = f.event(1, EventId::ZERO, "index proof");
        append(&mut store, event.clone(), &f);
        let index_path = store.sequence_path(f.author(), 1);
        let head_path = store.author_path(f.author()).join(HEAD);
        match damage {
            0 => {
                let file = open(&index_path, store.uid, INDEX_BYTES).unwrap();
                file.set_len(7).unwrap();
            }
            1 => {
                fs::remove_file(store.record_path(1)).unwrap();
            }
            2 => {
                let file = open(&head_path, store.uid, INDEX_BYTES).unwrap();
                file.set_len(7).unwrap();
            }
            _ => {
                let mut index =
                    Index::decode(&read(&index_path, store.uid, INDEX_BYTES).unwrap()).unwrap();
                index.sequence = 2;
                let mut file = open(&index_path, store.uid, INDEX_BYTES).unwrap();
                file.write_all(&index.encode()).unwrap();
            }
        }
        let context = f.context();
        assert!(
            store
                .append(event, None, &context, *context.registry_digest())
                .is_err(),
            "damage {damage}"
        );
        assert_eq!(store.pin().count(), 1);
        assert!(!store.recovery_required().unwrap());
    }
}

#[test]
fn lifetime_history_exceeds_social_archive_limit_with_bounded_pages() {
    let temp = Temp::new();
    let f = Fixture::new();
    let context = f.context();
    let mut store = Store::create(temp.path(), f.scope, limits()).unwrap();
    let mut previous = EventId::ZERO;
    let mut head = None;
    for sequence in 1..=4_101 {
        let event = f.event(sequence, previous, "x");
        previous = event.id();
        store
            .append(event, head, &context, *context.registry_digest())
            .unwrap();
        head = store.author_head(f.author()).unwrap();
    }
    let pin = store.pin();
    drop(store);
    let store = Store::open(temp.path(), f.scope, limits(), Some(pin)).unwrap();
    let mut cursor = 0;
    let mut count = 0;
    loop {
        let page = store.read_page(cursor, 37).unwrap();
        assert!(page.records().len() <= 37);
        if page.records().is_empty() {
            break;
        }
        for receipt in page.records() {
            count += 1;
            assert_eq!(receipt.event().claims().sequence, count);
        }
        cursor = page.next_cursor();
    }
    assert_eq!(count, 4_101);
    assert_eq!(cursor, pin.count());
    assert!(matches!(
        store.read_page(0, MAX_PAGE + 1),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        store.read_page(pin.count() + 1, 1),
        Err(Error::Conflict)
    ));
}

#[test]
fn capacity_refuses_new_writes_but_preserves_replay_and_history() {
    for budget in [
        Limits {
            max_events: 1,
            max_history_bytes: 100_000,
        },
        Limits {
            max_events: 100,
            max_history_bytes: 600,
        },
    ] {
        let temp = Temp::new();
        let f = Fixture::new();
        let mut store = Store::create(temp.path(), f.scope, budget).unwrap();
        let first = f.event(1, EventId::ZERO, "x");
        append(&mut store, first.clone(), &f);
        let pin = store.pin();
        let head = store.author_head(f.author()).unwrap();
        let context = f.context();
        assert!(matches!(
            store.append(
                f.event(2, first.id(), "x"),
                head,
                &context,
                *context.registry_digest()
            ),
            Err(Error::Capacity)
        ));
        assert_eq!(store.pin(), pin);
        assert!(!store.recovery_required().unwrap());
        assert!(store
            .append(first, None, &context, *context.registry_digest())
            .unwrap()
            .reconciled());
        assert_eq!(store.read_page(0, 1).unwrap().records().len(), 1);
        drop(store);
        assert!(matches!(
            Store::open(temp.path(), f.scope, limits(), None),
            Err(Error::Conflict)
        ));
    }
}

#[test]
fn private_paths_lock_scope_and_external_anchor_are_enforced() {
    let temp = Temp::new();
    let f = Fixture::new();
    let mut store = Store::create(temp.path(), f.scope, limits()).unwrap();
    assert!(matches!(
        Store::open(temp.path(), f.scope, limits(), None),
        Err(Error::Busy)
    ));
    assert!(Store::create(temp.path(), f.scope, limits()).is_err());
    append(&mut store, f.event(1, EventId::ZERO, "private"), &f);
    let old = Pin::EMPTY;
    drop(store);
    assert!(matches!(
        Store::open(temp.path(), f.scope, limits(), Some(old)),
        Err(Error::Freshness)
    ));
    let wrong = RoomScope {
        network: [8; 32],
        ..f.scope
    };
    assert!(matches!(
        Store::open(temp.path(), wrong, limits(), None),
        Err(Error::Conflict)
    ));
    fs::set_permissions(temp.path().join(HEAD), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Store::open(temp.path(), f.scope, limits(), None),
        Err(Error::UnsafePath)
    ));
}

#[test]
fn symlink_and_hardlink_substitution_refuse_before_publication() {
    for kind in 0..4 {
        let temp = Temp::new();
        let f = Fixture::new();
        let mut store = Store::create(temp.path(), f.scope, limits()).unwrap();
        let event = f.event(1, EventId::ZERO, "link test");
        append(&mut store, event, &f);
        let target = match kind {
            0 => store.record_path(1),
            1 => store.author_path(f.author()).join(HEAD),
            2 => temp.path().join(HEAD),
            _ => store.record_path(1),
        };
        drop(store);
        let retained = temp.0.join("retained");
        fs::rename(&target, &retained).unwrap();
        if kind == 3 {
            fs::hard_link(&retained, &target).unwrap();
        } else {
            symlink(&retained, &target).unwrap();
        }
        assert!(
            matches!(
                Store::open(temp.path(), f.scope, limits(), None),
                Err(Error::UnsafePath)
            ),
            "kind {kind}"
        );
        assert!(retained.exists());
    }
}

#[test]
fn exact_pending_retry_resolves_uncertain_ack_without_reauthorizing_old_policy() {
    let temp = Temp::new();
    let mut f = Fixture::new();
    let event = f.event(1, EventId::ZERO, "exact pending retry");
    let mut store = Store::create(temp.path(), f.scope, limits()).unwrap();
    store.fault = Some(Step::IntentDurable);
    let context = f.context();
    assert!(store
        .append(event.clone(), None, &context, *context.registry_digest())
        .is_err());
    drop(store);
    f.set_policy(false);
    let mut store = Store::open(temp.path(), f.scope, limits(), None).unwrap();
    let different = f.event(1, EventId::ZERO, "replacement refused");
    let context = f.context();
    assert!(matches!(
        store.append(different, None, &context, *context.registry_digest()),
        Err(Error::RecoveryRequired)
    ));
    assert!(store.recovery_required().unwrap());
    let receipt = store
        .append(event.clone(), None, &context, *context.registry_digest())
        .unwrap();
    assert!(receipt.reconciled());
    assert_eq!(receipt.event().encode(), event.encode());
    assert_eq!(store.pin().count(), 1);
    assert!(!store.recovery_required().unwrap());
}

#[test]
fn complete_unsynced_intent_is_synced_before_recovery_writes() {
    let temp = Temp::new();
    let f = Fixture::new();
    let event = f.event(1, EventId::ZERO, "recover intent sync first");
    let mut store = Store::create(temp.path(), f.scope, limits()).unwrap();
    let context = f.context();
    store.fault = Some(Step::IntentWritten);
    assert!(store
        .append(event.clone(), None, &context, *context.registry_digest())
        .is_err());
    drop(store);
    let mut store = Store::open(temp.path(), f.scope, limits(), None).unwrap();
    store.fault = Some(Step::RecoveryIntentSynced);
    assert!(matches!(store.recover(), Err(Error::Indeterminate(_))));
    assert!(!store.record_path(1).exists());
    assert!(!store.author_path(f.author()).exists());
    drop(store);
    let mut store = Store::open(temp.path(), f.scope, limits(), None).unwrap();
    assert_eq!(
        store.recover().unwrap().unwrap().event().encode(),
        event.encode()
    );
}

#[test]
fn observed_live_record_directory_symlink_refuses_first_publication() {
    let temp = Temp::new();
    let f = Fixture::new();
    let mut store = Store::create(temp.path(), f.scope, limits()).unwrap();
    let retained = temp.0.join("original-records");
    fs::rename(temp.path().join(RECORDS), &retained).unwrap();
    let target = temp.0.join("substitute-records");
    fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
    symlink(&target, temp.path().join(RECORDS)).unwrap();
    let context = f.context();
    assert!(matches!(
        store.append(
            f.event(1, EventId::ZERO, "refuse link"),
            None,
            &context,
            *context.registry_digest()
        ),
        Err(Error::UnsafePath)
    ));
    assert!(fs::read_dir(&target).unwrap().next().is_none());
    assert!(fs::read_dir(&retained).unwrap().next().is_none());
    assert_eq!(store.pin(), Pin::EMPTY);
}
