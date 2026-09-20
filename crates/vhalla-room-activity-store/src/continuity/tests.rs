use super::*;
use crate::common;
use crate::Limits;
use ed25519_dalek::SigningKey;
use std::os::unix::fs::DirBuilderExt;
use std::{fs, path::PathBuf};
use vhalla_room_activity::{Content, EventClaims, Text, UnsignedEvent};
use vhalla_rooms::{Applied, RoomRecordId, RoomUpdate, UpdateAction};
use vhalla_social::{archive::Archive, control::ControlView};
const NETWORK: [u8; 32] = [7; 32];
fn limits() -> ContinuityLimits {
    ContinuityLimits {
        history: Limits {
            max_events: 20000,
            max_history_bytes: 64 * 1024 * 1024,
        },
        max_stage_slots: 64,
        max_stage_events: 4096,
        max_stage_bytes: 32 * 1024 * 1024,
        stage_ttl_seconds: 60,
    }
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut random = [0; 32];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!("vhalla-continuity-{}", hex(&random)));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("continuity")
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

fn history(f: &Fixture, count: u64) -> Vec<VerifiedEvent> {
    let mut previous = EventId::ZERO;
    (1..=count)
        .map(|sequence| {
            let event = f.event(sequence, previous, "retained causal predecessor");
            previous = event.id();
            event
        })
        .collect()
}
#[test]
fn continuity_history_is_hidden_until_terminal_and_survives_restart_revocation() {
    let temp = Temp::new();
    let mut f = Fixture::new();
    let ancestors = history(&f, 65);
    let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
    let first = store
        .stage(ancestors[..32].to_vec(), &f.context(), 10)
        .unwrap();
    assert_eq!(store.pin().feed_count(), 0);
    assert!(store.author_evidence(f.author(), 0, 32).unwrap().is_empty());
    assert_eq!(
        store
            .stage(ancestors[..32].to_vec(), &f.context(), 11)
            .unwrap()
            .expires_at(),
        first.expires_at()
    );
    drop(store);
    let mut store = ContinuityStore::open(temp.path(), f.scope, None).unwrap();
    f.set_policy(false);
    f.set_policy(true);
    store
        .stage(ancestors[32..64].to_vec(), &f.context(), 12)
        .unwrap();
    let terminal = f.event(66, ancestors[64].id(), "current policy terminal");
    let receipt = store
        .commit(
            vec![ancestors[64].clone()],
            terminal.clone(),
            &f.context(),
            13,
        )
        .unwrap();
    assert_eq!(receipt.cursor(), 1);
    assert_eq!(store.pin().evidence_count(), 66);
    assert_eq!(store.feed(0, 32).unwrap().len(), 1);
    let mut count = 0;
    while count < 66 {
        let page = store.author_evidence(f.author(), count, 32).unwrap();
        for evidence in &page {
            let seq = evidence.event().claims().sequence;
            assert_eq!(
                evidence.role(),
                if seq == 66 {
                    EvidenceRole::CurrentAdmission
                } else {
                    EvidenceRole::HistoricalContinuity
                }
            );
        }
        count += page.len() as u64;
    }
    let pin = store.pin();
    drop(store);
    f.set_policy(false);
    let mut store = ContinuityStore::open(temp.path(), f.scope, Some(pin)).unwrap();
    assert!(store
        .commit(vec![], terminal, &f.context(), 14)
        .unwrap()
        .reconciled());
    assert!(matches!(
        store.commit(vec![], ancestors[0].clone(), &f.context(), 14),
        Err(Error::Conflict)
    ));
    store.maintain(100).unwrap();
    assert_eq!(store.pin(), pin);
    assert_eq!(store.author_evidence(f.author(), 64, 32).unwrap().len(), 2);
}
#[test]
fn continuity_expired_never_published_pages_reclaim_capacity_without_resetting_floor() {
    let temp = Temp::new();
    let f = Fixture::new();
    let ancestors = history(&f, 32);
    let mut budget = limits();
    budget.max_stage_slots = 1;
    budget.max_stage_events = 32;
    let mut store = ContinuityStore::create(temp.path(), f.scope, budget).unwrap();
    let ticket = store.stage(ancestors.clone(), &f.context(), 10).unwrap();
    assert_eq!(ticket.expires_at(), 70);
    assert_eq!(store.maintain(69).unwrap().pages_removed, 0);
    assert_eq!(store.maintain(70).unwrap().pages_removed, 1);
    assert!(store.stage_ticket(f.author()).unwrap().is_none());
    assert_eq!(store.pin().evidence_count(), 0);
    let replacement = store.stage(ancestors, &f.context(), 71).unwrap();
    assert_ne!(replacement.id(), ticket.id());
    assert!(matches!(store.maintain(70), Err(Error::Conflict)));
}
#[test]
fn continuity_terminal_publication_faults_reconcile_exact_prior_decision() {
    for fault in [
        ("INTENT.tmp", "write"),
        ("INTENT.tmp", "file-sync"),
        ("INTENT", "rename"),
        ("INTENT", "rename-sync"),
        ("INTENT", "confirmed"),
        ("evidence/", "rename"),
        ("feed/", "rename"),
        ("authors/", "rename"),
        ("HEAD", "rename"),
        ("STAGES", "rename"),
        ("INTENT", "unlink"),
        ("INTENT", "unlink-sync"),
    ] {
        let temp = Temp::new();
        let mut f = Fixture::new();
        let ancestors = history(&f, 32);
        let terminal = f.event(33, ancestors[31].id(), "terminal before revocation");
        let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
        store.stage(ancestors, &f.context(), 10).unwrap();
        store.disk.fault.replace(Some(fault));
        assert!(
            store
                .commit(vec![], terminal.clone(), &f.context(), 10)
                .is_err(),
            "{fault:?}"
        );
        assert!(
            matches!(store.feed(0, 1), Err(Error::RecoveryRequired)),
            "{fault:?}"
        );
        drop(store);
        f.set_policy(false);
        let mut store = ContinuityStore::open(temp.path(), f.scope, None).unwrap();
        let installed = fault.0 != "INTENT.tmp";
        assert_eq!(store.pin().feed_count(), u64::from(installed), "{fault:?}");
        if installed {
            assert_eq!(
                store.author_evidence(f.author(), 32, 1).unwrap()[0]
                    .event()
                    .encode(),
                terminal.encode()
            );
            assert!(store
                .commit(vec![], terminal, &f.context(), 11)
                .unwrap()
                .reconciled());
        } else {
            assert!(store.commit(vec![], terminal, &f.context(), 11).is_err());
        }
    }
}
#[test]
fn continuity_cleanup_fault_retains_ownership_until_directory_sync_and_catalogue_commit() {
    for fault in [
        ("INTENT", "confirmed"),
        ("pages/", "unlink"),
        ("pages/", "unlink-sync"),
        ("STAGES", "rename"),
    ] {
        let temp = Temp::new();
        let f = Fixture::new();
        let ancestors = history(&f, 32);
        let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
        store.stage(ancestors, &f.context(), 10).unwrap();
        // Persist expiry separately so each fault concerns reclamation itself.
        let after = clock_transition(&store.catalogue, 70).unwrap();
        store
            .transact(Intent {
                before: store.catalogue.clone(),
                after,
                pin: store.pin,
                next_pin: store.pin,
                operation: Operation::Clock,
            })
            .unwrap();
        store.disk.fault.replace(Some(fault));
        assert!(store.maintain(70).is_err());
        if fault.1 == "confirmed" {
            assert_eq!(fs::read_dir(temp.path().join("pages")).unwrap().count(), 1);
        }
        drop(store);
        let mut store = ContinuityStore::open(temp.path(), f.scope, None).unwrap();
        store.maintain(70).unwrap();
        assert!(store.catalogue.stages.is_empty());
        assert_eq!(store.pin().feed_count(), 0);
        assert_eq!(fs::read_dir(temp.path().join("pages")).unwrap().count(), 0);
    }
}
#[test]
fn continuity_corrupt_intent_and_missing_author_head_fail_closed_preserving_evidence() {
    let temp = Temp::new();
    let f = Fixture::new();
    let event = f.event(1, EventId::ZERO, "published");
    let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
    store
        .commit(vec![], event.clone(), &f.context(), 1)
        .unwrap();
    let pin = store.pin();
    drop(store);
    let head = temp.path().join(author_path(f.author()));
    let exact = fs::read(&head).unwrap();
    fs::remove_file(&head).unwrap();
    assert!(ContinuityStore::open(temp.path(), f.scope, None).is_err());
    // Restore only the test's exact retained index, never a reconstructed floor.
    let mut file = vhalla_custody::create_private_file(&head).unwrap();
    use std::io::Write;
    file.write_all(&exact).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let mut store = ContinuityStore::open(temp.path(), f.scope, Some(pin)).unwrap();
    let next = f.event(2, event.id(), "protected");
    store.disk.fault.replace(Some(("INTENT", "rename")));
    assert!(store.commit(vec![], next, &f.context(), 1).is_err());
    drop(store);
    let path = temp.path().join("INTENT");
    let mut raw = fs::read(&path).unwrap();
    raw[10] ^= 1;
    fs::write(&path, &raw).unwrap();
    assert!(ContinuityStore::open(temp.path(), f.scope, None).is_err());
    assert_eq!(fs::read(&path).unwrap(), raw);
    assert!(temp.path().join(evidence_path(f.author(), 1)).exists());
}
#[test]
fn continuity_policy_scope_fork_capacity_and_tampered_metadata_never_publish() {
    let temp = Temp::new();
    let mut f = Fixture::new();
    let ancestors = history(&f, 32);
    let mut budget = limits();
    budget.history.max_events = 32;
    let mut store = ContinuityStore::create(temp.path(), f.scope, budget).unwrap();
    store.stage(ancestors.clone(), &f.context(), 1).unwrap();
    let terminal = f.event(33, ancestors[31].id(), "exceeds permanent quota");
    assert!(matches!(
        store.commit(vec![], terminal, &f.context(), 1),
        Err(Error::Capacity)
    ));
    assert_eq!(store.pin().feed_count(), 0);
    assert!(!temp.path().join("INTENT").exists());
    let old = f.event(33, ancestors[31].id(), "old policy");
    f.set_policy(false);
    f.set_policy(true);
    assert!(matches!(
        store.commit(vec![], old, &f.context(), 1),
        Err(Error::Activity(vhalla_room_activity::Error::Policy))
    ));
    let mut catalogue = store.catalogue.clone();
    catalogue.stages.get_mut(&f.author()).unwrap().event_bytes = 0;
    assert!(Catalogue::decode(&catalogue.encode(), store.pin.scope, f.scope, budget).is_err());
    assert_eq!(store.pin().feed_count(), 0);
}

#[test]
fn continuity_stage_publication_faults_reconcile_pages_without_acknowledging_posts() {
    for fault in [
        ("INTENT.tmp", "write"),
        ("INTENT", "rename"),
        ("pages/", "rename"),
        ("STAGES", "rename"),
        ("INTENT", "unlink"),
    ] {
        let temp = Temp::new();
        let f = Fixture::new();
        let ancestors = history(&f, 64);
        let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
        store
            .stage(ancestors[..32].to_vec(), &f.context(), 10)
            .unwrap();
        store.disk.fault.replace(Some(fault));
        assert!(
            store
                .stage(ancestors[32..].to_vec(), &f.context(), 10)
                .is_err(),
            "{fault:?}"
        );
        drop(store);
        let mut store = ContinuityStore::open(temp.path(), f.scope, None).unwrap();
        let expected = if fault.0 == "INTENT.tmp" { 32 } else { 64 };
        assert_eq!(
            store.stage_ticket(f.author()).unwrap().unwrap().sequence(),
            expected
        );
        assert_eq!(store.pin().feed_count(), 0);
        let retry = store
            .stage(ancestors[32..].to_vec(), &f.context(), 10)
            .unwrap();
        assert_eq!(retry.sequence(), 64);
        assert_eq!(store.pin().evidence_count(), 0);
    }
}
#[test]
fn continuity_unrelated_external_pin_preserves_exact_pending_recovery_evidence() {
    let temp = Temp::new();
    let f = Fixture::new();
    let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
    let first = f.event(1, EventId::ZERO, "first");
    store
        .commit(vec![], first.clone(), &f.context(), 10)
        .unwrap();
    let before = store.pin();
    let mut unrelated = before;
    unrelated.tail[0] ^= 1;
    let next = f.event(2, first.id(), "protected next");
    store.disk.fault.replace(Some(("INTENT", "rename")));
    assert!(store.commit(vec![], next, &f.context(), 10).is_err());
    drop(store);
    let retained = fs::read(temp.path().join("INTENT")).unwrap();
    let head = fs::read(temp.path().join("HEAD")).unwrap();
    assert!(matches!(
        ContinuityStore::open(temp.path(), f.scope, Some(unrelated)),
        Err(Error::Freshness)
    ));
    assert_eq!(fs::read(temp.path().join("INTENT")).unwrap(), retained);
    assert_eq!(fs::read(temp.path().join("HEAD")).unwrap(), head);
    let store = ContinuityStore::open(temp.path(), f.scope, Some(before)).unwrap();
    assert_eq!(store.pin().feed_count(), 2);
}

#[test]
fn continuity_maximum_canonical_page_and_inline_terminal_fit_transaction_bounds() {
    let temp = Temp::new();
    let f = Fixture::new();
    let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
    let text = "x".repeat(vhalla_room_activity::MAX_TEXT_BYTES);
    let mut previous = EventId::ZERO;
    let events: Vec<_> = (1..=65)
        .map(|sequence| {
            let event = f.event(sequence, previous, &text);
            previous = event.id();
            event
        })
        .collect();
    store
        .stage(events[..32].to_vec(), &f.context(), 10)
        .unwrap();
    store
        .commit(
            events[32..64].to_vec(),
            events[64].clone(),
            &f.context(),
            10,
        )
        .unwrap();
    assert_eq!(store.pin().evidence_count(), 65);
    assert_eq!(store.author_evidence(f.author(), 0, 32).unwrap().len(), 32);
    assert_eq!(
        store.feed(0, 32).unwrap()[0].event().encode(),
        events[64].encode()
    );
}

#[test]
fn continuity_terminal_retry_only_acknowledges_exact_retained_inline_suffix() {
    let temp = Temp::new();
    let mut f = Fixture::new();
    let ancestors = history(&f, 2);
    let terminal = f.event(3, ancestors[1].id(), "terminal");
    let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
    store
        .commit(ancestors.clone(), terminal.clone(), &f.context(), 1)
        .unwrap();
    let pin = store.pin();
    f.set_policy(false);
    assert!(store
        .commit(ancestors.clone(), terminal.clone(), &f.context(), 2)
        .unwrap()
        .reconciled());
    assert!(store
        .commit(
            vec![ancestors[1].clone()],
            terminal.clone(),
            &f.context(),
            2
        )
        .unwrap()
        .reconciled());
    assert!(matches!(
        store.commit(
            vec![ancestors[0].clone()],
            terminal.clone(),
            &f.context(),
            2
        ),
        Err(Error::Conflict)
    ));
    let foreign = f.event(2, ancestors[0].id(), "same author signed fork");
    assert!(matches!(
        store.commit(vec![foreign], terminal, &f.context(), 2),
        Err(Error::Conflict)
    ));
    assert_eq!(store.pin(), pin);
}

#[test]
fn continuity_never_adopts_or_resets_existing_version_one_activity_store() {
    let temp = Temp::new();
    let f = Fixture::new();
    let mut old = crate::Store::create(temp.path(), f.scope, limits().history).unwrap();
    let event = f.event(1, EventId::ZERO, "existing user evidence");
    let context = f.context();
    old.append(event.clone(), None, &context, *context.registry_digest())
        .unwrap();
    let pin = old.pin();
    drop(old);
    let original = fs::read(temp.path().join("HEAD")).unwrap();
    assert!(ContinuityStore::open(temp.path(), f.scope, None).is_err());
    assert!(ContinuityStore::create(temp.path(), f.scope, limits()).is_err());
    assert_eq!(fs::read(temp.path().join("HEAD")).unwrap(), original);
    let old = crate::Store::open(temp.path(), f.scope, limits().history, Some(pin)).unwrap();
    assert_eq!(
        old.read_page(0, 1).unwrap().records()[0].event().encode(),
        event.encode()
    );
}
