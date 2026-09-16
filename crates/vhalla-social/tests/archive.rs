//! Adversarial archive, monotonic-publication, and bounded anti-entropy regressions.
use ed25519_dalek::SigningKey;
use hegel::generators as gs;
use hegel::TestCase;
use proptest::prelude::*;
use vhalla_core::RealmId;
use vhalla_social::{
    archive::{Archive, Bucket, Budget, Limits, SyncCursor, MAX_PAGE_TURNS, MAX_SNAPSHOT_BYTES},
    *,
};

const REALM: RealmId = RealmId(71);

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn signed(body: Body, key: &SigningKey, ack: Option<&SigningKey>) -> SignedRecord {
    let primary = UnsignedRecord::new(key.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(key)
        .unwrap();
    match ack {
        Some(key) => primary.countersign(key).unwrap(),
        None => primary.finish().unwrap(),
    }
}
fn genesis(key: &SigningKey, nonce: u8) -> SignedRecord {
    signed(
        Body::OwnerGenesis {
            controller: key.verifying_key().to_bytes(),
            recovery: None,
            nonce: [nonce; 32],
        },
        key,
        None,
    )
}
fn id(record: &SignedRecord) -> RecordId {
    record.clone().verify().unwrap().id()
}
fn owner(record: &SignedRecord) -> OwnerId {
    OwnerId::from_bytes(*id(record).as_bytes())
}
fn insert(archive: &mut Archive, record: &SignedRecord) -> Result<archive::IngestReceipt, Error> {
    archive.ingest(
        &record.encode(),
        &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
    )
}
fn seal(key: &SigningKey, owner: OwnerId, previous: RecordId) -> SignedRecord {
    signed(
        Body::Control {
            owner,
            previous,
            action: ControlAction::Seal {
                realm: REALM,
                heads: References::default(),
            },
        },
        key,
        None,
    )
}
fn post(
    key: &SigningKey,
    root: &SignedRecord,
    sequence: u64,
    previous: Option<RecordId>,
    text: &str,
) -> SignedRecord {
    signed(
        Body::Social {
            actor: Actor::Owner {
                owner: owner(root),
                control: id(root),
            },
            realm: REALM,
            sequence,
            previous,
            operation: Operation::Post {
                placement: Placement::Profile,
                text: Text::new(text).unwrap(),
                reply: None,
                quote: None,
            },
        },
        key,
        None,
    )
}
fn fixture() -> Vec<SignedRecord> {
    let k = key(1);
    let root = genesis(&k, 1);
    let first = post(&k, &root, 0, None, "retained text");
    let retract = signed(
        Body::Social {
            actor: Actor::Owner {
                owner: owner(&root),
                control: id(&root),
            },
            realm: REALM,
            sequence: 1,
            previous: Some(id(&first)),
            operation: Operation::Retract { post: id(&first) },
        },
        &k,
        None,
    );
    let control = seal(&k, owner(&root), id(&root));
    vec![root, first, retract, control]
}
fn archive_of(records: &[SignedRecord], limits: Limits) -> Archive {
    let mut archive = Archive::new(REALM, limits).unwrap();
    for record in records {
        insert(&mut archive, record).unwrap();
    }
    archive
}

#[test]
fn malformed_attempts_and_invalid_duplicate_signatures_consume_budget_without_poisoning() {
    let mut archive = Archive::new(REALM, Limits::default()).unwrap();
    let mut budget = Budget::new(2, MAX_RECORD_BYTES * 2).unwrap();
    assert!(archive.ingest(&[0], &mut budget).is_err());
    assert_eq!(budget.remaining(), (1, MAX_RECORD_BYTES * 2 - 1));
    assert!(archive.is_empty());
    let record = genesis(&key(1), 1);
    let mut broken = record.encode();
    let last = broken.len() - 1;
    broken[last] ^= 1;
    assert!(archive.ingest(&broken, &mut budget).is_err());
    assert_eq!(budget.remaining().0, 0);
    assert!(archive.is_empty());
    assert_eq!(
        archive.ingest(&record.encode(), &mut budget),
        Err(Error::Budget)
    );
    insert(&mut archive, &record).unwrap();
    let root = archive.root();
    assert!(archive
        .ingest(&broken, &mut Budget::new(1, MAX_RECORD_BYTES).unwrap())
        .is_err());
    assert_eq!(archive.root(), root);
    assert!(!insert(&mut archive, &record).unwrap().inserted);
}

#[test]
fn claimed_victim_and_control_kind_cannot_consume_protected_capacity() {
    let limits = Limits {
        records: 8,
        control_reserve: 4,
        data_per_owner: 4,
        data_per_writer: 4,
        control_per_owner: 4,
        pending: 3,
        pending_per_signer: 2,
    };
    let victim_key = key(1);
    let victim = genesis(&victim_key, 1);
    let mut archive = archive_of(std::slice::from_ref(&victim), limits);
    let attacker = key(2);
    for n in 0..2 {
        let spoof = signed(
            Body::Control {
                owner: owner(&victim),
                previous: id(&victim),
                action: ControlAction::Seal {
                    realm: REALM,
                    heads: References::new(vec![RecordId::from_bytes([n; 32])]).unwrap(),
                },
            },
            &attacker,
            None,
        );
        assert_eq!(
            insert(&mut archive, &spoof).unwrap().bucket,
            Bucket::Pending(attacker.verifying_key().to_bytes())
        );
    }
    let extra = signed(
        Body::Control {
            owner: OwnerId::from_bytes([99; 32]),
            previous: id(&victim),
            action: ControlAction::Seal {
                realm: REALM,
                heads: References::default(),
            },
        },
        &attacker,
        None,
    );
    assert_eq!(insert(&mut archive, &extra), Err(Error::Capacity));
    let other = key(3);
    let unknown = seal(&other, owner(&victim), id(&victim));
    insert(&mut archive, &unknown).unwrap(); // General data region is now full.
    assert_eq!(archive.len(), 4);
    let legitimate = seal(&victim_key, owner(&victim), id(&victim));
    assert_eq!(
        insert(&mut archive, &legitimate).unwrap().bucket,
        Bucket::Control(owner(&victim))
    );
}

#[test]
fn complete_canonical_restore_does_not_apply_network_staging_quota_to_prefixes() {
    let limits = Limits {
        records: 32,
        control_reserve: 16,
        data_per_owner: 8,
        data_per_writer: 8,
        control_per_owner: 16,
        pending: 4,
        pending_per_signer: 1,
    };
    let k = key(1);
    let mut reproduced = false;
    for nonce in 0..32 {
        let root = genesis(&k, nonce);
        let mut records = vec![root.clone()];
        for _ in 0..8 {
            records.push(seal(&k, owner(&root), id(records.last().unwrap())));
        }
        let source = archive_of(&records, limits);
        let restored = Archive::from_snapshot(REALM, limits, &source.snapshot()).unwrap();
        assert_eq!(restored.root(), source.root());
        let mut network = Archive::new(REALM, limits).unwrap();
        let mut rejected = false;
        for record in source.records() {
            rejected |= network.ingest(
                &record.encode(),
                &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
            ) == Err(Error::Capacity);
        }
        if rejected {
            reproduced = true;
            // Union can discharge an offered fragment's staging pressure with
            // dependencies already present locally; it classifies only the union.
            let merged = network.merged_snapshot(&source.snapshot()).unwrap();
            assert_eq!(merged.root(), source.root());
            break;
        }
    }
    assert!(
        reproduced,
        "fixture must demonstrate the unsafe streaming-restore ordering"
    );
}

#[test]
fn forward_publication_cannot_truncate_retraction_evidence_or_change_local_context() {
    let records = fixture();
    let retained = archive_of(&records, Limits::default());
    let truncated = archive_of(&records[..2], Limits::default());
    assert!(!truncated.is_extension_of(&retained));
    let union = retained.merged_snapshot(&truncated.snapshot()).unwrap();
    assert!(union.is_extension_of(&retained));
    assert_eq!(union.root(), retained.root());
    assert!(union.get(id(&records[2])).is_some());
    let changed = Archive::from_snapshot(
        REALM,
        Limits {
            data_per_owner: 127,
            ..Limits::default()
        },
        &retained.snapshot(),
    )
    .unwrap();
    assert!(!changed.is_extension_of(&retained));
    assert!(matches!(
        Archive::from_snapshot(RealmId(99), Limits::default(), &retained.snapshot()),
        Err(Error::Context)
    ));
}

#[test]
fn rejected_union_does_not_poison_retained_evidence_or_change_its_root() {
    let limits = Limits {
        data_per_owner: 3,
        data_per_writer: 3,
        pending: 1,
        pending_per_signer: 1,
        ..Limits::default()
    };
    let records = fixture();
    let retained = archive_of(&records, limits);
    let extra = post(&key(1), &records[0], 0, None, "additional branch");
    let another = post(&key(1), &records[0], 0, None, "another additional branch");
    let offered = archive_of(&[records[0].clone(), extra, another], limits);
    let root = retained.root();
    let bytes = retained.snapshot();
    assert!(matches!(
        retained.merged_snapshot(&offered.snapshot()),
        Err(Error::Capacity)
    ));
    assert_eq!(retained.root(), root);
    assert_eq!(retained.snapshot(), bytes);
    assert_eq!(
        Archive::from_snapshot(REALM, limits, &bytes)
            .unwrap()
            .root(),
        root
    );
}

#[test]
fn one_authenticated_writer_cannot_consume_another_writers_allowance() {
    let limits = Limits {
        records: 16,
        control_reserve: 4,
        data_per_owner: 9,
        data_per_writer: 3,
        control_per_owner: 4,
        pending: 4,
        pending_per_signer: 2,
    };
    let controller = key(1);
    let root = genesis(&controller, 1);
    let mut archive = archive_of(std::slice::from_ref(&root), limits);
    let mut previous = id(&root);
    let mut writers = Vec::new();
    for n in 2..4 {
        let writer = key(n);
        let agent = signed(
            Body::AgentGenesis {
                owner: owner(&root),
                control: previous,
                key: writer.verifying_key().to_bytes(),
                nonce: [n; 32],
            },
            &controller,
            Some(&writer),
        );
        insert(&mut archive, &agent).unwrap();
        let grant = signed(
            Body::Control {
                owner: owner(&root),
                previous,
                action: ControlAction::Grant {
                    agent: AgentId::from_bytes(*id(&agent).as_bytes()),
                    realm: REALM,
                    rights: Rights::POST,
                    expires_at: 1000,
                    nonce: [n; 32],
                },
            },
            &controller,
            None,
        );
        insert(&mut archive, &grant).unwrap();
        previous = id(&grant);
        writers.push((writer, agent, grant));
    }
    for (index, (writer, agent, grant)) in writers.iter().enumerate() {
        let mut previous = None;
        for sequence in 0..if index == 0 { 4 } else { 1 } {
            let record = signed(
                Body::Social {
                    actor: Actor::Agent {
                        owner: owner(&root),
                        agent: AgentId::from_bytes(*id(agent).as_bytes()),
                        grant: id(grant),
                    },
                    realm: REALM,
                    sequence,
                    previous,
                    operation: Operation::Post {
                        placement: Placement::Profile,
                        text: Text::new("bounded writer data").unwrap(),
                        reply: None,
                        quote: None,
                    },
                },
                writer,
                None,
            );
            let result = insert(&mut archive, &record);
            if sequence == 3 {
                assert_eq!(result, Err(Error::Capacity));
            } else {
                assert_eq!(result.unwrap().bucket, Bucket::Data(owner(&root)));
                previous = Some(id(&record));
            }
        }
    }
}

#[test]
fn control_page_bypasses_repeatedly_rejected_data_and_uses_reserved_storage() {
    let k = key(1);
    let a = key(2);
    let root = genesis(&k, 1);
    let agent = signed(
        Body::AgentGenesis {
            owner: owner(&root),
            control: id(&root),
            key: a.verifying_key().to_bytes(),
            nonce: [2; 32],
        },
        &k,
        Some(&a),
    );
    let grant = signed(
        Body::Control {
            owner: owner(&root),
            previous: id(&root),
            action: ControlAction::Grant {
                agent: AgentId::from_bytes(*id(&agent).as_bytes()),
                realm: REALM,
                rights: Rights::ALL,
                expires_at: 1000,
                nonce: [3; 32],
            },
        },
        &k,
        None,
    );
    let revoke = signed(
        Body::Control {
            owner: owner(&root),
            previous: id(&grant),
            action: ControlAction::Revoke {
                grant: id(&grant),
                accepted: References::default(),
            },
        },
        &k,
        None,
    );
    let base = vec![root.clone(), agent, grant];
    let mut source = archive_of(&base, Limits::default());
    let mut smaller = Vec::new();
    for n in 0..256 {
        let p = post(&k, &root, 0, None, &format!("quota-rejected {n}"));
        if id(&p) < id(&revoke) {
            smaller.push(p);
        }
        if smaller.len() == 2 {
            break;
        }
    }
    assert_eq!(
        smaller.len(),
        2,
        "old first-two-ID pager must fail for this fixture"
    );
    for p in &smaller {
        insert(&mut source, p).unwrap();
    }
    insert(&mut source, &revoke).unwrap();
    let peer_limits = Limits {
        data_per_owner: 2,
        data_per_writer: 2,
        ..Limits::default()
    };
    let mut peer = archive_of(&base, peer_limits);
    let inventory: Vec<_> = peer.records().map(VerifiedRecord::id).collect();
    let old_page: Vec<_> = source
        .records()
        .filter(|r| !inventory.contains(&r.id()))
        .take(2)
        .map(VerifiedRecord::id)
        .collect();
    assert!(!old_page.contains(&id(&revoke)));
    for p in &smaller {
        assert_eq!(insert(&mut peer, p), Err(Error::Capacity));
    }
    let page = source
        .next_page(&inventory, &mut SyncCursor::default(), 1, MAX_RECORD_BYTES)
        .unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(
        SignedRecord::decode(&page.records[0])
            .unwrap()
            .verify()
            .unwrap()
            .id(),
        id(&revoke)
    );
    let receipt = peer
        .ingest(
            &page.records[0],
            &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
        )
        .unwrap();
    assert_eq!(receipt.bucket, Bucket::Control(owner(&root)));
}

#[test]
fn static_inventory_cursor_is_fair_across_owners_and_bounds_empty_byte_pages() {
    let mut archive = Archive::new(REALM, Limits::default()).unwrap();
    let mut ids = Vec::new();
    for n in 1..5 {
        let root = genesis(&key(n), n);
        ids.push(id(&root));
        insert(&mut archive, &root).unwrap();
    }
    let mut cursor = SyncCursor::default();
    let mut delivered = std::collections::BTreeSet::new();
    for _ in 0..ids.len() {
        let page = archive
            .next_page(&[], &mut cursor, 1, MAX_RECORD_BYTES)
            .unwrap();
        assert_eq!(page.records.len(), 1);
        delivered.insert(
            SignedRecord::decode(&page.records[0])
                .unwrap()
                .verify()
                .unwrap()
                .id(),
        );
    }
    assert_eq!(delivered, ids.into_iter().collect());
    let page = archive.next_page(&[], &mut cursor, 1, 0).unwrap();
    assert!(page.records.is_empty());
    assert_eq!(page.remaining, 4);
    assert!(page.examined <= MAX_PAGE_TURNS);
}

#[test]
fn snapshot_framing_scope_and_lengths_are_checked_before_record_work() {
    let archive = archive_of(&fixture(), Limits::default());
    let valid = archive.snapshot();
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(matches!(
        Archive::from_snapshot(REALM, Limits::default(), &trailing),
        Err(Error::Encoding)
    ));
    let mut oversize = valid.clone();
    oversize[28..32].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        Archive::from_snapshot(REALM, Limits::default(), &oversize),
        Err(Error::Bounds)
    ));
    let mut excessive_count = valid.clone();
    excessive_count[24..28].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        Archive::from_snapshot(REALM, Limits::default(), &excessive_count),
        Err(Error::Capacity)
    ));
    let mut wrong_version = valid;
    wrong_version[7] = 2;
    assert!(matches!(
        Archive::from_snapshot(REALM, Limits::default(), &wrong_version),
        Err(Error::Encoding)
    ));
    assert!(Budget::new(1, MAX_SNAPSHOT_BYTES + 1).is_err());
    assert!(Archive::new(
        REALM,
        Limits {
            records: MAX_RECORDS + 1,
            ..Limits::default()
        }
    )
    .is_err());
}

fn withheld_rotation_fixture(staged_count: usize) -> (Archive, Vec<SignedRecord>, AgentId) {
    let controller = key(51);
    let successor = key(52);
    let delegate = key(53);
    let root = genesis(&controller, 51);
    let owner = owner(&root);
    let agent_root = signed(
        Body::AgentGenesis {
            owner,
            control: root.id(),
            key: delegate.verifying_key().to_bytes(),
            nonce: [53; 32],
        },
        &controller,
        Some(&delegate),
    );
    let agent = AgentId::from_bytes(*agent_root.id().as_bytes());
    let grant = signed(
        Body::Control {
            owner,
            previous: root.id(),
            action: ControlAction::Grant {
                agent,
                realm: REALM,
                rights: Rights::ALL,
                expires_at: 1000,
                nonce: [54; 32],
            },
        },
        &controller,
        None,
    );
    let rotation = signed(
        Body::Control {
            owner,
            previous: grant.id(),
            action: ControlAction::Rotate {
                new_key: successor.verifying_key().to_bytes(),
            },
        },
        &controller,
        Some(&successor),
    );
    let limits = Limits {
        records: 32,
        control_reserve: 8,
        data_per_owner: 2,
        data_per_writer: 2,
        control_per_owner: 8,
        pending: 8,
        pending_per_signer: 4,
    };
    let mut records = vec![root, agent_root, grant];
    let mut archive = archive_of(&records, limits);
    let mut previous = None;
    for sequence in 0..staged_count {
        let record = signed(
            Body::Social {
                actor: Actor::Owner {
                    owner,
                    control: rotation.id(),
                },
                realm: REALM,
                sequence: sequence as u64,
                previous,
                operation: Operation::Post {
                    placement: Placement::Profile,
                    text: Text::new("before the successor's authority is revealed").unwrap(),
                    reply: None,
                    quote: None,
                },
            },
            &successor,
            None,
        );
        assert_eq!(
            insert(&mut archive, &record).unwrap().bucket,
            Bucket::Pending(successor.verifying_key().to_bytes())
        );
        previous = Some(record.id());
        records.push(record);
    }
    let before = archive.root();
    assert!(vhalla_social::control::ControlView::new(&archive, 1)
        .agent(agent)
        .unwrap()
        .active());
    insert(&mut archive, &rotation).unwrap();
    records.push(rotation);
    assert_ne!(archive.root(), before);
    assert_eq!(archive.capacity().pending, 0);
    assert_eq!(archive.capacity().data_spill, staged_count);
    assert!(!vhalla_social::control::ControlView::new(&archive, 1)
        .agent(agent)
        .unwrap()
        .active());
    (archive, records, agent)
}

#[test]
fn withheld_rotation_migrates_existing_staging_debt_without_losing_control() {
    for count in 1..=4 {
        let (archive, records, agent) = withheld_rotation_fixture(count);
        let restored =
            Archive::from_snapshot(REALM, archive.limits(), &archive.snapshot()).unwrap();
        assert_eq!(restored.root(), archive.root());
        assert_eq!(restored.capacity(), archive.capacity());
        assert_eq!(restored.len(), records.len());
        assert!(!vhalla_social::control::ControlView::new(&restored, 1)
            .agent(agent)
            .unwrap()
            .active());
        // Once the rotated key is known, an ordinary new post cannot consume
        // the recovery allowance by pretending its affiliation is still unknown.
        let old_root = restored.root();
        let mut incoming = restored.clone();
        let source = records.last().unwrap();
        let Body::Control { owner, .. } = source.body() else {
            panic!("rotation fixture")
        };
        let extra = signed(
            Body::Social {
                actor: Actor::Owner {
                    owner: *owner,
                    control: source.id(),
                },
                realm: REALM,
                sequence: 0,
                previous: None,
                operation: Operation::Post {
                    placement: Placement::Profile,
                    text: Text::new("ordinary overflow denied").unwrap(),
                    reply: None,
                    quote: None,
                },
            },
            &key(52),
            None,
        );
        assert_eq!(insert(&mut incoming, &extra), Err(Error::Capacity));
        assert_eq!(incoming.root(), old_root);
    }
}

#[test]
fn source_proved_pending_control_descendants_reserve_before_revealing_revocation() {
    for descendants in 1..=4 {
        let controller = key(61);
        let delegate = key(62);
        let root = genesis(&controller, 61);
        let owner = owner(&root);
        let agent_root = signed(
            Body::AgentGenesis {
                owner,
                control: root.id(),
                key: delegate.verifying_key().to_bytes(),
                nonce: [62; 32],
            },
            &controller,
            Some(&delegate),
        );
        let agent = AgentId::from_bytes(*agent_root.id().as_bytes());
        let grant = signed(
            Body::Control {
                owner,
                previous: root.id(),
                action: ControlAction::Grant {
                    agent,
                    realm: REALM,
                    rights: Rights::ALL,
                    expires_at: 1000,
                    nonce: [63; 32],
                },
            },
            &controller,
            None,
        );
        let revoke = signed(
            Body::Control {
                owner,
                previous: grant.id(),
                action: ControlAction::Revoke {
                    grant: grant.id(),
                    accepted: References::default(),
                },
            },
            &controller,
            None,
        );
        let limits = Limits {
            records: 32,
            control_reserve: 8,
            data_per_owner: 4,
            data_per_writer: 4,
            control_per_owner: 3,
            pending: 8,
            pending_per_signer: 4,
        };
        let mut archive = archive_of(&[root, agent_root, grant], limits);
        let mut previous = revoke.id();
        for _ in 0..descendants {
            let future = seal(&controller, owner, previous);
            previous = future.id();
            assert_eq!(
                insert(&mut archive, &future).unwrap().bucket,
                Bucket::ReservedControl(owner)
            );
        }
        if descendants >= 2 {
            assert!(!vhalla_social::control::ControlView::new(&archive, 1)
                .agent(agent)
                .unwrap()
                .active());
        }
        insert(&mut archive, &revoke).unwrap();
        assert!(!vhalla_social::control::ControlView::new(&archive, 1)
            .agent(agent)
            .unwrap()
            .active());
        assert_eq!(
            archive.capacity().control_spill,
            (descendants + 2usize).saturating_sub(3)
        );
        let restored = Archive::from_snapshot(REALM, limits, &archive.snapshot()).unwrap();
        assert_eq!(restored.root(), archive.root());
        assert_eq!(restored.capacity(), archive.capacity());
    }
}

/// The proptest `uniform7` sort key becomes seven byte draws taken while the
/// delivery permutation is assembled; the replay then mutates `received`
/// across steps exactly as before.
#[hegel::test(test_cases = 32)]
fn complete_migration_set_restores_identical_pressure_after_delivery_permutations(tc: TestCase) {
    let (expected, records, agent) = withheld_rotation_fixture(3);
    let mut order = [0u8; 7];
    for byte in &mut order {
        *byte = tc.draw(gs::integers::<u8>());
    }
    let mut indices = [0, 1, 2, 3, 4, 5, 6];
    indices.sort_by_key(|i| order[*i]);
    let mut received = Archive::new(REALM, expected.limits()).unwrap();
    for index in indices {
        let before = received.root();
        if insert(&mut received, &records[index]).is_err() {
            assert_eq!(received.root(), before);
        }
    }
    let received = received.merged_snapshot(&expected.snapshot()).unwrap();
    assert_eq!(received.root(), expected.root());
    assert_eq!(received.capacity(), expected.capacity());
    assert!(!vhalla_social::control::ControlView::new(&received, 1)
        .agent(agent)
        .unwrap()
        .active());
}

/// Same interleaved style for the four-record `uniform4` delivery order.
#[hegel::test(test_cases = 32)]
fn complete_under_cap_event_sets_converge_with_reordering_and_duplicates(tc: TestCase) {
    let records = fixture();
    let expected = archive_of(&records, Limits::default());
    let mut order = [0u8; 4];
    for byte in &mut order {
        *byte = tc.draw(gs::integers::<u8>());
    }
    let mut indices = [0, 1, 2, 3];
    indices.sort_by_key(|i| order[*i]);
    let mut got = Archive::new(REALM, Limits::default()).unwrap();
    for i in indices {
        insert(&mut got, &records[i]).unwrap();
        insert(&mut got, &records[i]).unwrap();
    }
    assert_eq!(got.root(), expected.root());
    assert_eq!(got.snapshot(), expected.snapshot());
    assert!(got.is_extension_of(&expected));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn arbitrary_bounded_foreign_bytes_do_not_mutate_an_archive(raw in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut archive = archive_of(&fixture(), Limits::default());
        let root = archive.root();
        let mut budget = Budget::new(1, MAX_RECORD_BYTES).unwrap();
        let result = archive.ingest(&raw, &mut budget);
        prop_assert!(result.is_err());
        prop_assert_eq!(archive.root(), root);
        prop_assert_eq!(budget.remaining().0, 0);
        prop_assert!(Archive::from_snapshot(REALM, Limits::default(), &raw).is_err());
    }
}
