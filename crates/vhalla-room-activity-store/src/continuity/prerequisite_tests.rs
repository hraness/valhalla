use super::*;

fn allowance() -> WorkAllowance {
    WorkAllowance {
        frames: 33,
        retained_ancestors: 4096,
    }
}
fn empty() -> WorkExpectation {
    WorkExpectation {
        published: AuthorPosition::EMPTY,
        stage: None,
    }
}
fn expected(ticket: StageTicket) -> WorkExpectation {
    WorkExpectation {
        published: ticket.base(),
        stage: Some(ticket),
    }
}
fn image(path: &std::path::Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &std::path::Path, at: &std::path::Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(at).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                collect(root, &entry.path(), out);
            } else {
                out.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    collect(path, path, &mut result);
    result
}

#[test]
fn prerequisite_wrong_limits_preserve_intent_and_unpublished_scratch_before_recovery() {
    for fault in [("INTENT.tmp", "write"), ("feed/", "rename")] {
        let temp = Temp::new();
        let f = Fixture::new();
        let event = f.event(1, EventId::ZERO, "interrupted decision");
        let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
        store.disk.fault.replace(Some(fault));
        assert!(store
            .commit_checked(vec![], event, empty(), &f.context(), 10, allowance())
            .is_err());
        drop(store);
        let before = image(&temp.path());
        for field in 0..6 {
            let mut different = limits();
            match field {
                0 => different.history.max_events -= 1,
                1 => different.history.max_history_bytes -= 1,
                2 => different.max_stage_slots -= 1,
                3 => different.max_stage_events -= 32,
                4 => different.max_stage_bytes -= 1,
                _ => different.stage_ttl_seconds += 1,
            }
            assert!(matches!(
                ContinuityStore::open_checked(temp.path(), f.scope, different, None),
                Err(Error::Conflict)
            ));
            assert_eq!(image(&temp.path()), before, "{fault:?}, field {field}");
        }
        let restored = ContinuityStore::open_checked(temp.path(), f.scope, limits(), None).unwrap();
        assert_eq!(restored.pin().feed_count(), u64::from(fault.0 == "feed/"));
    }
}

#[test]
fn prerequisite_checked_status_binds_published_base_tail_and_readonly_expiry() {
    let temp = Temp::new();
    let f = Fixture::new();
    let events = history(&f, 33);
    let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
    store
        .commit_checked(
            vec![],
            events[0].clone(),
            empty(),
            &f.context(),
            10,
            allowance(),
        )
        .unwrap();
    let base = AuthorPosition::new(1, events[0].id()).unwrap();
    let ticket = store
        .stage_checked(
            events[1..].to_vec(),
            WorkExpectation {
                published: base,
                stage: None,
            },
            &f.context(),
            11,
            allowance(),
        )
        .unwrap();
    let before = image(&temp.path());
    let status = store.author_status(f.author(), 70).unwrap();
    assert_eq!(status.published(), base);
    assert_eq!(status.stage(), Some(ticket));
    assert_eq!(ticket.base(), base);
    assert_eq!(
        ticket.tail(),
        AuthorPosition::new(33, events[32].id()).unwrap()
    );
    let expired = store.author_status(f.author(), 71).unwrap();
    assert_eq!(expired.published(), base);
    assert_eq!(expired.stage(), None);
    assert_eq!(expired.cleanup_pages(), 1);
    assert!(matches!(
        store.author_status(f.author(), 10),
        Err(Error::Conflict)
    ));
    assert!(store.author_status([0; 32], 71).is_err());
    assert_eq!(image(&temp.path()), before);
}

#[test]
fn prerequisite_status_refuses_missing_stage_page_and_author_head() {
    let temp = Temp::new();
    let f = Fixture::new();
    let events = history(&f, 33);
    let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
    store
        .commit_checked(
            vec![],
            events[0].clone(),
            empty(),
            &f.context(),
            1,
            allowance(),
        )
        .unwrap();
    let expected = WorkExpectation {
        published: AuthorPosition::new(1, events[0].id()).unwrap(),
        stage: None,
    };
    let ticket = store
        .stage_checked(events[1..].to_vec(), expected, &f.context(), 2, allowance())
        .unwrap();
    let path = temp.path().join(page_path(ticket.id(), 0));
    let retained = fs::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    let broken = image(&temp.path());
    assert!(store.author_status(f.author(), 3).is_err());
    assert_eq!(image(&temp.path()), broken);
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&retained).unwrap();
    file.sync_all().unwrap();
    fs::remove_file(temp.path().join(author_path(f.author()))).unwrap();
    let broken = image(&temp.path());
    assert!(store.author_status(f.author(), 3).is_err());
    assert_eq!(image(&temp.path()), broken);
}

#[test]
fn prerequisite_exact_old_stage_page_retry_returns_later_aggregate_without_lease_extension() {
    let temp = Temp::new();
    let f = Fixture::new();
    let events = history(&f, 96);
    let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
    let first = store
        .stage_checked(
            events[..32].to_vec(),
            empty(),
            &f.context(),
            10,
            allowance(),
        )
        .unwrap();
    let second = store
        .stage_checked(
            events[32..64].to_vec(),
            expected(first),
            &f.context(),
            11,
            allowance(),
        )
        .unwrap();
    let third = store
        .stage_checked(
            events[64..].to_vec(),
            expected(second),
            &f.context(),
            12,
            allowance(),
        )
        .unwrap();
    let before = image(&temp.path());
    assert!(store
        .quote_stage(&events[32..64], expected(first), 13)
        .unwrap()
        .reconciled());
    assert_eq!(
        store
            .stage_checked(
                events[32..64].to_vec(),
                expected(first),
                &f.context(),
                13,
                allowance()
            )
            .unwrap(),
        third
    );
    assert_eq!(
        store
            .stage_checked(
                events[..32].to_vec(),
                empty(),
                &f.context(),
                14,
                allowance()
            )
            .unwrap(),
        third
    );
    assert_eq!(third.expires_at(), first.expires_at());
    assert_eq!(image(&temp.path()), before);
    let mut fork = events[32..64].to_vec();
    let mut previous = events[31].id();
    for event in &mut fork {
        *event = f.event(event.claims().sequence, previous, "same-sequence fork");
        previous = event.id();
    }
    assert!(store.quote_stage(&fork, expected(first), 15).is_err());
    assert_eq!(image(&temp.path()), before);
}

#[test]
fn prerequisite_foreign_ticket_or_stale_commit_prefix_refuses_without_effects() {
    let temp = Temp::new();
    let f = Fixture::new();
    let events = history(&f, 64);
    let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
    let first = store
        .stage_checked(
            events[..32].to_vec(),
            empty(),
            &f.context(),
            10,
            allowance(),
        )
        .unwrap();
    let before = image(&temp.path());
    for field in 0..3 {
        let forged = StageTicket::new(
            if field == 0 { [8; 32] } else { first.id() },
            if field == 1 {
                SigningKey::from_bytes(&[80; 32]).verifying_key().to_bytes()
            } else {
                f.author()
            },
            first.base(),
            first.tail(),
            first.pages(),
            first.expires_at() + u64::from(field == 2),
        )
        .unwrap();
        assert!(store
            .stage_checked(
                events[32..].to_vec(),
                expected(forged),
                &f.context(),
                11,
                allowance()
            )
            .is_err());
        assert_eq!(image(&temp.path()), before);
    }
    let second = store
        .stage_checked(
            events[32..].to_vec(),
            expected(first),
            &f.context(),
            11,
            allowance(),
        )
        .unwrap();
    let terminal = f.event(65, events[63].id(), "terminal");
    let before = image(&temp.path());
    assert!(matches!(
        store.commit_checked(
            events[32..].to_vec(),
            terminal.clone(),
            expected(first),
            &f.context(),
            12,
            allowance()
        ),
        Err(Error::Conflict)
    ));
    assert_eq!(image(&temp.path()), before);
    store
        .commit_checked(
            vec![],
            terminal,
            expected(second),
            &f.context(),
            12,
            allowance(),
        )
        .unwrap();
}

#[test]
fn prerequisite_direct_admission_cannot_consume_or_skip_an_active_prefix() {
    let temp = Temp::new();
    let f = Fixture::new();
    let events = history(&f, 32);
    let terminal = f.event(33, events[31].id(), "not a legacy next event");
    let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
    store
        .stage_checked(events.clone(), empty(), &f.context(), 10, allowance())
        .unwrap();
    let before = image(&temp.path());
    for event in [events[0].clone(), terminal.clone()] {
        assert!(matches!(
            store.commit_checked(vec![], event, empty(), &f.context(), 11, allowance()),
            Err(Error::Conflict)
        ));
        assert_eq!(image(&temp.path()), before);
    }
    let claimed_published = WorkExpectation {
        published: AuthorPosition::new(32, events[31].id()).unwrap(),
        stage: None,
    };
    assert!(matches!(
        store.commit_checked(
            vec![],
            terminal,
            claimed_published,
            &f.context(),
            11,
            allowance()
        ),
        Err(Error::Conflict)
    ));
    assert_eq!(image(&temp.path()), before);
}

#[test]
fn prerequisite_work_allowance_refuses_before_write_and_counts_exact_retained_prefix() {
    let temp = Temp::new();
    let f = Fixture::new();
    let events = history(&f, 32);
    let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
    let before = image(&temp.path());
    assert!(matches!(
        store.stage_checked(
            events.clone(),
            empty(),
            &f.context(),
            10,
            WorkAllowance {
                frames: 31,
                retained_ancestors: 4096
            }
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(image(&temp.path()), before);
    let ticket = store
        .stage_checked(events.clone(), empty(), &f.context(), 10, allowance())
        .unwrap();
    let terminal = f.event(33, events[31].id(), "terminal");
    let quote = store
        .quote_commit(&[], &terminal, expected(ticket), 11)
        .unwrap();
    assert_eq!(quote.frames(), 1);
    assert_eq!(quote.retained_ancestors(), 32);
    assert!(!quote.reconciled());
    let before = image(&temp.path());
    assert!(matches!(
        store.commit_checked(
            vec![],
            terminal.clone(),
            expected(ticket),
            &f.context(),
            11,
            WorkAllowance {
                frames: 1,
                retained_ancestors: 31
            }
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(image(&temp.path()), before);
    store
        .commit_checked(
            vec![],
            terminal,
            expected(ticket),
            &f.context(),
            11,
            WorkAllowance {
                frames: 1,
                retained_ancestors: 32,
            },
        )
        .unwrap();
}

#[test]
fn prerequisite_retained_terminal_retry_after_revocation_cleanup_and_restart_is_not_readmission() {
    let temp = Temp::new();
    let mut f = Fixture::new();
    let events = history(&f, 33);
    let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
    let ticket = store
        .stage_checked(
            events[..32].to_vec(),
            empty(),
            &f.context(),
            10,
            allowance(),
        )
        .unwrap();
    let terminal = f.event(34, events[32].id(), "terminal");
    let receipt = store
        .commit_checked(
            vec![events[32].clone()],
            terminal.clone(),
            expected(ticket),
            &f.context(),
            11,
            allowance(),
        )
        .unwrap();
    let original = receipt.event().encode();
    let registry = *receipt.registry_digest();
    f.set_policy(false);
    store.maintain_bounded(12, 1).unwrap();
    drop(store);
    let mut store = ContinuityStore::open_checked(temp.path(), f.scope, limits(), None).unwrap();
    let before = image(&temp.path());
    let quote = store
        .quote_commit(&events[32..], &terminal, expected(ticket), 13)
        .unwrap();
    assert!(quote.reconciled());
    assert_eq!(quote.retained_ancestors(), 0);
    let receipt = store
        .commit_checked(
            events[32..].to_vec(),
            terminal.clone(),
            expected(ticket),
            &f.context(),
            13,
            WorkAllowance {
                frames: 2,
                retained_ancestors: 0,
            },
        )
        .unwrap();
    assert!(receipt.reconciled());
    assert_eq!(receipt.event().encode(), original);
    assert_eq!(*receipt.registry_digest(), registry);
    assert_eq!(image(&temp.path()), before);
    let fork = f.event(33, events[31].id(), "unrelated inline");
    assert!(store
        .commit_checked(
            vec![fork],
            terminal,
            expected(ticket),
            &f.context(),
            14,
            allowance()
        )
        .is_err());
    assert_eq!(image(&temp.path()), before);
}

#[test]
fn prerequisite_checked_work_never_hides_cleanup_and_maintenance_honors_zero_one_page_budgets() {
    let temp = Temp::new();
    let mut f = Fixture::new();
    let events = history(&f, 64);
    let first_author = f.author();
    let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
    let first = store
        .stage_checked(
            events[..32].to_vec(),
            empty(),
            &f.context(),
            10,
            allowance(),
        )
        .unwrap();
    store
        .stage_checked(
            events[32..].to_vec(),
            expected(first),
            &f.context(),
            11,
            allowance(),
        )
        .unwrap();
    f.key = SigningKey::from_bytes(&[55; 32]);
    let terminal = f.event(1, EventId::ZERO, "other author after expiry");
    store
        .commit_checked(vec![], terminal, empty(), &f.context(), 71, allowance())
        .unwrap();
    assert_eq!(fs::read_dir(temp.path().join("pages")).unwrap().count(), 2);
    let before = image(&temp.path());
    let quote = store.maintenance_quote(71, 0).unwrap();
    assert_eq!(quote.pages(), 0);
    assert!(quote.more());
    assert!(quote.clock_transition());
    assert_eq!(
        store
            .author_status(first_author, 71)
            .unwrap()
            .cleanup_pages(),
        2
    );
    assert_eq!(image(&temp.path()), before);
    assert!(matches!(
        store.maintain_bounded(71, 33),
        Err(Error::Capacity)
    ));
    assert_eq!(image(&temp.path()), before);
    assert_eq!(store.maintain_bounded(71, 0).unwrap().pages_removed, 0);
    let quote = store.maintenance_quote(71, 1).unwrap();
    assert_eq!(quote.pages(), 1);
    assert!(quote.more());
    assert!(!quote.clock_transition());
    assert!(store.maintain_bounded(71, 1).unwrap().more);
    assert_eq!(fs::read_dir(temp.path().join("pages")).unwrap().count(), 1);
    assert!(!store.maintain_bounded(71, 1).unwrap().more);
    assert_eq!(fs::read_dir(temp.path().join("pages")).unwrap().count(), 0);
    assert_eq!(store.pin().feed_count(), 1);
}

#[test]
fn prerequisite_expired_page_retry_and_fresh_policy_refusal_preserve_all_files() {
    let temp = Temp::new();
    let mut f = Fixture::new();
    let events = history(&f, 32);
    let mut store = ContinuityStore::create(temp.path(), f.scope, limits()).unwrap();
    store
        .stage_checked(events.clone(), empty(), &f.context(), 10, allowance())
        .unwrap();
    let before = image(&temp.path());
    assert!(matches!(
        store.stage_checked(events, empty(), &f.context(), 70, allowance()),
        Err(Error::Capacity)
    ));
    assert_eq!(image(&temp.path()), before);
    f.key = SigningKey::from_bytes(&[56; 32]);
    let terminal = f.event(1, EventId::ZERO, "old policy");
    f.set_policy(false);
    assert!(matches!(
        store.commit_checked(vec![], terminal, empty(), &f.context(), 71, allowance()),
        Err(Error::Activity(_))
    ));
    assert_eq!(image(&temp.path()), before);
    assert!(matches!(
        store.maintenance_quote(9, 1),
        Err(Error::Conflict)
    ));
    assert_eq!(image(&temp.path()), before);
}

#[test]
fn prerequisite_position_and_ticket_shape_bounds_prevent_ambiguous_expectations() {
    let f = Fixture::new();
    let events = history(&f, 32);
    let tail = AuthorPosition::new(32, events[31].id()).unwrap();
    assert!(StageTicket::new([1; 32], [0; 32], AuthorPosition::EMPTY, tail, 1, 10).is_err());
    assert!(AuthorPosition::new(0, events[0].id()).is_err());
    assert!(AuthorPosition::new(1, EventId::ZERO).is_err());
    for pages in [0, 2, 129, u32::MAX] {
        assert!(
            StageTicket::new([1; 32], f.author(), AuthorPosition::EMPTY, tail, pages, 10).is_err()
        );
    }
    assert!(StageTicket::new([0; 32], f.author(), AuthorPosition::EMPTY, tail, 1, 10).is_err());
    assert!(StageTicket::new([1; 32], f.author(), AuthorPosition::EMPTY, tail, 1, 0).is_err());
}
