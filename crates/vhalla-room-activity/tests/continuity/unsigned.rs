use super::*;

#[test]
fn historical_unsigned_preserves_exact_bytes_after_revocation_and_archival() {
    let mut f = Fixture::new();
    let old = f.policy(true);
    let request = UnsignedEvent::new(claims(f.scope, old)).unwrap();
    let bytes = request.encode();
    let id = request.id();
    for archive in [false, true] {
        if archive {
            f.update(UpdateAction::Archive);
        } else {
            f.policy(false);
        }
        let checked = f
            .context()
            .check_historical_unsigned(request.clone())
            .unwrap();
        assert_eq!(checked.request().encode(), bytes);
        assert_eq!(checked.request().id(), id);
        assert_eq!(checked.registry_digest(), f.context().registry_digest());
        assert!(f.chain().position().is_none());
        assert_eq!(
            f.chain()
                .prepare_next(verified(request.claims().clone()), &f.context())
                .unwrap_err(),
            Error::Policy
        );
    }
}

#[test]
fn historical_unsigned_rejects_disabled_unknown_foreign_and_wrong_action_revisions() {
    let mut f = Fixture::new();
    let enabled = f.policy(true);
    let disabled = f.policy(false);
    let archived = f.update(UpdateAction::Archive);
    for policy in [disabled, archived, RoomRecordId::from_bytes([99; 32])] {
        assert_eq!(
            f.context()
                .check_historical_unsigned(UnsignedEvent::new(claims(f.scope, policy)).unwrap())
                .unwrap_err(),
            Error::Policy
        );
    }
    for field in 0..4 {
        let mut body = claims(f.scope, enabled);
        match field {
            0 => body.scope.network[0] ^= 1,
            1 => body.scope.realm = vhalla_core::RealmId(body.scope.realm.0 + 1),
            2 => body.scope.directory = vhalla_rooms::DirectoryId::from_bytes([99; 32]),
            _ => body.scope.room = vhalla_rooms::RoomGenesisId::from_bytes([99; 32]),
        }
        assert!(f
            .context()
            .check_historical_unsigned(UnsignedEvent::new(body).unwrap())
            .is_err());
    }
    // An enabled revision explicitly naming a different network cannot qualify.
    let mut foreign = Fixture::new();
    let revision = foreign.update(UpdateAction::SetPublicActivityPolicy {
        network: [99; 32],
        enabled: true,
    });
    assert_eq!(
        foreign
            .context()
            .check_historical_unsigned(UnsignedEvent::new(claims(foreign.scope, revision)).unwrap())
            .unwrap_err(),
        Error::Policy
    );
}

#[test]
fn historical_unsigned_remains_distinct_from_a_later_current_terminal() {
    let mut f = Fixture::new();
    let old = f.policy(true);
    let request = UnsignedEvent::new(claims(f.scope, old)).unwrap();
    f.policy(false);
    let current = f.policy(true);
    let checked = f.context().check_historical_unsigned(request).unwrap();
    // Only after the unsigned check does this test create its first signature.
    let signed = checked
        .request()
        .clone()
        .sign_with_key(&author())
        .unwrap()
        .verify()
        .unwrap();
    let mut chain = f.chain();
    assert_eq!(
        chain
            .prepare_next(signed.clone(), &f.context())
            .unwrap_err(),
        Error::Policy
    );
    let mut hidden = ContinuityPosition::begin(&chain);
    let prefix = hidden
        .prepare_segment(vec![signed.clone()], &f.context())
        .unwrap();
    hidden
        .commit_segment_after_persist(prefix, &f.context())
        .unwrap();
    assert!(chain.position().is_none());
    let terminal = next(f.scope, current, 2, signed.id());
    let candidate = chain
        .prepare_continuity_terminal(hidden, terminal.clone(), &f.context())
        .unwrap();
    let admitted = chain
        .commit_continuity_terminal_after_persist(candidate, hidden, &f.context())
        .unwrap();
    assert_eq!(admitted.event(), &terminal);
}
