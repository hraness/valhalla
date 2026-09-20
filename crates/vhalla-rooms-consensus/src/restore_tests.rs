use super::*;
use crate::fixture;

fn restored(app: &Application, frontier: Frontier) -> Result<Application, ApplyError> {
    Application::restore_locally_authenticated(
        app.social().clone(),
        app.registry().clone(),
        frontier,
    )
}

#[test]
fn restore_exact_genesis_preserves_the_full_frontier() {
    let scenario = fixture::scenario(1, 1);
    let app = &scenario.app;
    let resumed = restored(app, app.frontier()).unwrap();
    assert_eq!(resumed.frontier(), app.frontier());
    assert_eq!(resumed.social().root(), app.social().root());
    assert_eq!(resumed.registry().digest(), app.registry().digest());
}

#[test]
fn restore_genesis_refuses_a_different_value_or_clock() {
    let scenario = fixture::scenario(1, 1);
    let app = &scenario.app;
    for changed in [
        Frontier {
            value: [99; 32],
            ..app.frontier()
        },
        Frontier {
            time: 1,
            ..app.frontier()
        },
    ] {
        assert!(matches!(restored(app, changed), Err(ApplyError::Parent)));
    }
}

#[test]
fn restore_refuses_foreign_realm_even_with_matching_claimed_roots() {
    let scenario = fixture::scenario(1, 1);
    let social = Archive::new(RealmId(fixture::REALM.0 + 1), fixture::limits()).unwrap();
    let registry = scenario.app.registry().clone();
    let frontier = Application::genesis(social.clone(), registry.clone()).frontier();
    assert!(matches!(
        Application::restore_locally_authenticated(social, registry, frontier),
        Err(ApplyError::Result)
    ));
}

#[test]
fn restore_refuses_each_changed_state_commitment() {
    let mut scenario = fixture::scenario(1, 1);
    let checked = scenario.app.prepare(1, vec![], vec![], None).unwrap();
    scenario.app.apply_locally(checked);
    let app = &scenario.app;
    for changed in [
        Frontier {
            registry: [99; 32],
            ..app.frontier()
        },
        Frontier {
            social: [99; 32],
            ..app.frontier()
        },
        Frontier {
            control: [99; 32],
            ..app.frontier()
        },
    ] {
        assert!(matches!(restored(app, changed), Err(ApplyError::Result)));
    }
}

#[test]
fn restore_recomputes_control_at_the_saved_clock() {
    let mut scenario = fixture::scenario(1, 1);
    let before = scenario.app.frontier();
    // The fixture's grants expire at this clock, changing agent activity.
    let checked = scenario
        .app
        .prepare(1_000_000, vec![], vec![], None)
        .unwrap();
    scenario.app.apply_locally(checked);
    let app = &scenario.app;
    assert_ne!(before.control, app.frontier().control);
    assert_eq!(
        restored(app, app.frontier()).unwrap().frontier(),
        app.frontier()
    );
    let wrong_clock = Frontier {
        time: 0,
        ..app.frontier()
    };
    assert!(matches!(
        restored(app, wrong_clock),
        Err(ApplyError::Result)
    ));
}

#[test]
fn restore_after_real_room_state_matches_next_batch_replay() {
    let plan = fixture::plan(2, 2, 2);
    let mut original = Application::genesis(
        plan.genesis.archive.clone(),
        plan.genesis.registry().unwrap(),
    );
    original.apply_locally(original.validate(&plan.batches[&1]).unwrap());
    let mut resumed = restored(&original, original.frontier()).unwrap();
    let next = &plan.batches[&2];
    let expected = original.validate(next).unwrap();
    let actual = resumed.validate(next).unwrap();
    assert_eq!(actual.next(), expected.next());
    assert_eq!(actual.batch().encode(), expected.batch().encode());
    original.apply_locally(expected);
    resumed.apply_locally(actual);
    assert_eq!(resumed.frontier(), original.frontier());
    assert_eq!(resumed.registry().digest(), original.registry().digest());
    assert_eq!(resumed.social().root(), original.social().root());
}
