use super::*;

fn selection(draft: &vhalla_browser_storage::outbox::ReservedDraft) -> Vec<OsString> {
    vec![
        draft.request().claims().sequence.to_string().into(),
        hex(draft.request().id().as_bytes()).into(),
    ]
}

#[test]
fn historical_recovery_actual_certified_revocation_preserves_request_and_needs_later_current_terminal(
) {
    let mut home = Home::new();
    success(home.run("init", &[]));
    success(home.run(
        "reserve",
        &[home.text("reserved before actual certified revocation\nexact bytes")],
    ));
    let original = retained_draft(&home).unwrap();
    let selected = selection(&original);
    home.policy(false);
    // Ordinary resume catches up its stored policy head but cannot sign the
    // pending old policy. Historical recovery must safely rebase that metadata.
    assert!(!home.run("resume", &[]).status.success());
    assert_eq!(
        retained_draft(&home).unwrap().as_bytes(),
        original.as_bytes()
    );
    assert!(home.export("before-recovery").is_empty());
    let output = success(home.run("recover-history", &selected));
    assert!(output.contains("status signed-and-retained-for-continuity"));
    assert!(output.contains("current-posting-permission not-established"));
    assert!(output.contains("past-admission not-established"));
    let first = home.export("historical-only");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].id(), original.request().id());
    assert_eq!(first[0].claims(), original.request().claims());
    assert!(retained_draft(&home).is_none());
    assert!(!home
        .run("queue", &[home.text("cannot resurrect a closed grant")])
        .status
        .success());
    home.policy(true);
    success(home.run("queue", &[home.text("separate current-policy terminal")]));
    let events = home.export("with-current-terminal");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].encode(), first[0].encode());
    assert_eq!(events[1].claims().previous, events[0].id());
    assert_ne!(events[1].claims().policy, events[0].claims().policy);
    let context =
        vhalla_room_activity::AdmissionContext::new(home.network, home.scenario.app.registry())
            .unwrap();
    let mut chain =
        vhalla_room_activity::AuthorChain::new(home.scope(), events[0].claims().author).unwrap();
    assert_eq!(
        chain.prepare_next(events[0].clone(), &context).unwrap_err(),
        vhalla_room_activity::Error::Policy
    );
    let mut hidden = vhalla_room_activity::continuity::ContinuityPosition::begin(&chain);
    let candidate = hidden
        .prepare_segment(vec![events[0].clone()], &context)
        .unwrap();
    hidden
        .commit_segment_after_persist(candidate, &context)
        .unwrap();
    assert!(chain.position().is_none());
    let terminal = chain
        .prepare_continuity_terminal(hidden, events[1].clone(), &context)
        .unwrap();
    let admitted = chain
        .commit_continuity_terminal_after_persist(terminal, hidden, &context)
        .unwrap();
    assert_eq!(admitted.event(), &events[1]);
}

#[test]
fn historical_recovery_exact_selected_retry_preserves_newer_pending_even_with_bad_later_journal() {
    let mut home = Home::new();
    success(home.run("init", &[]));
    success(home.run("reserve", &[home.text("first exact held event")]));
    let draft = retained_draft(&home).unwrap();
    let selected = selection(&draft);
    home.policy(false);
    success(home.run("recover-history", &selected));
    let first = home.export("first")[0].encode();
    home.policy(true);
    success(home.run(
        "reserve",
        &[home.text("newer pending must not be signed by old retry")],
    ));
    let newer = retained_draft(&home).unwrap();
    let state = fs::read(home.path.join("outbox/STATE")).unwrap();
    home.commit(
        home.scenario.app.frontier().time + 100,
        vec![],
        vec![],
        true,
    );
    let output = success(home.run("recover-history", &selected));
    assert!(output.contains("status already-signed-retained-locally"));
    assert!(!output.contains("evaluation-height"));
    assert_eq!(retained_draft(&home).unwrap().as_bytes(), newer.as_bytes());
    assert_eq!(fs::read(home.path.join("outbox/STATE")).unwrap(), state);
    assert_eq!(home.export("retry")[0].encode(), first);
    let mut wrong = selected;
    wrong[1] = hex(&[99; 32]).into();
    assert!(!home.run("recover-history", &wrong).status.success());
    assert_eq!(fs::read(home.path.join("outbox/STATE")).unwrap(), state);
}

#[test]
fn historical_recovery_wrong_selection_and_bad_certificate_do_not_finalize_or_replace_pending() {
    let mut home = Home::new();
    success(home.run("init", &[]));
    success(home.run("reserve", &[home.text("retain after refusal")]));
    let draft = retained_draft(&home).unwrap();
    let selected = selection(&draft);
    let state = fs::read(home.path.join("outbox/STATE")).unwrap();
    for wrong in [
        vec!["2".into(), selected[1].clone()],
        vec!["1".into(), hex(&[99; 32]).into()],
        vec!["01".into(), selected[1].clone()],
    ] {
        assert!(!home.run("recover-history", &wrong).status.success());
        assert_eq!(fs::read(home.path.join("outbox/STATE")).unwrap(), state);
    }
    home.commit(
        home.scenario.app.frontier().time + 100,
        vec![],
        vec![],
        true,
    );
    assert!(!home.run("recover-history", &selected).status.success());
    assert_eq!(retained_draft(&home).unwrap().as_bytes(), draft.as_bytes());
    assert_eq!(fs::read(home.path.join("outbox/STATE")).unwrap(), state);
    assert!(home.export("no-signature").is_empty());
    fs::rename(home.path.join("outbox"), home.path.join("preserved-outbox")).unwrap();
    assert!(!home.run("recover-history", &selected).status.success());
    assert!(!home.path.join("outbox").exists());
}
