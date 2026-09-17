//! Bit-exact parity with the pinned Platonik engine on the bridge-v1 corpus
//! and on deterministic random v1 experiments.

mod common;

use common::{assert_parity, random_experiment, worst_case, Rng};
use platonik_core::model::RunStatus;

#[test]
fn every_fixture_matches() {
    for name in platonik_core::fixtures::names() {
        let experiment = platonik_core::fixtures::experiment(name).unwrap();
        let result = assert_parity(&experiment, name);
        assert_eq!(result.status, RunStatus::Complete, "{name}");
    }
}

#[test]
fn every_bridge_v1_suite_case_matches() {
    let report = platonik_core::suite::run_suite("bridge-v1").unwrap();
    assert_eq!(report.cases.len(), 21, "bridge-v1 declares 21 cases");
    assert!(report.passed, "the pinned suite passes on its own engine");
    for case in &report.cases {
        let result = assert_parity(&case.receipt.experiment, &case.id);
        assert_eq!(
            result, case.receipt.result,
            "{}: oracle run equals the suite receipt",
            case.id
        );
    }
}

#[test]
fn worst_case_matches() {
    let experiment = worst_case();
    platonik_core::validate_experiment(&experiment).unwrap();
    let result = assert_parity(&experiment, "worst-case");
    assert_eq!(result.ticks_completed, 128);
    println!("worst case total work: {}", result.costs.total());
    assert!(result.costs.total() > 250_000, "{}", result.costs.total());
}

#[test]
fn random_v1_experiments_match() {
    const COUNT: usize = 400;
    let mut rng = Rng::new(0x5eed_ec07);
    let mut complete = 0usize;
    let mut fuel_at_load = 0usize;
    let mut fuel_mid_run = 0usize;
    let mut activation_limit = 0usize;
    let mut activation_stops = 0usize;
    let mut passed = 0usize;
    let mut deliveries = 0usize;
    let mut signals = 0usize;
    for index in 0..COUNT {
        let experiment = random_experiment(&mut rng);
        let result = assert_parity(&experiment, &format!("random-{index}"));
        match result.status {
            RunStatus::Complete => complete += 1,
            RunStatus::FuelExhausted
                if result.ticks_completed == 0 && !result.frames[0].complete =>
            {
                fuel_at_load += 1
            }
            RunStatus::FuelExhausted => fuel_mid_run += 1,
            RunStatus::ActivationLimit => activation_limit += 1,
        }
        activation_stops += result
            .frames
            .iter()
            .flat_map(|frame| &frame.activations)
            .filter(|activation| activation.error.as_deref() == Some("activation_limit"))
            .count();
        passed += usize::from(result.outcome.passed);
        deliveries += result.final_state.delivered.len();
        signals += result
            .frames
            .iter()
            .map(|frame| frame.signals.len())
            .sum::<usize>();
    }
    println!(
        "random v1 experiments: {COUNT} total; complete {complete}, fuel exhausted at load {fuel_at_load}, \
         fuel exhausted mid-run {fuel_mid_run}, activation-limit status {activation_limit}; \
         {activation_stops} activation stops, {passed} passed missions, {deliveries} deliveries, {signals} signal events"
    );
    assert!(complete > 0 && fuel_at_load > 0 && fuel_mid_run > 0 && activation_limit > 0);
    assert!(passed > 0 && deliveries > 0 && signals > 0);
}
