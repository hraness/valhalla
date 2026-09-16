//! Wall-clock measurements; run with `--nocapture` (and `--release`) to read
//! them. The assertions are loose so the gate never depends on the machine.

mod common;

use std::time::Instant;

use common::{convert, worst_case};
use witness_restatement::vm;

fn time(experiment: &platonik_core::model::Experiment, label: &str) {
    let converted = convert(experiment);
    let mut best = u128::MAX;
    let mut total = 0u64;
    for _ in 0..5 {
        let start = Instant::now();
        let result = vm::run(
            &converted.world,
            &converted.assignment,
            &converted.case,
            &mut (),
        )
        .unwrap();
        best = best.min(start.elapsed().as_micros());
        total = result.ledger.total().unwrap();
    }
    let oracle_start = Instant::now();
    let oracle = platonik_core::run(experiment).unwrap();
    let oracle_micros = oracle_start.elapsed().as_micros();
    println!(
        "{label}: restated engine best of 5 = {best} us, oracle (with frame clones) = {oracle_micros} us, \
         work = {total} units, ticks = {}",
        oracle.ticks_completed
    );
    assert!(best < 60_000_000);
}

#[test]
fn densest_suite_case_and_worst_case() {
    let report = platonik_core::suite::run_suite("bridge-v1").unwrap();
    let densest = report
        .cases
        .iter()
        .max_by_key(|case| case.receipt.result.costs.total())
        .unwrap();
    time(
        &densest.receipt.experiment,
        &format!("densest suite case ({})", densest.id),
    );
    time(&worst_case(), "16-cell 128-tick worst case");
}
