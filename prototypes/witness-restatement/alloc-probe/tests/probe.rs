//! Zero allocations between `Machine::new` and the end of `Machine::run`.

#[path = "../../tests/common/mod.rs"]
mod common;

use common::{convert, random_experiment, worst_case, Rng};
use witness_restatement::vm::Machine;
use witness_restatement_alloc_probe::{counts, Counting};

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn probe(experiment: &platonik_core::model::Experiment, label: &str) -> u64 {
    let converted = convert(experiment);
    let machine = Machine::new(&converted.world, &converted.assignment, &converted.case).unwrap();
    let before = counts();
    let result = machine.run(&mut ()).unwrap();
    let after = counts();
    assert_eq!(
        (after.0 - before.0, after.1 - before.1),
        (0, 0),
        "{label}: (allocations, reallocations) during run"
    );
    result.ledger.total().unwrap()
}

#[test]
fn tick_loop_allocates_nothing() {
    let report = platonik_core::suite::run_suite("bridge-v1").unwrap();
    let mut work = 0;
    for case in &report.cases {
        work += probe(&case.receipt.experiment, &case.id);
    }
    work += probe(&worst_case(), "worst-case");
    let mut rng = Rng::new(0x5eed_ec07);
    for index in 0..100 {
        let experiment = random_experiment(&mut rng);
        work += probe(&experiment, &format!("random-{index}"));
    }
    println!("tick loop allocated nothing across 122 runs totalling {work} work units");
}
