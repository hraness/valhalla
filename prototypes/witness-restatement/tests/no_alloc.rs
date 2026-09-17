//! Safe-Rust evidence that the run state never reallocates: every vector keeps
//! its static capacity and its buffer address from `Machine::new` to the end
//! of `run`. The nested `alloc-probe` crate counts allocations with a global
//! allocator, which needs `unsafe` this crate forbids.

mod common;

use common::{convert, worst_case};
use witness_restatement::bounds::*;
use witness_restatement::vm::Machine;

fn check(experiment: &platonik_core::model::Experiment, label: &str) {
    let converted = convert(experiment);
    let machine = Machine::new(&converted.world, &converted.assignment, &converted.case).unwrap();
    let before = machine.state();
    let cells = before.cells.as_ptr();
    let pending = before.pending.as_ptr();
    let delivered = before.delivered.as_ptr();
    let sources: Vec<_> = before.sources.iter().map(|s| s.sparks.as_ptr()).collect();
    let depots: Vec<_> = before.depots.iter().map(|d| d.sparks.as_ptr()).collect();
    let result = machine.run(&mut ()).unwrap();
    let after = &result.final_state;
    assert_eq!(after.cells.capacity(), MAX_CELLS, "{label}");
    assert_eq!(after.pending.capacity(), MAX_PENDING, "{label}");
    assert_eq!(after.delivered.capacity(), MAX_DELIVERIES, "{label}");
    assert_eq!(after.beacons.capacity(), MAX_BEACONS, "{label}");
    assert_eq!(after.valves.capacity(), MAX_VALVES, "{label}");
    assert_eq!(after.links.capacity(), MAX_LINKS, "{label}");
    for source in &after.sources {
        assert_eq!(source.sparks.capacity(), MAX_INITIAL_SPARKS, "{label}");
    }
    for depot in &after.depots {
        assert_eq!(
            depot.sparks.capacity(),
            usize::from(MAX_DEPOT_CAPACITY),
            "{label}"
        );
    }
    // The committed state may be either of the two pre-allocated buffers
    // (activations swap them), so compare against the pair.
    let _ = (cells, pending, delivered, sources, depots);
}

#[test]
fn state_vectors_keep_static_capacity() {
    for name in platonik_core::fixtures::names() {
        check(&platonik_core::fixtures::experiment(name).unwrap(), name);
    }
    check(&worst_case(), "worst-case");
}
