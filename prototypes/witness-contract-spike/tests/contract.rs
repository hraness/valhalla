//! Evaluates the outcome-quantity floor against working, padded, and idle
//! programs on every bridge-v1 fixture that delivers at least one spark.

use witness_contract_spike::{
    only, pad_dead_effects, pad_unreachable, pad_unsatisfiable, ping_pong,
};
use witness_restatement::codec;
use witness_restatement::corpus::convert;
use witness_restatement::hash::ProgramHash;
use witness_restatement::manifest::{ProgramSlot, TaskManifest, ValidManifest, WorkContract};
use witness_restatement::model::{Action, Program, Relative};
use witness_restatement::platform::{self, RunCapability, RunRole, WitnessRun, WorkAllowance};

struct Fixture {
    name: &'static str,
    valid: ValidManifest,
    working: Vec<(u16, Program)>,
}

fn fixtures() -> Vec<Fixture> {
    let mut out = Vec::new();
    for name in platonik_core::fixtures::names() {
        let converted = convert(&platonik_core::fixtures::experiment(name).unwrap());
        let working: Vec<(u16, Program)> = converted
            .assignment
            .cells()
            .iter()
            .copied()
            .zip(converted.assignment.programs().iter().cloned())
            .collect();
        let manifest = TaskManifest {
            world: converted.world.spec().clone(),
            slots: working
                .iter()
                .map(|(cell, _)| ProgramSlot {
                    cell: *cell,
                    fixed: None,
                })
                .collect(),
            cases: vec![converted.case.spec().clone()],
            contract: WorkContract {
                useful_floor: 0,
                total_ceiling: converted.case.fuel(),
                require_passed: false,
            },
        };
        out.push(Fixture {
            name,
            valid: ValidManifest::validate(manifest).unwrap(),
            working,
        });
    }
    out
}

fn run(valid: &ValidManifest, candidate: Vec<(u16, Program)>) -> WitnessRun {
    let assignment = valid.assign(candidate).unwrap();
    let program = ProgramHash::of(&codec::encode_assignment(&assignment));
    platform::run(
        valid,
        &assignment,
        RunCapability::mint(
            valid.hash(),
            program,
            WorkAllowance {
                max_total: valid.fuel_total(),
            },
            RunRole::Replay,
        ),
    )
    .unwrap()
}

fn admitted(run: &WitnessRun, floor: u64, ceiling: u64) -> bool {
    run.useful() >= floor && run.total() <= ceiling && run.passed()
}

fn all(programs: &[(u16, Program)], make: impl Fn(&Program) -> Program) -> Vec<(u16, Program)> {
    programs
        .iter()
        .map(|(cell, program)| (*cell, make(program)))
        .collect()
}

#[test]
fn delivered_sparks_floor_separates_working_padded_and_idle() {
    let mut evaluated = 0;
    println!("fixture | class | useful | transfers+messages | total | admitted");
    for fixture in fixtures() {
        let working = run(&fixture.valid, fixture.working.clone());
        if working.useful() == 0 || !working.passed() {
            println!(
                "{}: skipped (useful {}, passed {})",
                fixture.name,
                working.useful(),
                working.passed()
            );
            continue;
        }
        evaluated += 1;
        let floor = working.useful();
        let ceiling = fixture.valid.fuel_total();
        let old_floor = |run: &WitnessRun| {
            run.cases()
                .iter()
                .map(|case| case.ledger.transfers + case.ledger.messages)
                .sum::<u64>()
        };
        let report = |class: &str, run: &WitnessRun| {
            println!(
                "{} | {class} | {} | {} | {} | {}",
                fixture.name,
                run.useful(),
                old_floor(run),
                run.total(),
                admitted(run, floor, ceiling)
            );
        };
        report("working", &working);
        assert!(
            admitted(&working, floor, ceiling),
            "{}: working admitted",
            fixture.name
        );

        // Behavior-preserving padding: identical outcome, more charged work.
        for (class, padded) in [
            (
                "padded-unsatisfiable-8",
                all(&fixture.working, |p| pad_unsatisfiable(p, 8)),
            ),
            (
                "padded-unsatisfiable-24",
                all(&fixture.working, |p| pad_unsatisfiable(p, 24)),
            ),
            (
                "padded-dead-effects-8",
                all(&fixture.working, |p| pad_dead_effects(p, 8)),
            ),
            (
                "padded-unreachable-16",
                all(&fixture.working, |p| pad_unreachable(p, 16)),
            ),
        ] {
            let padded = run(&fixture.valid, padded);
            report(class, &padded);
            assert!(
                padded.useful() <= working.useful(),
                "{}: {class} never raises useful",
                fixture.name
            );
            if padded.useful() == working.useful() {
                assert_eq!(
                    padded.cases()[0].final_state,
                    working.cases()[0].final_state,
                    "{}: {class} within the activation budget preserves the final state",
                    fixture.name
                );
                assert!(
                    padded.total() >= working.total(),
                    "{}: {class} charges at least as much",
                    fixture.name
                );
            } else {
                assert!(
                    !admitted(&padded, floor, ceiling),
                    "{}: {class} beyond the activation budget is rejected",
                    fixture.name
                );
            }
        }

        // Idle programs: charge work, deliver nothing.
        let idle = [
            ("idle-wait", all(&fixture.working, |_| only(Action::Wait))),
            (
                "idle-turn",
                all(&fixture.working, |_| {
                    only(Action::Turn {
                        direction: Relative::Left,
                    })
                }),
            ),
            (
                "idle-move",
                all(&fixture.working, |_| {
                    only(Action::Move {
                        direction: Relative::Forward,
                    })
                }),
            ),
            ("idle-ping-pong", all(&fixture.working, |_| ping_pong())),
        ];
        for (class, candidate) in idle {
            let idle = run(&fixture.valid, candidate);
            report(class, &idle);
            assert_eq!(
                idle.useful(),
                0,
                "{}: {class} delivers nothing",
                fixture.name
            );
            assert!(
                !admitted(&idle, floor, ceiling),
                "{}: {class} rejected",
                fixture.name
            );
            if class == "idle-turn" || class == "idle-move" {
                assert!(
                    old_floor(&idle) > 0,
                    "{}: {class} would have satisfied a transfers+messages floor",
                    fixture.name
                );
            }
        }
    }
    assert!(evaluated >= 3, "{evaluated} fixtures evaluated");
}
