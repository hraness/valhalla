//! Program mutations for the work-contract spike: behavior-preserving padding
//! that raises charged work without changing what a program does, and idle
//! programs that charge work without delivering anything.

use witness_restatement::model::{
    Action, BitSource, Condition, MemoryWrite, Port, Program, Relative, Rule, Slot,
};

/// Two conditions no cell can satisfy at once.
fn unsatisfiable() -> Vec<Condition> {
    vec![
        Condition::Carrying { value: true },
        Condition::Carrying { value: false },
    ]
}

/// Prepends `count` rules whose conditions never hold; every activation scans
/// them (charging `checking`, `conditions`, and `sensors`) and then continues
/// to the original first match, so behavior is unchanged.
#[must_use]
pub fn pad_unsatisfiable(program: &Program, count: usize) -> Program {
    let mut rules = Vec::with_capacity(program.rules().len() + count);
    for _ in 0..count {
        rules.push(
            Rule::new(
                unsatisfiable(),
                Action::Turn {
                    direction: Relative::Left,
                },
                None,
            )
            .unwrap(),
        );
    }
    rules.extend(program.rules().iter().cloned());
    Program::new(rules).unwrap()
}

/// Prepends unsatisfiable rules that would write memory and send bits if they
/// ever fired; they never do.
#[must_use]
pub fn pad_dead_effects(program: &Program, count: usize) -> Program {
    let mut rules = Vec::with_capacity(program.rules().len() + count);
    for index in 0..count {
        let action = if index % 2 == 0 {
            Action::WriteMemory {
                slot: Slot::new(3).unwrap(),
                value: 7,
            }
        } else {
            Action::Send {
                port: Port::new(0).unwrap(),
                bit: BitSource::Constant { value: true },
            }
        };
        rules.push(
            Rule::new(
                unsatisfiable(),
                action,
                Some(MemoryWrite::new(Slot::new(3).unwrap(), 1)),
            )
            .unwrap(),
        );
    }
    rules.extend(program.rules().iter().cloned());
    Program::new(rules).unwrap()
}

/// Appends a catch-all `Wait` (which changes nothing: no match already waits)
/// followed by rules that can never be reached.
#[must_use]
pub fn pad_unreachable(program: &Program, count: usize) -> Program {
    let mut rules: Vec<Rule> = program.rules().to_vec();
    rules.push(Rule::new(vec![], Action::Wait, None).unwrap());
    for _ in 0..count {
        rules.push(
            Rule::new(
                vec![],
                Action::Move {
                    direction: Relative::Forward,
                },
                None,
            )
            .unwrap(),
        );
    }
    Program::new(rules).unwrap()
}

/// A program that only ever performs `action`.
#[must_use]
pub fn only(action: Action) -> Program {
    Program::new(vec![Rule::new(vec![], action, None).unwrap()]).unwrap()
}

/// A program that keeps sending a constant bit on port 0 and taking whatever
/// arrives: with two linked cells this ping-pongs signals forever.
#[must_use]
pub fn ping_pong() -> Program {
    Program::new(vec![
        Rule::new(
            vec![Condition::HasMessage {
                port: Port::new(0).unwrap(),
                value: true,
            }],
            Action::TakeMessage {
                port: Port::new(0).unwrap(),
                slot: Slot::new(0).unwrap(),
            },
            None,
        )
        .unwrap(),
        Rule::new(
            vec![],
            Action::Send {
                port: Port::new(0).unwrap(),
                bit: BitSource::Constant { value: true },
            },
            None,
        )
        .unwrap(),
    ])
    .unwrap()
}
