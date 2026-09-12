//! Disposable prototype for deterministic Botcaptcha witness programs.
//!
//! This is deliberately a tiny typed expression language, not a network
//! interpreter. It tests the boundary between a challenge, a bounded program,
//! a useful result, and a reproducible work receipt.

use std::fmt;

pub const MAX_DEPTH: usize = 32;
pub const MAX_STEPS: u64 = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expr {
    Const(u64),
    Input,
    Add(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    RotateLeft(Box<Expr>, u8),
    IfZero(Box<Expr>, Box<Expr>, Box<Expr>),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Work {
    pub static_nodes: u32,
    pub dynamic_steps: u64,
    pub memory_bytes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvalError {
    Depth,
    Steps,
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Depth => f.write_str("expression depth exceeded"),
            Self::Steps => f.write_str("execution fuel exhausted"),
        }
    }
}

impl std::error::Error for EvalError {}

impl Expr {
    pub fn nodes(&self) -> u32 {
        match self {
            Self::Const(_) | Self::Input => 1,
            Self::Add(a, b) | Self::Xor(a, b) => 1 + a.nodes() + b.nodes(),
            Self::RotateLeft(value, _) => 1 + value.nodes(),
            Self::IfZero(test, yes, no) => 1 + test.nodes() + yes.nodes() + no.nodes(),
        }
    }

    fn eval(&self, input: u64, depth: usize, work: &mut Work) -> Result<u64, EvalError> {
        if depth > MAX_DEPTH {
            return Err(EvalError::Depth);
        }
        work.dynamic_steps += 1;
        if work.dynamic_steps > MAX_STEPS {
            return Err(EvalError::Steps);
        }
        match self {
            Self::Const(value) => Ok(*value),
            Self::Input => {
                work.memory_bytes += 8;
                Ok(input)
            }
            Self::Add(a, b) => {
                Ok(a.eval(input, depth + 1, work)?
                    .wrapping_add(b.eval(input, depth + 1, work)?))
            }
            Self::Xor(a, b) => {
                Ok(a.eval(input, depth + 1, work)? ^ b.eval(input, depth + 1, work)?)
            }
            Self::RotateLeft(value, amount) => Ok(value
                .eval(input, depth + 1, work)?
                .rotate_left(u32::from(*amount))),
            Self::IfZero(test, yes, no) => {
                if test.eval(input, depth + 1, work)? == 0 {
                    yes.eval(input, depth + 1, work)
                } else {
                    no.eval(input, depth + 1, work)
                }
            }
        }
    }

    pub fn run(&self, input: u64) -> Result<(u64, Work), EvalError> {
        let mut work = Work {
            static_nodes: self.nodes(),
            ..Work::default()
        };
        Ok((self.eval(input, 0, &mut work)?, work))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Challenge {
    pub id: [u8; 32],
    pub input: u64,
    pub min_dynamic_steps: u64,
    pub max_dynamic_steps: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Witness {
    pub challenge_id: [u8; 32],
    pub program_hash: [u8; 32],
    pub output: u64,
    pub work: Work,
}

pub fn program_hash(program: &Expr) -> [u8; 32] {
    // A tiny deterministic reference hash. Production must use the canonical
    // protocol hash, not this pedagogical byte mixer.
    let mut out = [0u8; 32];
    fn visit(expr: &Expr, out: &mut [u8; 32], cursor: &mut usize) {
        let tag = match expr {
            Expr::Const(_) => 1,
            Expr::Input => 2,
            Expr::Add(_, _) => 3,
            Expr::Xor(_, _) => 4,
            Expr::RotateLeft(_, _) => 5,
            Expr::IfZero(_, _, _) => 6,
        };
        out[*cursor % 32] ^= tag;
        *cursor += 1;
        match expr {
            Expr::Const(value) => {
                for byte in value.to_be_bytes() {
                    out[*cursor % 32] = out[*cursor % 32].wrapping_add(byte);
                    *cursor += 1;
                }
            }
            Expr::Input => {}
            Expr::Add(a, b) | Expr::Xor(a, b) => {
                visit(a, out, cursor);
                visit(b, out, cursor);
            }
            Expr::RotateLeft(value, amount) => {
                out[*cursor % 32] ^= *amount;
                *cursor += 1;
                visit(value, out, cursor);
            }
            Expr::IfZero(test, yes, no) => {
                visit(test, out, cursor);
                visit(yes, out, cursor);
                visit(no, out, cursor);
            }
        }
    }
    visit(program, &mut out, &mut 0);
    out
}

pub fn verify(challenge: Challenge, program: &Expr, witness: &Witness) -> Result<(), &'static str> {
    if witness.challenge_id != challenge.id {
        return Err("challenge mismatch");
    }
    if witness.program_hash != program_hash(program) {
        return Err("program hash mismatch");
    }
    let (output, work) = program
        .run(challenge.input)
        .map_err(|_| "execution failed")?;
    if witness.output != output || witness.work != work {
        return Err("receipt mismatch");
    }
    if work.dynamic_steps < challenge.min_dynamic_steps
        || work.dynamic_steps > challenge.max_dynamic_steps
    {
        return Err("work outside challenge range");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program() -> Expr {
        Expr::IfZero(
            Box::new(Expr::Xor(Box::new(Expr::Input), Box::new(Expr::Const(7)))),
            Box::new(Expr::RotateLeft(Box::new(Expr::Input), 3)),
            Box::new(Expr::Add(Box::new(Expr::Input), Box::new(Expr::Const(1)))),
        )
    }

    #[test]
    fn verifier_requires_exact_replay_and_work_range() {
        let program = program();
        let challenge = Challenge {
            id: [4; 32],
            input: 7,
            min_dynamic_steps: 4,
            max_dynamic_steps: 20,
        };
        let (output, work) = program.run(challenge.input).unwrap();
        let witness = Witness {
            challenge_id: challenge.id,
            program_hash: program_hash(&program),
            output,
            work,
        };
        assert_eq!(verify(challenge, &program, &witness), Ok(()));
        let mut altered = witness.clone();
        altered.output ^= 1;
        assert_eq!(
            verify(challenge, &program, &altered),
            Err("receipt mismatch")
        );
    }

    #[test]
    fn padding_is_visible_but_does_not_create_useful_output() {
        let compact = Expr::Input;
        let padded = Expr::Add(Box::new(Expr::Input), Box::new(Expr::Const(0)));
        assert!(padded.nodes() > compact.nodes());
        let challenge = Challenge {
            id: [1; 32],
            input: 9,
            min_dynamic_steps: 0,
            max_dynamic_steps: MAX_STEPS,
        };
        let (compact_output, compact_work) = compact.run(challenge.input).unwrap();
        let (padded_output, padded_work) = padded.run(challenge.input).unwrap();
        assert_eq!(compact_output, padded_output);
        assert!(padded_work.dynamic_steps > compact_work.dynamic_steps);
    }

    #[test]
    fn recursion_and_fuel_are_bounded() {
        let mut expression = Expr::Input;
        for _ in 0..(MAX_DEPTH + 2) {
            expression = Expr::RotateLeft(Box::new(expression), 1);
        }
        assert_eq!(expression.run(1), Err(EvalError::Depth));
    }
}
