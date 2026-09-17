//! Witness-mode program execution for Valhalla's Botcaptcha: the platform
//! side of a Roc-style platform/application split.
//!
//! The application supplies only an [`world::Assignment`] of finite-rule
//! programs. A program can name conditions, actions, four memory slots, and
//! four ports, and nothing else: no clock, randomness, host import, recursion,
//! or arithmetic. The platform owns the world, the tick loop, the work ledger,
//! the allowance, and every effect, and hands back plain data.
//!
//! - `bounds`, `model`, `world`, `ledger`, `vm`: the Platonik `habitat-v1`
//!   execution model restated bit for bit (see the witness platform plan).
//! - `codec`, `hash`: canonical fixed-width encodings and domain-separated
//!   SHA-256 digests.
//! - `manifest`: the verifier-authored task with fixed and open program slots.
//! - `platform`: the move-only `RunCapability`, `run`, `WitnessRun`,
//!   `WitnessReceipt`, and the decodable `ClaimedReceipt`.
//! - `vectors`: the committed corpus vector format and its replay.
//!
//! The crate is `no_std` plus `alloc`, depends only on `sha2`, reads no clock
//! or entropy, and has no key type. A valid run proves bounded, replayable
//! work on a verifier-selected task and nothing else.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod bounds;
pub mod codec;
pub mod hash;
pub mod ledger;
pub mod manifest;
pub mod model;
pub mod platform;
pub mod vectors;
pub mod vm;
pub mod world;
