//! Spike 1 of the Valhalla witness platform plan: the Platonik `habitat-v1`
//! execution model restated in Valhalla-style production types.
//!
//! The library is `no_std` plus `alloc`, depends only on `sha2`, and has no
//! clock, no entropy, no floats, and no `usize` in any charged quantity.
//! `codec` is the canonical binary encoding, `hash` the domain-separated
//! digests, `manifest` the verifier-authored task, and `platform` the
//! move-only run capability, the run, and the receipt. Every counter and state update uses checked arithmetic and the
//! tick loop allocates nothing after [`vm::Machine::new`].
//!
//! Only what the Platonik `bridge-v1` suite exercises is restated: the v2
//! `EdgeBlocked` hazard, the v3 construction catalog, the v4 direction edits,
//! and checkpoint continuation are absent. Every state field and every cost
//! counter that affects a v1 outcome or a v1 cost trajectory is kept.
//!
//! The parity oracle (the pinned `platonik-core` engine) is a dev-dependency
//! used only by `tests/parity.rs`.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod bounds;
pub mod codec;
#[cfg(feature = "std")]
pub mod corpus;
pub mod hash;
pub mod ledger;
pub mod manifest;
pub mod model;
pub mod platform;
pub mod vm;
pub mod world;
