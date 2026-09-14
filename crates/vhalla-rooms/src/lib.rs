#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Bounded signature evidence for vhalla (valhalla) room proposals.
//!
//! Valid signatures do not prove current controller authority, grant validity,
//! earned allowance, slug availability or directory finality. No public API in
//! this crate admits a room or maps a genesis to a routing identifier.

extern crate alloc;

pub mod model;
pub mod wire;

pub use model::*;
pub use wire::{AgentProposal, OwnerPermit, SignedRecord, VerifiedOwnerPermit, VerifiedRecord};
