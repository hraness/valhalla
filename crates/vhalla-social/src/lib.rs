#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Bounded signed social records for vhalla (valhalla).
//!
//! Signatures establish immutable evidence, not affiliation or host authority.
//! Current affiliation is a borrowed projection of complete control evidence.
//! The first version admits public-realm records only; private publication and
//! compromised-controller recovery are explicitly unavailable.

extern crate alloc;

pub mod archive;
pub mod control;
pub mod model;
pub mod view;
pub mod wire;

pub use model::*;
pub use wire::{PrimarySignedRecord, SignedRecord, UnsignedRecord, VerifiedRecord};
