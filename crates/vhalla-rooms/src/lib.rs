#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Bounded signature evidence for vhalla (valhalla) room proposals.
//!
//! Valid signatures do not prove current controller authority, grant validity,
//! earned allowance, slug availability or directory finality. The authority
//! module re-evaluates claimed bases against a borrowed social view and the
//! agreed room-control ledger; it still does not admit a room, debits no
//! allowance and maps no genesis to a routing identifier.

extern crate alloc;

pub mod authority;
pub mod awards;
pub mod model;
pub mod registry;
pub mod wire;

pub use authority::{Admission, Denial, RoomAuthority};
pub use awards::{assess_support, AwardDenial, SupportAward};
pub use model::*;
pub use registry::{Account, Applied, DirectoryPolicy, Registry, RegistryError, Room, Search};
pub use wire::{AgentProposal, OwnerPermit, SignedRecord, VerifiedOwnerPermit, VerifiedRecord};
