//! The Platonik session adapter: the games plan's `GameManifest`,
//! `SessionOpen`, `GameEvent`, `Checkpoint`, and `Settlement` over
//! `vhalla-witness`, so that Platonik runs through an optional Valhalla
//! session and a receiver independently verifies the result.
//!
//! Stage 1 lands the identifiers, the canonical encodings with every bound,
//! the audience-free signed carrier, the manifest, and the optional Platonik
//! oracle converter. The engine seam, sessions, checkpoints, settlement, the
//! receiver, and bounded artifacts follow in later stages, as the
//! [session adapter plan](../../kb/plans/valhalla-platonik-session-adapter.md)
//! stages them.
//!
//! Nothing here reads a clock, entropy, a file, or a socket. Nothing here
//! executes network-supplied code: programs are data interpreted by
//! `vhalla-witness`. A verified game object proves replayable work under one
//! explicit session authority and nothing else.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod ids;
pub mod manifest;
pub mod record;
pub mod wire;

#[cfg(feature = "oracle")]
pub mod oracle;
