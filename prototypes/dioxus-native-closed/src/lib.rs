#![forbid(unsafe_code)]
//! Disposable closed native launcher; not an OS sandbox or a promoted client.
#[cfg(feature = "renderer")]
pub mod launcher;
#[cfg(any(feature = "renderer", test))]
mod policy;

#[cfg(test)]
mod dx_features;
