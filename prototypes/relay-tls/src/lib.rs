//! Isolated, test-only qualification of authenticated TLS for opaque relays.
//! Nothing in the production workspace depends on this crate.
#![forbid(unsafe_code)]

#[cfg(test)]
mod adapter;
#[cfg(test)]
mod tests;
