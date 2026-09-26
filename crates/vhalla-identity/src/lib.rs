#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Explicit application-key custody. This is private-file storage, not
//! encryption, hostile-host isolation or adversarial disk rollback protection.
//! The directory and its ancestors must remain owner-controlled. No key is
//! generated while opening an existing store, even after an interrupted create.

mod custody;
pub use custody::{Identity, IdentityError};
