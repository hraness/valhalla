//! Owner-authorized creation of a new private delivery profile's local queues.
//!
//! The caller supplies the native room context under service custody. This is
//! explicitly a new-only operation, not a retry claim or an implicit attachment.

use super::catalog::Hash;
use crate::private_rooms::agent_delivery;
use hraness_control_kit::{ErrorBody, ErrorCode};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use vhalla_custody::{self as custody, Owner};
use vhalla_private_kernel::Context;
use zeroize::Zeroizing;

const PROFILE_BYTES: usize = 16_384;
const PATH_BYTES: usize = 4096;
type Result<T> = std::result::Result<T, ErrorBody>;

fn refused() -> ErrorBody {
    ErrorBody::new(ErrorCode::Conflict,
        "Private delivery setup was refused or may be incomplete. Preserve the profile and queue files; existing state is never initialized again.")
}
fn invalid() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::Usage,
        "Select the full hash and canonical path of an owner-private version 4 delivery profile.",
    )
}

struct ProfileGuard {
    path: PathBuf,
    parent: File,
    file: File,
    owner: Owner,
    hash: Hash,
}
impl ProfileGuard {
    fn open(path: &Path, hash: Hash) -> Result<Self> {
        if hash.0 == [0; 32]
            || !path.is_absolute()
            || path.as_os_str().as_encoded_bytes().len() > PATH_BYTES
            || path.canonicalize().map_err(|_| invalid())?.as_os_str() != path.as_os_str()
        {
            return Err(invalid());
        }
        let (parent, owner) = custody::open_private_directory(path.parent().ok_or_else(invalid)?)
            .map_err(|_| refused())?;
        if owner != Owner::current().map_err(|_| refused())? {
            return Err(refused());
        }
        let file = custody::open_private_file(path, owner, PROFILE_BYTES).map_err(|_| refused())?;
        let guard = Self {
            path: path.to_owned(),
            parent,
            file,
            owner,
            hash,
        };
        guard.check()?;
        Ok(guard)
    }
    fn check(&self) -> Result<()> {
        if self.path.canonicalize().map_err(|_| refused())?.as_os_str() != self.path.as_os_str() {
            return Err(refused());
        }
        let (parent, owner) =
            custody::open_private_directory(self.path.parent().ok_or_else(refused)?)
                .map_err(|_| refused())?;
        let mut file =
            custody::open_private_file(&self.path, owner, PROFILE_BYTES).map_err(|_| refused())?;
        if owner != self.owner
            || owner != Owner::current().map_err(|_| refused())?
            || !custody::same_open_file(&parent, &self.parent).map_err(|_| refused())?
            || !custody::same_open_file(&file, &self.file).map_err(|_| refused())?
        {
            return Err(refused());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take((PROFILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| refused())?;
        if bytes.is_empty()
            || bytes.len() > PROFILE_BYTES
            || <[u8; 32]>::from(Sha256::digest(bytes.as_slice())) != self.hash.0
        {
            return Err(refused());
        }
        let current =
            custody::open_private_file(&self.path, owner, PROFILE_BYTES).map_err(|_| refused())?;
        if !custody::same_open_file(&current, &self.file).map_err(|_| refused())? {
            return Err(refused());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Boundary {
    Selected,
    Initialized,
}

/// Create fresh local queues for exactly the selected version 4 profile. No
/// relay request, grant, native room operation or profile rewrite is performed.
pub(super) fn initialize(path: &Path, expected_hash: Hash, context: Context) -> Result<Value> {
    initialize_with(path, expected_hash, context, |_| Ok(()))
}

fn initialize_with(
    path: &Path,
    expected_hash: Hash,
    context: Context,
    mut boundary: impl FnMut(Boundary) -> Result<()>,
) -> Result<Value> {
    let guard = ProfileGuard::open(path, expected_hash)?;
    guard.check()?;
    boundary(Boundary::Selected)?;
    let initialized = agent_delivery::initialize_bound(&guard.path, context, expected_hash.0);
    boundary(Boundary::Initialized)?;
    // Run this even when initialization refused. Neither a transient profile
    // swap nor an uncertain result permits treating a partial setup as empty.
    guard.check()?;
    initialized.map_err(|error| match error {
        agent_delivery::InitializeBoundError::Version => invalid(),
        agent_delivery::InitializeBoundError::NamedTls => ErrorBody::new(ErrorCode::Usage,
            "Local delivery setup requires an Iroh endpoint or numeric TLS relay address; a TLS hostname requires DNS."),
        agent_delivery::InitializeBoundError::Refused => refused(),
    })?;
    guard.file.sync_all().map_err(|_| refused())?;
    guard.parent.sync_all().map_err(|_| refused())?;
    guard.check()?;
    Ok(json!({ "profile_hash": expected_hash, "initialized": true }))
}

#[cfg(test)]
#[path = "private_setup_tests.rs"]
mod tests;
