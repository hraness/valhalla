//! Windows backend: SID owners, owner-only DACLs, reparse-point refusal and
//! volume-serial/file-index identity.
//!
//! The Unix contract maps as follows:
//!
//! - *owner* — the object's owner SID (`OWNER_SECURITY_INFORMATION`), compared
//!   with `EqualSid` against the expected [`Owner`]'s bytes.
//! - *privacy* — a `0700`/`0600` mode becomes a DACL that holds exactly one ACE:
//!   `FILE_ALL_ACCESS` granted to the object's owner — no deny entries, no other
//!   principals, and no absent (NULL) DACL, which would grant everyone. Created
//!   objects get a *protected* DACL at creation so no inherited ACE can leak in.
//!   SYSTEM and Administrators ACEs are intentionally not tolerated: the
//!   contract is "the owner and only the owner".
//! - *link refusal* — opens carry `FILE_FLAG_OPEN_REPARSE_POINT`, so a symlink
//!   or junction is opened rather than followed and then refused by the
//!   `FILE_ATTRIBUTE_REPARSE_POINT` attribute check — the `O_NOFOLLOW` role.
//! - *TOCTOU identity* — the stable `MetadataExt` by-handle fields are unstable,
//!   so link counts and identity come from `GetFileInformationByHandle`
//!   (`nNumberOfLinks`, `dwVolumeSerialNumber` + `nFileIndex*`) on live handles.
//!   Every check that Unix answers from a stat snapshot is therefore answered
//!   from an opened object here: a light query handle takes the pre-open
//!   observation's role and the returned handle is re-checked and compared.
//!   NTFS provides real link counts and file indices; FAT-family filesystems
//!   cannot satisfy this contract.
//! - *directory open/sync* — directories open with `FILE_FLAG_BACKUP_SEMANTICS`
//!   read/write so `File::sync_all` reaches `FlushFileBuffers`; NTFS journals
//!   directory metadata, so the flush commits pending name changes the way a
//!   Unix directory `fsync` does.
//!
//! `unsafe` is confined to this module's Win32 FFI boundary (the crate otherwise
//! denies it); every call is checked and every allocation freed on drop.

#![allow(unsafe_code)]

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io,
    iter::once,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    ptr,
};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, LocalFree, ERROR_ACCESS_DENIED, GENERIC_READ, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        EqualSid, GetAce, GetLengthSid, GetTokenInformation, IsValidSid, TokenUser,
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        CREATE_NEW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
    System::{
        SystemServices::ACCESS_ALLOWED_ACE_TYPE,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

use crate::{absolute, Error, Owner};

/// Windows SIDs never exceed `SECURITY_MAX_SID_SIZE` bytes.
const MAX_SID_BYTES: usize = 68;
/// `SECURITY_INFORMATION` bits requested together for every object check.
const OWNER_AND_DACL: u32 = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
/// Every custody open never follows a reparse point; backup semantics is
/// harmless on files and required to open a directory at all.
const QUERY_FLAGS: u32 = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;

fn last_err() -> Error {
    Error::Io(io::Error::last_os_error())
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(once(0)).collect()
}

/// A handle that closes on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// A `LocalFree` allocation (security descriptor or SID string) freed on drop.
struct OwnedLocal(*mut core::ffi::c_void);

impl Drop for OwnedLocal {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

impl Owner {
    /// This owner as a `PSID` for `EqualSid` and descriptor queries. `Owner`
    /// stores the SID's canonical self-relative bytes, which is what a `PSID`
    /// points at.
    fn as_psid(&self) -> PSID {
        self.sid.as_ptr() as PSID
    }
}

/// Copy a Win32 `PSID` into an owned [`Owner`].
unsafe fn owner_from_sid(sid: PSID) -> Result<Owner, Error> {
    if sid.is_null() || IsValidSid(sid) == 0 {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid owner SID",
        )));
    }
    let len = GetLengthSid(sid) as usize;
    if len == 0 || len > MAX_SID_BYTES {
        return Err(Error::Capacity);
    }
    let mut bytes = [0u8; MAX_SID_BYTES];
    ptr::copy_nonoverlapping(sid as *const u8, bytes.as_mut_ptr(), len);
    Ok(Owner {
        len: len as u8,
        sid: bytes,
    })
}

/// The current process's user SID, as an `Owner`.
pub(crate) fn current_owner() -> Result<Owner, Error> {
    unsafe {
        let mut token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(last_err());
        }
        let token = OwnedHandle(token);
        let mut needed = 0u32;
        let _ = GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed);
        // TOKEN_USER is a pointer-width header plus a SID of at most 68 bytes.
        if needed == 0 || needed as usize > 16 + MAX_SID_BYTES {
            return Err(Error::Capacity);
        }
        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(
            token.0,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
        {
            return Err(last_err());
        }
        let user = buf.as_ptr() as *const TOKEN_USER;
        owner_from_sid((*user).User.Sid)
    }
}

/// A `PSID` rendered as an `S-1-...` string for SDDL construction.
unsafe fn sid_to_string(sid: PSID) -> Result<String, Error> {
    let mut text = ptr::null_mut();
    if ConvertSidToStringSidW(sid, &mut text) == 0 {
        return Err(last_err());
    }
    let text = OwnedLocal(text as _);
    let mut len = 0;
    while *text.0.cast::<u16>().add(len) != 0 {
        len += 1;
    }
    String::from_utf16(std::slice::from_raw_parts(text.0.cast::<u16>(), len))
        .map_err(|_| Error::Corrupt)
}

/// A `SECURITY_ATTRIBUTES` granting a fresh object's owner — the current user —
/// full control and nothing else, with inheritance blocked (`O:SID D:P(ACE)`).
///
/// The owner field is set explicitly so the owner check stays exact even under
/// an elevated token, where Windows can otherwise assign the Administrators
/// group as the default owner. The security descriptor must outlive the create
/// call; it is freed on drop.
struct PrivateAttributes {
    attributes: SECURITY_ATTRIBUTES,
    _descriptor: OwnedLocal,
}

fn private_attributes(owner: &Owner) -> Result<PrivateAttributes, Error> {
    unsafe {
        let sid = sid_to_string(owner.as_psid())?;
        let sddl = format!("O:{sid}D:P(A;;FA;;;{sid})");
        let mut descriptor = ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_string(&sddl).as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        ) == 0
        {
            return Err(last_err());
        }
        Ok(PrivateAttributes {
            attributes: SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            },
            _descriptor: OwnedLocal(descriptor),
        })
    }
}

fn wide_string(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(once(0)).collect()
}

/// Owner and DACL of an object, queried once and freed on drop.
struct Security {
    owner: PSID,
    dacl: *mut ACL,
    _descriptor: OwnedLocal,
}

fn security_of_handle(file: &File) -> Result<Security, Error> {
    unsafe {
        let mut owner = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        let code = GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_AND_DACL,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        );
        if code != 0 {
            return Err(security_err(code));
        }
        Ok(Security {
            owner,
            dacl,
            _descriptor: OwnedLocal(descriptor),
        })
    }
}

/// An object whose security descriptor cannot even be read is not one the
/// caller owns; deny it as unsafe rather than an opaque I/O failure.
fn security_err(code: u32) -> Error {
    if code == ERROR_ACCESS_DENIED {
        Error::UnsafePath
    } else {
        Error::Io(io::Error::from_raw_os_error(code as i32))
    }
}

/// Whether a DACL is exactly one `FILE_ALL_ACCESS` allow ACE for `sid`.
///
/// This is the `0600`/`0700` analogue: the object grants its owner everything
/// and every other principal nothing — a missing or NULL DACL grants everyone
/// and fails, and an extra allow, any deny, or an extra inherited ACE refuses.
unsafe fn owner_only_dacl(dacl: *mut ACL, sid: PSID) -> bool {
    if dacl.is_null() {
        return false;
    }
    let acl = &*dacl;
    if acl.AceCount != 1 {
        return false;
    }
    let mut ace = ptr::null_mut();
    if GetAce(dacl, 0, &mut ace) == 0 || ace.is_null() {
        return false;
    }
    if (*(ace as *const ACE_HEADER)).AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
        return false;
    }
    let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
    allowed.Mask == FILE_ALL_ACCESS && EqualSid(ptr::addr_of!(allowed.SidStart) as PSID, sid) != 0
}

/// The `BY_HANDLE_FILE_INFORMATION` identity of an open handle.
#[derive(PartialEq)]
struct Identity {
    volume: u32,
    index: u64,
}

fn identity(file: &File) -> Result<Identity, Error> {
    let info = handle_info(file)?;
    Ok(Identity {
        volume: info.dwVolumeSerialNumber,
        index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
    })
}

fn handle_info(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION, Error> {
    unsafe {
        let mut info: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        if GetFileInformationByHandle(file.as_raw_handle(), &mut info) == 0 {
            return Err(last_err());
        }
        Ok(info)
    }
}

/// An open handle that never follows a reparse point.
///
/// `FILE_FLAG_BACKUP_SEMANTICS` is harmless on regular files and required on
/// directories, so one flag set serves both the read-only query handle and the
/// returned working handle.
fn query_open(path: &Path, write: bool) -> Result<File, Error> {
    Ok(OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(QUERY_FLAGS)
        .open(path)?)
}

/// Whether `meta` plausibly describes a regular file inside the size bound —
/// the cheap name-side observation that refuses pipes, devices and links
/// before any open, the role `O_NOFOLLOW` pre-checks play on Unix.
fn plausible_file(meta: &Metadata, max_bytes: usize) -> Result<(), Error> {
    if !meta.is_file() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Error::UnsafePath);
    }
    if meta.len() > max_bytes as u64 {
        return Err(Error::Capacity);
    }
    Ok(())
}

/// The full private-regular-file check on an opened handle.
///
/// Checks the opened object is a plain file (no directory, no reparse point),
/// linked exactly once, owned by `owner`, private to `owner` and within
/// `max_bytes` — the same checks Unix `check_regular_file` runs on metadata.
fn check_opened_regular(file: &File, owner: Owner, max_bytes: usize) -> Result<(), Error> {
    let info = handle_info(file)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(Error::UnsafePath);
    }
    let len = ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64;
    if len > max_bytes as u64 {
        return Err(Error::Capacity);
    }
    let security = security_of_handle(file)?;
    if unsafe {
        EqualSid(security.owner, owner.as_psid()) == 0
            || !owner_only_dacl(security.dacl, owner.as_psid())
    } {
        return Err(Error::UnsafePath);
    }
    Ok(())
}

/// The full private-directory check on an opened handle, returning its owner.
///
/// Like Unix `open_private_directory`, the owner is observed and returned for
/// the caller to compare, not required to be the current process; the privacy
/// check is self-referential — the DACL must grant the object's own owner full
/// control and nothing else.
fn check_opened_directory(file: &File) -> Result<Owner, Error> {
    let info = handle_info(file)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(Error::UnsafePath);
    }
    let security = security_of_handle(file)?;
    if unsafe { !owner_only_dacl(security.dacl, security.owner) } {
        return Err(Error::UnsafePath);
    }
    unsafe { owner_from_sid(security.owner) }
}

pub(crate) fn create_private_directory(path: &Path) -> Result<(File, Owner), Error> {
    let path = absolute(path)?;
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
        Ok(_) => {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "private directory already exists",
            )));
        }
    }
    let owner = current_owner()?;
    let attributes = private_attributes(&owner)?;
    let name = wide(&path);
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes.attributes) } == 0 {
        return Err(last_err());
    }
    open_private_directory(&path)
}

pub(crate) fn ensure_private_directory(path: &Path) -> Result<(File, Owner), Error> {
    let path = absolute(path)?;
    if fs::symlink_metadata(&path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
        let owner = current_owner()?;
        let attributes = private_attributes(&owner)?;
        let name = wide(&path);
        if unsafe { CreateDirectoryW(name.as_ptr(), &attributes.attributes) } == 0 {
            return Err(last_err());
        }
    }
    open_private_directory(&path)
}

pub(crate) fn open_private_directory(path: &Path) -> Result<(File, Owner), Error> {
    let path = absolute(path)?;
    let before = fs::symlink_metadata(&path)?;
    if !before.is_dir() || before.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Error::UnsafePath);
    }
    // The name-side observation and the working handle must agree on identity,
    // exactly like the Unix `dev`/`ino` comparison after open.
    let query = query_open(&path, false)?;
    let owner = check_opened_directory(&query)?;
    let file = query_open(&path, true)?;
    if check_opened_directory(&file)? != owner {
        return Err(Error::UnsafePath);
    }
    if identity(&query)? != identity(&file)? {
        return Err(Error::UnsafePath);
    }
    Ok((file, owner))
}

pub(crate) fn create_private_file(path: &Path) -> Result<File, Error> {
    let owner = current_owner()?;
    let attributes = private_attributes(&owner)?;
    let name = wide(path);
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes.attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(last_err());
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

pub(crate) fn open_private_file(
    path: &Path,
    owner: Owner,
    max_bytes: usize,
) -> Result<File, Error> {
    let before = fs::symlink_metadata(path)?;
    plausible_file(&before, max_bytes)?;
    // `query` is the name-side observation: it is opened without following
    // reparse points and fully checked before the working handle is opened.
    let query = query_open(path, false)?;
    check_opened_regular(&query, owner, max_bytes)?;
    let file = query_open(path, true)?;
    check_opened_regular(&file, owner, max_bytes)?;
    if identity(&query)? != identity(&file)? {
        return Err(Error::UnsafePath);
    }
    Ok(file)
}

pub(crate) fn check_regular_file(
    path: &Path,
    meta: &Metadata,
    owner: Owner,
    max_bytes: usize,
) -> Result<(), Error> {
    plausible_file(meta, max_bytes)?;
    // Owner, privacy and link count live behind a handle on Windows; the query
    // open is cheap because the observation is read-only.
    let query = query_open(path, false)?;
    check_opened_regular(&query, owner, max_bytes)
}

pub(crate) fn same_file(path: &Path, file: &File) -> Result<bool, Error> {
    let query = query_open(path, false)?;
    Ok(identity(&query)? == identity(file)?)
}

pub(crate) fn same_open_file(first: &File, second: &File) -> Result<bool, Error> {
    Ok(identity(first)? == identity(second)?)
}

pub(crate) fn private_file_present(
    path: &Path,
    owner: Owner,
    max_bytes: usize,
) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            check_regular_file(path, &meta, owner, max_bytes)?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::Io(e)),
    }
}
