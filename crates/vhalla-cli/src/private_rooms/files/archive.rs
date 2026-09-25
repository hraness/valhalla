//! Bounded file container only. Header selections and length framing are not
//! authenticated authority; the kernel checks every required encrypted page.
use super::*;
use std::{
    fs::File,
    io::{Seek, SeekFrom},
};
use vhalla_private_kernel::{
    recovery::{IMAGE_FRAGMENT_BYTES, MAX_ARCHIVE_PAGE_BYTES},
    Context, MAX_IMAGE_BYTES,
};
use vhalla_private_native::private_rooms::Limits;

const MAGIC: &[u8; 8] = b"VHARCHF1";
const HEADER: usize = 8 + 128 + 32;
const REFUSED: &str = "archive file refused: use an exact complete private .vharchive file within the selected record/byte caps; preserve all evidence";
const FAILED: &str = "archive output failed or may be incomplete; preserve it and the source store; restart export into a NEW private .vharchive path, never overwrite or combine streams";

#[derive(Clone, Copy)]
pub(crate) struct Bounds {
    bytes: usize,
    pages: u64,
}
impl Bounds {
    pub(crate) fn new(limits: Limits) -> Result<Self, String> {
        if !(1..=1_000_000).contains(&limits.max_records)
            || !(40..=8 * 1024 * 1024 * 1024).contains(&limits.max_record_bytes)
        {
            return Err(REFUSED.into());
        }
        // At most one records page per record plus bounded image fragments and
        // one final page. 512/page covers header/AEAD/framing, 41/record covers
        // canonical key and blob lengths. This is a conservative container cap,
        // not a claim that an arbitrary file describes these many records.
        let pages = limits.max_records + MAX_IMAGE_BYTES.div_ceil(IMAGE_FRAGMENT_BYTES) as u64 + 1;
        let bytes = HEADER as u64
            + 4
            + MAX_IMAGE_BYTES as u64
            + limits.max_record_bytes
            + pages * 512
            + limits.max_records * 41;
        Ok(Self {
            bytes: usize::try_from(bytes).map_err(|_| REFUSED)?,
            pages,
        })
    }
}

pub(crate) struct Reader {
    file: File,
    _directory: File,
    context: Context,
    id: [u8; 32],
    size: u64,
    consumed: u64,
    pages: u64,
    bounds: Bounds,
    done: bool,
}
impl Reader {
    pub(crate) fn open(path: &Path, bounds: Bounds) -> Result<Self, String> {
        if path == Path::new("-") {
            return Err(REFUSED.into());
        }
        let path = resolved(path).map_err(|_| REFUSED)?;
        let (directory, owner) =
            custody::open_private_directory(path.parent().ok_or(REFUSED)?).map_err(|_| REFUSED)?;
        let mut file =
            custody::open_private_file(&path, owner, bounds.bytes).map_err(|_| REFUSED)?;
        custody::acquire_shared(&file).map_err(|_| REFUSED)?;
        let size = file.metadata().map_err(|_| REFUSED)?.len();
        let mut header = [0; HEADER];
        file.read_exact(&mut header).map_err(|_| REFUSED)?;
        if &header[..8] != MAGIC {
            return Err(REFUSED.into());
        }
        let context = super::super::context(header[8..136].try_into().map_err(|_| REFUSED)?)?;
        let id = header[136..].try_into().map_err(|_| REFUSED)?;
        if id == [0; 32] {
            return Err(REFUSED.into());
        }
        Ok(Self {
            file,
            _directory: directory,
            context,
            id,
            size,
            consumed: HEADER as u64,
            pages: 0,
            bounds,
            done: false,
        })
    }
    pub(crate) const fn context(&self) -> Context {
        self.context
    }
    pub(crate) const fn archive_id(&self) -> [u8; 32] {
        self.id
    }
    pub(crate) const fn pages(&self) -> u64 {
        self.pages
    }
    pub(crate) fn next_page(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.done {
            return Ok(None);
        }
        let mut raw = [0; 4];
        self.file.read_exact(&mut raw).map_err(|_| REFUSED)?;
        self.consumed = self.consumed.checked_add(4).ok_or(REFUSED)?;
        let length = u32::from_be_bytes(raw) as usize;
        if length == 0 {
            if self.pages < 2
                || self.consumed != self.size
                || self.file.read(&mut [0; 1]).map_err(|_| REFUSED)? != 0
                || self.file.metadata().map_err(|_| REFUSED)?.len() != self.size
            {
                return Err(REFUSED.into());
            }
            self.done = true;
            return Ok(None);
        }
        self.pages = self.pages.checked_add(1).ok_or(REFUSED)?;
        self.consumed = self.consumed.checked_add(length as u64).ok_or(REFUSED)?;
        if length > MAX_ARCHIVE_PAGE_BYTES
            || self.pages > self.bounds.pages
            || self.consumed > self.size
            || self.consumed > self.bounds.bytes as u64
        {
            return Err(REFUSED.into());
        }
        let mut bytes = vec![0; length];
        self.file.read_exact(&mut bytes).map_err(|_| REFUSED)?;
        Ok(Some(bytes))
    }
    /// Structural full stream scan with one page retained. This only locates the
    /// final candidate; ArchiveSession authenticates it against the stored view.
    pub(crate) fn final_page(&mut self) -> Result<Vec<u8>, String> {
        let mut last = None;
        while let Some(page) = self.next_page()? {
            last = Some(page);
        }
        last.ok_or_else(|| REFUSED.into())
    }
}

pub(crate) struct Writer {
    file: File,
    directory: File,
    path: PathBuf,
    owner: Owner,
    bounds: Bounds,
    bytes: u64,
    pages: u64,
}
impl Writer {
    pub(crate) fn create(
        path: &Path,
        bounds: Bounds,
        context: Context,
        id: [u8; 32],
    ) -> Result<Self, String> {
        if path == Path::new("-") || id == [0; 32] {
            return Err(FAILED.into());
        }
        let path = resolved(path).map_err(|_| FAILED)?;
        let (directory, owner) =
            custody::open_private_directory(path.parent().ok_or(FAILED)?).map_err(|_| FAILED)?;
        let file = custody::create_private_file(&path).map_err(|_| FAILED)?;
        custody::acquire_exclusive(&file).map_err(|_| FAILED)?;
        let mut writer = Self {
            file,
            directory,
            path,
            owner,
            bounds,
            bytes: 0,
            pages: 0,
        };
        let mut header = Vec::with_capacity(HEADER);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(context.scope.room.as_bytes());
        header.extend_from_slice(context.scope.anchor.as_bytes());
        header.extend_from_slice(context.account.as_bytes());
        header.extend_from_slice(context.device.as_bytes());
        header.extend_from_slice(&id);
        writer.write_exact(&header)?;
        Ok(writer)
    }
    fn write_exact(&mut self, bytes: &[u8]) -> Result<(), String> {
        let end = self.bytes.checked_add(bytes.len() as u64).ok_or(FAILED)?;
        if end > self.bounds.bytes as u64 {
            return Err(FAILED.into());
        }
        self.file.write_all(bytes).map_err(|_| FAILED)?;
        // Bounded descriptor readback, not a second whole-file allocation.
        self.file
            .seek(SeekFrom::Start(self.bytes))
            .map_err(|_| FAILED)?;
        let mut observed = vec![0; bytes.len()];
        self.file.read_exact(&mut observed).map_err(|_| FAILED)?;
        if observed != bytes {
            return Err(FAILED.into());
        }
        self.bytes = end;
        Ok(())
    }
    pub(crate) fn page(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty()
            || bytes.len() > MAX_ARCHIVE_PAGE_BYTES
            || self.pages >= self.bounds.pages
        {
            return Err(FAILED.into());
        }
        self.write_exact(&(bytes.len() as u32).to_be_bytes())?;
        self.write_exact(bytes)?;
        self.pages += 1;
        Ok(())
    }
    pub(crate) fn finish(mut self) -> Result<(), String> {
        if self.pages < 2 {
            return Err(FAILED.into());
        }
        self.write_exact(&0u32.to_be_bytes())?;
        self.file
            .sync_all()
            .and_then(|_| self.directory.sync_all())
            .map_err(|_| FAILED)?;
        let actual = custody::open_private_file(&self.path, self.owner, self.bounds.bytes)
            .map_err(|_| FAILED)?;
        let after = actual.metadata().map_err(|_| FAILED)?;
        if !custody::same_open_file(&self.file, &actual).map_err(|_| FAILED)?
            || after.len() != self.bytes
        {
            return Err(FAILED.into());
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;
