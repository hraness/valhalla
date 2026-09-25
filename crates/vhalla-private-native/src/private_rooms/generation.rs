use super::*;

const DIRECTORY: &str = "delivery-generations";
const MAX_GENERATIONS: u64 = 16;
const MAX_RECEIPT: usize = 650;
const SELECT_MAGIC: &[u8; 9] = b"VHCDSELE\x01";

pub(super) fn inventory(path: &Path, uid: u32) -> Result<()> {
    custody::open_private_directory(path).map_err(|_| Error::Corrupt)?;
    let mut count = 0;
    for entry in fs::read_dir(path).map_err(|_| Error::Corrupt)? {
        count += 1;
        if count > MAX_GENERATIONS * 2 {
            return Err(Error::Corrupt);
        }
        let entry = entry.map_err(|_| Error::Corrupt)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(Error::Corrupt)?;
        let (ordinal, suffix) = name.split_once('.').ok_or(Error::Corrupt)?;
        let generation = ordinal.parse::<u64>().map_err(|_| Error::Corrupt)?;
        if ordinal != format!("{generation:02}")
            || generation >= MAX_GENERATIONS
            || !["pause", "selected"].contains(&suffix)
        {
            return Err(Error::Corrupt);
        }
        custody::open_private_file(&entry.path(), uid, MAX_RECEIPT).map_err(|_| Error::Corrupt)?;
    }
    Ok(())
}

fn receipt_commitment(raw: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"vhalla/private/controller-pause-receipt/v1\0");
    hash.update(raw);
    hash.finalize().into()
}
fn valid_receipt(raw: &[u8], generation: u64) -> bool {
    matches!(raw.len(), 546 | 650)
        && &raw[..9] == b"VHCDRAIN\x01"
        && raw[233..241] == generation.to_be_bytes()
}

impl NativePrivateStore {
    fn generation_directory(&self) -> Result<Option<PathBuf>> {
        let path = self.path.join(DIRECTORY);
        match path.symlink_metadata() {
            Ok(_) => {
                inventory(&path, self.uid)?;
                Ok(Some(path))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::Corrupt),
        }
    }

    /// Whether a retained maintenance record prevents new kernel publication.
    /// Empty or interrupted maintenance also pauses; absence alone means legacy.
    pub fn delivery_is_paused(&self) -> Result<bool> {
        let Some(path) = self.generation_directory()? else {
            return Ok(false);
        };
        let mut previous_selected = false;
        for generation in 0..MAX_GENERATIONS {
            let pause_path = path.join(format!("{generation:02}.pause"));
            let selected_path = path.join(format!("{generation:02}.selected"));
            if !custody::private_file_present(&pause_path, self.uid, MAX_RECEIPT)
                .map_err(|_| Error::Corrupt)?
            {
                // A later generation without its predecessors is corruption.
                for entry in fs::read_dir(&path).map_err(|_| Error::Corrupt)? {
                    let entry = entry.map_err(|_| Error::Corrupt)?;
                    let name = entry.file_name();
                    let name = name.to_str().ok_or(Error::Corrupt)?;
                    let ordinal = name
                        .split_once('.')
                        .ok_or(Error::Corrupt)?
                        .0
                        .parse::<u64>()
                        .map_err(|_| Error::Corrupt)?;
                    if ordinal >= generation {
                        return Err(Error::Corrupt);
                    }
                }
                return Ok(!previous_selected);
            }
            let raw = custody::read_private_file(&pause_path, self.uid, MAX_RECEIPT)
                .map_err(|_| Error::Corrupt)?;
            if !valid_receipt(&raw, generation) {
                return Ok(true);
            }
            if !custody::private_file_present(&selected_path, self.uid, MAX_RECEIPT)
                .map_err(|_| Error::Corrupt)?
            {
                return Ok(true);
            }
            let selected = custody::read_private_file(&selected_path, self.uid, MAX_RECEIPT)
                .map_err(|_| Error::Corrupt)?;
            if selected.len() != 73
                || &selected[..9] != SELECT_MAGIC
                || selected[9..41] != receipt_commitment(&raw)
                || selected[41..] == [0; 32]
            {
                return Ok(true);
            }
            previous_selected = true;
        }
        Ok(false)
    }

    /// Retain exact private pause evidence while this store still owns custody.
    /// The image must be the kernel-authenticated image inspected by the caller.
    /// A partial exact write can finish; changed evidence never replaces it.
    pub fn pause_delivery(
        &mut self,
        context: Context,
        generation: u64,
        image_commitment: [u8; 32],
        receipt: &[u8],
    ) -> Result<()> {
        self.ready(context)?;
        if generation >= MAX_GENERATIONS - 1 || !valid_receipt(receipt, generation) {
            return Err(Error::Refused);
        }
        let image = self.meta()?.image.ok_or(Error::Refused)?;
        if <[u8; 32]>::from(Sha256::digest(&image)) != image_commitment {
            return Err(Error::Conflict);
        }
        let path = self.path.join(DIRECTORY);
        if self.generation_directory()?.is_none() {
            if generation != 0 {
                return Err(Error::Refused);
            }
            self.poisoned = true;
            custody::create_private_directory(&path).map_err(|_| Error::Uncertain)?;
            self.directory.sync_all().map_err(|_| Error::Uncertain)?;
            self.poisoned = false;
        }
        // All previous transitions must already be selected; no skipped lineage.
        for previous in 0..generation {
            let old = custody::read_private_file(
                &path.join(format!("{previous:02}.pause")),
                self.uid,
                MAX_RECEIPT,
            )
            .map_err(|_| Error::Refused)?;
            let selected = custody::read_private_file(
                &path.join(format!("{previous:02}.selected")),
                self.uid,
                MAX_RECEIPT,
            )
            .map_err(|_| Error::Refused)?;
            if !valid_receipt(&old, previous)
                || selected.len() != 73
                || &selected[..9] != SELECT_MAGIC
                || selected[9..41] != receipt_commitment(&old)
            {
                return Err(Error::Refused);
            }
        }
        if custody::private_file_present(
            &path.join(format!("{generation:02}.selected")),
            self.uid,
            MAX_RECEIPT,
        )
        .map_err(|_| Error::Refused)?
        {
            return Err(Error::Refused);
        }
        self.append_exact(&path, &format!("{generation:02}.pause"), receipt)
    }

    /// Finish only the exact paused generation after the caller has durably
    /// published its independently validated successor selector. No unpause API.
    pub fn select_delivery_successor(
        &mut self,
        context: Context,
        generation: u64,
        receipt: &[u8],
        successor_binding: [u8; 32],
    ) -> Result<()> {
        self.ready(context)?;
        if !valid_receipt(receipt, generation)
            || generation >= MAX_GENERATIONS - 1
            || successor_binding == [0; 32]
        {
            return Err(Error::Refused);
        }
        let path = self.generation_directory()?.ok_or(Error::Refused)?;
        let stored = custody::read_private_file(
            &path.join(format!("{generation:02}.pause")),
            self.uid,
            MAX_RECEIPT,
        )
        .map_err(|_| Error::Refused)?;
        if stored != receipt {
            return Err(Error::Conflict);
        }
        let mut selected = SELECT_MAGIC.to_vec();
        selected.extend(receipt_commitment(receipt));
        selected.extend(successor_binding);
        self.append_exact(&path, &format!("{generation:02}.selected"), &selected)
    }

    fn append_exact(&mut self, directory: &Path, name: &str, expected: &[u8]) -> Result<()> {
        use std::io::{Seek, SeekFrom};
        let target = directory.join(name);
        let present = custody::private_file_present(&target, self.uid, MAX_RECEIPT)
            .map_err(|_| Error::Corrupt)?;
        let prior = if present {
            custody::read_private_file(&target, self.uid, MAX_RECEIPT)
                .map_err(|_| Error::Corrupt)?
        } else {
            Vec::new()
        };
        if !expected.starts_with(&prior) {
            return Err(Error::Conflict);
        }
        self.poisoned = true;
        let mut file = if present {
            custody::open_private_file(&target, self.uid, MAX_RECEIPT)
        } else {
            custody::create_private_file(&target)
        }
        .map_err(|_| Error::Uncertain)?;
        file.seek(SeekFrom::End(0))
            .and_then(|_| file.write_all(&expected[prior.len()..]))
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::Uncertain)?;
        File::open(directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Uncertain)?;
        if custody::read_private_file(&target, self.uid, MAX_RECEIPT)
            .map_err(|_| Error::Uncertain)?
            != expected
        {
            return Err(Error::Uncertain);
        }
        self.poisoned = false;
        Ok(())
    }
}
