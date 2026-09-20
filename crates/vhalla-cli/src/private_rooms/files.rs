use std::{
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
};
use vhalla_custody as custody;
use zeroize::Zeroizing;

const OUTPUT_LIMIT: usize = 1024 * 1024;
const OUTPUT_ERROR: &str = "private output failed or may be incomplete; preserve every file and the original store, reopen exact custody, then retry the same operation/inputs into a NEW output path or export its retained ciphertext; never reset or regenerate a device";

fn resolved(path: &Path) -> Result<PathBuf, String> {
    let absolute = custody::absolute(path).map_err(|_| "invalid private file path")?;
    let parent = absolute
        .parent()
        .ok_or("private file parent required")?
        .canonicalize()
        .map_err(|_| "private file parent unavailable")?;
    let name = absolute.file_name().ok_or("private file name required")?;
    Ok(parent.join(name))
}
pub(super) fn read(
    path: &Path,
    limit: usize,
    allow_stdin: bool,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    if path == Path::new("-") {
        if !allow_stdin || std::io::stdin().is_terminal() {
            return Err("use a bounded input pipe or owner-private 0600 file; interactive secret input is refused".into());
        }
        std::io::stdin()
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "private input read failed")?;
    } else {
        let path = resolved(path)?;
        let (_directory, uid) =
            custody::open_private_directory(path.parent().ok_or("missing private parent")?)
                .map_err(|_| "input parent must be owner-private 0700")?;
        let mut file = custody::open_private_file(&path, uid, limit)
            .map_err(|_| "input must be bounded, regular, owner-private 0600 and not linked")?;
        let size = usize::try_from(
            file.metadata()
                .map_err(|_| "private input metadata failed")?
                .len(),
        )
        .map_err(|_| "private input too large")?;
        if size > limit {
            return Err("private input too large".into());
        }
        bytes.resize(size, 0);
        file.read_exact(&mut bytes)
            .map_err(|_| "private input changed or read failed")?;
        if file
            .read(&mut [0; 1])
            .map_err(|_| "private input changed")?
            != 0
        {
            return Err("private input grew during read".into());
        }
    }
    if bytes.len() > limit {
        return Err("private input exceeds fixed byte bound".into());
    }
    Ok(bytes)
}
pub(super) fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path == Path::new("-") || bytes.len() > OUTPUT_LIMIT {
        return Err(OUTPUT_ERROR.into());
    }
    let path = resolved(path).map_err(|_| OUTPUT_ERROR)?;
    let (directory, uid) = custody::open_private_directory(path.parent().ok_or(OUTPUT_ERROR)?)
        .map_err(|_| OUTPUT_ERROR)?;
    // Output is a recoverable copy, never state authority. A failed prefix is
    // preserved; exact kernel evidence supports retry to a fresh output path.
    let mut file = custody::create_private_file(&path).map_err(|_| OUTPUT_ERROR)?;
    custody::check_regular_file(
        &file.metadata().map_err(|_| OUTPUT_ERROR)?,
        uid,
        OUTPUT_LIMIT,
    )
    .map_err(|_| OUTPUT_ERROR)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .and_then(|_| directory.sync_all())
        .map_err(|_| OUTPUT_ERROR)?;
    // Ensure the selected name still denotes our just-published regular file.
    let actual = read(&path, OUTPUT_LIMIT, false).map_err(|_| OUTPUT_ERROR)?;
    if actual.as_slice() != bytes {
        return Err(OUTPUT_ERROR.into());
    }
    Ok(())
}
