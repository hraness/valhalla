//! Bounded owner-private lifecycle log shared by the host and the gateway.
//!
//! Every entry is a single small JSON line with a timestamp, a fixed event
//! name and numeric or fixed-string fields. By construction this module never
//! writes tokens, keys, message bodies, peer payloads or free-form errors;
//! field values are bounded printable ASCII supplied by the caller's own
//! lifecycle code. Rotation keeps at most one earlier generation.
use super::launchd::LOG_NAME;
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    path::Path,
};
use vhalla_custody as custody;

const ROTATED: &str = "events.log.1";
/// Total live log bound; one rotated generation is kept alongside it.
const LIMIT: u64 = 256 * 1024;
const LINE_MAX: usize = 512;
const REFUSED: &str = "event log refused; preserve the owner-private home";

fn owner(dir: &Path) -> Result<(fs::File, u32), String> {
    let (directory, uid) = custody::open_private_directory(dir).map_err(|_| REFUSED)?;
    if uid != rustix::process::geteuid().as_raw() {
        return Err(REFUSED.into());
    }
    Ok((directory, uid))
}
fn clean(value: &str, limit: usize) -> Result<&str, String> {
    if value.is_empty()
        || value.len() > limit
        || !value
            .bytes()
            .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
    {
        return Err(REFUSED.into());
    }
    Ok(value)
}
/// Append one bounded lifecycle line, rotating a full log to a single earlier
/// generation first. Callers pass only fixed names and numeric/fixed values.
pub(crate) fn append(dir: &Path, event: &str, fields: &[(&str, &str)]) -> Result<(), String> {
    let mut line = format!(
        "{{\"at\":{},\"event\":\"{}\"",
        time::OffsetDateTime::now_utc().unix_timestamp(),
        clean(event, 32)?
    );
    for (key, value) in fields {
        line.push_str(&format!(
            ",\"{}\":\"{}\"",
            clean(key, 24)?,
            clean(value, 96)?
        ));
    }
    line.push_str("}\n");
    if line.len() > LINE_MAX {
        return Err(REFUSED.into());
    }
    let (directory, uid) = owner(dir)?;
    let path = dir.join(LOG_NAME);
    let rotated = dir.join(ROTATED);
    if custody::private_file_present(&path, uid, LIMIT as usize).map_err(|_| REFUSED)? {
        let meta = fs::metadata(&path).map_err(|_| REFUSED)?;
        if meta.len() + line.len() as u64 > LIMIT {
            match fs::remove_file(&rotated) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(REFUSED.into()),
            }
            fs::rename(&path, &rotated).map_err(|_| REFUSED)?;
        }
    }
    let mut file =
        if custody::private_file_present(&path, uid, LIMIT as usize).map_err(|_| REFUSED)? {
            custody::open_private_file(&path, uid, LIMIT as usize).map_err(|_| REFUSED)?
        } else {
            custody::create_private_file(&path).map_err(|_| REFUSED)?
        };
    file.seek(SeekFrom::End(0)).map_err(|_| REFUSED)?;
    file.write_all(line.as_bytes())
        .and_then(|()| file.sync_data())
        .and_then(|()| directory.sync_all())
        .map_err(|_| REFUSED.to_owned())
}
/// Most recent complete lines, oldest first, for operator inspection. A torn
/// or oversized log refuses rather than guessing; missing logs are empty.
pub(crate) fn tail(dir: &Path, lines: usize) -> Result<Vec<String>, String> {
    let (_directory, uid) = owner(dir)?;
    let path = dir.join(LOG_NAME);
    if !custody::private_file_present(&path, uid, LIMIT as usize).map_err(|_| REFUSED)? {
        return Ok(Vec::new());
    }
    let bytes = custody::read_private_file(&path, uid, LIMIT as usize).map_err(|_| REFUSED)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| REFUSED)?;
    if !text.is_ascii() {
        return Err(REFUSED.into());
    }
    let mut entries: Vec<String> = text
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    if entries.len() > lines {
        entries.drain(..entries.len() - lines);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    #[test]
    fn log_is_private_bounded_rotated_and_never_records_secrets() {
        let dir = std::env::temp_dir().join(format!(
            "vhalla-events-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        append(
            &dir,
            "serve-start",
            &[("listen", "127.0.0.1:1"), ("attempt", "3")],
        )
        .unwrap();
        append(&dir, "listening", &[]).unwrap();
        let path = dir.join(LOG_NAME);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        let entries = tail(&dir, 10).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].contains("\"event\":\"serve-start\""));
        assert!(entries[1].contains("\"event\":\"listening\""));
        assert!(append(&dir, "bad\nname", &[]).is_err());
        assert!(append(&dir, "x", &[("k", &"v".repeat(200))]).is_err());
        // Fill the log near the limit directly; the next bounded append must
        // rotate exactly one earlier generation rather than grow forever.
        fs::write(&path, "x".repeat(LIMIT as usize - 1024)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        for index in 0..40 {
            append(&dir, "tick", &[("n", &index.to_string())]).unwrap();
        }
        assert!(fs::metadata(&path).unwrap().len() <= LIMIT);
        assert_eq!(
            fs::metadata(dir.join(ROTATED)).unwrap().mode() & 0o7777,
            0o600
        );
        assert!(fs::metadata(dir.join(ROTATED)).unwrap().len() <= LIMIT);
        let tail_entries = tail(&dir, 5).unwrap();
        assert_eq!(tail_entries.len(), 5);
        assert!(tail_entries[4].contains("\"event\":\"tick\""));
        // A foreign log is refused, never repaired or appended to.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(append(&dir, "x", &[]).is_err());
        assert!(tail(&dir, 1).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
