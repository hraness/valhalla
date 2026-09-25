//! Bounded owner-private lifecycle log shared by the host and the gateway.
//!
//! Every entry is a single small JSON line with a timestamp, a fixed event
//! name and numeric or fixed-string fields. By construction this module never
//! writes tokens, keys, message bodies, peer payloads or free-form errors;
//! field values are bounded printable ASCII supplied by the caller's own
//! lifecycle code. Rotation keeps at most one earlier generation.
use super::launchd::{LOG_NAME, SUPERVISOR_LOG_NAME};
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    path::Path,
};
use vhalla_custody::{self as custody, Owner};

const ROTATED: &str = "events.log.1";
/// Total live log bound; one rotated generation is kept alongside it.
const LIMIT: u64 = 256 * 1024;
const SUPERVISOR_ROTATED: &str = "supervisor.log.1";
/// Live supervisor output bound; one rotated generation is kept alongside it.
const SUPERVISOR_LIMIT: u64 = 256 * 1024;
const LINE_MAX: usize = 512;
const REFUSED: &str = "event log refused; preserve the owner-private home";

fn owner(dir: &Path) -> Result<(fs::File, Owner), String> {
    let (directory, owner) = custody::open_private_directory(dir).map_err(|_| REFUSED)?;
    if owner != Owner::current().map_err(|_| REFUSED)? {
        return Err(REFUSED.into());
    }
    Ok((directory, owner))
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
    let (directory, owner) = owner(dir)?;
    let path = dir.join(LOG_NAME);
    // A live log that another writer pushed past its bound (an earlier agent
    // shape redirected launchd output here) is still owner-private evidence:
    // rotate it into the single earlier generation instead of refusing every
    // later append, which would otherwise turn each restart into a crash loop.
    if let Some(len) = private_length(&path, owner, LIMIT)? {
        if len + line.len() as u64 > LIMIT {
            rotate(&path, &dir.join(ROTATED))?;
        }
    }
    let mut file =
        if custody::private_file_present(&path, owner, LIMIT as usize).map_err(|_| REFUSED)? {
            custody::open_private_file(&path, owner, LIMIT as usize).map_err(|_| REFUSED)?
        } else {
            custody::create_private_file(&path).map_err(|_| REFUSED)?
        };
    file.seek(SeekFrom::End(0)).map_err(|_| REFUSED)?;
    file.write_all(line.as_bytes())
        .and_then(|()| file.sync_data())
        .and_then(|()| directory.sync_all())
        .map_err(|_| REFUSED.to_owned())
}
/// Length of the owner-private regular file at `path`, `None` when absent. A
/// foreign type, link, owner or mode refuses; exceeding `limit` does not,
/// because callers rotate oversized evidence rather than discarding it.
fn private_length(path: &Path, owner: Owner, limit: u64) -> Result<Option<u64>, String> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(REFUSED.into()),
    };
    match custody::check_regular_file(path, &meta, owner, limit as usize) {
        Ok(()) | Err(custody::Error::Capacity) => Ok(Some(meta.len())),
        Err(_) => Err(REFUSED.into()),
    }
}
/// Keep exactly one earlier generation: any previous one is replaced.
fn rotate(path: &Path, rotated: &Path) -> Result<(), String> {
    match fs::remove_file(rotated) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(REFUSED.into()),
    }
    fs::rename(path, rotated).map_err(|_| REFUSED.into())
}
/// Rotate launchd's supervisor output once it exceeds its bound. Services call
/// this at startup before their first structured event. The file launchd
/// opened for this launch keeps receiving this process's output under the
/// rotated name; an empty owner-private live file is created in its place so
/// the reported path exists, and launchd appends to it from the next launch.
/// A rotation is recorded as an event; a foreign file at that name is left
/// untouched and recorded as refused. This cannot refuse startup: it returns
/// nothing, so no caller can turn its outcome into a failed start.
pub(crate) fn bound_supervisor_output(dir: &Path) {
    let outcome: Result<Option<u64>, String> = (|| {
        let (directory, owner) = owner(dir)?;
        let path = dir.join(SUPERVISOR_LOG_NAME);
        match private_length(&path, owner, SUPERVISOR_LIMIT)? {
            Some(len) if len > SUPERVISOR_LIMIT => {
                rotate(&path, &dir.join(SUPERVISOR_ROTATED))?;
                custody::create_private_file(&path).map_err(|_| REFUSED)?;
                directory.sync_all().map_err(|_| REFUSED)?;
                Ok(Some(len))
            }
            _ => Ok(None),
        }
    })();
    let _ = match outcome {
        Ok(Some(len)) => append(
            dir,
            "supervisor-log-rotated",
            &[("bytes", &len.to_string())],
        ),
        Ok(None) => Ok(()),
        Err(_) => append(dir, "supervisor-log-refused", &[]),
    };
}
/// Most recent complete lines, oldest first, for operator inspection. A torn
/// or oversized log refuses rather than guessing; missing logs are empty.
pub(crate) fn tail(dir: &Path, lines: usize) -> Result<Vec<String>, String> {
    let (_directory, owner) = owner(dir)?;
    let path = dir.join(LOG_NAME);
    if !custody::private_file_present(&path, owner, LIMIT as usize).map_err(|_| REFUSED)? {
        return Ok(Vec::new());
    }
    let bytes = custody::read_private_file(&path, owner, LIMIT as usize).map_err(|_| REFUSED)?;
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
    fn private_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vhalla-events-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        dir
    }
    fn write_owned(path: &Path, bytes: usize, byte: u8, mode: u32) {
        fs::write(path, vec![byte; bytes]).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    #[test]
    fn oversized_live_log_rotates_into_the_earlier_generation_instead_of_refusing() {
        let dir = private_dir("oversized");
        let path = dir.join(LOG_NAME);
        // An earlier agent shape let launchd push supervisor output past the
        // bound. Every later append used to refuse, so each restart failed.
        write_owned(&path, LIMIT as usize + 4096, b'x', 0o600);
        append(&dir, "serve-start", &[("listen", "127.0.0.1:1")]).unwrap();
        assert_eq!(
            fs::metadata(dir.join(ROTATED)).unwrap().len(),
            LIMIT + 4096,
            "oversized evidence is retained as the earlier generation"
        );
        assert!(fs::metadata(&path).unwrap().len() < LINE_MAX as u64);
        let entries = tail(&dir, 5).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].contains("\"event\":\"serve-start\""));
        // A foreign oversized file is still refused and never touched.
        write_owned(&path, LIMIT as usize + 1, b'y', 0o644);
        assert!(append(&dir, "x", &[]).is_err());
        assert_eq!(fs::metadata(&path).unwrap().len(), LIMIT + 1);
        assert_eq!(fs::metadata(dir.join(ROTATED)).unwrap().len(), LIMIT + 4096);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn supervisor_output_rotates_only_when_owned_and_oversized_and_never_fails() {
        let dir = private_dir("supervisor");
        let path = dir.join(SUPERVISOR_LOG_NAME);
        let rotated = dir.join(SUPERVISOR_ROTATED);
        // The function has no failure path at all: absent, bounded, oversized
        // and foreign inputs all return, and only the event log tells them apart.
        let _: () = bound_supervisor_output(&dir);
        assert!(
            tail(&dir, 5).unwrap().is_empty(),
            "absent output records nothing"
        );
        write_owned(&path, 5, b's', 0o600);
        bound_supervisor_output(&dir);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            5,
            "bounded output is untouched"
        );
        assert!(!rotated.exists());
        write_owned(&rotated, 3, b'o', 0o600);
        write_owned(&path, SUPERVISOR_LIMIT as usize + 1, b'z', 0o600);
        bound_supervisor_output(&dir);
        let live = fs::metadata(&path).unwrap();
        assert_eq!(
            live.len(),
            0,
            "an empty owner-private live file replaces the rotated one"
        );
        assert_eq!(live.mode() & 0o7777, 0o600);
        assert_eq!(fs::metadata(&rotated).unwrap().len(), SUPERVISOR_LIMIT + 1);
        let entries = tail(&dir, 5).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].contains("\"event\":\"supervisor-log-rotated\""));
        assert!(entries[0].contains(&format!("\"bytes\":\"{}\"", SUPERVISOR_LIMIT + 1)));
        // A foreign file at that name is refused, recorded and left untouched.
        fs::remove_file(&path).unwrap();
        write_owned(&path, SUPERVISOR_LIMIT as usize + 1, b'w', 0o644);
        bound_supervisor_output(&dir);
        assert_eq!(fs::metadata(&path).unwrap().len(), SUPERVISOR_LIMIT + 1);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o644);
        assert_eq!(fs::metadata(&rotated).unwrap().len(), SUPERVISOR_LIMIT + 1);
        assert!(tail(&dir, 1).unwrap()[0].contains("\"event\":\"supervisor-log-refused\""));
        // A foreign home refuses without touching anything and without panicking.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
        bound_supervisor_output(&dir);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
