//! Immutable generation records become visible only after a complete write.
//! Callers hold the host maintenance lock throughout publication/recovery.
use super::{config, custody, TRANSITION_ERROR};
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

pub(super) fn publish(home: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    publish_with(home, name, bytes, |_| Ok(()))
}

fn publish_with(
    home: &Path,
    name: &str,
    bytes: &[u8],
    mut after: impl FnMut(&str) -> Result<(), String>,
) -> Result<(), String> {
    if bytes.is_empty()
        || bytes.len() > 65536
        || name.is_empty()
        || name.contains(['/', '\\'])
        || name.starts_with('.')
    {
        return Err(TRANSITION_ERROR.into());
    }
    let (directory, uid) = custody::open_private_directory(home).map_err(|_| TRANSITION_ERROR)?;
    if uid != rustix::process::geteuid().as_raw() {
        return Err(TRANSITION_ERROR.into());
    }
    let path = home.join(name);
    // Neither a torn final record nor different complete bytes are replaced.
    if custody::private_file_present(&path, uid, 65536).map_err(|_| TRANSITION_ERROR)? {
        return if config::read(home, name, 65536)?.as_slice() == bytes {
            directory.sync_all().map_err(|_| TRANSITION_ERROR.into())
        } else {
            Err(TRANSITION_ERROR.into())
        };
    }
    let prefix = format!("{name}.publish-");
    let staged_name = format!("{prefix}{}", config::digest(bytes));
    // The full digest in the filename binds even an empty interrupted write.
    // A different retained attempt is evidence, not scratch to be discarded.
    for entry in fs::read_dir(home).map_err(|_| TRANSITION_ERROR)? {
        let entry = entry.map_err(|_| TRANSITION_ERROR)?;
        let candidate = entry.file_name();
        let candidate = candidate.to_str().ok_or(TRANSITION_ERROR)?;
        if candidate.starts_with(&prefix) && candidate != staged_name {
            return Err(TRANSITION_ERROR.into());
        }
    }
    let staged = home.join(&staged_name);
    let mut file =
        if custody::private_file_present(&staged, uid, 65536).map_err(|_| TRANSITION_ERROR)? {
            custody::open_private_file(&staged, uid, 65536).map_err(|_| TRANSITION_ERROR)?
        } else {
            let file = custody::create_private_file(&staged).map_err(|_| TRANSITION_ERROR)?;
            directory.sync_all().map_err(|_| TRANSITION_ERROR)?;
            file
        };
    after("staging-created")?;
    let retained = config::read(home, &staged_name, 65536)?;
    if !bytes.starts_with(&retained) {
        return Err(TRANSITION_ERROR.into());
    }
    file.seek(SeekFrom::Start(retained.len() as u64))
        .map_err(|_| TRANSITION_ERROR)?;
    let split = retained.len().max(bytes.len() / 2);
    file.write_all(&bytes[retained.len()..split])
        .map_err(|_| TRANSITION_ERROR)?;
    after("staging-prefix-written")?;
    file.write_all(&bytes[split..])
        .map_err(|_| TRANSITION_ERROR)?;
    after("staging-written")?;
    file.sync_all().map_err(|_| TRANSITION_ERROR)?;
    after("staging-synced")?;
    if config::read(home, &staged_name, 65536)?.as_slice() != bytes {
        return Err(TRANSITION_ERROR.into());
    }
    let named = fs::symlink_metadata(&staged).map_err(|_| TRANSITION_ERROR)?;
    let held = file.metadata().map_err(|_| TRANSITION_ERROR)?;
    custody::check_regular_file(&named, uid, 65536).map_err(|_| TRANSITION_ERROR)?;
    if named.dev() != held.dev()
        || named.ino() != held.ino()
        || custody::private_file_present(&path, uid, 65536).map_err(|_| TRANSITION_ERROR)?
    {
        return Err(TRANSITION_ERROR.into());
    }
    // Cooperating publishers are excluded by maintenance.lock. Rename publishes
    // all bytes at once; restart sees either the exact staging file or final.
    fs::rename(&staged, &path).map_err(|_| TRANSITION_ERROR)?;
    after("record-published")?;
    directory.sync_all().map_err(|_| TRANSITION_ERROR)?;
    after("directory-synced")?;
    if config::read(home, name, 65536)?.as_slice() != bytes {
        return Err(TRANSITION_ERROR.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};

    struct Home(PathBuf);
    impl Home {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "vhalla-generation-publication-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            custody::create_private_directory(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn every_publication_boundary_resumes_exact_bytes_without_torn_selection() {
        let bytes = b"complete immutable private transition record";
        for boundary in [
            "staging-created",
            "staging-prefix-written",
            "staging-written",
            "staging-synced",
            "record-published",
            "directory-synced",
        ] {
            let home = Home::new();
            let _guard = config::maintenance_lock(&home.0).unwrap();
            assert!(publish_with(&home.0, "generation.pending", bytes, |step| {
                if step == boundary {
                    Err("injected interruption".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
            if home.0.join("generation.pending").exists() {
                assert_eq!(fs::read(home.0.join("generation.pending")).unwrap(), bytes);
            }
            publish(&home.0, "generation.pending", bytes).unwrap();
            publish(&home.0, "generation.pending", bytes).unwrap();
            assert_eq!(fs::read(home.0.join("generation.pending")).unwrap(), bytes);
            assert_eq!(fs::read_dir(&home.0).unwrap().count(), 2);
            assert_eq!(
                fs::metadata(home.0.join("generation.pending"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn incomplete_staging_refuses_substitution_tampering_and_unsafe_files() {
        let bytes = b"complete immutable private transition record";
        for kind in 0..4 {
            let home = Home::new();
            let _guard = config::maintenance_lock(&home.0).unwrap();
            let stage = format!("generation.pending.publish-{}", config::digest(bytes));
            match kind {
                0 => config::write(&home.0, &stage, b"").unwrap(),
                1 => config::write(&home.0, &stage, b"conflicting prefix").unwrap(),
                2 => {
                    config::write(&home.0, "other", b"private original").unwrap();
                    std::os::unix::fs::symlink(home.0.join("other"), home.0.join(&stage)).unwrap();
                }
                _ => {
                    config::write(&home.0, &stage, b"").unwrap();
                    fs::set_permissions(home.0.join(&stage), fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
            }
            let original = fs::read(home.0.join(&stage)).unwrap();
            let proposed: &[u8] = if kind == 0 {
                b"different record"
            } else {
                bytes
            };
            assert!(publish(&home.0, "generation.pending", proposed).is_err());
            assert_eq!(fs::read(home.0.join(&stage)).unwrap(), original);
            assert!(!home.0.join("generation.pending").exists());
        }
    }

    #[test]
    fn an_existing_final_record_is_never_completed_or_replaced() {
        let home = Home::new();
        let _guard = config::maintenance_lock(&home.0).unwrap();
        config::write(&home.0, "generation.pending", b"retained prefix").unwrap();
        assert!(publish(&home.0, "generation.pending", b"retained prefix and suffix").is_err());
        assert_eq!(
            fs::read(home.0.join("generation.pending")).unwrap(),
            b"retained prefix"
        );
    }
}
