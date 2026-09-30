//! Historical mutable releases are accepted only by reviewed, fixed byte pins.
//! Nothing in this table grants ownership to a different or newer executable.
use super::{valid_digest, ARCHIVE_LIMIT, BINARY_LIMIT, CHECKSUM_LIMIT, HISTORICAL_RELEASE};
use anyhow::{ensure, Result};
use hraness_cli_update::Product;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Asset {
    id: u64,
    name: String,
    size: usize,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Release {
    tag: String,
    release_id: u64,
    platform: String,
    archive: Asset,
    checksum: Asset,
    binary_size: usize,
    binary_sha256: String,
}

pub(super) fn matches(profile: &Product, hash: &str, size: usize) -> Result<bool> {
    let releases: Vec<Release> = serde_json::from_str(include_str!("legacy-releases.json"))?;
    ensure!(
        !releases.is_empty() && releases.len() <= 8,
        "Historical release pin count"
    );
    let mut matched = false;
    for release in releases {
        let mut target = profile.clone();
        target.platform = release.platform.clone();
        let names = target.asset_names(&release.tag)?;
        ensure!(
            release.tag == HISTORICAL_RELEASE
                && release.release_id > 0
                && release.binary_size > 0
                && release.binary_size <= BINARY_LIMIT
                && valid_digest(&release.binary_sha256)
                && release.archive.id > 0
                && release.archive.name == names[0]
                && release.archive.size > 0
                && release.archive.size <= ARCHIVE_LIMIT
                && valid_digest(&release.archive.sha256)
                && release.checksum.id > 0
                && release.checksum.name == names[1]
                && release.checksum.size > 0
                && release.checksum.size <= CHECKSUM_LIMIT
                && valid_digest(&release.checksum.sha256),
            "Historical release evidence is inconsistent"
        );
        matched |= release.platform == profile.platform
            && release.binary_sha256 == hash
            && release.binary_size == size;
    }
    Ok(matched)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_requires_the_exact_recorded_platform_hash_and_size() {
        let records: Vec<Release> =
            serde_json::from_str(include_str!("legacy-releases.json")).unwrap();
        for record in records {
            let mut profile = crate::self_update::product();
            profile.platform = record.platform;
            assert!(matches(&profile, &record.binary_sha256, record.binary_size).unwrap());
            assert!(!matches(&profile, &"0".repeat(64), record.binary_size).unwrap());
            assert!(!matches(&profile, &record.binary_sha256, record.binary_size + 1).unwrap());
            profile.platform = "unknown-platform".into();
            assert!(!matches(&profile, &record.binary_sha256, record.binary_size).unwrap());
        }
    }
}
