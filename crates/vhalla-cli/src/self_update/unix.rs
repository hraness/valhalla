//! Valhalla's native transaction preserves its release archive and Apple
//! signature contract. Only this process writes installed files or receipts.
use super::{paths, product, released_tag, InitialInstall};
use anyhow::{bail, ensure, Context, Result};
use hraness_cli_update::{
    run_bounded, Asset, CurlGithub, InstallReceipt, InstallRequest, InstallationKind, Installer,
    Product, Release,
};
use serde::Deserialize;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

#[path = "unix/files.rs"]
mod files;
#[path = "unix/legacy.rs"]
mod legacy;
use files::{digest, read_path, Directory, Stage};

#[cfg(target_os = "macos")]
const MACOS_REQUIREMENT: &str = "=anchor apple generic and identifier \"dev.hraness.vhalla\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"8AAP53VTW3\"";

const ARCHIVE_LIMIT: usize = 128 * 1024 * 1024;
const BINARY_LIMIT: usize = 256 * 1024 * 1024;
const CHECKSUM_LIMIT: usize = 1024;
const RECEIPT_LIMIT: usize = 64 * 1024;
// The last release before installer ownership receipts. Compare verified bytes,
// never execute an unknown installed binary to discover its claimed version.
const HISTORICAL_RELEASE: &str = "v0.2.10";
const LEGACY_RELEASE: &str = "v0.2.11";

pub(super) struct NativeInstaller;

impl Installer for NativeInstaller {
    fn install(&self, request: &InstallRequest<'_>) -> hraness_cli_update::Result<()> {
        install_update(request).map_err(|error| {
            hraness_cli_update::Error::new(
                hraness_cli_update::ErrorCode::Installer,
                format!("{error:#}"),
            )
        })
    }
}

struct Published {
    release: Release,
    archive: Asset,
    checksum: Asset,
    archive_sha256: String,
    checksum_sha256: String,
}

#[derive(Deserialize)]
struct AssetDigest {
    id: u64,
    name: String,
    digest: Option<String>,
}

#[derive(Deserialize)]
struct DigestList {
    assets: Vec<AssetDigest>,
}

impl Published {
    fn parse(profile: &Product, expected_tag: &str, bytes: &[u8]) -> Result<Self> {
        let release: Release =
            serde_json::from_slice(bytes).context("Read canonical release metadata")?;
        release.validate(profile)?;
        ensure!(
            release.tag_name == expected_tag,
            "Canonical release tag differs from the requested version"
        );
        let raw: DigestList = serde_json::from_slice(bytes)?;
        let names = profile.asset_names(expected_tag)?;
        ensure!(
            names.len() == 2,
            "Valhalla requires an archive and checksum"
        );
        let archive = release
            .asset(&names[0])
            .context("Missing release archive")?
            .clone();
        let checksum = release
            .asset(&names[1])
            .context("Missing release checksum")?
            .clone();
        ensure!(
            archive.size <= ARCHIVE_LIMIT as u64 && checksum.size <= CHECKSUM_LIMIT as u64,
            "Release assets exceed the native install size limits"
        );
        let published_digest = |asset: &Asset| -> Result<String> {
            let rows: Vec<_> = raw
                .assets
                .iter()
                .filter(|row| row.id == asset.id && row.name == asset.name)
                .collect();
            ensure!(
                rows.len() == 1,
                "Canonical release asset digest is ambiguous"
            );
            let hash = rows[0]
                .digest
                .as_deref()
                .and_then(|value| value.strip_prefix("sha256:"))
                .context("Canonical release is missing its asset SHA-256")?;
            ensure!(valid_digest(hash), "Canonical asset SHA-256 is invalid");
            Ok(hash.to_owned())
        };
        let archive_sha256 = published_digest(&archive)?;
        let checksum_sha256 = published_digest(&checksum)?;
        Ok(Self {
            release,
            archive,
            checksum,
            archive_sha256,
            checksum_sha256,
        })
    }

    fn fetch(profile: &Product, tag: &str) -> Result<Self> {
        let version = profile.version(tag)?;
        ensure!(
            profile.accepts(&version),
            "Release is outside Valhalla's stable channel"
        );
        let url = format!(
            "https://api.github.com/repos/{}/releases/tags/{}",
            profile.repository,
            tag.replace('+', "%2B")
        );
        let mut command = Command::new("/usr/bin/curl");
        // No redirect, credential lookup, curl config, or replaceable authority.
        command.args([
            "--disable",
            "--silent",
            "--show-error",
            "--fail",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "5",
            "--max-time",
            "30",
            "--max-filesize",
            "2097152",
            "--header",
            "Accept: application/vnd.github+json",
            "--user-agent",
            "vhalla-native-update",
            "--write-out",
            "\n%{http_code}",
            "--url",
            &url,
        ]);
        let output = run_bounded(
            &mut command,
            2 * 1024 * 1024 + 4,
            8192,
            Duration::from_secs(32),
        )?;
        ensure!(
            output.status.success(),
            "Could not read canonical GitHub release metadata; installation was not changed"
        );
        let bytes = output
            .stdout
            .strip_suffix(b"\n200")
            .context("GitHub did not return an exact HTTP 200 release response")?;
        Self::parse(profile, tag, bytes)
    }

    fn matches_selected(&self, selected: &Release) -> Result<()> {
        ensure!(
            self.release.id == selected.id && self.release.tag_name == selected.tag_name,
            "Selected release changed during verification"
        );
        for asset in [&self.archive, &self.checksum] {
            let selected_asset = selected
                .asset(&asset.name)
                .context("Selected release asset disappeared")?;
            ensure!(
                asset.id == selected_asset.id
                    && asset.size == selected_asset.size
                    && asset.browser_download_url == selected_asset.browser_download_url,
                "Selected release asset changed during verification"
            );
        }
        Ok(())
    }

    fn download(&self, profile: &Product, stage: &Stage<'_>) -> Result<()> {
        let source = CurlGithub::new("/usr/bin/curl")?;
        source.download_verified(
            profile,
            &self.release,
            &self.archive,
            &self.archive_sha256,
            &stage.directory.path.join("archive"),
            ARCHIVE_LIMIT,
        )?;
        source.download_verified(
            profile,
            &self.release,
            &self.checksum,
            &self.checksum_sha256,
            &stage.directory.path.join("checksum"),
            CHECKSUM_LIMIT,
        )?;
        self.verify_staged(stage)
    }

    fn import(&self, stage: &Stage<'_>, archive: &Path, checksum: &Path) -> Result<()> {
        stage
            .directory
            .write_new("archive", &read_path(archive, ARCHIVE_LIMIT)?, false)?;
        stage
            .directory
            .write_new("checksum", &read_path(checksum, CHECKSUM_LIMIT)?, false)?;
        self.verify_staged(stage)
    }

    fn verify_staged(&self, stage: &Stage<'_>) -> Result<()> {
        let archive = stage
            .directory
            .read("archive", ARCHIVE_LIMIT)?
            .context("Missing staged archive")?;
        let checksum = stage
            .directory
            .read("checksum", CHECKSUM_LIMIT)?
            .context("Missing staged checksum")?;
        ensure!(
            archive.len() as u64 == self.archive.size && digest(&archive) == self.archive_sha256,
            "Release archive differs from its canonical size or SHA-256"
        );
        ensure!(
            checksum.len() as u64 == self.checksum.size
                && digest(&checksum) == self.checksum_sha256,
            "Release checksum differs from its canonical size or SHA-256"
        );
        verify_checksum(&checksum, &self.archive.name, &self.archive_sha256)
    }

    fn receipt(&self, executable: &Path, binary_sha256: String, pinned: bool) -> InstallReceipt {
        InstallReceipt {
            schema: InstallReceipt::SCHEMA.into(),
            product: "valhalla".into(),
            repository: "hraness/valhalla".into(),
            kind: InstallationKind::NativeRelease,
            executable: executable.into(),
            binary_sha256,
            release_tag: self.release.tag_name.clone(),
            build_sha: None,
            release_id: self.release.id,
            archive_name: self.archive.name.clone(),
            archive_sha256: self.archive_sha256.clone(),
            platform: super::platform().into(),
            pinned,
        }
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn verify_checksum(bytes: &[u8], archive: &str, expected: &str) -> Result<()> {
    let text = std::str::from_utf8(bytes)?.trim_end_matches(['\r', '\n']);
    let plain = format!("{expected}  {archive}");
    let binary = format!("{expected} *{archive}");
    ensure!(
        text == plain || text == binary,
        "Checksum must name only the exact release archive with its canonical SHA-256"
    );
    Ok(())
}

fn tar(archive: &Path, mode: &str, member: Option<&str>, limit: usize) -> Result<Vec<u8>> {
    let mut command = Command::new("/usr/bin/tar");
    command.env("LC_ALL", "C").env_remove("TAR_OPTIONS");
    // bsdtar understands the mac-ext switch; GNU tar does not. This is chosen
    // at compile time, never from archive contents or a replaceable executable.
    #[cfg(target_os = "macos")]
    command.args(["--options", "!mac-ext"]);
    command.arg(mode).arg(archive);
    if let Some(member) = member {
        command.arg(member);
    }
    let output = run_bounded(&mut command, limit, 8192, Duration::from_secs(30))?;
    ensure!(
        output.status.success(),
        "Release archive could not be inspected or extracted"
    );
    Ok(output.stdout)
}

fn unpack(stage: &Stage<'_>, archive_name: &str) -> Result<String> {
    let archive = stage.directory.path.join("archive");
    let prefix = archive_name
        .strip_suffix(".tar.gz")
        .context("Expected a tar.gz release archive")?;
    let member = format!("{prefix}/vhalla");
    let directory = format!("{prefix}/");
    let names = tar(&archive, "-tzf", None, 4096)?;
    let names: Vec<_> = std::str::from_utf8(&names)?.lines().collect();
    ensure!(
        names == [&member] || names == [&directory, &member] || names == [&member, &directory],
        "Release archive must contain only its platform directory and vhalla"
    );
    let listing = tar(&archive, "-tvzf", None, 8192)?;
    let listing: Vec<_> = std::str::from_utf8(&listing)?.lines().collect();
    ensure!(
        names.len() == listing.len(),
        "Archive entry listing changed"
    );
    for (name, row) in names.iter().zip(listing) {
        ensure!(
            row.starts_with(if *name == member { '-' } else { 'd' }),
            "Release archive must contain one regular file and no links"
        );
    }
    let binary = tar(&archive, "-xzOf", Some(&member), BINARY_LIMIT)?;
    ensure!(!binary.is_empty(), "Release binary is empty");
    let hash = digest(&binary);
    stage.directory.write_new("vhalla", &binary, true)?;
    Ok(hash)
}

fn verify_candidate(stage: &Stage<'_>, tag: &str) -> Result<()> {
    let candidate = stage.directory.path.join("vhalla");
    #[cfg(target_os = "macos")]
    {
        let mut command = Command::new("/usr/bin/codesign");
        command
            .args([
                "--verify",
                "--strict",
                "--check-notarization",
                "--test-requirement",
                MACOS_REQUIREMENT,
            ])
            .arg(&candidate);
        ensure!(
            run_bounded(&mut command, 8192, 8192, Duration::from_secs(30))?
                .status
                .success(),
            "Release does not have Valhalla's required Apple Developer ID signature and notarization"
        );
        let mut command = Command::new("/usr/bin/codesign");
        command.args(["--display", "--verbose=4"]).arg(&candidate);
        let output = run_bounded(&mut command, 8192, 8192, Duration::from_secs(10))?;
        ensure!(
            output.status.success(),
            "Release signature inspection failed"
        );
        let signature = String::from_utf8(output.stderr)? + &String::from_utf8(output.stdout)?;
        ensure!(
            signature
                .lines()
                .any(|line| line.starts_with("CodeDirectory ")
                    && line.contains("flags=")
                    && line
                        .split_once('(')
                        .and_then(|(_, rest)| rest.split_once(')'))
                        .is_some_and(|(flags, _)| flags.split(',').any(|flag| flag == "runtime"))),
            "Release lacks hardened runtime"
        );
        ensure!(
            signature.lines().any(|line| line
                .strip_prefix("Timestamp=")
                .is_some_and(|stamp| !stamp.trim().is_empty())),
            "Release lacks a secure timestamp"
        );
    }
    let mut command = Command::new(&candidate);
    command.arg("--version");
    let output = run_bounded(&mut command, 4096, 4096, Duration::from_secs(10))?;
    ensure!(
        output.status.success()
            && output.stdout.starts_with(
                format!("vhalla {} features=[", tag.trim_start_matches('v')).as_bytes()
            )
            && output.stdout.ends_with(b"]\n"),
        "Release executable reports the wrong version"
    );
    let mut command = Command::new(&candidate);
    command.arg("__build-identity");
    let output = run_bounded(&mut command, 4096, 4096, Duration::from_secs(10))?;
    ensure!(
        output.status.success(),
        "Release executable cannot report its embedded identity"
    );
    let identity: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        identity["schema"] == "valhalla.build.v1"
            && identity["releaseTag"] == tag
            && identity["platform"] == super::platform(),
        "Release executable is not an official build for this tag and platform"
    );
    Ok(())
}

fn eligible_destination(executable: &Path) -> Result<()> {
    ensure!(
        !rustix::process::geteuid().is_root(),
        "Install Valhalla as your ordinary user; root-owned installations do not self-update"
    );
    ensure!(executable.is_absolute(), "Install prefix must be absolute");
    for component in executable.components() {
        ensure!(
            !matches!(
                component.as_os_str().to_str(),
                Some("Cellar" | ".cargo" | "target" | "node_modules" | ".git")
            ),
            "Cargo, Homebrew and source installations must use their original update workflow"
        );
    }
    for parent in executable.ancestors().skip(1) {
        ensure!(
            !(parent.join(".git").exists() && parent.join("Cargo.toml").exists()),
            "Install destination is inside a source checkout; use its source workflow"
        );
    }
    Ok(())
}

fn install_update(request: &InstallRequest<'_>) -> Result<()> {
    let target = &request.installation.receipt.executable;
    eligible_destination(target)?;
    let bin = Directory::open(
        target.parent().context("Install target has no parent")?,
        false,
        false,
    )?;
    let state = Directory::open(
        request
            .paths
            .receipt
            .parent()
            .context("Receipt has no parent")?,
        false,
        true,
    )?;
    let mut stage = Stage::new(&bin)?;
    let published = Published::fetch(request.product, &request.release.tag_name)?;
    published.matches_selected(request.release)?;
    published.download(request.product, &stage)?;
    let binary_sha = unpack(&stage, &published.archive.name)?;
    verify_candidate(&stage, &published.release.tag_name)?;
    let receipt = published.receipt(target, binary_sha, false);
    let old = snapshot(&bin, &state, &stage)?;
    request.revalidate()?;
    replace(
        &bin,
        &state,
        &mut stage,
        &old,
        &receipt,
        || {
            request.revalidate()?;
            Ok(())
        },
        || {
            request.publish_receipt(&receipt)?;
            Ok(())
        },
    )
}

struct Previous {
    binary_sha256: Option<String>,
    receipt: Option<Vec<u8>>,
}

fn snapshot(bin: &Directory, state: &Directory, stage: &Stage<'_>) -> Result<Previous> {
    let binary = bin.read("vhalla", BINARY_LIMIT)?;
    if let Some(bytes) = &binary {
        stage.directory.write_new("previous", bytes, true)?;
        stage.directory.copy_mode("previous", bin, "vhalla")?;
    }
    let receipt = state.read("install.json", RECEIPT_LIMIT)?;
    if let Some(bytes) = &receipt {
        stage.directory.write_new("old-receipt", bytes, false)?;
    }
    Ok(Previous {
        binary_sha256: binary.as_deref().map(digest),
        receipt,
    })
}

/// Keep binary replacement, receipt publication and rollback in the lock owner.
/// If rollback fails, retain the private backup and fail closed on the next run.
fn replace(
    bin: &Directory,
    state: &Directory,
    stage: &mut Stage<'_>,
    old: &Previous,
    receipt: &InstallReceipt,
    revalidate: impl FnOnce() -> Result<()>,
    publish: impl FnOnce() -> Result<()>,
) -> Result<()> {
    ensure!(
        bin.read("vhalla", BINARY_LIMIT)?.as_deref().map(digest) == old.binary_sha256,
        "Installed bytes changed before replacement"
    );
    ensure!(
        state.read("install.json", RECEIPT_LIMIT)? == old.receipt,
        "Install receipt changed before replacement"
    );
    ensure!(
        stage
            .directory
            .read("vhalla", BINARY_LIMIT)?
            .as_deref()
            .map(digest)
            .as_deref()
            == Some(&receipt.binary_sha256),
        "Staged binary changed after verification"
    );
    revalidate()?;
    let result: Result<()> = (|| {
        stage.directory.rename("vhalla", bin, "vhalla")?;
        publish()?;
        Ok(())
    })();
    if let Err(error) = result {
        let rollback: Result<()> = (|| {
            let now = bin.read("vhalla", BINARY_LIMIT)?.as_deref().map(digest);
            ensure!(
                now == old.binary_sha256 || now.as_deref() == Some(&receipt.binary_sha256),
                "Installed binary changed outside the transaction; backup was retained"
            );
            if old.binary_sha256.is_some() {
                stage.directory.rename("previous", bin, "vhalla")?;
            } else {
                bin.remove("vhalla", false)?;
            }
            if old.receipt.is_some() {
                stage
                    .directory
                    .rename("old-receipt", state, "install.json")?;
            } else {
                state.remove("install.json", false)?;
            }
            Ok(())
        })();
        if let Err(rollback) = rollback {
            stage.preserve = true;
            bail!("Installation failed: {error:#}; restoration failed: {rollback:#}. Verified backup retained at {}", stage.directory.path.display());
        }
        return Err(error).context("Installation failed; original files were restored");
    }
    Ok(())
}

fn verify_previous(
    profile: &Product,
    published: &Published,
    bin: &Directory,
    current: Option<&[u8]>,
    receipt: Option<&[u8]>,
    explicit_pin: bool,
) -> Result<bool> {
    let Some(binary) = current else {
        ensure!(
            receipt.is_none(),
            "An install receipt exists without its executable"
        );
        return Ok(explicit_pin);
    };
    if let Some(bytes) = receipt {
        let old: InstallReceipt =
            serde_json::from_slice(bytes).context("Read previous native install receipt")?;
        ensure!(
            old.schema == InstallReceipt::SCHEMA
                && old.product == profile.id
                && old.repository == profile.repository
                && old.kind == InstallationKind::NativeRelease
                && old.platform == profile.platform
                && old.executable == bin.path.join("vhalla")
                && old.binary_sha256 == digest(binary)
                && old.release_id != 0
                && valid_digest(&old.archive_sha256)
                && profile
                    .asset_names(&old.release_tag)?
                    .contains(&old.archive_name),
            "Previous install receipt does not match the installed native release"
        );
        ensure!(
            !old.pinned || explicit_pin || old.release_tag == published.release.tag_name,
            "This install is pinned; set VHALLA_VERSION to explicitly select a replacement version"
        );
        return Ok(old.pinned || explicit_pin);
    }
    // The older release was mutable. Its reviewed archive and executable hashes
    // are fixed in source; downloaded release metadata cannot widen this set.
    let current_hash = digest(binary);
    if legacy::matches(profile, &current_hash, binary.len())? {
        return Ok(explicit_pin);
    }
    // The following signing release may precede this updater. It must be an
    // immutable canonical release; never execute an unknown installed binary.
    let legacy = Published::fetch(profile, LEGACY_RELEASE)
        .context("Cannot verify the pre-update installation; use a new VHALLA_INSTALL_DIR")?;
    let stage = Stage::new(bin)?;
    legacy.download(profile, &stage)?;
    let old_hash = unpack(&stage, &legacy.archive.name)?;
    ensure!(current_hash == old_hash, "Existing file is not a verified {HISTORICAL_RELEASE} or {LEGACY_RELEASE} release; use its source/package-manager update workflow or select a new VHALLA_INSTALL_DIR");
    Ok(explicit_pin)
}

pub(super) fn initial_install(args: &InitialInstall) -> Result<()> {
    let tag = released_tag()?;
    let profile = product();
    let target = args.prefix.join("vhalla");
    eligible_destination(&target)?;
    let bin = Directory::open(
        target.parent().context("Install target has no parent")?,
        true,
        false,
    )?;
    let mut stage = Stage::new(&bin)?;
    let published = Published::fetch(&profile, tag)?;
    published.import(&stage, &args.archive, &args.checksum)?;
    let binary_sha = unpack(&stage, &published.archive.name)?;
    let running = std::env::current_exe()?.canonicalize()?;
    ensure!(
        digest(&read_path(&running, BINARY_LIMIT)?) == binary_sha,
        "Installer executable differs from the verified release archive"
    );
    verify_candidate(&stage, tag)?;
    let pinned = enroll_verified(
        &profile,
        &published,
        &bin,
        &mut stage,
        &target,
        &binary_sha,
        args.pinned,
    )?;
    println!(
        "Installed {} ({}); automatic updates {}",
        target.display(),
        tag,
        if pinned {
            "off for this pinned version"
        } else {
            "enabled by default"
        }
    );
    Ok(())
}

fn enroll_verified(
    profile: &Product,
    published: &Published,
    bin: &Directory,
    stage: &mut Stage<'_>,
    target: &Path,
    binary_sha: &str,
    explicit_pin: bool,
) -> Result<bool> {
    let update_paths = paths(target)?;
    let coordination = update_paths
        .receipt
        .parent()
        .context("Receipt has no parent")?;
    let state_name = ".hraness-cli-update-valhalla";
    // Verify an old unmanaged installation before creating the coordination
    // authority; a failed ownership check must not disable the old executable.
    let current = bin.read("vhalla", BINARY_LIMIT)?;
    let old_receipt = match std::fs::symlink_metadata(coordination) {
        Ok(_) => Directory::open(coordination, false, true)?.read("install.json", RECEIPT_LIMIT)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let pinned =
        if old_receipt.is_none() && current.as_deref().map(digest).as_deref() == Some(binary_sha) {
            explicit_pin
        } else {
            verify_previous(
                profile,
                published,
                bin,
                current.as_deref(),
                old_receipt.as_deref(),
                explicit_pin,
            )?
        };
    let created_state = bin.mkdir(state_name)?;
    let state = Directory::open(coordination, false, true)?;
    let lock = state.lock()?;
    let outcome = (|| {
        let old = snapshot(bin, &state, stage)?;
        ensure!(
            old.binary_sha256 == current.as_deref().map(digest) && old.receipt == old_receipt,
            "Installation changed while its release identity was checked; retry installation"
        );
        let receipt = published.receipt(target, binary_sha.to_owned(), pinned);
        replace(
            bin,
            &state,
            stage,
            &old,
            &receipt,
            || lock.validate(),
            || {
                receipt.write_verified(profile, &update_paths.receipt)?;
                Ok(())
            },
        )
    })();
    if outcome.is_err() && created_state && !stage.preserve {
        // No managed install survived this failed first enrollment. Remove only
        // our freshly created empty authority, while still holding its lock.
        let _ = state.remove("activity.lock", false);
        let _ = bin.remove(state_name, true);
    }
    outcome?;
    Ok(pinned)
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_requirement_is_compilable_inline_source() {
        let mut command = Command::new("/usr/bin/csreq");
        command.args(["-r", MACOS_REQUIREMENT, "-t"]);
        let output = run_bounded(&mut command, 8192, 8192, Duration::from_secs(10)).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    use super::*;
    use hraness_cli_update::{
        ReleaseSource, RunningIdentity, StartupContext, StartupOutcome, Updater,
    };
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SERIAL: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir().canonicalize().unwrap();
            let root = base.join(format!(
                "vhalla-native-test-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            Self { root }
        }
        fn bin(&self) -> Directory {
            Directory::open(&self.root.join("bin"), true, false).unwrap()
        }
        fn state(&self) -> Directory {
            Directory::open(
                &self.root.join("bin/.hraness-cli-update-valhalla"),
                true,
                true,
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn metadata() -> serde_json::Value {
        let names = product().asset_names("v1.0.0").unwrap();
        serde_json::json!({
            "id":42,"tag_name":"v1.0.0","draft":false,"prerelease":false,"immutable":true,
            "assets": names.iter().enumerate().map(|(index, name)| serde_json::json!({
                "id": index + 1, "name":name, "size":123,
                "browser_download_url":format!("https://github.com/hraness/valhalla/releases/download/v1.0.0/{name}"),
                "digest":format!("sha256:{}", "a".repeat(64)),
            })).collect::<Vec<_>>()
        })
    }

    fn published() -> Published {
        Published::parse(
            &product(),
            "v1.0.0",
            &serde_json::to_vec(&metadata()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_release_proof_requires_immutable_assets_and_digests() {
        published();
        let mut variants = vec![];
        let mut value = metadata();
        value["immutable"] = false.into();
        variants.push(value);
        let mut value = metadata();
        value["assets"][0]["digest"] = serde_json::Value::Null;
        variants.push(value);
        let mut value = metadata();
        value["assets"][0]["digest"] = format!("sha256:{}", "A".repeat(64)).into();
        variants.push(value);
        let mut value = metadata();
        value["assets"][0]["browser_download_url"] = "https://example.test/vhalla".into();
        variants.push(value);
        let mut value = metadata();
        value["tag_name"] = "v1.0.1".into();
        variants.push(value);
        for value in variants {
            assert!(
                Published::parse(&product(), "v1.0.0", &serde_json::to_vec(&value).unwrap())
                    .is_err()
            );
        }
    }

    #[test]
    fn checksum_binds_one_exact_archive() {
        let hash = "b".repeat(64);
        for text in [
            format!("{hash}  exact.tar.gz\n"),
            format!("{hash} *exact.tar.gz\r\n"),
        ] {
            verify_checksum(text.as_bytes(), "exact.tar.gz", &hash).unwrap();
        }
        for text in [
            format!("{hash}  other.tar.gz\n"),
            format!("{hash}  exact.tar.gz\n{hash}  other.tar.gz\n"),
            "b".repeat(64),
        ] {
            assert!(verify_checksum(text.as_bytes(), "exact.tar.gz", &hash).is_err());
        }
    }

    #[test]
    fn local_archive_cannot_claim_canonical_release_ownership() {
        let fixture = Fixture::new();
        let bin = fixture.bin();
        let stage = Stage::new(&bin).unwrap();
        stage
            .directory
            .write_new("archive", b"foreign archive", false)
            .unwrap();
        stage
            .directory
            .write_new("checksum", b"foreign checksum", false)
            .unwrap();
        assert!(published().verify_staged(&stage).is_err());
        assert!(fixture
            .bin()
            .read("vhalla", BINARY_LIMIT)
            .unwrap()
            .is_none());
    }

    fn make_archive(source: &Path, archive: &Path, members: &[&str]) {
        let mut command = Command::new("/usr/bin/tar");
        command
            .env("COPYFILE_DISABLE", "1")
            .env_remove("TAR_OPTIONS")
            .arg("-czf")
            .arg(archive)
            .arg("-C")
            .arg(source)
            .args(members);
        assert!(
            run_bounded(&mut command, 8192, 8192, Duration::from_secs(10))
                .unwrap()
                .status
                .success()
        );
    }

    #[test]
    fn archive_refuses_links_and_extra_members_without_execution() {
        let fixture = Fixture::new();
        let bin = fixture.bin();
        let source = fixture.root.join("source");
        fs::create_dir(&source).unwrap();
        let archive_name = published().archive.name;
        let prefix = archive_name.strip_suffix(".tar.gz").unwrap();
        let member = format!("{prefix}/vhalla");
        fs::create_dir(source.join(prefix)).unwrap();
        fs::write(source.join(&member), b"not executed").unwrap();
        fs::write(source.join("extra"), b"extra").unwrap();
        {
            let stage = Stage::new(&bin).unwrap();
            make_archive(&source, &stage.directory.path.join("archive"), &[prefix]);
            assert_eq!(
                unpack(&stage, &archive_name).unwrap(),
                digest(b"not executed")
            );
        }
        {
            let stage = Stage::new(&bin).unwrap();
            make_archive(
                &source,
                &stage.directory.path.join("archive"),
                &[prefix, "extra"],
            );
            assert!(unpack(&stage, &archive_name).is_err());
        }
        fs::remove_file(source.join(&member)).unwrap();
        symlink("/bin/sh", source.join(&member)).unwrap();
        let stage = Stage::new(&bin).unwrap();
        make_archive(&source, &stage.directory.path.join("archive"), &[prefix]);
        assert!(unpack(&stage, &archive_name).is_err());
    }

    #[test]
    fn rollback_restores_binary_and_receipt_after_publication_failure() {
        let fixture = Fixture::new();
        let bin = fixture.bin();
        let state = fixture.state();
        bin.write_new("vhalla", b"old binary", true).unwrap();
        fs::set_permissions(bin.path.join("vhalla"), fs::Permissions::from_mode(0o700)).unwrap();
        state
            .write_new("install.json", b"old receipt", false)
            .unwrap();
        let mut stage = Stage::new(&bin).unwrap();
        stage
            .directory
            .write_new("vhalla", b"new binary", true)
            .unwrap();
        let old = snapshot(&bin, &state, &stage).unwrap();
        let receipt = published().receipt(&bin.path.join("vhalla"), digest(b"new binary"), false);
        let result = replace(
            &bin,
            &state,
            &mut stage,
            &old,
            &receipt,
            || Ok(()),
            || {
                state.remove("install.json", false)?;
                state.write_new("install.json", b"partially published receipt", false)?;
                bail!("injected receipt publication failure")
            },
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("original files were restored"));
        assert_eq!(
            bin.read("vhalla", BINARY_LIMIT).unwrap().unwrap(),
            b"old binary"
        );
        assert_eq!(
            state.read("install.json", RECEIPT_LIMIT).unwrap().unwrap(),
            b"old receipt"
        );
    }

    #[test]
    fn failed_final_revalidation_performs_no_installed_writes() {
        let fixture = Fixture::new();
        let bin = fixture.bin();
        let state = fixture.state();
        bin.write_new("vhalla", b"old", true).unwrap();
        state.write_new("install.json", b"old", false).unwrap();
        let mut stage = Stage::new(&bin).unwrap();
        stage.directory.write_new("vhalla", b"new", true).unwrap();
        let old = snapshot(&bin, &state, &stage).unwrap();
        let receipt = published().receipt(&bin.path.join("vhalla"), digest(b"new"), false);
        assert!(replace(
            &bin,
            &state,
            &mut stage,
            &old,
            &receipt,
            || bail!("policy disabled"),
            || panic!("publication must not run")
        )
        .is_err());
        assert_eq!(bin.read("vhalla", BINARY_LIMIT).unwrap().unwrap(), b"old");
        assert_eq!(
            state.read("install.json", RECEIPT_LIMIT).unwrap().unwrap(),
            b"old"
        );
    }

    #[test]
    fn installed_symlinks_and_shared_files_are_never_replaced() {
        let fixture = Fixture::new();
        let bin = fixture.bin();
        let foreign = fixture.root.join("foreign");
        fs::write(&foreign, b"preserve").unwrap();
        symlink(&foreign, bin.path.join("vhalla")).unwrap();
        assert!(bin.read("vhalla", BINARY_LIMIT).is_err());
        fs::remove_file(bin.path.join("vhalla")).unwrap();
        fs::hard_link(&foreign, bin.path.join("vhalla")).unwrap();
        assert!(bin.read("vhalla", BINARY_LIMIT).is_err());
        assert_eq!(fs::read(&foreign).unwrap(), b"preserve");
    }

    #[test]
    fn manager_and_source_destinations_are_ineligible() {
        for path in [
            "/opt/homebrew/Cellar/vhalla/1/bin/vhalla",
            "/home/user/.cargo/bin/vhalla",
            "/work/target/release/vhalla",
        ] {
            assert!(eligible_destination(Path::new(path)).is_err());
        }
        let fixture = Fixture::new();
        fs::create_dir(fixture.root.join(".git")).unwrap();
        fs::write(fixture.root.join("Cargo.toml"), b"").unwrap();
        assert!(eligible_destination(&fixture.root.join("bin/vhalla")).is_err());
    }

    #[test]
    fn initial_enrollment_refuses_an_unpublished_source_build() {
        if matches!(product().running_identity, RunningIdentity::Source) {
            let args = InitialInstall {
                archive: "/missing".into(),
                checksum: "/missing".into(),
                prefix: "/missing".into(),
                pinned: false,
            };
            assert!(initial_install(&args)
                .unwrap_err()
                .to_string()
                .contains("source build"));
        }
    }

    #[test]
    fn reinstall_preserves_pins_and_rejects_foreign_receipts() {
        let fixture = Fixture::new();
        let bin = fixture.bin();
        let published = published();
        let profile = product();
        let binary = b"verified binary";
        let mut receipt = published.receipt(&bin.path.join("vhalla"), digest(binary), true);
        let bytes = serde_json::to_vec(&receipt).unwrap();
        assert!(verify_previous(
            &profile,
            &published,
            &bin,
            Some(binary),
            Some(&bytes),
            false
        )
        .unwrap());
        receipt.release_tag = "v0.9.0".into();
        receipt.archive_name = profile.asset_names("v0.9.0").unwrap()[0].clone();
        let bytes = serde_json::to_vec(&receipt).unwrap();
        assert!(verify_previous(
            &profile,
            &published,
            &bin,
            Some(binary),
            Some(&bytes),
            false
        )
        .is_err());
        assert!(
            verify_previous(&profile, &published, &bin, Some(binary), Some(&bytes), true).unwrap()
        );
        receipt.kind = InstallationKind::Cargo;
        assert!(verify_previous(
            &profile,
            &published,
            &bin,
            Some(binary),
            Some(&serde_json::to_vec(&receipt).unwrap()),
            true
        )
        .is_err());
    }

    struct NeverNetwork;
    impl ReleaseSource for NeverNetwork {
        fn releases(&self, _: &Product) -> hraness_cli_update::Result<Vec<Release>> {
            panic!("offline command must not fetch")
        }
    }

    #[test]
    fn initial_install_keeps_preferences_separate_from_ownership() {
        let fixture = Fixture::new();
        let bin = fixture.bin();
        bin.write_new("vhalla", b"source bytes", true).unwrap();
        let target = bin.path.join("vhalla");
        let profile = product();
        let update_paths = paths(&target).unwrap();
        let updater =
            Updater::for_executable(profile.clone(), update_paths.clone(), target.clone()).unwrap();
        updater
            .execute(
                hraness_cli_update::CommandAction::Disable,
                &NeverNetwork,
                &NativeInstaller,
            )
            .unwrap();
        assert!(update_paths.state_dir.exists());
        assert!(!update_paths.receipt.parent().unwrap().exists());
        bin.remove("vhalla", false).unwrap();
        let mut stage = Stage::new(&bin).unwrap();
        stage
            .directory
            .write_new("vhalla", b"verified native bytes", true)
            .unwrap();
        let pinned = enroll_verified(
            &profile,
            &published(),
            &bin,
            &mut stage,
            &target,
            &digest(b"verified native bytes"),
            false,
        )
        .unwrap();
        assert!(!pinned);
        let receipt: InstallReceipt =
            serde_json::from_slice(&fs::read(&update_paths.receipt).unwrap()).unwrap();
        assert_eq!(receipt.binary_sha256, digest(b"verified native bytes"));
        assert!(update_paths
            .receipt
            .parent()
            .unwrap()
            .join("activity.lock")
            .exists());
        let status = updater
            .execute(
                hraness_cli_update::CommandAction::Status,
                &NeverNetwork,
                &NativeInstaller,
            )
            .unwrap();
        assert_eq!(status.policy, hraness_cli_update::Policy::Disabled);
    }

    #[test]
    fn installer_lock_obeys_the_running_command_sdk_lease() {
        let fixture = Fixture::new();
        let bin = fixture.bin();
        let state = fixture.state();
        bin.write_new("vhalla", b"release bytes", true).unwrap();
        let target = bin.path.join("vhalla");
        let paths = paths(&target).unwrap();
        let mut profile = product();
        profile.running_identity = RunningIdentity::Release {
            release_tag: "v1.0.0",
            build_sha: None,
        };
        let receipt = published().receipt(&target, digest(b"release bytes"), false);
        receipt.write_verified(&profile, &paths.receipt).unwrap();
        let updater = Updater::for_executable(profile, paths, target).unwrap();
        let mut context = StartupContext::from_process();
        context.args = vec!["proxy".into(), "serve".into()];
        context.no_update = true;
        let outcome = updater
            .startup(&context, &NeverNetwork, &NativeInstaller)
            .unwrap();
        let StartupOutcome::Continue {
            lease: Some(lease), ..
        } = outcome
        else {
            panic!("command must retain an active lease")
        };
        assert!(state.lock().is_err());
        drop(lease);
        state.lock().unwrap();
    }
}
