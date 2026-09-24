//! Immutable host selection and owner-private, fail-closed initialization.
use super::{launchd, service, REFUSED};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    net::SocketAddr,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use vhalla_custody as custody;
use vhalla_private_native::relay::{
    net::RelayToken, tls, tls::Service, FileStore, Limits, RelayNamespace,
};
use zeroize::Zeroizing;

/// Files initialized before any credential; `client-N.token` names follow.
const STATIC_FILES: [&str; 6] = [
    "ca.der",
    "ca-key.der",
    "server.der",
    "server-key.der",
    "connection.json",
    "launch-agent.plist",
];
/// Immutable sealed files for a home with this many enrolled credentials.
fn expected_files(config: &Config) -> Vec<String> {
    STATIC_FILES
        .iter()
        .map(|name| (*name).to_owned())
        .chain((1..=config.credential_ids.len()).map(|index| format!("client-{index}.token")))
        .chain(
            config
                .credential_generations
                .iter()
                .enumerate()
                .flat_map(|(index, generation)| {
                    (1..*generation)
                        .map(move |old| format!("client-{}.generation-{old}.token", index + 1))
                }),
        )
        .collect()
}
fn default_mailbox() -> String {
    "mailbox".into()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedGeneration {
    pub generation: u64,
    pub namespace: String,
    pub mailbox: String,
    pub listen: SocketAddr,
    pub credential_ids: Vec<String>,
    pub transition: String,
    pub intent_sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retained_generations: Vec<RetainedGeneration>,
    pub label: String,
    pub listen: SocketAddr,
    pub tls_name: String,
    pub executable: PathBuf,
    pub namespace: String,
    /// Stable random credential identities; the token files are `client-N.token`.
    pub credential_ids: Vec<String>,
    /// Absent only in legacy homes. Replacement never changes the quota ID.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_generations: Vec<u32>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub revoked_credential_ids: BTreeSet<String>,
    /// Mailbox directory relative to the home. Rotation advances it while
    /// every earlier mailbox directory remains untouched evidence.
    #[serde(default = "default_mailbox")]
    pub mailbox: String,
    pub created_at: i64,
    pub certificate_expires_at: i64,
    pub authority_expires_at: i64,
    /// Legacy renewal may already have inflated expiry, so never infer this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf_lifetime_seconds: Option<i64>,
    pub files: BTreeMap<String, String>,
}
pub(super) struct Loaded {
    pub home: PathBuf,
    pub config: Config,
}

pub(super) fn resolve(path: &Path) -> Result<PathBuf, String> {
    let absolute = custody::absolute(path).map_err(|_| REFUSED)?;
    let parent = absolute
        .parent()
        .ok_or(REFUSED)?
        .canonicalize()
        .map_err(|_| REFUSED)?;
    let name = absolute.file_name().ok_or(REFUSED)?;
    if name == "." || name == ".." {
        return Err(REFUSED.into());
    }
    Ok(parent.join(name))
}
fn owner(home: &Path) -> Result<(fs::File, u32), String> {
    let (directory, uid) = custody::open_private_directory(home).map_err(|_| REFUSED)?;
    if uid != rustix::process::geteuid().as_raw() {
        return Err(REFUSED.into());
    }
    Ok((directory, uid))
}
/// One stable inode serializes maintenance and startup selection independently
/// of the mailbox writer. Never unlink or replace this file, even after exit.
pub(super) fn maintenance_lock(home: &Path) -> Result<fs::File, String> {
    let (directory, uid) = owner(home)?;
    let path = home.join("maintenance.lock");
    match custody::create_private_file(&path) {
        Ok(file) => {
            file.sync_all()
                .and_then(|()| directory.sync_all())
                .map_err(|_| REFUSED)?;
        }
        Err(custody::Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(REFUSED.into()),
    }
    let file = custody::open_private_file(&path, uid, 0).map_err(|_| REFUSED)?;
    file.try_lock().map_err(|error| match error {
        fs::TryLockError::WouldBlock => {
            "host maintenance busy; retry after the active operation completes".to_owned()
        }
        fs::TryLockError::Error(_) => REFUSED.to_owned(),
    })?;
    let named = fs::symlink_metadata(&path).map_err(|_| REFUSED)?;
    let held = file.metadata().map_err(|_| REFUSED)?;
    custody::check_regular_file(&named, uid, 0).map_err(|_| REFUSED)?;
    if named.dev() != held.dev() || named.ino() != held.ino() {
        return Err(REFUSED.into());
    }
    Ok(file)
}

const AUTHORITY_LIFETIME_SECONDS: i64 = 365 * 5 * 86400;
pub(super) fn valid_leaf_lifetime(seconds: i64) -> bool {
    (86400..AUTHORITY_LIFETIME_SECONDS).contains(&seconds)
}
pub(super) fn read(home: &Path, name: &str, limit: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let (_, uid) = owner(home)?;
    Ok(Zeroizing::new(
        custody::read_private_file(&home.join(name), uid, limit).map_err(|_| REFUSED)?,
    ))
}
/// Consume only bytes matching the selected immutable manifest, even if a
/// credential is replaced after the caller's initial whole-home validation.
pub(super) fn read_bound(
    home: &Path,
    config: &Config,
    name: &str,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let bytes = read(home, name, limit)?;
    if config.files.get(name) != Some(&digest(&bytes)) {
        return Err(REFUSED.into());
    }
    Ok(bytes)
}

pub(super) fn write(home: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > 65536 {
        return Err(REFUSED.into());
    }
    let (directory, uid) = owner(home)?;
    let path = home.join(name);
    let mut file = custody::create_private_file(&path).map_err(|_| REFUSED)?;
    custody::check_regular_file(&file.metadata().map_err(|_| REFUSED)?, uid, 65536)
        .map_err(|_| REFUSED)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| directory.sync_all())
        .map_err(|_| REFUSED)?;
    if read(home, name, 65536)?.as_slice() != bytes {
        return Err(REFUSED.into());
    }
    Ok(())
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(REFUSED.into());
    }
    let mut bytes = [0; N];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| REFUSED)?, 16)
            .map_err(|_| REFUSED)?;
    }
    Ok(bytes)
}
fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, String> {
    let mut bytes = Zeroizing::new([0; N]);
    getrandom::fill(bytes.as_mut()).map_err(|_| REFUSED)?;
    if *bytes == [0; N] {
        return Err(REFUSED.into());
    }
    Ok(bytes)
}
pub(super) fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn label(home: &Path) -> Result<String, String> {
    Ok(format!(
        "me.vhalla.private-host.{}",
        &digest(home.to_str().ok_or(REFUSED)?.as_bytes())[..32]
    ))
}

/// The one issuer shape this command family ever publishes. Renewal rebuilds
/// these exact params so the reissued leaf chains to the retained `ca.der`:
/// `signed_by` consumes only the issuer subject name and key identifier.
fn issuer_params(
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> Result<CertificateParams, String> {
    let mut issuer = CertificateParams::new(Vec::<String>::new()).map_err(|_| REFUSED)?;
    issuer.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    issuer.not_before = not_before;
    issuer.not_after = not_after;
    issuer.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    Ok(issuer)
}
fn leaf_params(
    name: &str,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> Result<CertificateParams, String> {
    let mut leaf =
        CertificateParams::new(vec![name.to_owned()]).map_err(|_| "invalid TLS server name")?;
    leaf.not_before = not_before;
    leaf.not_after = not_after;
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    Ok(leaf)
}

#[cfg(test)]
pub(super) fn initialize(
    path: &Path,
    listen: SocketAddr,
    name: &str,
    executable: &Path,
) -> Result<Loaded, String> {
    initialize_with_leaf_lifetime(path, listen, name, executable, time::Duration::days(365))
}

pub(super) fn initialize_with_leaf_lifetime(
    path: &Path,
    listen: SocketAddr,
    name: &str,
    executable: &Path,
    leaf_lifetime: time::Duration,
) -> Result<Loaded, String> {
    let home = resolve(path)?;
    if !super::loopback(listen)
        || listen.port() == 0
        || name.len() > 253
        || name.is_empty()
        || !valid_leaf_lifetime(leaf_lifetime.whole_seconds())
    {
        return Err(REFUSED.into());
    }
    let executable = executable
        .canonicalize()
        .map_err(|_| "selected executable unavailable")?;
    let metadata = fs::metadata(&executable).map_err(|_| REFUSED)?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 || metadata.mode() & 0o6022 != 0 {
        return Err(
            "selected executable must be a regular executable without set-ID or group/world write permission"
                .into(),
        );
    }
    let now = time::OffsetDateTime::now_utc();
    let expires = now + leaf_lifetime;
    let authority_expires = now + time::Duration::seconds(AUTHORITY_LIFETIME_SECONDS);
    let issuer_key = KeyPair::generate().map_err(|_| REFUSED)?;
    let issuer = issuer_params(now - time::Duration::minutes(5), authority_expires)?
        .self_signed(&issuer_key)
        .map_err(|_| REFUSED)?;
    let key = KeyPair::generate().map_err(|_| REFUSED)?;
    let leaf = leaf_params(name, now - time::Duration::minutes(5), expires)?
        .signed_by(&key, &issuer, &issuer_key)
        .map_err(|_| REFUSED)?;
    // TLS name validation and crypto happen before the first filesystem mutation.
    let namespace = RelayNamespace::from_bytes(*random::<32>()?).map_err(|_| REFUSED)?;
    let tokens = [random::<32>()?, random::<32>()?];
    vhalla_private_native::relay::tls::TlsRelay::new(
        listen,
        name,
        issuer.der().to_vec(),
        vhalla_private_native::relay::net::RelayToken::from_bytes(*tokens[0])
            .map_err(|_| REFUSED)?,
        namespace,
    )
    .map_err(|_| "invalid TLS trust/name selection")?;
    let mut config = Config {
        version: 2,
        retained_generations: Vec::new(),
        label: label(&home)?,
        listen,
        tls_name: name.to_owned(),
        executable,
        namespace: hex(namespace.as_bytes()),
        credential_ids: vec![hex(random::<16>()?.as_ref()), hex(random::<16>()?.as_ref())],
        credential_generations: vec![1, 1],
        revoked_credential_ids: BTreeSet::new(),
        mailbox: default_mailbox(),
        created_at: now.unix_timestamp(),
        certificate_expires_at: expires.unix_timestamp(),
        authority_expires_at: authority_expires.unix_timestamp(),
        leaf_lifetime_seconds: Some(leaf_lifetime.whole_seconds()),
        files: BTreeMap::new(),
    };
    let planned_agent = launchd::plist(&home, &config)?;
    custody::create_private_directory(&home).map_err(|_| {
        "host initialization requires a never-used path; preserve any existing or partial home"
    })?;
    write(&home, "ca.der", issuer.der())?;
    write(
        &home,
        "ca-key.der",
        &Zeroizing::new(issuer_key.serialize_der()),
    )?;
    write(&home, "server.der", leaf.der())?;
    write(
        &home,
        "server-key.der",
        &Zeroizing::new(key.serialize_der()),
    )?;
    for (index, token) in tokens.iter().enumerate() {
        write(
            &home,
            &format!("client-{}.token", index + 1),
            Zeroizing::new(hex(token.as_ref())).as_bytes(),
        )?;
    }
    let connection = connection_document(&home, &config, None)?;
    write(&home, "connection.json", &connection)?;
    write(&home, "launch-agent.plist", planned_agent.as_bytes())?;
    Service::initialize(
        FileStore::create_new(
            home.join("mailbox"),
            namespace,
            Limits {
                max_items: 4096,
                max_bytes: 256 * 1024 * 1024,
            },
        )
        .map_err(|_| REFUSED)?,
    )
    .map_err(|_| REFUSED)?;
    for name in expected_files(&config) {
        config
            .files
            .insert(name.clone(), digest(&read(&home, &name, 65536)?));
    }
    // Enroll immutable per-credential quotas from those exact file commitments
    // before publishing a complete home.
    drop(service(&home, &config)?);
    let bytes = serde_json::to_vec(&config).map_err(|_| REFUSED)?;
    write(&home, "config.json", &bytes)?;
    write(&home, "complete", digest(&bytes).as_bytes())?;
    fs::File::open(home.parent().ok_or(REFUSED)?)
        .and_then(|file| file.sync_all())
        .map_err(|_| REFUSED)?;
    load(&home)
}

/// Service removal needs intact selection/template evidence, not readable TLS
/// secrets. This lets an operator stop a failed host without repairing or
/// replacing its retained credential files first.
pub(super) fn load_for_stop(path: &Path) -> Result<Loaded, String> {
    let home = resolve(path)?;
    let bytes = read(&home, "config.json", 65536)?;
    if read(&home, "complete", 64)?.as_slice() != digest(&bytes).as_bytes() {
        return Err(REFUSED.into());
    }
    let config: Config = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
    validate_config(&home, &config)?;
    let template = read(&home, "launch-agent.plist", 65536)?;
    if config.files.get("launch-agent.plist") != Some(&digest(&template))
        || !launchd::template_ours(
            &Loaded {
                home: home.clone(),
                config: config.clone(),
            },
            &template,
        )?
    {
        return Err(REFUSED.into());
    }
    Ok(Loaded { home, config })
}

/// Validate proposed manifests before publication, using the same structural
/// constraints as readers. File commitments are checked separately.
fn validate_config(home: &Path, config: &Config) -> Result<(), String> {
    if ![1, 2, 3].contains(&config.version)
        || config.label != label(&resolve(home)?)?
        || !super::loopback(config.listen)
        || config.listen.port() == 0
        || !config.executable.is_absolute()
        || config.certificate_expires_at <= config.created_at
        || config.authority_expires_at <= config.certificate_expires_at
        || !(2..=64).contains(&config.credential_ids.len())
        || !valid_mailbox(&config.mailbox)
        || config
            .leaf_lifetime_seconds
            .is_some_and(|seconds| !valid_leaf_lifetime(seconds))
        || (config.version == 1
            && (!config.credential_generations.is_empty()
                || !config.revoked_credential_ids.is_empty()
                || config.leaf_lifetime_seconds.is_some()))
        || (config.version >= 2
            && (config.credential_generations.len() != config.credential_ids.len()
                || config
                    .credential_generations
                    .iter()
                    .any(|generation| !(1..=65).contains(generation))
                || config
                    .credential_generations
                    .iter()
                    .map(|generation| generation.saturating_sub(1) as usize)
                    .sum::<usize>()
                    > 64))
        || config
            .revoked_credential_ids
            .iter()
            .any(|id| !config.credential_ids.contains(id))
    {
        return Err(REFUSED.into());
    }
    super::generation::validate_selection(config)?;
    RelayNamespace::from_bytes(decode_hex(&config.namespace)?).map_err(|_| REFUSED)?;
    let expected = expected_files(config);
    if config.files.len() != expected.len()
        || config
            .credential_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != config.credential_ids.len()
    {
        return Err(REFUSED.into());
    }
    for id in &config.credential_ids {
        if decode_hex::<16>(id)? == [0; 16] {
            return Err(REFUSED.into());
        }
    }
    for name in &expected {
        decode_hex::<32>(config.files.get(name).ok_or(REFUSED)?)?;
    }
    Ok(())
}

/// Mailbox directory names are bounded relative names created only by this
/// command family: the original `mailbox` or a monotonically numbered
/// `mailbox-N` from an explicit rotation.
fn valid_mailbox(name: &str) -> bool {
    name == "mailbox"
        || name
            .strip_prefix("mailbox-")
            .and_then(|raw| raw.parse::<u32>().ok())
            .is_some_and(|n| n >= 2)
}

pub(super) fn load(path: &Path) -> Result<Loaded, String> {
    let loaded = load_for_stop(path)?;
    for name in expected_files(&loaded.config) {
        if loaded.config.files.get(&name) != Some(&digest(&read(&loaded.home, &name, 65536)?)) {
            return Err(REFUSED.into());
        }
    }
    Ok(loaded)
}

/// The client-facing document a member copies into a delivery profile. It
/// carries no token and no private path outside the home.
pub(super) fn connection_document(
    home: &Path,
    config: &Config,
    previous: Option<&str>,
) -> Result<Vec<u8>, String> {
    let mut document = serde_json::json!({"version":1,"namespace":config.namespace,"listen":config.listen,"tls_name":config.tls_name,"ca_file":"ca.der","ca_sha256":digest(&read(home,"ca.der",65536)?),"certificate_expires_at":config.certificate_expires_at,"mailbox":config.mailbox,"transport":"TLS 1.3; copy CA and one separate private credential through a trusted channel","client_tokens":"not included"});
    if let Some(previous) = previous {
        document["previous_namespace"] = previous.into();
    }
    serde_json::to_vec(&document).map_err(|_| REFUSED.into())
}

/// Atomically replace one bounded private file: verified tmp write, fsync,
/// rename over the target, directory fsync and a read-back check.
pub(super) fn rewrite(home: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > 65536 || name.is_empty() || name.contains(['/', '\\']) || name.starts_with('.')
    {
        return Err(REFUSED.into());
    }
    let (directory, uid) = owner(home)?;
    let tmp = home.join(format!("{name}.rewrite-tmp"));
    // A selected target may be absent (additive publication), but unsafe
    // existing custody is never repaired by replacing it.
    custody::private_file_present(&home.join(name), uid, 65536).map_err(|_| REFUSED)?;
    if custody::private_file_present(&tmp, uid, 65536).map_err(|_| REFUSED)? {
        fs::remove_file(&tmp).map_err(|_| REFUSED)?;
    }
    let mut file = custody::create_private_file(&tmp).map_err(|_| REFUSED)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| REFUSED)?;
    fs::rename(&tmp, home.join(name)).map_err(|_| REFUSED)?;
    directory.sync_all().map_err(|_| REFUSED)?;
    if read(home, name, 65536)?.as_slice() != bytes {
        return Err(REFUSED.into());
    }
    Ok(())
}

/// A sealed mutation writes one marker plus one byte-exact backup per file it
/// may replace. The marker exists only after every backup, so its presence
/// always proves every planned backup exists. Recovery replays the last fully
/// sealed snapshot; it never invents or prunes state.
const SEAL_PENDING: &str = "seal.pending";
const SEAL_BACKUP: &str = ".seal-backup";

fn seal_scratch(home: &Path, uid: u32) -> Result<(Option<Vec<u8>>, Vec<String>), String> {
    let pending = home.join(SEAL_PENDING);
    let pending = if custody::private_file_present(&pending, uid, 64).map_err(|_| REFUSED)? {
        Some(custody::read_private_file(&pending, uid, 64).map_err(|_| REFUSED)?)
    } else {
        None
    };
    let mut backups = Vec::new();
    for entry in fs::read_dir(home).map_err(|_| REFUSED)? {
        let entry = entry.map_err(|_| REFUSED)?;
        let name = entry.file_name();
        // Only exact ASCII-suffixed scratch names are ours; unrelated files the
        // operator keeps in the home are not mutation evidence.
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(file) = name.strip_suffix(SEAL_BACKUP) {
            if !file.is_empty() && !file.contains(['/', '\\']) {
                let path = home.join(name);
                if custody::private_file_present(&path, uid, 65536).map_err(|_| REFUSED)? {
                    backups.push(name.to_owned());
                } else {
                    return Err(REFUSED.into());
                }
            }
        }
    }
    Ok((pending, backups))
}
fn sealed_config(home: &Path, uid: u32) -> Option<Vec<u8>> {
    let config = custody::read_private_file(&home.join("config.json"), uid, 65536).ok()?;
    let complete = custody::read_private_file(&home.join("complete"), uid, 64).ok()?;
    (complete.as_slice() == digest(&config).as_bytes()).then_some(config)
}
fn remove_seal_scratch(home: &Path, backups: &[String]) -> Result<(), String> {
    remove_seal_scratch_with(home, backups, fs::File::sync_all)
}
fn remove_seal_scratch_with(
    home: &Path,
    backups: &[String],
    mut sync_directory: impl FnMut(&fs::File) -> std::io::Result<()>,
) -> Result<(), String> {
    let (directory, uid) = owner(home)?;
    let pending = home.join(SEAL_PENDING);
    if custody::private_file_present(&pending, uid, 64).map_err(|_| REFUSED)? {
        fs::remove_file(&pending).map_err(|_| REFUSED)?;
    }
    // A previous process can have unlinked the marker without reaching its
    // directory sync. Visible absence on this retry is not durable absence:
    // fence it even when no marker was present before deleting any backup.
    sync_directory(&directory).map_err(|_| REFUSED)?;
    for name in backups {
        // A previous cleanup may have stopped partway through this list.
        match fs::remove_file(home.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(REFUSED.into()),
        }
    }
    sync_directory(&directory).map_err(|_| REFUSED.into())
}
/// Restore every backup over its sealed name and recompute `complete` from the
/// restored config, returning the home to the pre-mutation snapshot.
fn restore_seal_backups(home: &Path, backups: &[String]) -> Result<(), String> {
    restore_seal_backups_with(home, backups, |_| Ok(()))
}
fn restore_seal_backups_with(
    home: &Path,
    backups: &[String],
    mut after_restore: impl FnMut(&str) -> Result<(), String>,
) -> Result<(), String> {
    let (_, uid) = owner(home)?;
    let config_bytes =
        custody::read_private_file(&home.join("config.json.seal-backup"), uid, 65536)
            .map_err(|_| REFUSED)?;
    let config: Config = serde_json::from_slice(&config_bytes).map_err(|_| REFUSED)?;
    validate_config(home, &config)?;
    // Verify every retained backup before the first restoration write.
    for name in backups {
        let target = name.strip_suffix(SEAL_BACKUP).ok_or(REFUSED)?;
        let bytes =
            custody::read_private_file(&home.join(name), uid, 65536).map_err(|_| REFUSED)?;
        if target != "config.json" && config.files.get(target) != Some(&digest(&bytes)) {
            return Err(REFUSED.into());
        }
    }
    for name in backups {
        let backup = home.join(name);
        if !custody::private_file_present(&backup, uid, 65536).map_err(|_| REFUSED)? {
            return Err(REFUSED.into());
        }
        let target = name.strip_suffix(SEAL_BACKUP).ok_or(REFUSED)?;
        let bytes =
            Zeroizing::new(custody::read_private_file(&backup, uid, 65536).map_err(|_| REFUSED)?);
        // Never consume the snapshot: another interruption can replay every
        // file, including config.json, from these same durable source bytes.
        rewrite(home, target, &bytes)?;
        after_restore(target)?;
    }
    let restored =
        custody::read_private_file(&home.join("config.json"), uid, 65536).map_err(|_| REFUSED)?;
    let _: Config = serde_json::from_slice(&restored).map_err(|_| REFUSED)?;
    rewrite(home, "complete", digest(&restored).as_bytes())
}
/// Recover the last fully sealed snapshot after an interrupted mutation.
/// Runs before every mutating command so a torn update is always re-runnable;
/// read paths stay strict and still refuse a torn home.
pub(super) fn recover_seal(home: &Path) -> Result<(), String> {
    let (_, uid) = owner(home)?;
    let (pending, backups) = seal_scratch(home, uid)?;
    let consistent = sealed_config(home, uid);
    let config_backup = backups.iter().any(|name| name == "config.json.seal-backup");
    match (pending.as_deref(), consistent.as_deref()) {
        // No mutation in progress; stale backups are inert scratch.
        (None, Some(_)) => {
            load(home)?;
            remove_seal_scratch(home, &backups)
        }
        // A mutation stopped before the config phase: restore every backup.
        (Some(b"files"), _) if config_backup => {
            restore_seal_backups(home, &backups)?;
            load(home)?;
            remove_seal_scratch(home, &backups)
        }
        // The config pair sealed (old or new). If the live config is still the
        // backup, the commit never happened and data files may have drifted.
        (Some(b"committing"), Some(config)) if config_backup => {
            let backup =
                custody::read_private_file(&home.join("config.json.seal-backup"), uid, 65536)
                    .map_err(|_| REFUSED)?;
            if config == backup.as_slice() {
                restore_seal_backups(home, &backups)?;
            }
            load(home)?;
            remove_seal_scratch(home, &backups)
        }
        // Torn between the config and seal writes: restore the snapshot.
        (Some(b"committing"), None) if config_backup => {
            restore_seal_backups(home, &backups)?;
            load(home)?;
            remove_seal_scratch(home, &backups)
        }
        _ => Err("sealed host recovery is uncertain; preserve seal.pending, every backup and the exact home for diagnosis; never reset retained custody".into()),
    }
}
pub(super) fn recover(home: &Path) -> Result<(), String> {
    let _maintenance = maintenance_lock(home)?;
    recover_seal(home)
}
/// Begin a sealed mutation: back up `config.json` plus every named file that
/// exists, then mark the file phase. Callers must pass a `load`ed home.
pub(super) fn begin_seal(home: &Path, extra: &[&str]) -> Result<(), String> {
    recover_seal(home)?;
    let (_, uid) = owner(home)?;
    for name in ["config.json"].iter().chain(extra.iter()) {
        let path = home.join(name);
        if custody::private_file_present(&path, uid, 65536).map_err(|_| REFUSED)? {
            let bytes = custody::read_private_file(&path, uid, 65536).map_err(|_| REFUSED)?;
            rewrite(home, &format!("{name}{SEAL_BACKUP}"), &bytes)?;
        }
    }
    rewrite(home, SEAL_PENDING, b"files")
}
/// Mark the commit phase: data files are now durable; only the pair remains.
pub(super) fn seal_files(home: &Path) -> Result<(), String> {
    rewrite(home, SEAL_PENDING, b"committing")
}
/// Publish the mutated config and its seal, then clear mutation scratch.
pub(super) fn commit_seal(home: &Path, config: &Config) -> Result<(), String> {
    validate_config(home, config)?;
    for name in expected_files(config) {
        if config.files.get(&name) != Some(&digest(&read(home, &name, 65536)?)) {
            return Err(REFUSED.into());
        }
    }
    let bytes = serde_json::to_vec(config).map_err(|_| REFUSED)?;
    rewrite(home, "config.json", &bytes)?;
    rewrite(home, "complete", digest(&bytes).as_bytes())?;
    let (_, uid) = owner(home)?;
    let (_, backups) = seal_scratch(home, uid)?;
    remove_seal_scratch(home, &backups)
}

/// Mint one additional client credential under the retained CA and namespace.
/// The new `client-N.token` is created before the sealed manifest references
/// it, so a crash leaves inert residue rather than a dangling commitment.
pub(super) fn add_credential(home: &Path) -> Result<(usize, String), String> {
    let _maintenance = maintenance_lock(home)?;
    super::generation::require_idle(home)?;
    recover_seal(home)?;
    let loaded = load(home)?;
    if loaded.config.credential_ids.len() >= 64 {
        return Err("credential enrollment is bounded at 64 client identities".into());
    }
    let index = loaded.config.credential_ids.len() + 1;
    let name = format!("client-{index}.token");
    let token = random::<32>()?;
    // Additive unlisted file first; a torn run rewrites the same name safely.
    rewrite(
        &loaded.home,
        &name,
        Zeroizing::new(hex(token.as_ref())).as_bytes(),
    )?;
    begin_seal(&loaded.home, &[])?;
    let mut config = loaded.config.clone();
    let id = hex(random::<16>()?.as_ref());
    config.credential_ids.push(id.clone());
    if config.version >= 2 {
        config.credential_generations.push(1);
    }
    config
        .files
        .insert(name.clone(), digest(&read(&loaded.home, &name, 65)?));
    seal_files(&loaded.home)?;
    commit_seal(&loaded.home, &config)?;
    // Verify the committed credential parses exactly as a restart reads it.
    // Quota enrollment and live admission happen at the next service open, so
    // this never takes the mailbox custody lock of a running server.
    let raw = read_bound(&loaded.home, &config, &name, 65)?;
    let text = std::str::from_utf8(&raw).map_err(|_| REFUSED)?;
    RelayToken::from_bytes(decode_hex::<32>(text.trim_end_matches('\n'))?).map_err(|_| REFUSED)?;
    Ok((index, id))
}

/// Synthetic namespace mutation retained only to exercise the maintenance
/// barrier. Production rotation refuses: changing this selection cannot migrate
/// pending or uncertain client work and must never be exposed as recovery.
#[cfg(test)]
fn rotate(home: &Path) -> Result<(String, String), String> {
    let _maintenance = maintenance_lock(home)?;
    recover_seal(home)?;
    let loaded = load(home)?;
    let mut index = 2u32;
    for entry in fs::read_dir(&loaded.home).map_err(|_| REFUSED)? {
        let name = entry.map_err(|_| REFUSED)?.file_name();
        if let Some(n) = name
            .to_str()
            .and_then(|n| n.strip_prefix("mailbox-"))
            .and_then(|raw| raw.parse::<u32>().ok())
        {
            index = index.max(n.saturating_add(1));
        }
    }
    let mailbox = format!("mailbox-{index}");
    let namespace = RelayNamespace::from_bytes(*random::<32>()?).map_err(|_| REFUSED)?;
    // Create and enroll the new mailbox before any sealed mutation; a torn
    // creation leaves a bounded inert directory that the next run skips.
    let store = FileStore::create_new(
        loaded.home.join(&mailbox),
        namespace,
        Limits {
            max_items: 4096,
            max_bytes: 256 * 1024 * 1024,
        },
    )
    .map_err(|_| REFUSED)?;
    Service::initialize(store).map_err(|_| REFUSED)?;
    begin_seal(&loaded.home, &["connection.json"])?;
    let mut config = loaded.config.clone();
    let previous = std::mem::replace(&mut config.namespace, hex(namespace.as_bytes()));
    config.mailbox = mailbox.clone();
    let connection = connection_document(&loaded.home, &config, Some(&previous))?;
    rewrite(&loaded.home, "connection.json", &connection)?;
    config.files.insert(
        "connection.json".to_owned(),
        digest(&read(&loaded.home, "connection.json", 65536)?),
    );
    seal_files(&loaded.home)?;
    commit_seal(&loaded.home, &config)?;
    // Prove the rotated selection opens exactly as a restart will see it.
    drop(service(&loaded.home, &config)?);
    Ok((config.namespace, mailbox))
}

/// Reissue the serving leaf under the retained CA. The binding, namespace,
/// mailbox, credential set and CA are unchanged; only `server.der`,
/// `server-key.der`, the expiry in `connection.json` and the sealed manifest
/// advance. Renewal refuses without the CA private key and never weakens the
/// owner-private modes of the files it replaces.
pub(super) fn renew(home: &Path, leaf_days: Option<i64>) -> Result<i64, String> {
    renew_at(home, leaf_days, time::OffsetDateTime::now_utc())
}
pub(super) fn upgrade_config(config: &mut Config) {
    if config.version == 1 {
        config.version = 2;
        config.credential_generations = vec![1; config.credential_ids.len()];
    }
}
fn renew_at(home: &Path, leaf_days: Option<i64>, now: time::OffsetDateTime) -> Result<i64, String> {
    let _maintenance = maintenance_lock(home)?;
    super::generation::require_idle(home)?;
    recover_seal(home)?;
    let loaded = load(home)?;
    let lifetime = match leaf_days {
        Some(days) => days.checked_mul(86400).ok_or(REFUSED)?,
        None => loaded.config.leaf_lifetime_seconds.ok_or(
            "legacy leaf lifetime is unknown; renew with explicit --leaf-days once to establish the retained renewal policy",
        )?,
    };
    if !valid_leaf_lifetime(lifetime) {
        return Err(
            "leaf lifetime must be positive and shorter than the five-year CA lifetime".into(),
        );
    }
    let ca_key = read_bound(&loaded.home, &loaded.config, "ca-key.der", 65536).map_err(|_| {
        "leaf renewal requires the retained CA private key; preserve custody, never replace the CA"
    })?;
    let issuer_key = KeyPair::try_from(ca_key.to_vec()).map_err(|_| REFUSED)?;
    // Rebuilt issuer params give `signed_by` the same subject name and key
    // identifier as the original CA object, so the new leaf chains to ca.der.
    let authority = time::OffsetDateTime::from_unix_timestamp(loaded.config.authority_expires_at)
        .map_err(|_| REFUSED)?;
    let issuer = issuer_params(
        time::OffsetDateTime::from_unix_timestamp(loaded.config.created_at).map_err(|_| REFUSED)?
            - time::Duration::minutes(5),
        authority,
    )?
    .self_signed(&issuer_key)
    .map_err(|_| REFUSED)?;
    // Renewal preserves the operator's chosen leaf lifetime, never the CA's.
    let expires = now
        .checked_add(time::Duration::seconds(lifetime))
        .ok_or(REFUSED)?
        .min(authority - time::Duration::seconds(1));
    if now.unix_timestamp() < loaded.config.created_at - 300 || expires <= now {
        return Err("the retained CA has expired; a new CA is a new host, not a renewal".into());
    }
    let key = KeyPair::generate().map_err(|_| REFUSED)?;
    let leaf = leaf_params(
        &loaded.config.tls_name,
        now - time::Duration::minutes(5),
        expires,
    )?
    .signed_by(&key, &issuer, &issuer_key)
    .map_err(|_| REFUSED)?;
    // Carry a rotation's previous namespace forward unchanged.
    let previous = serde_json::from_slice::<serde_json::Value>(&read_bound(
        &loaded.home,
        &loaded.config,
        "connection.json",
        65536,
    )?)
    .ok()
    .and_then(|v| {
        v.get("previous_namespace")
            .and_then(|p| p.as_str().map(str::to_owned))
    });
    begin_seal(
        &loaded.home,
        &["server.der", "server-key.der", "connection.json"],
    )?;
    rewrite(&loaded.home, "server.der", leaf.der())?;
    rewrite(
        &loaded.home,
        "server-key.der",
        &Zeroizing::new(key.serialize_der()),
    )?;
    let mut config = loaded.config.clone();
    upgrade_config(&mut config);
    config.leaf_lifetime_seconds = Some(lifetime);
    config.certificate_expires_at = expires.unix_timestamp();
    let connection = connection_document(&loaded.home, &config, previous.as_deref())?;
    rewrite(&loaded.home, "connection.json", &connection)?;
    for name in ["server.der", "server-key.der", "connection.json"] {
        config
            .files
            .insert(name.to_owned(), digest(&read(&loaded.home, name, 65536)?));
    }
    seal_files(&loaded.home)?;
    commit_seal(&loaded.home, &config)?;
    // Prove the committed leaf pair loads as a serving TLS configuration
    // without taking the mailbox custody lock of a running server.
    tls::server_config(
        vec![read_bound(&loaded.home, &config, "server.der", 65536)?.to_vec()],
        read_bound(&loaded.home, &config, "server-key.der", 65536)?.to_vec(),
    )
    .map_err(|_| REFUSED)?;
    Ok(config.certificate_expires_at)
}

/// Revoke an identity, or replace its token without resetting its quota. Old
/// token generations remain sealed owner-private evidence; no overlap is
/// admitted. A running service keeps its startup selection until drained.
pub(super) fn credential_lifecycle(
    home: &Path,
    index: usize,
    replace: bool,
) -> Result<(String, u32), String> {
    let _maintenance = maintenance_lock(home)?;
    super::generation::require_idle(home)?;
    recover_seal(home)?;
    let loaded = load(home)?;
    let offset = index
        .checked_sub(1)
        .ok_or("credential index must select an enrolled identity")?;
    let id = loaded
        .config
        .credential_ids
        .get(offset)
        .ok_or("credential index must select an enrolled identity")?
        .clone();
    let mut config = loaded.config.clone();
    upgrade_config(&mut config);
    let generation = config.credential_generations[offset];
    if replace {
        let retired: usize = config
            .credential_generations
            .iter()
            .map(|generation| (generation - 1) as usize)
            .sum();
        if retired >= 64 {
            return Err("retained token history is bounded at 64 replacements; preserve the home and select a separately reviewed migration".into());
        }
        let name = format!("client-{index}.token");
        let old = read_bound(&loaded.home, &loaded.config, &name, 65)?;
        let history = format!("client-{index}.generation-{generation}.token");
        let token = random::<32>()?;
        // Additive history precedes the transaction. An interrupted attempt
        // may leave an unlisted identical copy, never an admitted credential.
        rewrite(&loaded.home, &history, &old)?;
        begin_seal(&loaded.home, &[&name])?;
        rewrite(
            &loaded.home,
            &name,
            Zeroizing::new(hex(token.as_ref())).as_bytes(),
        )?;
        config.files.insert(history, digest(&old));
        config
            .files
            .insert(name.clone(), digest(&read(&loaded.home, &name, 65)?));
        config.credential_generations[offset] += 1;
        config.revoked_credential_ids.remove(&id);
    } else {
        if config.revoked_credential_ids.contains(&id) {
            return Ok((id, generation));
        }
        begin_seal(&loaded.home, &[])?;
        config.revoked_credential_ids.insert(id.clone());
    }
    seal_files(&loaded.home)?;
    commit_seal(&loaded.home, &config)?;
    Ok((id, config.credential_generations[offset]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    struct Home(PathBuf);
    impl Home {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "vhalla-host-maintenance-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let home = root.join("host");
            initialize_with_leaf_lifetime(
                &home,
                "127.0.0.1:9473".parse().unwrap(),
                "maintenance.test.invalid",
                &std::env::current_exe().unwrap(),
                time::Duration::days(1),
            )
            .unwrap();
            Self(home)
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(self.0.parent().unwrap());
        }
    }
    fn snapshot(home: &Path) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(home)
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.file_type().unwrap().is_file())
            .map(|entry| {
                (
                    entry.file_name().into_string().unwrap(),
                    fs::read(entry.path()).unwrap(),
                )
            })
            .collect()
    }
    fn legacy(home: &Path) {
        let mut config = load(home).unwrap().config;
        config.version = 1;
        config.credential_generations.clear();
        config.leaf_lifetime_seconds = None;
        let bytes = serde_json::to_vec(&config).unwrap();
        rewrite(home, "config.json", &bytes).unwrap();
        rewrite(home, "complete", digest(&bytes).as_bytes()).unwrap();
        assert!(load(home).is_ok());
    }
    #[test]
    fn repeated_renewal_preserves_policy_and_ca_boundary_remains_loadable() {
        let home = Home::new();
        let config = load(&home.0).unwrap().config;
        let origin = time::OffsetDateTime::from_unix_timestamp(config.created_at).unwrap();
        for day in [1, 2, 3, 40, 400] {
            let now = origin + time::Duration::days(day);
            let expiry = renew_at(&home.0, None, now).unwrap();
            assert_eq!(expiry - now.unix_timestamp(), 86400);
            assert_eq!(
                load(&home.0).unwrap().config.leaf_lifetime_seconds,
                Some(86400)
            );
        }
        let before_ca =
            time::OffsetDateTime::from_unix_timestamp(config.authority_expires_at - 60).unwrap();
        assert_eq!(
            renew_at(&home.0, None, before_ca).unwrap(),
            config.authority_expires_at - 1
        );
        assert!(load(&home.0).is_ok());
        let before = snapshot(&home.0);
        assert!(renew_at(&home.0, None, before_ca + time::Duration::seconds(59)).is_err());
        assert_eq!(snapshot(&home.0), before);
    }
    #[test]
    fn legacy_home_requires_explicit_renewal_policy_and_migrates_without_rebinding() {
        let home = Home::new();
        legacy(&home.0);
        assert!(!home.0.join("maintenance.lock").exists());
        let old = load(&home.0).unwrap();
        let ca = read(&home.0, "ca.der", 65536).unwrap();
        // Read and stop selection remain compatible and create no lock file.
        load_for_stop(&home.0).unwrap();
        assert!(!home.0.join("maintenance.lock").exists());
        drop(service(&home.0, &old.config).unwrap());
        assert!(renew(&home.0, None)
            .unwrap_err()
            .contains("explicit --leaf-days"));
        assert_eq!(load(&home.0).unwrap().config.version, 1);
        renew(&home.0, Some(2)).unwrap();
        let new = load(&home.0).unwrap();
        assert_eq!(new.config.version, 2);
        assert_eq!(new.config.leaf_lifetime_seconds, Some(2 * 86400));
        assert_eq!(new.config.credential_ids, old.config.credential_ids);
        assert_eq!(new.config.namespace, old.config.namespace);
        assert_eq!(new.config.mailbox, old.config.mailbox);
        assert_eq!(
            read(&home.0, "ca.der", 65536).unwrap().as_slice(),
            ca.as_slice()
        );
        // The legacy version check refuses this selection before interpreting
        // any new credential semantics; wire/CA/mailbox formats stay unchanged.
        assert_ne!(new.config.version, 1);
    }
    #[test]
    fn interrupted_restore_replays_every_backup_without_consuming_evidence() {
        for boundary in 0..4 {
            let home = Home::new();
            let _lock = maintenance_lock(&home.0).unwrap();
            let before = snapshot(&home.0);
            begin_seal(
                &home.0,
                &["server.der", "server-key.der", "connection.json"],
            )
            .unwrap();
            for name in [
                "config.json",
                "server.der",
                "server-key.der",
                "connection.json",
            ] {
                rewrite(&home.0, name, b"interrupted mutation").unwrap();
            }
            let (_, uid) = owner(&home.0).unwrap();
            let (_, mut backups) = seal_scratch(&home.0, uid).unwrap();
            backups.sort();
            let mut restored = 0;
            assert!(restore_seal_backups_with(&home.0, &backups, |_| {
                let at = restored;
                restored += 1;
                if at == boundary {
                    Err("injected recovery interruption".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
            for backup in &backups {
                assert!(home.0.join(backup).exists());
            }
            recover_seal(&home.0).unwrap();
            recover_seal(&home.0).unwrap();
            assert_eq!(snapshot(&home.0), before);
            load(&home.0).unwrap();
        }
    }
    #[test]
    fn maintenance_busy_precedes_mutation_and_does_not_take_mailbox_custody() {
        let home = Home::new();
        let service = service(&home.0, &load(&home.0).unwrap().config).unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let path = home.0.clone();
        let thread = std::thread::spawn(move || {
            let _lock = maintenance_lock(&path).unwrap();
            begin_seal(&path, &["server.der"]).unwrap();
            ready_tx.send(()).unwrap();
            done_rx.recv().unwrap();
            recover_seal(&path).unwrap();
        });
        ready_rx.recv().unwrap();
        let before = snapshot(&home.0);
        for result in [
            add_credential(&home.0).map(|_| ()),
            rotate(&home.0).map(|_| ()),
            renew(&home.0, None).map(|_| ()),
            recover(&home.0),
            credential_lifecycle(&home.0, 1, false).map(|_| ()),
        ] {
            assert!(result.unwrap_err().contains("maintenance busy"));
            assert_eq!(snapshot(&home.0), before);
        }
        done_tx.send(()).unwrap();
        thread.join().unwrap();
        // Maintenance succeeds while the original service still holds mailbox
        // writer custody; only the next service open activates this selection.
        renew(&home.0, None).unwrap();
        add_credential(&home.0).unwrap();
        drop(service);
    }
    #[test]
    fn invalid_proposed_manifest_never_publishes_and_torn_commit_rolls_back() {
        let home = Home::new();
        let _lock = maintenance_lock(&home.0).unwrap();
        let before = snapshot(&home.0);
        let mut config = load(&home.0).unwrap().config;
        begin_seal(&home.0, &[]).unwrap();
        seal_files(&home.0).unwrap();
        config.certificate_expires_at = config.authority_expires_at;
        assert!(commit_seal(&home.0, &config).is_err());
        recover_seal(&home.0).unwrap();
        assert_eq!(snapshot(&home.0), before);
        begin_seal(&home.0, &[]).unwrap();
        seal_files(&home.0).unwrap();
        rewrite(&home.0, "config.json", b"torn config/complete pair").unwrap();
        recover_seal(&home.0).unwrap();
        assert_eq!(snapshot(&home.0), before);
    }
    #[test]
    fn missing_recovery_evidence_and_linked_lock_refuse_without_repair() {
        let home = Home::new();
        {
            let _lock = maintenance_lock(&home.0).unwrap();
            begin_seal(&home.0, &["server.der"]).unwrap();
            rewrite(&home.0, "server.der", b"unsealed leaf").unwrap();
            fs::rename(
                home.0.join("config.json.seal-backup"),
                home.0.join("retained-config-evidence"),
            )
            .unwrap();
        }
        let before = snapshot(&home.0);
        assert!(recover(&home.0)
            .unwrap_err()
            .contains("recovery is uncertain"));
        assert_eq!(snapshot(&home.0), before);
        fs::rename(
            home.0.join("retained-config-evidence"),
            home.0.join("config.json.seal-backup"),
        )
        .unwrap();
        recover(&home.0).unwrap();
        fs::rename(
            home.0.join("maintenance.lock"),
            home.0.join("retained-lock"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            home.0.join("retained-lock"),
            home.0.join("maintenance.lock"),
        )
        .unwrap();
        let before = fs::read(home.0.join("config.json")).unwrap();
        assert!(add_credential(&home.0).is_err());
        assert_eq!(fs::read(home.0.join("config.json")).unwrap(), before);
        assert!(fs::symlink_metadata(home.0.join("maintenance.lock"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
    #[test]
    fn invalid_leaf_lifetime_refuses_before_creating_home() {
        let parent =
            std::env::temp_dir().join(format!("vhalla-host-invalid-ttl-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
        for days in [0, 365 * 5, 3650] {
            let home = parent.join(format!("home-{days}"));
            assert!(initialize_with_leaf_lifetime(
                &home,
                "127.0.0.1:9473".parse().unwrap(),
                "ttl.test.invalid",
                &std::env::current_exe().unwrap(),
                time::Duration::days(days)
            )
            .is_err());
            let mutated = home.exists();
            if mutated {
                fs::remove_dir_all(&home).unwrap();
            }
            assert!(!mutated, "invalid lifetime must not create a partial home");
        }
        fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn exact_stop_selection_survives_missing_credentials_without_repairing_them() {
        let parent =
            std::env::temp_dir().join(format!("vhalla-host-stop-evidence-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let home = parent.join("home");
        initialize(
            &home,
            "127.0.0.1:9473".parse().unwrap(),
            "stop.test.invalid",
            &std::env::current_exe().unwrap(),
        )
        .unwrap();
        let source = home.join("client-1.token");
        let retained = home.join("retained-token");
        fs::rename(&source, &retained).unwrap();
        let bytes = fs::read(&retained).unwrap();
        assert!(load(&home).is_err());
        assert!(load_for_stop(&home).is_ok());
        assert!(!source.exists());
        assert_eq!(fs::read(&retained).unwrap(), bytes);
        let template = home.join("launch-agent.plist");
        let original = fs::read(&template).unwrap();
        fs::write(&template, b"foreign selection").unwrap();
        assert!(load_for_stop(&home).is_err());
        assert_eq!(fs::read(&template).unwrap(), b"foreign selection");
        fs::write(&template, original).unwrap();
        fs::rename(&retained, &source).unwrap();
        let selected = load(&home).unwrap();
        let changed = b"1111111111111111111111111111111111111111111111111111111111111111";
        fs::write(&source, changed).unwrap();
        assert!(
            service(&home, &selected.config).is_err(),
            "a replaced credential after validation cannot alter admitted service authority"
        );
        assert_eq!(fs::read(&source).unwrap(), changed);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn formal_host_recovery_absent_marker_sync_failure_preserves_every_backup() {
        let home = Home::new();
        let _lock = maintenance_lock(&home.0).unwrap();
        let sealed = snapshot(&home.0);
        begin_seal(&home.0, &["server.der", "connection.json"]).unwrap();
        let (_, uid) = owner(&home.0).unwrap();
        let (_, backups) = seal_scratch(&home.0, uid).unwrap();
        // This is the visible state a retry can see after process interruption
        // between unlink and sync. The test checks ordering, not power loss.
        fs::remove_file(home.0.join(SEAL_PENDING)).unwrap();
        let before = snapshot(&home.0);
        let mut syncs = 0;
        assert!(remove_seal_scratch_with(&home.0, &backups, |_| {
            syncs += 1;
            Err(std::io::Error::other("injected directory sync failure"))
        })
        .is_err());
        assert_eq!(syncs, 1);
        assert_eq!(snapshot(&home.0), before, "no backup may precede the fence");
        recover_seal(&home.0).unwrap();
        recover_seal(&home.0).unwrap();
        assert_eq!(snapshot(&home.0), sealed);
    }

    #[test]
    fn formal_host_recovery_two_interruptions_retain_exact_snapshot() {
        for first in 0..4 {
            for second in 0..4 {
                let home = Home::new();
                let _lock = maintenance_lock(&home.0).unwrap();
                let sealed = snapshot(&home.0);
                begin_seal(
                    &home.0,
                    &["server.der", "server-key.der", "connection.json"],
                )
                .unwrap();
                for name in [
                    "config.json",
                    "server.der",
                    "server-key.der",
                    "connection.json",
                ] {
                    rewrite(&home.0, name, b"interrupted update").unwrap();
                }
                let (_, uid) = owner(&home.0).unwrap();
                let (_, mut backups) = seal_scratch(&home.0, uid).unwrap();
                backups.sort();
                let retained: BTreeMap<_, _> = backups
                    .iter()
                    .map(|name| (name.clone(), fs::read(home.0.join(name)).unwrap()))
                    .collect();
                for boundary in [first, second] {
                    let mut restored = 0;
                    assert!(restore_seal_backups_with(&home.0, &backups, |_| {
                        let at = restored;
                        restored += 1;
                        if at == boundary {
                            Err("injected repeated recovery interruption".into())
                        } else {
                            Ok(())
                        }
                    })
                    .is_err());
                    for (name, bytes) in &retained {
                        assert_eq!(fs::read(home.0.join(name)).unwrap(), *bytes);
                    }
                }
                recover_seal(&home.0).unwrap();
                recover_seal(&home.0).unwrap();
                assert_eq!(snapshot(&home.0), sealed);
                load(&home.0).unwrap();
            }
        }
    }

    #[test]
    fn formal_host_recovery_matching_pair_still_checks_live_commitments() {
        let home = Home::new();
        let _lock = maintenance_lock(&home.0).unwrap();
        let mut config = load(&home.0).unwrap().config;
        begin_seal(&home.0, &["connection.json"]).unwrap();
        let new_connection = b"new synthetic connection document";
        rewrite(&home.0, "connection.json", new_connection).unwrap();
        let (_, uid) = owner(&home.0).unwrap();
        assert!(sealed_config(&home.0, uid).is_some());
        assert!(
            load(&home.0).is_err(),
            "the old pair cannot admit mixed files"
        );
        config
            .files
            .insert("connection.json".into(), digest(new_connection));
        seal_files(&home.0).unwrap();
        let bytes = serde_json::to_vec(&config).unwrap();
        rewrite(&home.0, "config.json", &bytes).unwrap();
        rewrite(&home.0, "complete", digest(&bytes).as_bytes()).unwrap();
        load(&home.0).unwrap();

        rewrite(&home.0, "connection.json", b"drifted live file").unwrap();
        assert!(sealed_config(&home.0, uid).is_some());
        assert!(load(&home.0).is_err());
        let before = snapshot(&home.0);
        assert!(recover_seal(&home.0).is_err());
        assert_eq!(
            snapshot(&home.0),
            before,
            "refusal retains recovery evidence"
        );

        rewrite(&home.0, "connection.json", new_connection).unwrap();
        recover_seal(&home.0).unwrap();
        assert_eq!(
            read(&home.0, "config.json", 65536).unwrap().as_slice(),
            bytes
        );
        assert_eq!(seal_scratch(&home.0, uid).unwrap(), (None, Vec::new()));
        load(&home.0).unwrap();
    }

    #[test]
    fn formal_host_recovery_partial_cleanup_retries_without_changing_snapshot() {
        for removed in 0..=3 {
            let home = Home::new();
            let _lock = maintenance_lock(&home.0).unwrap();
            let sealed = snapshot(&home.0);
            begin_seal(&home.0, &["server.der", "connection.json"]).unwrap();
            let (directory, uid) = owner(&home.0).unwrap();
            let (_, mut backups) = seal_scratch(&home.0, uid).unwrap();
            backups.sort();
            fs::remove_file(home.0.join(SEAL_PENDING)).unwrap();
            directory.sync_all().unwrap();
            for name in backups.iter().take(removed) {
                fs::remove_file(home.0.join(name)).unwrap();
            }
            recover_seal(&home.0).unwrap();
            recover_seal(&home.0).unwrap();
            assert_eq!(snapshot(&home.0), sealed);
            load(&home.0).unwrap();
        }
    }

    #[test]
    fn formal_host_recovery_corrupt_backup_refuses_before_any_restore() {
        let home = Home::new();
        let _lock = maintenance_lock(&home.0).unwrap();
        begin_seal(&home.0, &["server.der", "connection.json"]).unwrap();
        for name in ["config.json", "server.der", "connection.json"] {
            rewrite(&home.0, name, b"interrupted update").unwrap();
        }
        let (_, uid) = owner(&home.0).unwrap();
        let (_, mut backups) = seal_scratch(&home.0, uid).unwrap();
        backups.sort();
        rewrite(&home.0, backups.last().unwrap(), b"corrupt backup").unwrap();
        let before = snapshot(&home.0);
        assert!(recover_seal(&home.0).is_err());
        assert_eq!(snapshot(&home.0), before);
    }
}
