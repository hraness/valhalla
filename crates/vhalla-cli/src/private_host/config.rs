//! Immutable host selection and owner-private, fail-closed initialization.
use super::{launchd, service, REFUSED};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
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
fn expected_files(credentials: usize) -> Vec<String> {
    STATIC_FILES
        .iter()
        .map(|name| (*name).to_owned())
        .chain((1..=credentials).map(|index| format!("client-{index}.token")))
        .collect()
}
fn default_mailbox() -> String {
    "mailbox".into()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub version: u32,
    pub label: String,
    pub listen: SocketAddr,
    pub tls_name: String,
    pub executable: PathBuf,
    pub namespace: String,
    /// Stable random credential identities; the token files are `client-N.token`.
    pub credential_ids: Vec<String>,
    /// Mailbox directory relative to the home. Rotation advances it while
    /// every earlier mailbox directory remains untouched evidence.
    #[serde(default = "default_mailbox")]
    pub mailbox: String,
    pub created_at: i64,
    pub certificate_expires_at: i64,
    pub authority_expires_at: i64,
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
fn digest(bytes: &[u8]) -> String {
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
    if !super::loopback(listen) || listen.port() == 0 || name.len() > 253 || name.is_empty() {
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
    let authority_expires = now + time::Duration::days(365 * 5);
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
        version: 1,
        label: label(&home)?,
        listen,
        tls_name: name.to_owned(),
        executable,
        namespace: hex(namespace.as_bytes()),
        credential_ids: vec![hex(random::<16>()?.as_ref()), hex(random::<16>()?.as_ref())],
        mailbox: default_mailbox(),
        created_at: now.unix_timestamp(),
        certificate_expires_at: expires.unix_timestamp(),
        authority_expires_at: authority_expires.unix_timestamp(),
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
    for name in expected_files(config.credential_ids.len()) {
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
    let bytes = read(&home, "config.json", 16384)?;
    if read(&home, "complete", 64)?.as_slice() != digest(&bytes).as_bytes() {
        return Err(REFUSED.into());
    }
    let config: Config = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
    if config.version != 1
        || config.label != label(&home)?
        || !super::loopback(config.listen)
        || config.listen.port() == 0
        || !config.executable.is_absolute()
        || config.certificate_expires_at <= config.created_at
        || config.authority_expires_at <= config.certificate_expires_at
        || !(2..=64).contains(&config.credential_ids.len())
        || !valid_mailbox(&config.mailbox)
    {
        return Err(REFUSED.into());
    }
    RelayNamespace::from_bytes(decode_hex(&config.namespace)?).map_err(|_| REFUSED)?;
    let expected = expected_files(config.credential_ids.len());
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
    let template = read(&home, "launch-agent.plist", 65536)?;
    if config.files.get("launch-agent.plist") != Some(&digest(&template))
        || template.as_slice() != launchd::plist(&home, &config)?.as_bytes()
    {
        return Err(REFUSED.into());
    }
    Ok(Loaded { home, config })
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
    for name in expected_files(loaded.config.credential_ids.len()) {
        if loaded.config.files.get(&name) != Some(&digest(&read(&loaded.home, &name, 65536)?)) {
            return Err(REFUSED.into());
        }
    }
    Ok(loaded)
}

/// The client-facing document a member copies into a delivery profile. It
/// carries no token and no private path outside the home.
fn connection_document(
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
    let config = custody::read_private_file(&home.join("config.json"), uid, 16384).ok()?;
    let complete = custody::read_private_file(&home.join("complete"), uid, 64).ok()?;
    (complete.as_slice() == digest(&config).as_bytes()).then_some(config)
}
fn remove_seal_scratch(home: &Path, backups: &[String]) -> Result<(), String> {
    let (directory, uid) = owner(home)?;
    let pending = home.join(SEAL_PENDING);
    if custody::private_file_present(&pending, uid, 64).map_err(|_| REFUSED)? {
        fs::remove_file(&pending).map_err(|_| REFUSED)?;
    }
    for name in backups {
        // A restored backup was renamed over its target; absence is expected.
        match fs::remove_file(home.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(REFUSED.into()),
        }
    }
    directory.sync_all().map_err(|_| REFUSED.into())
}
/// Restore every backup over its sealed name and recompute `complete` from the
/// restored config, returning the home to the pre-mutation snapshot.
fn restore_seal_backups(home: &Path, backups: &[String]) -> Result<(), String> {
    let (directory, uid) = owner(home)?;
    for name in backups {
        let backup = home.join(name);
        if !custody::private_file_present(&backup, uid, 65536).map_err(|_| REFUSED)? {
            return Err(REFUSED.into());
        }
        let target = name.strip_suffix(SEAL_BACKUP).ok_or(REFUSED)?;
        fs::rename(&backup, home.join(target)).map_err(|_| REFUSED)?;
    }
    directory.sync_all().map_err(|_| REFUSED)?;
    let restored =
        custody::read_private_file(&home.join("config.json"), uid, 16384).map_err(|_| REFUSED)?;
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
        (None, Some(_)) => remove_seal_scratch(home, &backups),
        // A mutation stopped before the config phase: restore every backup.
        (Some(b"files"), _) if config_backup => {
            restore_seal_backups(home, &backups)?;
            remove_seal_scratch(home, &backups)
        }
        // The config pair sealed (old or new). If the live config is still the
        // backup, the commit never happened and data files may have drifted.
        (Some(b"committing"), Some(config)) if config_backup => {
            let backup =
                custody::read_private_file(&home.join("config.json.seal-backup"), uid, 16384)
                    .map_err(|_| REFUSED)?;
            if config == backup.as_slice() {
                restore_seal_backups(home, &backups)?;
            }
            remove_seal_scratch(home, &backups)
        }
        // Torn between the config and seal writes: restore the snapshot.
        (Some(b"committing"), None) if config_backup => {
            restore_seal_backups(home, &backups)?;
            remove_seal_scratch(home, &backups)
        }
        _ => Err(REFUSED.into()),
    }
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

/// Open a fresh opaque namespace and empty mailbox under the retained CA,
/// credentials and listener. The previous mailbox directory and sealed
/// namespace stay untouched as evidence; members keep their tokens and only
/// point a fresh delivery state at the published new namespace.
pub(super) fn rotate(home: &Path) -> Result<(String, String), String> {
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
pub(super) fn renew(home: &Path) -> Result<i64, String> {
    recover_seal(home)?;
    let loaded = load(home)?;
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
    let now = time::OffsetDateTime::now_utc();
    // Renewal preserves the operator's chosen leaf lifetime, never the CA's.
    let expires = (now
        + time::Duration::seconds(loaded.config.certificate_expires_at - loaded.config.created_at))
    .min(authority);
    if expires <= now {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
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
}
