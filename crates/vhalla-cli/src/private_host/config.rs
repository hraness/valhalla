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
use vhalla_private_native::relay::{tls::Service, FileStore, Limits, RelayNamespace};
use zeroize::Zeroizing;

const FILES: [&str; 8] = [
    "ca.der",
    "ca-key.der",
    "server.der",
    "server-key.der",
    "client-1.token",
    "client-2.token",
    "connection.json",
    "launch-agent.plist",
];
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub version: u32,
    pub label: String,
    pub listen: SocketAddr,
    pub tls_name: String,
    pub executable: PathBuf,
    pub namespace: String,
    pub credential_ids: [String; 2],
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

pub(super) fn initialize(
    path: &Path,
    listen: SocketAddr,
    name: &str,
    executable: &Path,
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
    let expires = now + time::Duration::days(365);
    let authority_expires = now + time::Duration::days(365 * 5);
    let issuer_key = KeyPair::generate().map_err(|_| REFUSED)?;
    let mut issuer = CertificateParams::new(Vec::<String>::new()).map_err(|_| REFUSED)?;
    issuer.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    issuer.not_before = now - time::Duration::minutes(5);
    issuer.not_after = authority_expires;
    issuer.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let issuer = issuer.self_signed(&issuer_key).map_err(|_| REFUSED)?;
    let key = KeyPair::generate().map_err(|_| REFUSED)?;
    let mut leaf =
        CertificateParams::new(vec![name.to_owned()]).map_err(|_| "invalid TLS server name")?;
    leaf.not_before = now - time::Duration::minutes(5);
    leaf.not_after = expires;
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf
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
        credential_ids: [hex(random::<16>()?.as_ref()), hex(random::<16>()?.as_ref())],
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
    let connection = serde_json::json!({"version":1,"namespace":config.namespace,"listen":listen,"tls_name":name,"ca_file":"ca.der","ca_sha256":digest(issuer.der()),"certificate_expires_at":config.certificate_expires_at,"transport":"TLS 1.3; copy CA and one separate private credential through a trusted channel","client_tokens":"not included"});
    write(
        &home,
        "connection.json",
        &serde_json::to_vec(&connection).map_err(|_| REFUSED)?,
    )?;
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
    for name in FILES {
        config
            .files
            .insert(name.to_owned(), digest(&read(&home, name, 65536)?));
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
        || config.files.len() != FILES.len()
    {
        return Err(REFUSED.into());
    }
    RelayNamespace::from_bytes(decode_hex(&config.namespace)?).map_err(|_| REFUSED)?;
    if config.credential_ids[0] == config.credential_ids[1] {
        return Err(REFUSED.into());
    }
    for id in &config.credential_ids {
        if decode_hex::<16>(id)? == [0; 16] {
            return Err(REFUSED.into());
        }
    }
    for name in FILES {
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

pub(super) fn load(path: &Path) -> Result<Loaded, String> {
    let loaded = load_for_stop(path)?;
    for name in FILES {
        if loaded.config.files.get(name) != Some(&digest(&read(&loaded.home, name, 65536)?)) {
            return Err(REFUSED.into());
        }
    }
    Ok(loaded)
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
