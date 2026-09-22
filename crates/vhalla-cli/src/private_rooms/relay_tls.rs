//! Explicit TLS endpoint and operator admission configuration, never room custody.
use super::{files, relay_addr, relay_error, relay_token, Args};
use serde_json::Value;
use std::{net::TcpListener, path::Path, time::Duration};
use vhalla_private_native::relay::{
    tls::{self, Credential, Permissions, Service, ServiceLimits, TlsRelay},
    FileStore, Limits, RelayNamespace,
};

pub(super) fn client(args: &Args, namespace: RelayNamespace) -> Result<TlsRelay, String> {
    let ca = args.input("tls-ca", 65536, false)?;
    TlsRelay::new(
        relay_addr(args, "addr")?,
        args.text("tls-name")?,
        ca.to_vec(),
        relay_token(args)?,
        namespace,
    )
    .map_err(super::net_error)
}
fn number(value: &Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("TLS configuration needs unsigned {field}"))
}
fn fields(value: &Value, allowed: &[&str]) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or("TLS configuration object required")?;
    if object.len() != allowed.len() || object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("TLS configuration has missing or unknown fields".into());
    }
    Ok(())
}
fn hex<const N: usize>(value: &Value, field: &str) -> Result<[u8; N], String> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or("TLS configuration hex field required")?;
    hex_text(text)
}
fn hex_text<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("TLS configuration requires canonical lowercase hex".into());
    }
    let mut out = [0; N];
    for (i, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[i] = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_| "TLS hex encoding")?,
            16,
        )
        .map_err(|_| "TLS hex encoding")?;
    }
    Ok(out)
}
pub(super) fn execute(args: &Args) -> Result<(), String> {
    let namespace = args.namespace()?;
    if args.command == "relay-tls-init" {
        return Service::initialize(
            FileStore::open(&args.identity, namespace).map_err(relay_error)?,
        )
        .map_err(super::net_error);
    }
    if args.command != "relay-tls-serve" {
        return Err("unknown TLS service operation".into());
    }
    let listen = relay_addr(args, "listen")?;
    let bytes = args.input("config", 65536, false)?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "malformed TLS service configuration")?;
    fields(
        &value,
        &[
            "max_connections",
            "request_timeout_ms",
            "window_ms",
            "requests_per_window",
            "bytes_per_window",
            "credentials",
        ],
    )?;
    let limits = ServiceLimits {
        max_connections: usize::try_from(number(&value, "max_connections")?)
            .map_err(|_| "TLS connection bound")?,
        request_timeout: Duration::from_millis(number(&value, "request_timeout_ms")?),
        window: Duration::from_millis(number(&value, "window_ms")?),
        requests_per_window: u32::try_from(number(&value, "requests_per_window")?)
            .map_err(|_| "TLS work bound")?,
        bytes_per_window: number(&value, "bytes_per_window")?,
    };
    let keys = value
        .get("credentials")
        .and_then(Value::as_array)
        .ok_or("TLS credentials array required")?;
    if keys.is_empty() || keys.len() > 64 {
        return Err("TLS credential count must be 1..64".into());
    }
    let mut credentials = Vec::with_capacity(keys.len());
    for key in keys {
        fields(
            key,
            &[
                "id",
                "namespace",
                "token_files",
                "put",
                "page",
                "max_items",
                "max_bytes",
                "max_inflight",
                "requests_per_window",
                "bytes_per_window",
            ],
        )?;
        let paths = key
            .get("token_files")
            .and_then(Value::as_array)
            .ok_or("TLS token_files array required")?;
        if paths.is_empty() || paths.len() > 2 {
            return Err("TLS identity needs one or two token files".into());
        }
        let mut tokens = Vec::with_capacity(paths.len());
        for path in paths {
            let path = path.as_str().ok_or("TLS token file path required")?;
            let raw = files::read(Path::new(path), 65, false)?;
            let text = std::str::from_utf8(&raw).map_err(|_| "TLS token encoding")?;
            let token = hex_text::<32>(text.strip_suffix('\n').unwrap_or(text))?;
            tokens.push(
                vhalla_private_native::relay::net::RelayToken::from_bytes(token)
                    .map_err(super::net_error)?,
            );
        }
        credentials.push(Credential {
            id: hex(key, "id")?,
            namespace: RelayNamespace::from_bytes(hex(key, "namespace")?).map_err(relay_error)?,
            tokens,
            permissions: Permissions {
                put: key
                    .get("put")
                    .and_then(Value::as_bool)
                    .ok_or("TLS put boolean required")?,
                page: key
                    .get("page")
                    .and_then(Value::as_bool)
                    .ok_or("TLS page boolean required")?,
            },
            storage: Limits {
                max_items: usize::try_from(number(key, "max_items")?)
                    .map_err(|_| "TLS storage count")?,
                max_bytes: usize::try_from(number(key, "max_bytes")?)
                    .map_err(|_| "TLS storage bytes")?,
            },
            max_inflight: usize::try_from(number(key, "max_inflight")?)
                .map_err(|_| "TLS inflight count")?,
            requests_per_window: u32::try_from(number(key, "requests_per_window")?)
                .map_err(|_| "TLS credential work bound")?,
            bytes_per_window: number(key, "bytes_per_window")?,
        });
    }
    let cert = args.input("cert", 65536, false)?;
    let key = args.input("key", 65536, false)?;
    let config = tls::server_config(vec![cert.to_vec()], key.to_vec()).map_err(super::net_error)?;
    let service = Service::new(
        FileStore::open(&args.identity, namespace).map_err(relay_error)?,
        config,
        credentials,
        limits,
    )
    .map_err(super::net_error)?;
    let listener = TcpListener::bind(listen).map_err(|_| "TLS listener bind failed")?;
    println!(
        "relay-tls-serve {}",
        listener
            .local_addr()
            .map_err(|_| "TLS listener unavailable")?
    );
    service.serve(listener, None).map_err(super::net_error)
}
