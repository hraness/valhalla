use super::*;
fn root(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "vhalla-gateway-{}-{}-{label}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&path).unwrap();
    path
}
#[test]
fn production_manifest_is_exact_bounded_and_never_serves_extra_paths() {
    let root = root("manifest");
    let body = b"production";
    std::fs::write(root.join("index.html"), body).unwrap();
    let digest: String = Sha256::digest(body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let manifest = serde_json::json!({"format":1,"purpose":"production","assets":{"index.html":{"bytes":body.len(),"sha256":digest}}});
    std::fs::write(
        root.join("artifact.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(root.join("secret-unlisted"), b"do not serve").unwrap();
    assert!(assets(&root).is_ok());
    std::fs::write(root.join("index.html"), b"modified").unwrap();
    assert!(assets(&root).is_err());
    std::fs::write(root.join("index.html"), body).unwrap();
    let mut local = manifest.clone();
    local["purpose"] = "local-qualification".into();
    std::fs::write(
        root.join("artifact.json"),
        serde_json::to_vec(&local).unwrap(),
    )
    .unwrap();
    assert!(assets(&root).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn configuration_refuses_unsafe_origin_unknown_fields_and_noncanonical_hex() {
    assert!(hex(&"AB".repeat(32)).is_err());
    assert!(hex(&"08".repeat(32)).is_ok());
    let value = serde_json::json!({"format":1,"listen":"127.0.0.1:8088","namespace":"09".repeat(32),"browser_token_file":"/tmp/browser-token","upstream":{"addr":"127.0.0.1:9001","tls_name":"relay.local","tls_ca_file":"/tmp/ca","token_file":"/tmp/token"},"assets_dir":"/tmp/artifact","initial_cursor":"0","extra":"refused"});
    assert!(serde_json::from_value::<Config>(value).is_err());
}

#[test]
fn invalid_initial_cursor_refuses_before_credentials_or_assets_are_read() {
    use std::os::unix::fs::PermissionsExt;
    let root = root("cursor");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("gateway.json");
    let mut value = serde_json::json!({"format":1,"listen":"127.0.0.1:8088","namespace":"09".repeat(32),"browser_token_file":root.join("absent-browser-token"),"upstream":{"addr":"127.0.0.1:9001","tls_name":"relay.local","tls_ca_file":root.join("absent-ca"),"token_file":root.join("absent-token")},"assets_dir":root.join("absent-artifact"),"initial_cursor":"0"});
    for cursor in [
        (MAX_RELAY_ITEMS as u64 + 1).to_string(),
        u64::MAX.to_string(),
        "00".into(),
        "-1".into(),
        "0".into(),
        MAX_RELAY_ITEMS.to_string(),
    ] {
        value["initial_cursor"] = cursor.clone().into();
        let bytes = serde_json::to_vec(&value).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = load(&path).err().expect("absent credentials must refuse");
        let within_capacity = cursor == "0" || cursor == MAX_RELAY_ITEMS.to_string();
        assert_eq!(error.contains("initial_cursor"), !within_capacity);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    }
    std::fs::remove_dir_all(root).unwrap();
}

fn write_private(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
fn https_config_fixture() -> (PathBuf, serde_json::Value) {
    use std::os::unix::fs::PermissionsExt;
    let root = root("https-config");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["gateway.test".into()]).unwrap();
    write_private(&root.join("leaf.der"), certificate.cert.der());
    write_private(&root.join("key.der"), &certificate.key_pair.serialize_der());
    write_private(&root.join("browser-token"), "08".repeat(32).as_bytes());
    write_private(
        &root.join("second-browser-token"),
        "06".repeat(32).as_bytes(),
    );
    write_private(&root.join("upstream-token"), "07".repeat(32).as_bytes());
    let body = b"production UI";
    std::fs::write(root.join("index.html"), body).unwrap();
    let digest: String = Sha256::digest(body)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let manifest = serde_json::json!({"format":1,"purpose":"production","assets":{"index.html":{"bytes":body.len(),"sha256":digest}}});
    std::fs::write(
        root.join("artifact.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let client = serde_json::json!({"id":"01".repeat(16),"token_file":root.join("browser-token"),"expires_unix_secs":expires,"revoked":false,"max_inflight":2,"requests_per_window":64,"bytes_per_window":1048576});
    let config = serde_json::json!({"format":2,"listen":"0.0.0.0:8443","origin":"https://gateway.test:8443","namespace":"09".repeat(32),
        "tls":{"certificate_chain_files":[root.join("leaf.der")],"private_key_file":root.join("key.der")},"clients":[client],
        "upstream":{"addr":"127.0.0.1:1","tls_name":"gateway.test","tls_ca_file":root.join("leaf.der"),"token_file":root.join("upstream-token")},
        "assets_dir":root,"initial_cursor":"0"});
    (root, config)
}
#[test]
fn explicit_https_config_accepts_direct_tls_and_inert_expired_or_revoked_clients() {
    let (root, mut config) = https_config_fixture();
    let path = root.join("gateway.json");
    let mut second = config["clients"][0].clone();
    second["id"] = "02".repeat(16).into();
    second["token_file"] = root.join("second-browser-token").to_str().unwrap().into();
    config["clients"].as_array_mut().unwrap().push(second);
    for mode in 0..3 {
        config["clients"][0]["revoked"] = (mode == 1).into();
        config["clients"][0]["expires_unix_secs"] = if mode == 2 {
            0u64.into()
        } else {
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600)
                .into()
        };
        write_private(&path, &serde_json::to_vec(&config).unwrap());
        let (gateway, address) = load(&path).unwrap();
        assert_eq!(gateway.origin(), "https://gateway.test:8443");
        assert_eq!(address, "0.0.0.0:8443".parse::<SocketAddr>().unwrap());
    }
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn https_config_refuses_ambiguous_origin_duplicate_secrets_and_unbounded_authority_without_effects()
{
    let (root, original) = https_config_fixture();
    let path = root.join("gateway.json");
    for mutation in 0..14 {
        let mut config = original.clone();
        match mutation {
            0 => config["origin"] = "http://gateway.test:8443".into(),
            1 => config["origin"] = "https://gateway.test:443".into(),
            2 => config["origin"] = "https://gateway.test:8443/".into(),
            3 => config["listen"] = "0.0.0.0:8444".into(),
            4 => config["browser_token_file"] = "/unselected".into(),
            5 => {
                config["clients"][0]["token_file"] =
                    root.join("upstream-token").to_str().unwrap().into()
            }
            6 => {
                let duplicate = config["clients"][0].clone();
                config["clients"].as_array_mut().unwrap().push(duplicate);
            }
            7 => {
                let mut duplicate = config["clients"][0].clone();
                duplicate["id"] = "02".repeat(16).into();
                config["clients"].as_array_mut().unwrap().push(duplicate);
            }
            8 => config["clients"][0]["id"] = "00".repeat(16).into(),
            9 => config["clients"][0]["max_inflight"] = 9.into(),
            10 => config["clients"][0]["requests_per_window"] = 0.into(),
            11 => config["clients"][0]["bytes_per_window"] = 67108865.into(),
            12 => config["clients"][0]["expires_unix_secs"] = u64::MAX.into(),
            _ => {
                config["tls"]["private_key_file"] =
                    root.join("browser-token").to_str().unwrap().into()
            }
        }
        let raw = serde_json::to_vec(&config).unwrap();
        write_private(&path, &raw);
        assert!(load(&path).is_err(), "mutation {mutation}");
        assert_eq!(std::fs::read(&path).unwrap(), raw);
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            8,
            "load must not create state"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
