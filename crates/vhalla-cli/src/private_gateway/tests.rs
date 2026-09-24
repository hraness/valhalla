use super::*;
#[test]
fn launch_agent_redirects_supervisor_output_beside_the_config_and_keeps_the_event_log_shape_ours() {
    let dir = root("launchd");
    let config = dir.join("gateway.json");
    let agent = launchd::spec(&config).unwrap();
    let canonical = dir.canonicalize().unwrap();
    for key in ["StandardOutPath", "StandardErrorPath"] {
        assert!(agent.plist.contains(&format!(
            "<key>{key}</key><string>{}</string>",
            canonical.join("supervisor.log").display()
        )));
    }
    assert!(!agent.plist.contains("events.log"));
    assert!(agent
        .plist
        .contains("<string>private-gateway</string><string>serve</string>"));
    // The earlier emitted shape differs only in its output redirection, so an
    // installation from that version is still recognized as ours.
    assert_eq!(agent.alternates.len(), 1);
    assert!(agent.alternates[0].contains(&format!(
        "<key>StandardOutPath</key><string>{}</string>",
        canonical.join("events.log").display()
    )));
    assert_eq!(
        agent.alternates[0].replace("events.log", "supervisor.log"),
        agent.plist
    );
    assert_eq!(agent.label, launchd::label(&config).unwrap());
    std::fs::remove_dir_all(dir).unwrap();
}
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
