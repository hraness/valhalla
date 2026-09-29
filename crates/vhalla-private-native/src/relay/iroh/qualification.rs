//! Explicit, synthetic two-runner qualification. Never part of ordinary tests.
use super::*;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    role: String,
    work: PathBuf,
    source_sha: String,
    run_id: String,
    run_attempt: String,
    nonce: String,
    machine: String,
    secret: Option<[u8; 32]>,
    token: Option<[u8; 32]>,
    namespace: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    schema: u32,
    source_sha: String,
    run_id: String,
    run_attempt: String,
    nonce: String,
    machine: String,
    endpoint: IrohEndpoint,
    // This newly generated test credential expires when the bounded host exits.
    // It authorizes only this disposable synthetic mailbox, never product data.
    token: [u8; 32],
    namespace: [u8; 32],
}

fn write_json(path: PathBuf, value: &impl Serialize) {
    let temporary = path.with_extension("writing");
    fs::write(&temporary, serde_json::to_vec(value).unwrap()).unwrap();
    fs::rename(temporary, path).unwrap();
}

fn synthetic(namespace: RelayNamespace, sequence: u8) -> RelayItem {
    RelayItem::new(
        namespace,
        u64::from(sequence),
        OperationId::from_bytes([sequence; 16]).unwrap(),
        OutboxKind::Application,
        &[sequence; 128],
    )
    .unwrap()
}

fn host(config: &Config) {
    let namespace = RelayNamespace::from_bytes(config.namespace.unwrap()).unwrap();
    let token = RelayToken::from_bytes(config.token.unwrap()).unwrap();
    let path = config.work.join("mailbox");
    let limits = Limits {
        max_items: 8,
        max_bytes: 8192,
    };
    Service::initialize(FileStore::create_new(&path, namespace, limits).unwrap()).unwrap();
    let credential = Credential {
        id: [1; 16],
        tokens: vec![token],
        namespace,
        permissions: Permissions {
            put: true,
            page: true,
        },
        storage: limits,
        max_inflight: 4,
        requests_per_window: 128,
        bytes_per_window: 1024 * 1024,
    };
    let service = Service::new_iroh(
        FileStore::open(&path, namespace).unwrap(),
        vec![credential],
        ServiceLimits {
            max_connections: 16,
            ..ServiceLimits::default()
        },
    )
    .unwrap();
    let listener = IrohListener::bind(
        config.secret.unwrap(),
        "0.0.0.0:0".parse().unwrap(),
        Some(DEFAULT_RELAY_URL),
    )
    .unwrap();
    listener.set_namespace(namespace);
    let mut endpoint = listener.endpoint();
    // A runner's private interface addresses are neither useful routes nor evidence.
    endpoint.addresses.clear();
    let descriptor = Descriptor {
        schema: 1,
        source_sha: config.source_sha.clone(),
        run_id: config.run_id.clone(),
        run_attempt: config.run_attempt.clone(),
        nonce: config.nonce.clone(),
        machine: config.machine.clone(),
        endpoint,
        token: *token.as_bytes(),
        namespace: *namespace.as_bytes(),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let worker = thread::spawn(move || service.serve_iroh_until(listener, None, stopping));
    write_json(config.work.join("descriptor.json"), &descriptor);
    let deadline = Instant::now() + Duration::from_secs(600);
    while !config.work.join("stop").exists() && Instant::now() < deadline && !worker.is_finished() {
        thread::sleep(Duration::from_millis(100));
    }
    let requested = config.work.join("stop").exists();
    stop.store(true, Ordering::Release);
    worker.join().unwrap().unwrap();
    let store = FileStore::open(&path, namespace).unwrap();
    let page = store.page(0, 8).unwrap();
    let exact = page.records.len() == 2
        && page.records[0].position == 1
        && page.records[0].item == synthetic(namespace, 1)
        && page.records[1].position == 2
        && page.records[1].item == synthetic(namespace, 2);
    write_json(
        config.work.join("host-result.json"),
        &serde_json::json!({
            "stopped_on_request": requested, "service_joined": true,
            "exact_durable_records": exact, "retained_records": page.records.len(),
        }),
    );
    assert!(
        requested && exact,
        "independent runner host qualification incomplete"
    );
}

fn client(config: &Config) {
    let raw = fs::read(config.work.join("descriptor.json")).unwrap();
    assert!(raw.len() <= 16384);
    let descriptor: Descriptor = serde_json::from_slice(&raw).unwrap();
    assert!(
        descriptor.schema == 1
            && descriptor.source_sha == config.source_sha
            && descriptor.run_id == config.run_id
            && descriptor.run_attempt == config.run_attempt
            && descriptor.nonce == config.nonce
            && descriptor.machine != config.machine
    );
    assert_eq!(
        descriptor.endpoint.relay_url.as_deref(),
        Some(DEFAULT_RELAY_URL)
    );
    assert!(descriptor.endpoint.addresses.is_empty());
    let namespace = RelayNamespace::from_bytes(descriptor.namespace).unwrap();
    let token = RelayToken::from_bytes(descriptor.token).unwrap();
    let relay = IrohRelay::new(descriptor.endpoint.clone(), token, namespace).unwrap();
    let first = synthetic(namespace, 1);
    write_json(config.work.join("phase.json"), &"automatic_put_page");
    assert_eq!(relay.page(0, 8).unwrap().head, 0);
    let receipt = relay.submit(&first).unwrap();
    assert_eq!(receipt.position, 1);
    assert!(!receipt.duplicate);
    let repeated = relay.submit(&first).unwrap();
    assert_eq!(repeated.position, receipt.position);
    assert_eq!(repeated.digest, receipt.digest);
    assert!(repeated.duplicate);
    assert_eq!(relay.page(0, 8).unwrap().records[0].item, first);
    write_json(config.work.join("phase.json"), &"wrong_token");
    let mut wrong_token = descriptor.token;
    wrong_token[0] ^= 1;
    let bad = IrohRelay::new(
        descriptor.endpoint.clone(),
        RelayToken::from_bytes(wrong_token).unwrap(),
        namespace,
    )
    .unwrap();
    assert_eq!(bad.page(0, 1).err(), Some(NetError::Denied));
    write_json(config.work.join("phase.json"), &"wrong_endpoint");
    let mut wrong_endpoint = descriptor.endpoint.clone();
    wrong_endpoint.endpoint_id = endpoint_id_from_secret(&wrong_token);
    let bad_identity = IrohRelay::new(wrong_endpoint, token, namespace).unwrap();
    assert!(matches!(
        bad_identity.page_until(0, 1, Instant::now() + Duration::from_secs(5)),
        Err(NetError::Connect | NetError::Timeout)
    ));
    write_json(config.work.join("phase.json"), &"wrong_namespace");
    let mut other_namespace = descriptor.namespace;
    other_namespace[0] ^= 1;
    let bad_namespace = IrohRelay::new(
        descriptor.endpoint.clone(),
        token,
        RelayNamespace::from_bytes(other_namespace).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        bad_namespace.page_until(0, 1, Instant::now() + Duration::from_secs(5)),
        Err(NetError::Connect | NetError::Timeout)
    ));
    drop((relay, bad, bad_identity, bad_namespace));
    write_json(config.work.join("phase.json"), &"fresh_client_reconnect");
    let reopened = IrohRelay::new(descriptor.endpoint.clone(), token, namespace).unwrap();
    assert_eq!(reopened.page(0, 8).unwrap().records[0].item, first);
    drop(reopened);

    let second = synthetic(namespace, 2);
    write_json(config.work.join("phase.json"), &"forced_relay_put_page");
    runtime().unwrap().block_on(async {
        tokio::time::timeout(Duration::from_secs(90), async {
            let endpoint = builder(Some(DEFAULT_RELAY_URL))
                .unwrap()
                .clear_ip_transports()
                .bind()
                .await
                .unwrap();
            tokio::time::timeout(STARTUP_TIMEOUT, endpoint.online())
                .await
                .unwrap();
            for op in [OP_PUT, OP_PAGE] {
                let connection = tokio::time::timeout(
                    STARTUP_TIMEOUT,
                    endpoint.connect(descriptor.endpoint.address().unwrap(), &protocol(namespace)),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(!connection.paths().is_empty());
                assert!(connection.paths().iter().all(|path| path.is_relay()));
                let (mut send, mut recv) = connection.open_bi().await.unwrap();
                let mut payload = token.as_bytes().to_vec();
                if op == OP_PUT {
                    payload.extend(second.encode().unwrap());
                } else {
                    payload.extend(page_request(0, 8).unwrap());
                }
                send.write_all(&frame(op, &payload)).await.unwrap();
                send.finish().unwrap();
                let raw = recv.read_to_end(MAX_RESPONSE + 4).await.unwrap();
                let (status, body) = decode_frame(&raw, MAX_RESPONSE).unwrap();
                let body = decode_status(status, body).unwrap();
                if op == OP_PUT {
                    assert_eq!(decode_receipt(&body, &second).unwrap().position, 2);
                } else {
                    let page = decode_page(&body, 0, 8).unwrap();
                    assert_eq!(page.records.len(), 2);
                    assert_eq!(page.records[0].item, first);
                    assert_eq!(page.records[1].item, second);
                }
                assert!(connection.paths().iter().all(|path| path.is_relay()));
                connection.close(0u32.into(), b"qualified");
            }
            endpoint.close().await;
        })
        .await
        .expect("forced relay qualification deadline");
    });
    write_json(
        config.work.join("client-result.json"),
        &serde_json::json!({
            "automatic_client_put_page": true, "exact_duplicate": true,
            "wrong_token_refused": true, "wrong_endpoint_refused": true,
            "wrong_namespace_refused": true,
            "fresh_client_reconnect": true, "raw_client_forced_relay_put_page": true,
            "forced_relay_paths_observed": true, "host_machine": descriptor.machine,
        }),
    );
}

#[test]
#[ignore = "explicit synthetic GitHub runner qualification; requires bounded controller configuration"]
fn independent_runner_transport_qualification() {
    let path = std::env::var_os("VHALLA_IROH_QUALIFICATION_CONFIG").expect("qualification config");
    let raw = fs::read(path).unwrap();
    assert!(raw.len() <= 16384);
    let config: Config = serde_json::from_slice(&raw).unwrap();
    match config.role.as_str() {
        "host" => host(&config),
        "client" => client(&config),
        _ => panic!("unknown role"),
    }
}
