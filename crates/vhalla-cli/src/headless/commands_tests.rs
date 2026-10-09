use super::*;
use crate::headless::catalog::{Hex, Id};
use std::{
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;
use vhalla_private_native::client::agent_rpc::MCP_VERSION;

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn temp() -> TempDir {
    // Unix sockets have a short pathname limit, including on macOS where the
    // default temporary directory is too long once control/admin.sock is added.
    let parent = if cfg!(target_os = "macos") {
        "/private/tmp"
    } else {
        "/tmp"
    };
    tempfile::Builder::new()
        .prefix("vh-cmd-")
        .tempdir_in(parent)
        .unwrap()
}

fn command(action: Action, home: &Path) -> Command {
    Command {
        action,
        home: home.into(),
        grant: None,
        listen: test_listen(),
    }
}

fn test_listen() -> Listen {
    Listen {
        bind: "127.0.0.1:0".parse().unwrap(),
        relay_url: None,
        relay_only: false,
    }
}

async fn run(home: &Path, shutdown: impl Future<Output = ()>) -> Result<(), ErrorBody> {
    run_home(home, &test_listen(), shutdown).await
}

async fn run_local(home: &Path, shutdown: impl Future<Output = ()>) -> Result<(), ErrorBody> {
    // Grant checks need the retained backend and real local sockets, not an
    // unrelated peer endpoint bind before the readiness handshake.
    local::serve_factory(
        home,
        |generation| launch(home, generation, false, None),
        shutdown,
    )
    .await
}

fn id(value: u8) -> Id {
    Hex([value; 16])
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = custody::create_private_file(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn grant_value() -> Value {
    json!({"generation":Hex([8;32]),"token":Hex([9;32]),"room":id(1),
        "scope":{"kind":"display only"},"permissions":{"send":true},
        "expires_at":u64::MAX,"allowance":"display only"})
}

#[test]
fn command_futures_keep_native_work_off_the_caller_stack() {
    use crate::headless::local::Backend as _;

    // Infer each future's layout without constructing or polling it. This
    // diagnostic itself must not allocate its largest case on the test stack.
    fn bytes<F: Future>(_: impl FnOnce() -> F) -> usize {
        std::mem::size_of::<F>()
    }
    fn backend_bytes<'a, F: Future>(_: impl FnOnce(&'a mut ServiceBackend) -> F) -> usize {
        std::mem::size_of::<F>()
    }
    let home = Path::new("/tmp/unopened-vhalla-size-probe");
    let listen = test_listen();
    let generation = Hex([1; 32]);
    let sizes = [
        ("backend.value", std::mem::size_of::<ServiceBackend>()),
        (
            "backend.dispatch",
            backend_bytes(|backend| {
                backend.dispatch(local::Channel::Admin, json!({"op":"service.status"}))
            }),
        ),
        (
            "backend.initialize",
            bytes(|| ServiceBackend::initialize(home, generation)),
        ),
        (
            "backend.open",
            bytes(|| ServiceBackend::open(home, generation)),
        ),
        (
            "launch",
            bytes(|| launch(home, generation, false, Some(&listen))),
        ),
        (
            "serve_factory",
            bytes(|| {
                local::serve_factory(
                    home,
                    |generation| launch(home, generation, false, Some(&listen)),
                    std::future::pending(),
                )
            }),
        ),
        ("initialize_home", bytes(|| initialize_home(home))),
        (
            "run_home",
            bytes(|| run_home(home, &listen, std::future::pending())),
        ),
        (
            "execute_with_io",
            bytes(|| {
                execute_with_io(
                    command(Action::Call, home),
                    tokio::io::empty(),
                    tokio::io::sink(),
                    std::future::pending(),
                )
            }),
        ),
        ("execute", bytes(|| execute(&[]))),
        (
            "owner_test_helper",
            bytes(|| owner(home, Action::Status, Value::Null)),
        ),
    ];
    for (name, size) in sizes {
        eprintln!("{name}: {size} bytes");
        if matches!(
            name,
            "serve_factory"
                | "initialize_home"
                | "run_home"
                | "execute_with_io"
                | "execute"
                | "owner_test_helper"
        ) {
            assert!(
                size <= 16 * 1024,
                "{name} embeds {size} bytes of async state"
            );
        }
    }
}

#[test]
fn parser_accepts_only_explicit_absolute_paths_and_known_options() {
    for (verb, action) in [
        ("init", Action::Init),
        ("run", Action::Run),
        ("status", Action::Status),
        ("stop", Action::Stop),
        ("call", Action::Call),
    ] {
        let parsed = parse(&args(&[verb, "--home", "/tmp/service"])).unwrap();
        assert_eq!(parsed.action, action);
        assert_eq!(parsed.home, Path::new("/tmp/service"));
        assert!(parsed.grant.is_none());
        assert_eq!(parsed.listen.bind, Listen::default().bind);
        assert!(parsed.listen.relay_url.is_none());
    }
    let parsed = parse(&args(&[
        "mcp",
        "--grant",
        "/tmp/grant.json",
        "--home",
        "/tmp/service",
    ]))
    .unwrap();
    assert_eq!(parsed.action, Action::Mcp);
    assert_eq!(parsed.grant, Some(PathBuf::from("/tmp/grant.json")));

    for invalid in [
        vec![],
        vec!["unknown"],
        vec!["run"],
        vec!["run", "--home"],
        vec!["run", "--home", "relative"],
        vec!["run", "--home", "/tmp/../service"],
        vec!["run", "--home", "/tmp/a", "--home", "/tmp/b"],
        vec!["run", "--home", "/tmp/a", "--grant", "/tmp/grant"],
        vec!["run", "--home", "/tmp/a", "--unknown", "/tmp/b"],
        vec!["run", "--home", "/tmp/a", "extra"],
        vec!["mcp", "--home", "/tmp/a"],
        vec!["mcp", "--home", "/tmp/a", "--grant", "relative"],
        vec!["mcp", "--home", "/tmp/a", "--token", "/tmp/token"],
        vec![
            "mcp",
            "--home",
            "/tmp/a",
            "--grant",
            "/tmp/grant",
            "--grant",
            "/tmp/other",
        ],
    ] {
        assert_eq!(parse(&args(&invalid)).unwrap_err().code, ErrorCode::Usage);
    }
}

#[test]
fn managed_actions_and_relay_only_are_explicit_and_closed() {
    for (verb, action) in [
        ("install", Action::ManagedInstall),
        ("status", Action::ManagedStatus),
        ("uninstall", Action::ManagedUninstall),
    ] {
        assert_eq!(
            parse(&args(&["managed", verb, "--home", "/tmp/service"]))
                .unwrap()
                .action,
            action
        );
    }
    for prefix in [vec!["run"], vec!["managed", "install"]] {
        let mut values = prefix;
        values.extend([
            "--relay-only",
            "--home",
            "/tmp/service",
            "--relay-url",
            "https://relay.example.com/",
        ]);
        assert!(parse(&args(&values)).unwrap().listen.relay_only);
        values.push("--relay-only");
        assert_eq!(parse(&args(&values)).unwrap_err().code, ErrorCode::Usage);
    }
    for values in [
        vec!["managed"],
        vec!["managed", "unknown"],
        vec!["managed", "install", "--home", "/tmp/a", "--relay-only"],
        vec!["run", "--home", "/tmp/a", "--relay-only"],
        vec![
            "managed",
            "status",
            "--home",
            "/tmp/a",
            "--relay-url",
            "https://relay.example.com/",
        ],
        vec![
            "managed",
            "uninstall",
            "--home",
            "/tmp/a",
            "--bind",
            "127.0.0.1:0",
        ],
        vec![
            "mcp",
            "--home",
            "/tmp/a",
            "--grant",
            "/tmp/g",
            "--relay-only",
        ],
    ] {
        assert_eq!(parse(&args(&values)).unwrap_err().code, ErrorCode::Usage);
    }
}

#[tokio::test]
async fn managed_preflight_preserves_state_and_releases_custody_before_startup() {
    let root = temp();
    let home = root.path().join("service");
    initialize_home(&home).await.unwrap();
    let identity = fs::read(home.join("account/identity")).unwrap();
    let peer = fs::read(home.join("peer.key")).unwrap();
    verify_retained_home(&home).await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let (_, server) = tokio::join!(
        async {
            ready(&home).await;
            assert!(verify_retained_home(&home).await.is_err());
            stop.send(()).unwrap();
        },
        run(&home, async {
            let _ = stopped.await;
        }),
    );
    server.unwrap();
    verify_retained_home(&home).await.unwrap();
    let reopened = ServiceBackend::open(&home, Hex([71; 32])).await.unwrap();
    assert!(fs::read(home.join("account/identity")).unwrap() == identity);
    assert!(fs::read(home.join("peer.key")).unwrap() == peer);
    drop(reopened);
    fs::remove_file(home.join("peer.key")).unwrap();
    assert!(verify_retained_home(&home).await.is_err());
    assert!(!home.join("peer.key").exists());
    assert!(fs::read(home.join("account/identity")).unwrap() == identity);
}

#[test]
fn only_run_and_managed_install_accept_valid_explicit_network_options() {
    let parsed = parse(&args(&[
        "run",
        "--home",
        "/tmp/service/./",
        "--bind",
        "127.0.0.1:0",
        "--relay-url",
        "https://relay.example.com/",
    ]))
    .unwrap();
    assert_eq!(
        parsed.home.as_os_str(),
        Path::new("/tmp/service").as_os_str()
    );
    assert_eq!(parsed.listen.bind, test_listen().bind);
    assert_eq!(
        parsed.listen.relay_url.as_deref(),
        Some("https://relay.example.com/")
    );
    for invalid in [
        vec!["init", "--home", "/tmp/a", "--bind", "127.0.0.1:0"],
        vec![
            "status",
            "--home",
            "/tmp/a",
            "--relay-url",
            "https://relay.example.com/",
        ],
        vec!["stop", "--home", "/tmp/a", "--bind", "127.0.0.1:0"],
        vec!["call", "--home", "/tmp/a", "--bind", "127.0.0.1:0"],
        vec![
            "mcp",
            "--home",
            "/tmp/a",
            "--grant",
            "/tmp/g",
            "--bind",
            "127.0.0.1:0",
        ],
        vec!["run", "--home", "/tmp/a", "--bind", "localhost:3"],
        vec!["run", "--home", "/tmp/a", "--bind", "127.0.0.1:70000"],
        vec![
            "run",
            "--home",
            "/tmp/a",
            "--bind",
            "127.0.0.1:0",
            "--bind",
            "127.0.0.1:1",
        ],
        vec![
            "run",
            "--home",
            "/tmp/a",
            "--relay-url",
            "http://relay.example.com/",
        ],
        vec![
            "run",
            "--home",
            "/tmp/a",
            "--relay-url",
            "https://user:pass@relay.example.com/",
        ],
        vec![
            "run",
            "--home",
            "/tmp/a",
            "--relay-url",
            "https://relay.example.com/",
            "--relay-url",
            "https://relay.example.com/",
        ],
    ] {
        assert!(parse(&args(&invalid)).is_err());
    }
}

#[test]
fn stdio_admission_requires_real_pipes_or_sockets() {
    let root = temp();
    let file = custody::create_private_file(&root.path().join("regular")).unwrap();
    assert_eq!(require_pipe(&file).unwrap_err().code, ErrorCode::Usage);
    assert_eq!(
        require_pipe(fs::File::open(root.path()).unwrap())
            .unwrap_err()
            .code,
        ErrorCode::Usage
    );
    let (left, right) = UnixStream::pair().unwrap();
    require_pipe(&left).unwrap();
    require_pipe(&right).unwrap();
    let fifo = root.path().join("input.pipe");
    assert!(std::process::Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let file = rustix::fs::open(
        &fifo,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    require_pipe(file).unwrap();
}

#[tokio::test]
async fn call_accepts_one_object_and_counts_all_input_bytes() {
    assert_eq!(
        read_request(&b" \n{\"op\":\"service.status\"}\n\t"[..])
            .await
            .unwrap(),
        json!({"op":"service.status"})
    );
    for bytes in [
        &b""[..],
        &b"[]"[..],
        &b"null"[..],
        &b"1"[..],
        &b"{} {}"[..],
        &b"{}\nfalse"[..],
        &b"{\"op\":"[..],
    ] {
        assert_eq!(
            read_request(bytes).await.unwrap_err().code,
            ErrorCode::Usage
        );
    }
    let mut exact = br#"{"data":""#.to_vec();
    exact.resize(MAX_CALL_BYTES - 2, b'x');
    exact.extend_from_slice(b"\"}");
    assert_eq!(exact.len(), MAX_CALL_BYTES);
    assert!(read_request(exact.as_slice()).await.unwrap().is_object());
    exact.push(b' ');
    assert_eq!(
        read_request(exact.as_slice()).await.unwrap_err().code,
        ErrorCode::Usage
    );
}

#[tokio::test]
async fn rejected_call_input_emits_nothing_and_never_connects() {
    let root = temp();
    let home = root.path().join("absent");
    let mut output = Vec::new();
    let error = execute_with_io(
        command(Action::Call, &home),
        &b"{} {}"[..],
        &mut output,
        std::future::pending(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Usage);
    assert!(output.is_empty());
    assert!(!home.exists());
}

#[test]
fn grant_loader_accepts_metadata_without_treating_it_as_authority() {
    let root = temp();
    let path = root.path().join("grant.json");
    let mut value = grant_value();
    value["cap"] = json!("this is not an admin capability source");
    value["home"] = json!("/other/service");
    value["method"] = json!("control.stop");
    value["budget"] = json!({"calls":u64::MAX});
    write_private(&path, &serde_json::to_vec(&value).unwrap());
    let grant = read_grant(&path).unwrap();
    assert_eq!(grant.generation, Hex([8; 32]));
    assert_eq!(grant.token, Hex([9; 32]));
}

#[test]
fn grant_loader_refuses_wrong_modes_links_types_and_oversized_files() {
    let root = temp();
    let bytes = serde_json::to_vec(&grant_value()).unwrap();
    for mode in [0o644, 0o400, 0o660, 0o700] {
        let path = root.path().join(format!("mode-{mode:o}"));
        write_private(&path, &bytes);
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            matches!(read_grant(&path), Err(error) if error.code == ErrorCode::PermissionDenied)
        );
    }
    let target = root.path().join("target");
    write_private(&target, &bytes);
    let symlink = root.path().join("symlink");
    std::os::unix::fs::symlink(&target, &symlink).unwrap();
    assert!(read_grant(&symlink).is_err());
    let hardlink = root.path().join("hardlink");
    fs::hard_link(&target, &hardlink).unwrap();
    assert!(read_grant(&hardlink).is_err());
    assert!(read_grant(&target).is_err());
    assert!(read_grant(root.path()).is_err());
    assert!(read_grant(Path::new("relative.json")).is_err());
    let huge = root.path().join("huge");
    write_private(&huge, &vec![b' '; MAX_GRANT_BYTES + 1]);
    assert!(read_grant(&huge).is_err());
}

#[test]
fn grant_loader_refuses_missing_noncanonical_or_ambiguous_credentials() {
    let root = temp();
    let valid = grant_value();
    let mut zero = valid.clone();
    zero["token"] = json!("00".repeat(32));
    let mut uppercase = valid.clone();
    uppercase["generation"] = json!("AB".repeat(32));
    for (index, value) in [
        json!({"generation":valid["generation"]}),
        json!({"token":valid["token"]}),
        json!({"ok":true,"result":valid}),
        zero,
        uppercase,
        json!([]),
    ]
    .into_iter()
    .enumerate()
    {
        let path = root.path().join(format!("invalid-{index}"));
        write_private(&path, &serde_json::to_vec(&value).unwrap());
        assert!(read_grant(&path).is_err());
    }
    let duplicate = format!(
        "{{\"generation\":\"{}\",\"token\":\"{}\",\"token\":\"{}\"}}",
        Hex([8; 32]),
        Hex([9; 32]),
        Hex([10; 32])
    );
    let path = root.path().join("duplicate");
    write_private(&path, duplicate.as_bytes());
    assert!(read_grant(&path).is_err());
    let path = root.path().join("trailing");
    write_private(&path, format!("{} {{}}", grant_value()).as_bytes());
    assert!(read_grant(&path).is_err());
}

#[tokio::test]
async fn init_accepts_only_a_private_home_and_never_overwrites_native_state() {
    let root = temp();
    let unsafe_home = root.path().join("unsafe");
    fs::create_dir(&unsafe_home).unwrap();
    fs::set_permissions(&unsafe_home, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(initialize_home(&unsafe_home).await.is_err());
    assert!(!unsafe_home.join("account").exists());
    let home = root.path().join("home");
    initialize_home(&home).await.unwrap();
    assert_eq!(
        fs::metadata(&home).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    let link = root.path().join("linked-home");
    std::os::unix::fs::symlink(&home, &link).unwrap();
    assert!(initialize_home(&link).await.is_err());
    assert!(initialize_home(&link.join("")).await.is_err());
    assert!(initialize_home(&link.join(".")).await.is_err());
    assert!(initialize_home(&home).await.is_err());
    // A failed repeated init releases service custody without replacing state.
    run(&home, async {}).await.unwrap();
}

#[tokio::test]
async fn run_never_initializes_missing_native_state_and_init_releases_its_lock() {
    let root = temp();
    let home = root.path().join("home");
    assert!(run(&home, async {}).await.is_err());
    assert!(!home.exists());
    custody::create_private_directory(&home).unwrap();
    assert!(run(&home, async {}).await.is_err());
    assert!(!home.join("account").exists());
    assert!(!home.join("catalog").exists());
    initialize_home(&home).await.unwrap();
    run(&home, async {}).await.unwrap();
    assert!(!home.join("control/admin.sock").exists());
    assert!(!home.join("control/agent.sock").exists());
}

async fn ready(home: &Path) {
    timeout(Duration::from_secs(20), async {
        loop {
            if local::admin_request(home, json!({"op":"control.hello"}))
                .await
                .is_ok()
            {
                break;
            }
            // Give startup I/O time to progress without hot-polling custody.
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("daemon became ready");
}

async fn owner(home: &Path, action: Action, request: Value) -> Value {
    let input = serde_json::to_vec(&request).unwrap();
    let mut output = Vec::new();
    execute_with_io(
        command(action, home),
        input.as_slice(),
        &mut output,
        std::future::pending(),
    )
    .await
    .unwrap();
    let envelope: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(envelope["ok"], true);
    assert!(envelope.get("error").is_none());
    envelope["result"].clone()
}

fn create(operation: u8) -> Value {
    json!({"op":"room.create","operation":id(operation),"kind":"public",
        "limits":{"max_records":10_000,"max_record_bytes":8*1024*1024}})
}

fn issue(status: &Value, operation: u8) -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    json!({"op":"grant.issue","operation":id(operation),"room":status["room"],"grant":{
        "scope":{"kind":"public","pin":status["pin"],"author":status["author"],
            "policy":status["policy"]["id"],"revision":status["policy"]["revision"]},
        "permissions":{"status":true,"messages":true,"send":true,"outbox_status":true},
        "budget":{"calls":32,"send_attempts":4,"body_bytes":16_384,"read_records":32,"read_bytes":1_048_576},
        "not_before":now-1,"expires_at":now+600}})
}

fn tool(number: u64, name: &str, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":number,"method":"tools/call","params":{
        "_meta":{"io.modelcontextprotocol/protocolVersion":MCP_VERSION,
            "io.modelcontextprotocol/clientCapabilities":{}},"name":name,"arguments":arguments}})
}

async fn mcp_requests(home: &Path, grant: &Path, requests: &[Value]) -> Vec<Value> {
    let mut input = Vec::new();
    for request in requests {
        serde_json::to_writer(&mut input, request).unwrap();
        input.push(b'\n');
    }
    let mut output = Vec::new();
    let mut command = command(Action::Mcp, home);
    command.grant = Some(grant.into());
    execute_with_io(
        command,
        input.as_slice(),
        &mut output,
        std::future::pending(),
    )
    .await
    .unwrap();
    output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

#[tokio::test]
async fn real_commands_create_send_read_stop_and_reopen_retained_messages() {
    let root = temp();
    let home = root.path().join("home");
    assert_eq!(
        owner(&home, Action::Init, Value::Null).await["initialized"],
        true
    );
    let interaction = async {
        ready(&home).await;
        let status = owner(&home, Action::Status, Value::Null).await;
        assert!(status["account"].is_string());
        let room = owner(&home, Action::Call, create(1)).await;
        owner(
            &home,
            Action::Call,
            json!({"op":"room.send","room":room["room"],
            "operation":id(2),"body":"hello from the owner"}),
        )
        .await;
        let page = owner(
            &home,
            Action::Call,
            json!({"op":"room.messages","room":room["room"],
            "after":0,"limit":16}),
        )
        .await;
        assert_eq!(page["records"].as_array().unwrap().len(), 1);
        assert_eq!(page["records"][0]["body"], "hello from the owner");
        owner(&home, Action::Stop, Value::Null).await;
    };
    let (result, ()) = timeout(Duration::from_secs(30), async {
        tokio::join!(run(&home, std::future::pending()), interaction)
    })
    .await
    .unwrap();
    result.unwrap();
    let interaction = async {
        ready(&home).await;
        let page = owner(
            &home,
            Action::Call,
            json!({"op":"room.messages","room":id(1),
            "after":0,"limit":16}),
        )
        .await;
        assert_eq!(page["records"][0]["body"], "hello from the owner");
        owner(&home, Action::Stop, Value::Null).await;
    };
    let (result, ()) = timeout(Duration::from_secs(30), async {
        tokio::join!(run(&home, std::future::pending()), interaction)
    })
    .await
    .unwrap();
    result.unwrap();
}

#[tokio::test]
async fn mcp_grant_cannot_select_other_rooms_administer_or_survive_a_restart() {
    let root = temp();
    let home = root.path().join("home");
    let grant_file = root.path().join("grant.json");
    initialize_home(&home).await.unwrap();
    let interaction = async {
        ready(&home).await;
        let room = owner(&home, Action::Call, create(1)).await;
        let other = owner(&home, Action::Call, create(2)).await;
        owner(
            &home,
            Action::Call,
            json!({"op":"room.send","room":other["room"],
            "operation":id(3),"body":"other room sentinel"}),
        )
        .await;
        let mut grant = owner(&home, Action::Call, issue(&room, 4)).await;
        // These fields are descriptive. Editing them cannot retarget the
        // daemon's retained generation/token or enable an administration tool.
        grant["room"] = other["room"].clone();
        grant["cap"] = json!("pretend owner capability");
        grant["permissions"] = json!({"all":true});
        write_private(&grant_file, &serde_json::to_vec(&grant).unwrap());
        let replies = mcp_requests(
            &home,
            &grant_file,
            &[
                tool(1, "agent.status", json!({})),
                tool(
                    2,
                    "agent.send",
                    json!({"operation":id(5),"text":"hello from the agent"}),
                ),
                tool(3, "agent.messages", json!({"after":0,"limit":16})),
                tool(4, "agent.status", json!({"room":other["room"]})),
                tool(5, "control.stop", json!({})),
                tool(6, "room.create", create(6)),
            ],
        )
        .await;
        assert_eq!(replies.len(), 6);
        assert_eq!(
            replies[0]["result"]["structuredContent"]["room"],
            room["room"]
        );
        assert_eq!(replies[1]["result"]["isError"], false);
        let page = &replies[2]["result"]["structuredContent"];
        assert_eq!(page["records"].as_array().unwrap().len(), 1);
        assert_eq!(page["records"][0]["text"], "hello from the agent");
        for reply in &replies[3..] {
            assert!(reply.get("error").is_some());
        }
        let text = serde_json::to_string(&replies).unwrap();
        assert!(!text.contains("other room sentinel"));
        assert!(!text.contains(grant["token"].as_str().unwrap()));
        assert!(!text.contains(grant["generation"].as_str().unwrap()));
        assert!(owner(&home, Action::Status, Value::Null).await["account"].is_string());
        owner(&home, Action::Stop, Value::Null).await;
    };
    let (result, ()) = timeout(Duration::from_secs(30), async {
        tokio::join!(run_local(&home, std::future::pending()), interaction)
    })
    .await
    .unwrap();
    result.unwrap();
    let interaction = async {
        ready(&home).await;
        let replies = mcp_requests(&home, &grant_file, &[tool(1, "agent.status", json!({}))]).await;
        assert_eq!(replies[0]["result"]["isError"], true);
        assert_eq!(
            replies[0]["result"]["structuredContent"]["code"],
            serde_json::to_value(ErrorCode::PermissionDenied).unwrap()
        );
        owner(&home, Action::Stop, Value::Null).await;
    };
    let (result, ()) = timeout(Duration::from_secs(30), async {
        tokio::join!(run_local(&home, std::future::pending()), interaction)
    })
    .await
    .unwrap();
    result.unwrap();
}
