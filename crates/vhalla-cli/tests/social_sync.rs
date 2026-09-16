#![cfg(all(unix, feature = "experimental-sync"))]
//! Paired social retrieval between real CLI subprocesses: a provider serves
//! bounded signed pages over the pinned paired channel, the requester pulls
//! them across multiple fresh connections, and strangers are refused.

use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
};

use serde_json::Value;

const REALM: &str = "00000000000000000000000000000077";
const ROOM: &str = "000000000000000000000000000000aa";

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-cli-sync-{:032x}",
            u128::from_be_bytes(nonce)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Account {
    store: PathBuf,
    key: PathBuf,
    owner: String,
    app: String,
}
impl Account {
    fn init(temp: &Temp, label: &str) -> Self {
        let store = temp.path(&format!("{label}-store"));
        let key = temp.path(&format!("{label}-key"));
        let output = run(&["social", "init", path(&store), REALM, path(&key)]);
        assert!(output.status.success(), "init: {output:?}");
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        Self {
            store,
            key,
            owner: field(&value, "owner"),
            app: field(&value, "controller"),
        }
    }
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn field(value: &Value, name: &str) -> String {
    value[name]
        .as_str()
        .unwrap_or_else(|| panic!("{name}: {value}"))[0..64]
        .to_owned()
}

struct Output {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
impl std::fmt::Debug for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "status={} out={} err={}",
            self.status,
            String::from_utf8_lossy(&self.stdout),
            String::from_utf8_lossy(&self.stderr)
        )
    }
}

fn run(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .args(args)
        .args(["--now", "10"])
        .output()
        .unwrap();
    Output {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn post(account: &Account, text: &str) {
    let output = run(&[
        "social",
        "post",
        path(&account.store),
        REALM,
        path(&account.key),
        &format!("owner:{}", account.owner),
        &format!("channel:{ROOM}"),
        text,
    ]);
    assert!(output.status.success(), "post: {output:?}");
}

fn record_count(account: &Account) -> usize {
    let output = run(&["social", "records", path(&account.store), REALM]);
    assert!(output.status.success(), "records: {output:?}");
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    value["records"]["items"].as_array().unwrap().len()
}

/// Spawn `sync serve` and return the child plus its advertised route.
fn serve(account: &Account, requester_app: &str) -> (Child, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .args([
            "social",
            "sync",
            path(&account.store),
            REALM,
            "serve",
            path(&account.key),
            requester_app,
        ])
        .args(["--now", "10"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let route = lines
        .next()
        .expect("serve closed without a route")
        .expect("route line");
    assert!(route.starts_with("route "), "{route}");
    let mut parts = route.split_whitespace();
    parts.next();
    let address = parts.next().unwrap().to_owned();
    let expiry = parts.next().unwrap().to_owned();
    // Keep the remaining output draining so the child never blocks on a
    // full pipe; the test only needs the route and the exit status.
    thread::spawn(move || for _ in lines {});
    (child, address, expiry)
}

fn pull(requester: &Account, provider_app: &str, address: &str, expiry: &str) -> Output {
    run(&[
        "social",
        "sync",
        path(&requester.store),
        REALM,
        "pull",
        path(&requester.key),
        provider_app,
        address,
        expiry,
    ])
}

#[test]
fn pull_delivers_missing_records_across_paged_connections() {
    let temp = Temp::new();
    let alice = Account::init(&temp, "alice");
    let bob = Account::init(&temp, "bob");
    // Four owner posts produce nine records (each post pairs a content record
    // with an owner seal), forcing a second five-record page and therefore
    // the continuation path across another fresh connection.
    for i in 0..4 {
        post(&alice, &format!("shared post {i}"));
    }
    let alice_records = record_count(&alice);
    assert!(
        alice_records > 5,
        "fixture must span pages: {alice_records}"
    );
    let before = record_count(&bob);

    let (mut serve, address, expiry) = serve(&alice, &bob.app);
    let output = pull(&bob, &alice.app, &address, &expiry);
    assert!(output.status.success(), "pull: {output:?}");
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["complete"], true, "{value}");
    assert_eq!(value["accepted"], alice_records as u64, "{value}");
    assert_eq!(value["failures"], 0, "{value}");
    assert!(
        value["pages"].as_u64().unwrap() >= 2,
        "continuation must cross connections: {value}"
    );
    assert_eq!(record_count(&bob), before + alice_records);

    // The provider exits once the final page is acknowledged by the peer's
    // disconnect instead of holding the store for the whole lifetime.
    let status = serve.wait().unwrap();
    assert!(status.success());
}

#[test]
fn a_stranger_cannot_pull_from_a_pinned_serve() {
    let temp = Temp::new();
    let alice = Account::init(&temp, "alice");
    let bob = Account::init(&temp, "bob");
    let mallory = Account::init(&temp, "mallory");
    post(&alice, "for bob only");

    // The serve pins bob's application key; mallory's hello never completes.
    let (mut first, address, expiry) = serve(&alice, &bob.app);
    let output = pull(&mallory, &alice.app, &address, &expiry);
    assert!(!output.status.success(), "stranger pull: {output:?}");
    assert_eq!(record_count(&mallory), 1, "nothing may be admitted");
    let _ = first.kill();
    let _ = first.wait();

    // Bob still syncs normally afterward.
    let (mut second, address, expiry) = serve(&alice, &bob.app);
    let output = pull(&bob, &alice.app, &address, &expiry);
    assert!(output.status.success(), "pinned pull: {output:?}");
    assert!(second.wait().unwrap().success());
}

#[test]
fn pull_rejects_a_stale_route_before_dialing() {
    let temp = Temp::new();
    let alice = Account::init(&temp, "alice");
    let bob = Account::init(&temp, "bob");
    let (mut serve, address, _expiry) = serve(&alice, &bob.app);
    // A past expiry is rejected during local validation, before any dial.
    let output = pull(&bob, &alice.app, &address, "1");
    assert!(!output.status.success(), "stale route: {output:?}");
    let _ = serve.kill();
    let _ = serve.wait();
}
