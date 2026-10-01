use super::*;
use crate::headless::{catalog::Hex, local::Backend as _, network, peer};
use std::{fs, time::Duration};
use tempfile::TempDir;
use tokio::time::{sleep, timeout};

fn temp() -> TempDir {
    tempfile::Builder::new()
        .prefix("vh-live-")
        .tempdir_in(if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        })
        .unwrap()
}
fn id(value: u8) -> Id {
    Hex([value; 16])
}
fn limits() -> Value {
    json!({"max_records":10000,"max_record_bytes":8*1024*1024})
}
fn create(operation: u8) -> Value {
    json!({"op":"room.create","operation":id(operation),"kind":"public","limits":limits()})
}
async fn initialized(home: &Path, generation: u8) -> ServiceBackend {
    vhalla_custody::create_private_directory(home).unwrap();
    Box::pin(ServiceBackend::initialize(home, Hex([generation; 32])))
        .await
        .unwrap()
}
async fn direct(service: &mut ServiceBackend, value: Value) -> Value {
    service
        .dispatch(Channel::Admin, value)
        .await
        .unwrap()
        .checked_value()
        .unwrap()
        .clone()
}
async fn call(home: &Path, value: Value) -> Value {
    local::admin_request(home, value).await.unwrap()
}
async fn ready(home: &Path) {
    timeout(Duration::from_secs(10), async {
        loop {
            if local::admin_request(home, json!({"op":"service.status"}))
                .await
                .is_ok()
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("service ready");
}
async fn serve(home: &Path) -> Result<()> {
    local::serve_factory(
        home,
        |generation| async move {
            let mut backend = ServiceBackend::open(home, generation).await?;
            let endpoint = backend
                .bind_network(&network::Listen {
                    bind: "127.0.0.1:0".parse().unwrap(),
                    relay_url: None,
                    relay_only: false,
                })
                .await?;
            Ok(local::Launch {
                backend,
                endpoint: Some(endpoint),
            })
        },
        std::future::pending(),
    )
    .await
}
async fn wait_message(home: &Path, room: Id, text: &str) -> Value {
    timeout(Duration::from_secs(30), async {
        loop {
            let page = call(
                home,
                json!({"op":"room.messages","room":room,"after":0,"limit":32}),
            )
            .await;
            if page.to_string().contains(text) {
                return page;
            }
            sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("verified public message arrived")
}

#[tokio::test]
async fn facilities_are_retained_and_missing_network_identity_is_not_recreated() {
    let root = temp();
    let home = root.path().join("home");
    let mut service = initialized(&home, 90).await;
    let before = direct(&mut service, json!({"op":"service.status"})).await;
    assert_eq!(before["network"]["listening"], false);
    let key = fs::read(home.join("peer.key")).unwrap();
    drop(service);
    let mut service = ServiceBackend::open(&home, Hex([91; 32])).await.unwrap();
    let after = direct(&mut service, json!({"op":"service.status"})).await;
    assert_eq!(before["network"]["peer"], after["network"]["peer"]);
    assert_eq!(fs::read(home.join("peer.key")).unwrap(), key);
    drop(service);
    fs::rename(home.join("peer.key"), root.path().join("preserved.key")).unwrap();
    assert!(ServiceBackend::open(&home, Hex([92; 32])).await.is_err());
    assert!(!home.join("peer.key").exists());
    assert_eq!(fs::read(root.path().join("preserved.key")).unwrap(), key);
}

#[tokio::test]
async fn only_explicitly_published_public_rooms_are_peer_readable() {
    let root = temp();
    let home = root.path().join("home");
    let mut service = initialized(&home, 90).await;
    let room = direct(&mut service, create(1)).await;
    let pin: Hash = serde_json::from_value(room["pin"].clone()).unwrap();
    let request = peer::Request::Head {
        room: vhalla_direct_room::RoomId::from_bytes(pin.0),
    };
    assert_eq!(
        service.peer([9; 32], request.clone()).await.unwrap_err(),
        peer::PeerError::Unavailable
    );
    direct(
        &mut service,
        json!({"op":"public.publish","room":id(1),"operation":id(2)}),
    )
    .await;
    direct(
        &mut service,
        json!({"op":"room.send","room":id(1),"operation":id(3),"body":"published record"}),
    )
    .await;
    for _ in 0..8 {
        service.tick().await.unwrap();
    }
    let peer::Reply::Head(checkpoint) = service.peer([9; 32], request).await.unwrap() else {
        panic!("head")
    };
    let peer::Reply::Page(Some(page)) = service
        .peer(
            [9; 32],
            peer::Request::Page {
                room: vhalla_direct_room::RoomId::from_bytes(pin.0),
                checkpoint,
                after: 0,
                limit: 8,
            },
        )
        .await
        .unwrap()
    else {
        panic!("page")
    };
    assert!(page.frames.iter().any(|frame| frame
        .bytes
        .windows(16)
        .any(|bytes| bytes == b"published record")));
    let bad = service
        .dispatch(
            Channel::Admin,
            json!({"op":"public.source","room":id(1),"operation":id(4),
        "source":{"endpoint_id":"invalid","addresses":[],"relay_url":null}}),
        )
        .await;
    assert!(bad.is_err());
    assert!(service
        .dispatch(Channel::Admin, json!({"op":"room.status","room":id(1)}))
        .await
        .is_ok());
}

#[tokio::test]
async fn live_key_change_refuses_calls_and_peer_reads_then_drains_before_reopen() {
    let root = temp();
    let home = root.path().join("home");
    let mut service = initialized(&home, 90).await;
    let room = direct(&mut service, create(1)).await;
    direct(
        &mut service,
        json!({"op":"public.publish","room":id(1),"operation":id(2)}),
    )
    .await;
    drop(service);
    let key_path = home.join("peer.key");
    let retained = root.path().join("retained.key");
    let client = async {
        ready(&home).await;
        let status = call(&home, json!({"op":"service.status"})).await;
        let source: network::Source =
            serde_json::from_value(status["network"]["source"].clone()).unwrap();
        let endpoint = peer::endpoint_builder()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        fs::rename(&key_path, &retained).unwrap();
        let mut replacement = vhalla_custody::create_private_file(&key_path).unwrap();
        std::io::Write::write_all(&mut replacement, &fs::read(&retained).unwrap()).unwrap();
        replacement.sync_all().unwrap();
        assert!(local::admin_request(
            &home,
            json!({"op":"room.send","room":id(1),"operation":id(3),"body":"must refuse"})
        )
        .await
        .is_err());
        let pin: Hash = serde_json::from_value(room["pin"].clone()).unwrap();
        assert!(peer::Client::default()
            .call(
                &endpoint,
                network::address(&source).unwrap(),
                peer::Request::Head {
                    room: vhalla_direct_room::RoomId::from_bytes(pin.0),
                }
            )
            .await
            .is_err());
        endpoint.close().await;
    };
    let (result, ()) = timeout(Duration::from_secs(40), async {
        tokio::join!(Box::pin(serve(&home)), Box::pin(client))
    })
    .await
    .unwrap();
    assert!(result.is_err());
    assert!(!home.join("control/admin.sock").exists());
    assert!(!home.join("control/agent.sock").exists());
    fs::remove_file(&key_path).unwrap();
    fs::rename(&retained, &key_path).unwrap();
    // Opening succeeds only after the service and its network workers release
    // their shared native account and supervisor lifetime.
    let mut reopened = ServiceBackend::open(&home, Hex([92; 32])).await.unwrap();
    let page = direct(
        &mut reopened,
        json!({"op":"room.messages","room":id(1),"after":0,"limit":32}),
    )
    .await;
    assert!(!page.to_string().contains("must refuse"));
}

#[tokio::test]
async fn two_services_sync_signed_public_messages_and_catch_up_after_restart() {
    let root = temp();
    let alice = root.path().join("alice");
    let bob = root.path().join("bob");
    drop(initialized(&alice, 90).await);
    drop(initialized(&bob, 91).await);
    let journeys = async {
        ready(&alice).await;
        let first = async {
            ready(&bob).await;
            call(&alice, create(1)).await;
            call(
                &alice,
                json!({"op":"public.publish","room":id(1),"operation":id(2)}),
            )
            .await;
            let link = call(&alice, json!({"op":"public.link","room":id(1)})).await;
            let inspected = call(
                &bob,
                json!({"op":"public.inspect_link","link":link["link"]}),
            )
            .await;
            call(
                &bob,
                json!({"op":"room.join_public","operation":id(3),"pin":inspected["pin"],
                "genesis":inspected["genesis"],"limits":limits()}),
            )
            .await;
            call(
                &bob,
                json!({"op":"public.publish","room":id(3),"operation":id(4)}),
            )
            .await;
            call(&bob,json!({"op":"public.source","room":id(3),"operation":id(5),"source":inspected["source"]})).await;
            let send =
                json!({"op":"room.send","room":id(1),"operation":id(6),"body":"before disconnect"});
            let sent = call(&alice, send.clone()).await;
            let retried = call(&alice, send).await;
            assert_eq!(sent["exact_retry"], false);
            assert_eq!(retried["exact_retry"], true);
            assert_eq!(retried["artifact"], sent["artifact"]);
            assert_eq!(retried["operation"], sent["operation"]);
            wait_message(&bob, id(3), "before disconnect").await;
            call(&bob, json!({"op":"control.stop"})).await;
        };
        let (result, ()) = tokio::join!(Box::pin(serve(&bob)), Box::pin(first));
        result.unwrap();
        // Bob's native store and source cursor persist while the owner keeps
        // publishing. The original selected source remains at the same address.
        call(
            &alice,
            json!({"op":"room.send","room":id(1),"operation":id(7),"body":"while disconnected"}),
        )
        .await;
        let second = async {
            ready(&bob).await;
            let page = wait_message(&bob, id(3), "while disconnected").await;
            let encoded = page.to_string();
            assert_eq!(encoded.matches("before disconnect").count(), 1);
            assert_eq!(encoded.matches("while disconnected").count(), 1);
            let sync = call(&bob, json!({"op":"public.sync_status","room":id(3)})).await;
            assert!(sync["last_native_projection"].is_object());
            assert_eq!(sync["selected_sources"].as_array().unwrap().len(), 1);
            call(&bob, json!({"op":"control.stop"})).await;
        };
        let (result, ()) = tokio::join!(Box::pin(serve(&bob)), Box::pin(second));
        result.unwrap();
        call(&alice, json!({"op":"control.stop"})).await;
    };
    let (result, ()) = timeout(Duration::from_secs(90), async {
        tokio::join!(Box::pin(serve(&alice)), Box::pin(journeys))
    })
    .await
    .expect("public service journey finished");
    result.unwrap();
}
