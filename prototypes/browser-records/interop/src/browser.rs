use super::*;
use futures::{
    StreamExt,
    future::{Either, select},
};
use libp2p::{
    Multiaddr, SwarmBuilder, multiaddr::Protocol, request_response::Message, swarm::SwarmEvent,
};
use std::{cell::Cell, rc::Rc};
use wasm_bindgen::{JsCast, prelude::*};
use web_sys::{Element, HtmlInputElement};

fn error(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}
async fn echo(address: String, length: usize) -> Result<(), String> {
    if length > vhalla_browser_records_spike::MAX_OBJECT || address.len() > 256 {
        return Err("input limit".into());
    }
    let address: Multiaddr = address.parse().map_err(error)?;
    let parts: Vec<_> = address.iter().collect();
    let peer = match parts.as_slice() {
        [
            Protocol::Ip4(ip),
            Protocol::Udp(port),
            Protocol::WebRTCDirect,
            Protocol::Certhash(_),
            Protocol::P2p(peer),
        ] if ip.is_loopback() && *port != 0 => *peer,
        _ => {
            return Err(
                "expected literal loopback WebRTC route, certificate hash and peer ID".into(),
            );
        }
    };
    let mut swarm = SwarmBuilder::with_existing_identity(key(2))
        .with_wasm_bindgen()
        .with_other_transport(|key| {
            libp2p_webrtc_websys::Transport::new(libp2p_webrtc_websys::Config::new(key))
        })
        .map_err(error)?
        .with_behaviour(|_| behaviour(peer))
        .map_err(error)?
        .with_swarm_config(|c| {
            c.with_idle_connection_timeout(Duration::from_secs(10))
                .with_per_connection_event_buffer_size(4)
        })
        .build();
    swarm.dial(address).map_err(error)?;
    let payload: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
    let performance = web_sys::window().unwrap().performance().unwrap();
    let started = performance.now();
    let now = || (performance.now() - started) as u64;
    let mut sender = vhalla_browser_records_spike::Sender::new(payload, 0).map_err(error)?;
    let mut request = None;
    let mut connection = None;
    let mut received = false;
    let work = async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    connection_id,
                    ..
                } => {
                    if peer_id != peer || connection.is_some() {
                        return Err("unexpected transport peer/connection".into());
                    }
                    connection = Some(connection_id);
                    request = Some(
                        swarm
                            .behaviour_mut()
                            .echo
                            .send_request(&peer, sender.next_record(now()).map_err(error)?),
                    );
                }
                SwarmEvent::Behaviour(NetworkEvent::Echo(request_response::Event::Message {
                    peer: remote,
                    connection_id,
                    message:
                        Message::Response {
                            request_id,
                            response,
                        },
                    ..
                })) => {
                    if remote != peer
                        || Some(connection_id) != connection
                        || Some(request_id) != request
                    {
                        return Err("response mismatch".into());
                    }
                    if !sender.acknowledge(&response, now()).map_err(error)? {
                        request = Some(
                            swarm
                                .behaviour_mut()
                                .echo
                                .send_request(&peer, sender.next_record(now()).map_err(error)?),
                        );
                        continue;
                    }
                    received = true;
                    swarm
                        .disconnect_peer_id(peer)
                        .map_err(|_| "already closed".to_string())?;
                    continue;
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    return Err(format!("dial: {error:?}"));
                }
                SwarmEvent::Behaviour(NetworkEvent::Echo(
                    request_response::Event::OutboundFailure { error, .. },
                )) => return Err(format!("response: {error:?}")),
                SwarmEvent::ConnectionClosed { connection_id, .. } => {
                    if received && Some(connection_id) == connection {
                        futures_timer::Delay::new(Duration::from_millis(50)).await;
                        return Ok(());
                    }
                    return Err("closed before response".into());
                }
                SwarmEvent::Behaviour(NetworkEvent::Echo(request_response::Event::Message {
                    message: Message::Request { .. },
                    ..
                })) => return Err("unexpected inbound request".into()),
                _ => {}
            }
        }
    };
    match select(
        Box::pin(work),
        Box::pin(futures_timer::Delay::new(Duration::from_secs(10))),
    )
    .await
    {
        Either::Left((result, _)) => result,
        Either::Right(_) => Err("ten-second deadline".into()),
    }
}

#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    let window = web_sys::window().ok_or("window unavailable")?;
    let document = window.document().ok_or("document unavailable")?;
    let address: HtmlInputElement = document
        .get_element_by_id("address")
        .ok_or("address")?
        .dyn_into()?;
    let size: HtmlInputElement = document
        .get_element_by_id("size")
        .ok_or("size")?
        .dyn_into()?;
    let pause: HtmlInputElement = document
        .get_element_by_id("pause")
        .ok_or("pause")?
        .dyn_into()?;
    let output: Element = document.get_element_by_id("result").ok_or("result")?;
    let button = document.get_element_by_id("run").ok_or("run")?;
    let busy = Rc::new(Cell::new(false));
    let callback = Closure::<dyn FnMut()>::new(move || {
        if busy.replace(true) {
            return;
        }
        let (address, size, output, busy) =
            (address.value(), size.value(), output.clone(), busy.clone());
        let paused = pause.checked();
        PAUSE.store(paused, std::sync::atomic::Ordering::Relaxed);
        output.set_text_content(Some("Running real WebRTC exchange…"));
        wasm_bindgen_futures::spawn_local(async move {
            let result = match size.parse::<usize>() {
                Ok(n) => echo(address, n).await,
                Err(_) => Err("invalid byte count".into()),
            };
            output.set_text_content(Some(&match result {Ok(())=>format!("PASS bytes={size} pause={paused}: exact acknowledged 4 KiB records; native verified complete digest"),Err(e)=>format!("FAIL bytes={size} pause={paused}: {e}")}));
            busy.set(false);
        });
    });
    button.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())?;
    callback.forget();
    document
        .get_element_by_id("result")
        .unwrap()
        .set_text_content(Some("Rust/WASM loaded; ready for a loopback native peer."));
    Ok(())
}
