#![forbid(unsafe_code)]
use futures::StreamExt;
use libp2p::{
    SwarmBuilder,
    request_response::{self, Message},
    swarm::SwarmEvent,
};
use std::{
    collections::BTreeMap,
    io::Write,
    time::{Duration, Instant},
};
use vhalla_browser_records_spike::{Error, Receiver};
use vhalla_browser_webrtc_spike::{NetworkEvent, behaviour, key};

struct Active {
    receiver: Receiver,
    deadline: Instant,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let certificate = libp2p_webrtc::tokio::Certificate::generate(&mut rand::rng()).unwrap();
    let mut swarm = SwarmBuilder::with_existing_identity(key(1))
        .with_tokio()
        .with_other_transport(|key| libp2p_webrtc::tokio::Transport::new(key.clone(), certificate))
        .unwrap()
        .with_behaviour(|_| behaviour(key(2).public().to_peer_id()))
        .unwrap()
        .with_swarm_config(|c| {
            c.with_idle_connection_timeout(Duration::from_secs(10))
                .with_per_connection_event_buffer_size(4)
        })
        .build();
    swarm
        .listen_on("/ip4/127.0.0.1/udp/0/webrtc-direct".parse().unwrap())
        .unwrap();
    let started = Instant::now();
    let mut receivers = BTreeMap::new();
    let stop = tokio::time::sleep(Duration::from_secs(600));
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tokio::pin!(stop);
    loop {
        let event = tokio::select! {
            _ = &mut stop => break,
            _ = tick.tick() => {
                let expired: Vec<_> = receivers.iter()
                    .filter(|(_, active): &(_, &Active)| Instant::now() >= active.deadline)
                    .map(|(id, _)| *id).collect();
                for id in expired {
                    receivers.remove(&id);
                    swarm.close_connection(id);
                }
                continue;
            }
            event = swarm.select_next_some() => event,
        };
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("ROUTE {address}/p2p/{}", swarm.local_peer_id());
            }
            SwarmEvent::Behaviour(NetworkEvent::Echo(request_response::Event::Message {
                peer,
                connection_id,
                message:
                    Message::Request {
                        request, channel, ..
                    },
                ..
            })) => {
                let accepted = receivers
                    .get_mut(&connection_id)
                    .ok_or(Error::Closed)
                    .and_then(|active| {
                        active
                            .receiver
                            .accept(&request, started.elapsed().as_millis() as u64)
                    });
                match accepted {
                    Ok(accepted) => {
                        println!("RECORD {} {peer}", request.len());
                        if let Some(body) = accepted.complete {
                            println!("COMPLETE {} {peer}", body.len());
                        }
                        if swarm
                            .behaviour_mut()
                            .echo
                            .send_response(channel, accepted.acknowledgment)
                            .is_err()
                        {
                            receivers.remove(&connection_id);
                            swarm.close_connection(connection_id);
                        }
                    }
                    Err(error) => {
                        println!("REJECT_RECORD {error:?}");
                        receivers.remove(&connection_id);
                        swarm.close_connection(connection_id);
                    }
                }
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                ..
            } => {
                if receivers.len() >= 4 {
                    swarm.close_connection(connection_id);
                    continue;
                }
                receivers.insert(
                    connection_id,
                    Active {
                        receiver: Receiver::new(started.elapsed().as_millis() as u64).unwrap(),
                        deadline: Instant::now() + Duration::from_secs(10),
                    },
                );
                println!("CONNECTED {peer_id}");
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                ..
            } => {
                receivers.remove(&connection_id);
                println!("CLOSED {peer_id}");
            }
            SwarmEvent::Behaviour(NetworkEvent::Echo(
                request_response::Event::InboundFailure { error, .. },
            )) => {
                println!("REJECT {error:?}");
            }
            SwarmEvent::Behaviour(NetworkEvent::Echo(request_response::Event::ResponseSent {
                ..
            })) => {
                println!("RESPONSE_SENT");
            }
            _ => {}
        }
        std::io::stdout().flush().unwrap();
    }
}
