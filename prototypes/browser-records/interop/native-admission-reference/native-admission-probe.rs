#[cfg(test)]
mod valhalla_admission_probe {
    use super::*;
    use futures::future::poll_fn;
    use std::time::Duration;

    // Bounded reproduction, exclusively on owned loopback UDP sockets. Drop
    // each reported offer without polling its upgrade, as admission denial does.
    #[tokio::test]
    async fn declined_addresses_remain_before_any_connection_exists() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut mux = UDPMuxNewAddr::listen_on("127.0.0.1:0".parse().unwrap()).unwrap();
            let mut sockets = Vec::new();
            for index in 0_u8..32 {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let username = format!("fixture:probe{index:02}");
                let padded = (username.len() + 3) & !3;
                let mut packet = Vec::new();
                packet.extend_from_slice(&1_u16.to_be_bytes());
                packet.extend_from_slice(&((4 + padded) as u16).to_be_bytes());
                packet.extend_from_slice(&0x2112A442_u32.to_be_bytes());
                packet.extend_from_slice(&[index; 12]);
                packet.extend_from_slice(&6_u16.to_be_bytes());
                packet.extend_from_slice(&(username.len() as u16).to_be_bytes());
                packet.extend_from_slice(username.as_bytes());
                packet.resize(20 + 4 + padded, 0);
                socket.send_to(&packet, mux.listen_addr()).await.unwrap();
                let event = poll_fn(|cx| mux.poll(cx)).await;
                assert!(matches!(event, UDPMuxEvent::NewAddr(_)));
                // There is no admitted or pending connection state here.
                assert!(mux.conns.is_empty());
                assert!(mux.address_map.is_empty());
                assert_eq!(mux.new_addrs.len(), index as usize + 1);
                sockets.push(socket);
            }
            drop(sockets);
            assert!(
                tokio::time::timeout(Duration::from_millis(150), poll_fn(|cx| mux.poll(cx)))
                    .await
                    .is_err()
            );
            assert_eq!(mux.new_addrs.len(), 32);
            println!("OBSERVED retained_addresses=32 admitted_connections=0 mapped_addresses=0");
        })
        .await
        .unwrap();
    }
}
