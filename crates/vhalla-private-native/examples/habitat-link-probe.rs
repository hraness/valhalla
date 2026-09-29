//! Direct loopback Iroh probe against a running ALGAL Unix socket adapter.
//! Pass the socket path; stdin/stdout contain one JSON envelope per line.
#[cfg(unix)]
#[path = "habitat-link-probe/remote.rs"]
mod remote;
#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        io::{BufRead, Read, Write},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };
    use vhalla_private_native::habitat_link::{
        endpoint_builder, send_envelope, HabitatLinkService, UnixHabitatLinkHandler,
        HABITAT_LINK_ALPN, MAX_FRAME_BYTES,
    };
    let all: Vec<_> = std::env::args_os().skip(1).collect();
    if all.first().is_some_and(|arg| arg == "host") && all.len() == 4 {
        return remote::host(
            std::path::Path::new(&all[1]),
            std::path::Path::new(&all[2]),
            std::path::Path::new(&all[3]),
        );
    }
    if all.first().is_some_and(|arg| arg == "client") && all.len() == 2 {
        return remote::client(std::path::Path::new(&all[1]));
    }
    let mut args = all.into_iter();
    let path = args
        .next()
        .ok_or("usage: habitat-link-probe ABSOLUTE_SOCKET")?;
    if args.next().is_some() {
        return Err("usage: habitat-link-probe ABSOLUTE_SOCKET".into());
    }
    let handler =
        UnixHabitatLinkHandler::new(path).map_err(|error| format!("socket path: {error:?}"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let (host, client) = runtime.block_on(async {
        let host = endpoint_builder(None)
            .unwrap()
            .alpns(vec![HABITAT_LINK_ALPN.to_vec()])
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())?
            .bind()
            .await?;
        let client = endpoint_builder(None).unwrap().bind().await?;
        Ok::<_, Box<dyn std::error::Error>>((host, client))
    })?;
    let addr = host.addr();
    let stop = Arc::new(AtomicBool::new(false));
    let serving = {
        let (endpoint, stop) = (host.clone(), stop.clone());
        runtime.spawn(async move {
            HabitatLinkService::new(handler)
                .serve(&endpoint, stop)
                .await
        })
    };
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut input = std::io::stdin().lock();
        let mut output = std::io::stdout().lock();
        loop {
            let mut line = Vec::new();
            if input
                .by_ref()
                .take((MAX_FRAME_BYTES + 2) as u64)
                .read_until(b'\n', &mut line)?
                == 0
            {
                break;
            }
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.len() > MAX_FRAME_BYTES {
                return Err("envelope exceeds frame limit".into());
            }
            let reply = runtime
                .block_on(send_envelope(&client, addr.clone(), &line))
                .map_err(|error| format!("exchange: {error:?}"))?;
            output.write_all(&reply)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
        Ok(())
    })();
    stop.store(true, Ordering::Release);
    runtime.block_on(async {
        let _ = serving.await;
        host.close().await;
        client.close().await;
    });
    result
}
#[cfg(not(unix))]
fn main() {
    eprintln!("habitat-link-probe requires Unix sockets");
    std::process::exit(1);
}
