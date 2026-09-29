//! Disposable independent-runner roles; the client disables UDP and checks paths.
use std::{
    io::{BufRead, Read, Write},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use vhalla_private_native::{
    habitat_link::{
        decode_frame, encode_frame, endpoint_builder, HabitatLinkService, UnixHabitatLinkHandler,
        HABITAT_LINK_ALPN, MAX_FRAME_BYTES,
    },
    relay::iroh::DEFAULT_RELAY_URL,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?)
}
/// Serve a local acceptor through a temporary relayed Iroh endpoint.
pub fn host(socket: &Path, descriptor: &Path, stop_path: &Path) -> Result<()> {
    let handler =
        UnixHabitatLinkHandler::new(socket).map_err(|error| format!("handler: {error:?}"))?;
    let runtime = runtime()?;
    let endpoint = runtime.block_on(async {
        let endpoint = endpoint_builder(Some(DEFAULT_RELAY_URL))
            .map_err(|error| format!("endpoint: {error:?}"))?
            .alpns(vec![HABITAT_LINK_ALPN.to_vec()])
            .bind()
            .await?;
        tokio::time::timeout(Duration::from_secs(30), endpoint.online()).await?;
        Ok::<_, Box<dyn std::error::Error>>(endpoint)
    })?;
    let stop = Arc::new(AtomicBool::new(false));
    let serving = {
        let (endpoint, stop) = (endpoint.clone(), stop.clone());
        runtime.spawn(async move {
            HabitatLinkService::new(handler)
                .serve(&endpoint, stop)
                .await
        })
    };
    let document =
        serde_json::json!({"endpoint_id":endpoint.id().to_string(),"relay_url":DEFAULT_RELAY_URL});
    let temporary = descriptor.with_extension("writing");
    std::fs::write(&temporary, serde_json::to_vec(&document)?)?;
    std::fs::rename(temporary, descriptor)?;
    let deadline = Instant::now() + Duration::from_secs(600);
    while !stop_path.exists() && Instant::now() < deadline && !serving.is_finished() {
        std::thread::sleep(Duration::from_millis(100));
    }
    let requested = stop_path.exists();
    stop.store(true, Ordering::Release);
    runtime.block_on(async {
        let result = serving.await?;
        endpoint.close().await;
        result
            .map_err(|error| -> Box<dyn std::error::Error> { format!("service: {error:?}").into() })
    })?;
    if !requested {
        return Err("host deadline or premature service shutdown".into());
    }
    Ok(())
}
/// Exchange JSON lines through relay-only Iroh connections.
pub fn client(descriptor: &Path) -> Result<()> {
    let raw = std::fs::read(descriptor)?;
    if raw.len() > 65_536 {
        return Err("descriptor exceeds bound".into());
    }
    let value: serde_json::Value = serde_json::from_slice(&raw)?;
    // Permit the ALGAL fixture's enclosing descriptor or the endpoint file alone.
    let value = value.get("endpoint").unwrap_or(&value);
    if value["relay_url"] != DEFAULT_RELAY_URL {
        return Err("unexpected test relay".into());
    }
    let id = value["endpoint_id"]
        .as_str()
        .ok_or("missing endpoint identity")?
        .parse::<iroh::EndpointId>()?;
    let target = iroh::EndpointAddr::new(id).with_relay_url(DEFAULT_RELAY_URL.parse()?);
    let runtime = runtime()?;
    let endpoint = runtime.block_on(async {
        let endpoint = endpoint_builder(Some(DEFAULT_RELAY_URL))
            .map_err(|error| format!("endpoint: {error:?}"))?
            .clear_ip_transports()
            .bind()
            .await?;
        tokio::time::timeout(Duration::from_secs(30), endpoint.online()).await?;
        Ok::<_, Box<dyn std::error::Error>>(endpoint)
    })?;
    let result = (|| -> Result<()> {
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
                return Err("envelope exceeds limit".into());
            }
            let frame = encode_frame(&line).map_err(|error| format!("frame: {error:?}"))?;
            let reply = runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(25), async {
                    let connection = endpoint.connect(target.clone(), HABITAT_LINK_ALPN).await?;
                    if connection.paths().is_empty()
                        || connection.paths().iter().any(|path| !path.is_relay())
                    {
                        return Err("non-relay connection".into());
                    }
                    let (mut send, mut recv) = connection.open_bi().await?;
                    send.write_all(&frame).await?;
                    send.finish()?;
                    let reply = match recv.read_to_end(MAX_FRAME_BYTES + 4).await {
                        Ok(bytes) => {
                            decode_frame(&bytes).map_err(|error| format!("reply: {error:?}"))?
                        }
                        Err(iroh::endpoint::ReadToEndError::Read(
                            iroh::endpoint::ReadError::Reset(code),
                        )) if code
                            == iroh::endpoint::VarInt::from_u32(
                                vhalla_private_native::habitat_link::RESET_HANDLER,
                            ) =>
                        {
                            br#"{"error":"handler_refused"}"#.to_vec()
                        }
                        Err(error) => return Err(error.into()),
                    };
                    if connection.paths().is_empty()
                        || connection.paths().iter().any(|path| !path.is_relay())
                    {
                        return Err("non-relay response path".into());
                    }
                    connection.close(0u32.into(), b"qualified");
                    Ok::<_, Box<dyn std::error::Error>>(reply)
                })
                .await
            })??;
            output.write_all(&reply)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
        Ok(())
    })();
    runtime.block_on(endpoint.close());
    result
}
