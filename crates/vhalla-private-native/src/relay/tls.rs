//! Server-authenticated TLS for the canonical opaque relay protocol.
//!
//! Trust roots, exact server name and namespace are selected before dialing.
//! There is no ambient trust store, early data, DNS lookup or plaintext fallback.
//! Retention never establishes member acceptance. Service admission is bounded;
//! it does not promise availability under an unbounded distributed connection flood.
use super::{
    codec::*,
    net::{NetError, PageSource, RelayToken, ScanFailure},
    RelayItem, RelayNamespace, RelayPage, RelayReceipt,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, ClientConnection, ServerConfig, StreamOwned,
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};
mod service;
pub use service::{Credential, Permissions, Service, ServiceLimits};
#[cfg(test)]
mod tests;
type Result<T> = std::result::Result<T, NetError>;
const MAX_EXCHANGE: Duration = Duration::from_secs(25);
fn protocol(namespace: RelayNamespace) -> Vec<u8> {
    let mut value = b"vhalla-relay/1/".to_vec();
    value.extend_from_slice(namespace.as_bytes());
    value
}

fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "relay deadline"))
}
fn io(error: std::io::Error) -> NetError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => NetError::Timeout,
        std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted => NetError::Connect,
        _ => NetError::Unavailable,
    }
}
struct DeadlineSocket {
    stream: TcpStream,
    deadline: Instant,
}
impl Read for DeadlineSocket {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        self.stream.read(bytes)
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        remaining(self.deadline)?;
        self.stream.flush()
    }
}
fn read_frame(reader: &mut impl Read, max: usize, deadline: Instant) -> Result<Vec<u8>> {
    remaining(deadline).map_err(io)?;
    let mut length = [0; 4];
    reader.read_exact(&mut length).map_err(io)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > max {
        return Err(NetError::Malformed);
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).map_err(io)?;
    remaining(deadline).map_err(io)?;
    Ok(body)
}
fn write_frame(writer: &mut impl Write, code: u8, body: &[u8], deadline: Instant) -> Result<()> {
    remaining(deadline).map_err(io)?;
    writer.write_all(&frame(code, body)).map_err(io)?;
    writer.flush().map_err(io)?;
    remaining(deadline).map_err(io)?;
    Ok(())
}

/// Build a TLS 1.3 server with an explicit DER chain and PKCS#8 DER private key.
/// The caller owns key-file custody and certificate replacement at restart.
pub fn server_config(chain: Vec<Vec<u8>>, key: Vec<u8>) -> Result<Arc<ServerConfig>> {
    if chain.is_empty()
        || chain.len() > 8
        || chain.iter().any(|c| c.is_empty() || c.len() > 65536)
        || key.is_empty()
        || key.len() > 65536
    {
        return Err(NetError::Bounds);
    }
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| NetError::Bounds)?
            .with_no_client_auth()
            .with_single_cert(
                chain.into_iter().map(CertificateDer::from).collect(),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
            )
            .map_err(|_| NetError::Bounds)?;
    Ok(Arc::new(config))
}

/// One explicitly scoped authenticated endpoint; the credential is sent only
/// after the configured CA and exact server name pass a completed handshake.
pub struct TlsRelay {
    address: SocketAddr,
    name: ServerName<'static>,
    config: Arc<ClientConfig>,
    token: RelayToken,
    namespace: RelayNamespace,
    endpoint: super::delivery::EndpointId,
}
impl TlsRelay {
    /// Select independent server trust and namespace before any network effect.
    pub fn new(
        address: SocketAddr,
        name: &str,
        ca_der: Vec<u8>,
        token: RelayToken,
        namespace: RelayNamespace,
    ) -> Result<Self> {
        if ca_der.is_empty() || ca_der.len() > 65536 || name.len() > 253 {
            return Err(NetError::Bounds);
        }
        let endpoint = super::delivery::EndpointId::tls(address, name, &ca_der, namespace)
            .map_err(|_| NetError::Bounds)?;
        let name = ServerName::try_from(name.to_owned()).map_err(|_| NetError::Bounds)?;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_der))
            .map_err(|_| NetError::Bounds)?;
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| NetError::Bounds)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![protocol(namespace)];
        Ok(Self {
            address,
            name,
            config: Arc::new(config),
            token,
            namespace,
            endpoint,
        })
    }
    fn connect(&self, deadline: Instant) -> Result<StreamOwned<ClientConnection, DeadlineSocket>> {
        let stream = TcpStream::connect_timeout(
            &self.address,
            remaining(deadline)
                .map_err(io)?
                .min(Duration::from_secs(10)),
        )
        .map_err(io)?;
        let mut socket = DeadlineSocket { stream, deadline };
        let mut connection = ClientConnection::new(self.config.clone(), self.name.clone())
            .map_err(|_| NetError::Bounds)?;
        while connection.is_handshaking() {
            connection.complete_io(&mut socket).map_err(io)?;
        }
        remaining(deadline).map_err(io)?;
        if connection.alpn_protocol() != Some(protocol(self.namespace).as_slice()) {
            return Err(NetError::Scope);
        }
        Ok(StreamOwned::new(connection, socket))
    }
    fn exchange(&self, op: u8, body: &[u8], deadline: Instant) -> Result<Vec<u8>> {
        let mut tls = self.connect(deadline)?;
        // Do not construct token-bearing plaintext before certificate verification.
        let mut request = self.token.as_bytes().to_vec();
        request.extend_from_slice(body);
        write_frame(&mut tls, op, &request, deadline)?;
        let response = read_frame(&mut tls, MAX_RESPONSE, deadline)?;
        decode_status(response[0], &response[1..])
    }
    pub(super) fn token_matches(&self, candidate: &[u8; 32]) -> bool {
        self.token
            .as_bytes()
            .iter()
            .zip(candidate)
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
    }

    /// Exact namespace selected before any connection.
    pub fn namespace(&self) -> RelayNamespace {
        self.namespace
    }

    /// Submit already committed exact ciphertext; a timeout is an uncertain outcome.
    pub fn submit(&self, item: &RelayItem) -> Result<RelayReceipt> {
        self.submit_until(item, Instant::now() + MAX_EXCHANGE)
    }
    /// Submit within the caller's absolute operation budget.
    pub fn submit_until(&self, item: &RelayItem, deadline: Instant) -> Result<RelayReceipt> {
        if item.namespace() != self.namespace {
            return Err(NetError::Scope);
        }
        let encoded = item.encode().map_err(|_| NetError::Bounds)?;
        let body = self.exchange(
            OP_PUT,
            &encoded,
            deadline.min(Instant::now() + MAX_EXCHANGE),
        )?;
        decode_receipt(&body, item)
    }
    /// Fetch one canonical immutable page under the independently chosen namespace.
    pub fn page(&self, after: u64, limit: usize) -> Result<RelayPage> {
        self.page_until(after, limit, Instant::now() + MAX_EXCHANGE)
    }
    /// Fetch within the caller's absolute operation budget.
    pub fn page_until(&self, after: u64, limit: usize, deadline: Instant) -> Result<RelayPage> {
        let request = page_request(after, limit)?;
        let body = self.exchange(
            OP_PAGE,
            &request,
            deadline.min(Instant::now() + MAX_EXCHANGE),
        )?;
        let page = decode_page(&body, after, limit)?;
        if page
            .records
            .iter()
            .any(|r| r.item.namespace() != self.namespace)
        {
            return Err(NetError::Scope);
        }
        Ok(page)
    }
}
impl PageSource for TlsRelay {
    fn source_page(
        &self,
        after: u64,
        limit: usize,
        deadline: Instant,
    ) -> std::result::Result<RelayPage, ScanFailure> {
        self.page_until(after, limit, deadline)
            .map_err(ScanFailure::Net)
    }
}

impl super::delivery::Transport for TlsRelay {
    fn endpoint_id(&self) -> super::delivery::EndpointId {
        self.endpoint
    }
    fn namespace(&self) -> RelayNamespace {
        self.namespace
    }
    fn submit_until(&mut self, item: &RelayItem, deadline: Instant) -> Result<RelayReceipt> {
        TlsRelay::submit_until(self, item, deadline)
    }
}
impl TlsRelay {
    /// Exact non-secret trust-profile commitment for durable delivery binding.
    pub fn endpoint_id(&self) -> super::delivery::EndpointId {
        self.endpoint
    }
}
