//! Test-only TLS adapter. Framing parity is qualified against the native TCP
//! adapter; promotion would share that codec instead of maintaining two copies.
use rustls::{
    pki_types::ServerName, ClientConfig, ClientConnection, ServerConfig, ServerConnection,
    StreamOwned,
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};
use vhalla_private_native::relay::{
    net::{Mailbox, RelayToken},
    Error as StoreError, PositionedItem, RelayItem, RelayNamespace, RelayPage, RelayReceipt,
    MAX_RELAY_PAGE, MAX_RELAY_PAYLOAD,
};

const MAX_REQUEST: usize = 1 + 32 + 102 + MAX_RELAY_PAYLOAD;
const MAX_PAGE_BODY: usize = 4 * 1024 * 1024;
const MAX_RESPONSE: usize = MAX_PAGE_BODY + 1;
pub const PUT: u8 = 1;
pub const PAGE: u8 = 2;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    Timeout,
    Transport,
    Protocol,
    Denied,
    Conflict,
    Capacity,
    Scope,
    Unavailable,
}
pub type Result<T> = std::result::Result<T, Failure>;
fn io(error: std::io::Error) -> Failure {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Failure::Timeout,
        _ => Failure::Transport,
    }
}
fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "absolute TLS exchange deadline",
            )
        })
}
/// The same absolute deadline survives TLS handshake, partial records and the
/// encrypted application exchange. No per-read progress resets it.
pub struct DeadlineSocket {
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
pub fn frame(op: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(5 + body.len());
    bytes.extend_from_slice(&(u32::try_from(body.len() + 1).expect("bounded frame")).to_be_bytes());
    bytes.push(op);
    bytes.extend_from_slice(body);
    bytes
}
pub fn read_frame(reader: &mut impl Read, max: usize, deadline: Instant) -> Result<Vec<u8>> {
    remaining(deadline).map_err(io)?;
    let mut length = [0; 4];
    reader.read_exact(&mut length).map_err(io)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > max {
        return Err(Failure::Protocol);
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
fn store_status(error: StoreError) -> u8 {
    match error {
        StoreError::Conflict => 2,
        StoreError::Capacity => 3,
        StoreError::Bounds | StoreError::Confidential => 4,
        StoreError::Scope => 5,
        StoreError::Storage => 7,
    }
}
fn reply(code: u8, body: &[u8]) -> Result<Vec<u8>> {
    if code != 0 && !body.is_empty() {
        return Err(Failure::Protocol);
    }
    match code {
        0 => Ok(body.to_vec()),
        2 => Err(Failure::Conflict),
        3 => Err(Failure::Capacity),
        4 => Err(Failure::Protocol),
        5 => Err(Failure::Scope),
        6 => Err(Failure::Denied),
        7 => Err(Failure::Unavailable),
        _ => Err(Failure::Protocol),
    }
}

pub struct Client {
    address: SocketAddr,
    name: ServerName<'static>,
    config: Arc<ClientConfig>,
    token: RelayToken,
    namespace: RelayNamespace,
}
impl Client {
    /// Callers provide an explicit trust root and exact server name; no ambient
    /// OS roots, DNS lookup, dangerous verifier or fallback plaintext path.
    pub fn new(
        address: SocketAddr,
        name: &str,
        root: rustls::pki_types::CertificateDer<'static>,
        token: RelayToken,
        namespace: RelayNamespace,
    ) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root).unwrap();
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        assert!(!config.enable_early_data);
        Self {
            address,
            name: ServerName::try_from(name.to_owned()).unwrap(),
            config: Arc::new(config),
            token,
            namespace,
        }
    }
    fn connect(&self, deadline: Instant) -> Result<StreamOwned<ClientConnection, DeadlineSocket>> {
        let stream = TcpStream::connect_timeout(&self.address, remaining(deadline).map_err(io)?)
            .map_err(io)?;
        let mut socket = DeadlineSocket { stream, deadline };
        let mut connection = ClientConnection::new(self.config.clone(), self.name.clone())
            .map_err(|_| Failure::Transport)?;
        while connection.is_handshaking() {
            connection.complete_io(&mut socket).map_err(io)?;
        }
        remaining(deadline).map_err(io)?;
        // A token-bearing request cannot be constructed until the peer's full
        // chain and exact name have passed the configured TLS verifier.
        Ok(StreamOwned::new(connection, socket))
    }
    pub fn exchange(&self, op: u8, body: &[u8], deadline: Instant) -> Result<Vec<u8>> {
        let mut tls = self.connect(deadline)?;
        let mut request = self.token.as_bytes().to_vec();
        request.extend_from_slice(body);
        write_frame(&mut tls, op, &request, deadline)?;
        let response = read_frame(&mut tls, MAX_RESPONSE, deadline)?;
        reply(response[0], &response[1..])
    }
    pub fn submit(&self, item: &RelayItem, deadline: Instant) -> Result<RelayReceipt> {
        if item.namespace() != self.namespace {
            return Err(Failure::Scope);
        }
        let raw = self.exchange(
            PUT,
            &item.encode().map_err(|_| Failure::Protocol)?,
            deadline,
        )?;
        if raw.len() != 41 || raw[40] > 1 {
            return Err(Failure::Protocol);
        }
        let position = u64::from_be_bytes(raw[..8].try_into().unwrap());
        let digest = raw[8..40].try_into().unwrap();
        if position == 0 || item.digest() != digest {
            return Err(Failure::Protocol);
        }
        Ok(RelayReceipt {
            position,
            digest,
            duplicate: raw[40] == 1,
        })
    }
    pub fn page(&self, after: u64, limit: usize, deadline: Instant) -> Result<RelayPage> {
        if !(1..=MAX_RELAY_PAGE).contains(&limit) {
            return Err(Failure::Protocol);
        }
        let mut request = after.to_be_bytes().to_vec();
        request.extend_from_slice(&(limit as u16).to_be_bytes());
        let body = self.exchange(PAGE, &request, deadline)?;
        if body.len() < 11 || body[8] > 1 {
            return Err(Failure::Protocol);
        }
        let head = u64::from_be_bytes(body[..8].try_into().unwrap());
        let count = u16::from_be_bytes(body[9..11].try_into().unwrap()) as usize;
        if count > limit {
            return Err(Failure::Protocol);
        }
        let mut rest = &body[11..];
        let mut records = Vec::new();
        let mut previous = after;
        for _ in 0..count {
            if rest.len() < 12 {
                return Err(Failure::Protocol);
            }
            let position = u64::from_be_bytes(rest[..8].try_into().unwrap());
            let length = u32::from_be_bytes(rest[8..12].try_into().unwrap()) as usize;
            rest = &rest[12..];
            if length > rest.len() || Some(position) != previous.checked_add(1) || position > head {
                return Err(Failure::Protocol);
            }
            let item = RelayItem::decode(&rest[..length]).map_err(|_| Failure::Protocol)?;
            if item.namespace() != self.namespace {
                return Err(Failure::Scope);
            }
            records.push(PositionedItem { position, item });
            previous = position;
            rest = &rest[length..];
        }
        if !rest.is_empty()
            || (previous < head) != (body[8] == 1)
            || (previous < head && records.is_empty())
        {
            return Err(Failure::Protocol);
        }
        Ok(RelayPage {
            head,
            next: (body[8] == 1).then_some(previous),
            records,
        })
    }
    /// A test-only uncertain-outcome path: flush exact ciphertext, then lose the
    /// receipt. The next submission must retry the identical canonical item.
    pub fn lose_receipt(&self, item: &RelayItem, deadline: Instant) -> Result<()> {
        let mut tls = self.connect(deadline)?;
        let mut request = self.token.as_bytes().to_vec();
        request.extend_from_slice(&item.encode().map_err(|_| Failure::Protocol)?);
        write_frame(&mut tls, PUT, &request, deadline)
    }
    pub fn oversized_frame(&self, deadline: Instant) -> Result<()> {
        let mut tls = self.connect(deadline)?;
        tls.write_all(&u32::MAX.to_be_bytes()).map_err(io)?;
        tls.flush().map_err(io)
    }
}

#[derive(Default)]
pub struct Observation {
    pub application_bytes: usize,
    pub frames: Vec<Vec<u8>>,
}
struct ObservedReader<'a, R> {
    inner: &'a mut R,
    count: &'a mut usize,
}
impl<R: Read> Read for ObservedReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(bytes)?;
        *self.count += read;
        Ok(read)
    }
}

/// One accepted connection. Traces contain synthetic qualification bytes only,
/// stay in test memory and are never operational logging or persisted receipts.
pub fn serve_one(
    stream: TcpStream,
    config: Arc<ServerConfig>,
    store: &mut dyn Mailbox,
    token: RelayToken,
    deadline: Instant,
    observation: &mut Observation,
) -> Result<()> {
    let mut socket = DeadlineSocket { stream, deadline };
    let mut connection = ServerConnection::new(config).map_err(|_| Failure::Transport)?;
    while connection.is_handshaking() {
        connection.complete_io(&mut socket).map_err(io)?;
    }
    let mut tls = StreamOwned::new(connection, socket);
    let request = read_frame(
        &mut ObservedReader {
            inner: &mut tls,
            count: &mut observation.application_bytes,
        },
        MAX_REQUEST,
        deadline,
    )?;
    observation.frames.push(request.clone());
    if request.len() < 33
        || token
            .as_bytes()
            .iter()
            .zip(&request[1..33])
            .fold(0, |diff, (a, b)| diff | (a ^ b))
            != 0
    {
        return write_frame(&mut tls, 6, &[], deadline);
    }
    match request[0] {
        PUT => match RelayItem::decode(&request[33..]).and_then(|item| store.put(item)) {
            Ok(receipt) => {
                let mut body = receipt.position.to_be_bytes().to_vec();
                body.extend_from_slice(&receipt.digest);
                body.push(u8::from(receipt.duplicate));
                write_frame(&mut tls, 0, &body, deadline)
            }
            Err(error) => write_frame(&mut tls, store_status(error), &[], deadline),
        },
        PAGE if request.len() == 43 => {
            let after = u64::from_be_bytes(request[33..41].try_into().unwrap());
            let count = u16::from_be_bytes(request[41..43].try_into().unwrap()) as usize;
            match store.page(after, count) {
                Ok(page) => {
                    let mut records = Vec::new();
                    let mut count = 0u16;
                    let mut more = page.next.is_some();
                    for record in page.records {
                        let encoded = record.item.encode().map_err(|_| Failure::Protocol)?;
                        if 11 + records.len() + 12 + encoded.len() > MAX_PAGE_BODY && count > 0 {
                            more = true;
                            break;
                        }
                        records.extend_from_slice(&record.position.to_be_bytes());
                        records.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
                        records.extend_from_slice(&encoded);
                        count += 1;
                    }
                    let mut body = page.head.to_be_bytes().to_vec();
                    body.push(u8::from(more));
                    body.extend_from_slice(&count.to_be_bytes());
                    body.extend_from_slice(&records);
                    write_frame(&mut tls, 0, &body, deadline)
                }
                Err(error) => write_frame(&mut tls, store_status(error), &[], deadline),
            }
        }
        _ => write_frame(&mut tls, 4, &[], deadline),
    }
}
