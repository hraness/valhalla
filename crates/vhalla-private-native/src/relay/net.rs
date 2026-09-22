//! Token-authenticated TCP adapter for the canonical relay boundary.
//!
//! The adapter carries only canonical opaque `RelayItem` bytes; it never sees
//! plaintext, room metadata, identity custody or member acceptance. One mailbox
//! secret gates every request. The reference server serves accepted connections
//! sequentially with bounded reads and per-socket deadlines; it is a local or
//! operator-controlled relay, not a hardened Internet service. A retention
//! receipt is relay custody only and never proves delivery or acceptance.

use super::{
    Error, FileStore, PositionedItem, RelayItem, RelayNamespace, RelayPage, RelayReceipt, Result,
    Store, MAGIC, MAX_RELAY_ITEMS, MAX_RELAY_PAGE, MAX_RELAY_PAYLOAD,
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use vhalla_custody as custody;

/// Maximum request body: token plus one canonical item frame.
const MAX_PUT_BODY: usize = 32 + MAGIC.len() + 32 + 8 + 16 + 1 + 4 + MAX_RELAY_PAYLOAD + 32;
/// Request length field bound; GET-style operations are far below this.
const MAX_REQUEST: usize = 1 + MAX_PUT_BODY;
/// Response budget for one page: metadata plus whole item frames. A page that
/// cannot fit returns `more` so the caller resumes at its retained cursor.
const MAX_PAGE_BODY: usize = 4 * 1024 * 1024;
/// Largest response frame: status byte plus a full page body.
const MAX_RESPONSE: usize = 1 + MAX_PAGE_BODY;
/// Bounded per-socket IO deadlines; a stalled peer cannot hold the server.
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Absolute budget for a scan and its guarded local consumption. A budget
/// refusal retains progress for the next explicit invocation.
const SCAN_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_ITEM_BYTES: usize = MAGIC.len() + 32 + 8 + 16 + 1 + 4 + MAX_RELAY_PAYLOAD + 32;
const MAX_SCAN_BYTES: usize = MAX_RELAY_ITEMS * MAX_ITEM_BYTES;
const SCAN_MAGIC: &[u8] = b"VHSCAN\x01";
const OP_PUT: u8 = 1;
const OP_PAGE: u8 = 2;
const STATUS_OK: u8 = 0;
const STATUS_CONFLICT: u8 = 2;
const STATUS_CAPACITY: u8 = 3;
const STATUS_BOUNDS: u8 = 4;
const STATUS_SCOPE: u8 = 5;
const STATUS_DENIED: u8 = 6;
const STATUS_UNAVAILABLE: u8 = 7;

/// Closed adapter failures. None carries ciphertext, tokens or addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetError {
    /// The listener was unreachable or the connection failed.
    Connect,
    /// A bounded read, write or connect deadline elapsed.
    Timeout,
    /// The mailbox refused the presented token.
    Denied,
    /// The same sequence or operation arrived with different bytes.
    Conflict,
    /// The relay quota is full; retained items are never pruned.
    Capacity,
    /// Input or wire data was malformed, noncanonical or over a bound.
    Bounds,
    /// The item belongs to another opaque namespace.
    Scope,
    /// The peer answered with a noncanonical frame or status.
    Malformed,
    /// A durable or socket operation failed without a finer claim.
    Unavailable,
}
impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for NetError {}
type NetResult<T> = std::result::Result<T, NetError>;

/// A 32-byte mailbox admission secret shared out of band. It is a transport
/// credential only; it never derives from or grants room authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RelayToken([u8; 32]);
impl core::fmt::Debug for RelayToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RelayToken([REDACTED])")
    }
}
impl RelayToken {
    /// Construct a nonzero token supplied by the operator out of band.
    pub fn from_bytes(bytes: [u8; 32]) -> NetResult<Self> {
        if bytes == [0; 32] {
            return Err(NetError::Bounds);
        }
        Ok(Self(bytes))
    }
    /// Borrow the exact token bytes for the request frame.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn authorized(token: &RelayToken, presented: &[u8]) -> bool {
    if presented.len() != 32 {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in token.0.iter().zip(presented.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn status(error: Error) -> u8 {
    match error {
        Error::Conflict => STATUS_CONFLICT,
        Error::Capacity => STATUS_CAPACITY,
        Error::Scope => STATUS_SCOPE,
        Error::Storage => STATUS_UNAVAILABLE,
        Error::Bounds | Error::Confidential => STATUS_BOUNDS,
    }
}
fn decode_status(code: u8, body: &[u8]) -> NetResult<Vec<u8>> {
    if code != STATUS_OK && !body.is_empty() {
        return Err(NetError::Malformed);
    }
    match code {
        STATUS_OK => Ok(body.to_vec()),
        STATUS_CONFLICT => Err(NetError::Conflict),
        STATUS_CAPACITY => Err(NetError::Capacity),
        STATUS_BOUNDS => Err(NetError::Bounds),
        STATUS_SCOPE => Err(NetError::Scope),
        STATUS_DENIED => Err(NetError::Denied),
        STATUS_UNAVAILABLE => Err(NetError::Unavailable),
        _ => Err(NetError::Malformed),
    }
}
fn frame(op: u8, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(1 + body.len()).expect("bounded relay frame");
    let mut out = Vec::with_capacity(4 + len as usize);
    out.extend_from_slice(&len.to_be_bytes());
    out.push(op);
    out.extend_from_slice(body);
    out
}
fn io(error: std::io::Error) -> NetError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => NetError::Timeout,
        std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::NotConnected
        | std::io::ErrorKind::AddrNotAvailable
        | std::io::ErrorKind::AddrInUse => NetError::Connect,
        _ => NetError::Unavailable,
    }
}
fn remaining(deadline: Instant) -> NetResult<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(NetError::Timeout)
}
fn read_exact(stream: &mut TcpStream, mut buf: &mut [u8], deadline: Instant) -> NetResult<()> {
    while !buf.is_empty() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(io)?;
        match stream.read(buf) {
            Ok(0) => return Err(NetError::Unavailable),
            Ok(n) => buf = &mut buf[n..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io(error)),
        }
    }
    remaining(deadline)?;
    Ok(())
}
fn read_frame(stream: &mut TcpStream, max: usize, deadline: Instant) -> NetResult<Vec<u8>> {
    let mut len = [0u8; 4];
    read_exact(stream, &mut len, deadline)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > max {
        return Err(NetError::Malformed);
    }
    let mut body = vec![0u8; len];
    read_exact(stream, &mut body, deadline)?;
    Ok(body)
}
fn write_bytes(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> NetResult<()> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(io)?;
        match stream.write(bytes) {
            Ok(0) => return Err(NetError::Unavailable),
            Ok(n) => bytes = &bytes[n..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io(error)),
        }
    }
    remaining(deadline)?;
    Ok(())
}
fn write_frame(
    stream: &mut TcpStream,
    status: u8,
    body: &[u8],
    deadline: Instant,
) -> NetResult<()> {
    write_bytes(stream, &frame(status, body), deadline)
}

/// The retention surface one adapter serves. `Store` covers in-process use;
/// `FileStore` adds durable cross-process custody. Both never open identity.
pub trait Mailbox {
    /// Store an item idempotently, exactly as the local boundary defines.
    fn put(&mut self, item: RelayItem) -> Result<RelayReceipt>;
    /// Read one bounded immutable page of retained items.
    fn page(&self, after: u64, limit: usize) -> Result<RelayPage>;
}
impl Mailbox for Store {
    fn put(&mut self, item: RelayItem) -> Result<RelayReceipt> {
        Store::put(self, item)
    }
    fn page(&self, after: u64, limit: usize) -> Result<RelayPage> {
        Store::page(self, after, limit)
    }
}
impl Mailbox for FileStore {
    fn put(&mut self, item: RelayItem) -> Result<RelayReceipt> {
        FileStore::put(self, item)
    }
    fn page(&self, after: u64, limit: usize) -> Result<RelayPage> {
        FileStore::page(self, after, limit)
    }
}

/// One bounded request on one connection. Authentication precedes any parse of
/// the operation payload, and every outcome maps to a closed status.
fn handle(
    stream: &mut TcpStream,
    store: &mut dyn Mailbox,
    token: &RelayToken,
    deadline: Instant,
) -> NetResult<()> {
    let request = read_frame(stream, MAX_REQUEST, deadline)?;
    let op = request[0];
    let body = &request[1..];
    if body.len() < 32 || !authorized(token, &body[..32]) {
        return write_frame(stream, STATUS_DENIED, &[], deadline);
    }
    let body = &body[32..];
    match op {
        OP_PUT => {
            let result = RelayItem::decode(body).and_then(|item| store.put(item));
            match result {
                Ok(receipt) => {
                    let mut out = Vec::with_capacity(41);
                    out.extend_from_slice(&receipt.position.to_be_bytes());
                    out.extend_from_slice(&receipt.digest);
                    out.push(u8::from(receipt.duplicate));
                    write_frame(stream, STATUS_OK, &out, deadline)
                }
                Err(error) => write_frame(stream, status(error), &[], deadline),
            }
        }
        OP_PAGE => {
            if body.len() != 10 {
                return write_frame(stream, STATUS_BOUNDS, &[], deadline);
            }
            let after = u64::from_be_bytes(body[..8].try_into().expect("bounded"));
            let limit = u16::from_be_bytes(body[8..10].try_into().expect("bounded")) as usize;
            match store.page(after, limit) {
                Ok(page) => {
                    let mut out = Vec::new();
                    out.extend_from_slice(&page.head.to_be_bytes());
                    let mut more = page.next.is_some();
                    let mut count = 0u16;
                    let mut items = Vec::new();
                    for record in &page.records {
                        let encoded = record.item.encode().map_err(|_| NetError::Unavailable)?;
                        if 11 + items.len() + 12 + encoded.len() > MAX_PAGE_BODY && count > 0 {
                            more = true;
                            break;
                        }
                        items.extend_from_slice(&record.position.to_be_bytes());
                        items.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
                        items.extend_from_slice(&encoded);
                        count += 1;
                    }
                    out.push(u8::from(more));
                    out.extend_from_slice(&count.to_be_bytes());
                    out.extend_from_slice(&items);
                    write_frame(stream, STATUS_OK, &out, deadline)
                }
                Err(error) => write_frame(stream, status(error), &[], deadline),
            }
        }
        _ => write_frame(stream, STATUS_BOUNDS, &[], deadline),
    }
}

/// Serve one mailbox on an already bound listener until the optional accepted
/// connection count is reached or a socket operation fails. Each connection
/// carries one bounded request and is closed after its response.
pub fn serve(
    listener: TcpListener,
    store: impl Mailbox,
    token: RelayToken,
    limit: Option<u64>,
) -> Result<()> {
    serve_with_timeout(listener, store, token, limit, IO_TIMEOUT)
}
fn serve_with_timeout(
    listener: TcpListener,
    mut store: impl Mailbox,
    token: RelayToken,
    limit: Option<u64>,
    timeout: Duration,
) -> Result<()> {
    let mut accepted = 0u64;
    loop {
        if limit.is_some_and(|limit| accepted >= limit) {
            return Ok(());
        }
        let (mut stream, _) = listener.accept().map_err(|_| Error::Storage)?;
        accepted += 1;
        // One absolute deadline includes every partial read and write. A
        // trickling or dropped unauthenticated client cannot park this loop.
        let _ = handle(&mut stream, &mut store, &token, Instant::now() + timeout);
    }
}

/// A token-authenticated relay client for one explicit socket address. Every
/// call opens a short bounded connection; there is no pooled state to wedge.
pub struct SocketRelay {
    addr: SocketAddr,
    token: RelayToken,
}
impl SocketRelay {
    /// The relay address and mailbox token were agreed with the operator.
    pub fn new(addr: SocketAddr, token: RelayToken) -> Self {
        Self { addr, token }
    }
    fn exchange(&self, op: u8, body: &[u8], deadline: Instant) -> NetResult<Vec<u8>> {
        let connect = remaining(deadline)?.min(CONNECT_TIMEOUT);
        let mut stream = TcpStream::connect_timeout(&self.addr, connect).map_err(io)?;
        let mut request = Vec::with_capacity(32 + body.len());
        request.extend_from_slice(self.token.as_bytes());
        request.extend_from_slice(body);
        write_bytes(&mut stream, &frame(op, &request), deadline)?;
        let response = read_frame(&mut stream, MAX_RESPONSE, deadline)?;
        decode_status(response[0], &response[1..])
    }
    /// Retain one canonical item and return the relay's retention receipt.
    /// The position is mailbox-assigned; the receipt is never delivery or
    /// member acceptance.
    pub fn submit(&self, item: &RelayItem) -> NetResult<RelayReceipt> {
        self.submit_until(item, Instant::now() + CONNECT_TIMEOUT + IO_TIMEOUT)
    }
    /// Retain an exact item within a larger caller operation's absolute deadline.
    pub fn submit_until(&self, item: &RelayItem, deadline: Instant) -> NetResult<RelayReceipt> {
        let deadline = deadline.min(Instant::now() + CONNECT_TIMEOUT + IO_TIMEOUT);
        let encoded = item.encode().map_err(|_| NetError::Bounds)?;
        let body = self.exchange(OP_PUT, &encoded, deadline)?;
        if body.len() != 41 {
            return Err(NetError::Malformed);
        }
        let position = u64::from_be_bytes(body[..8].try_into().expect("bounded"));
        let digest: [u8; 32] = body[8..40].try_into().expect("bounded");
        if position == 0 || digest != item.digest() || body[40] > 1 {
            return Err(NetError::Malformed);
        }
        Ok(RelayReceipt {
            position,
            digest,
            duplicate: body[40] != 0,
        })
    }
    /// Read one authenticated page. A large retained page is truncated to the
    /// wire budget with `next` set, so catch-up can always resume.
    pub fn page(&self, after: u64, limit: usize) -> NetResult<RelayPage> {
        self.page_until(after, limit, Instant::now() + CONNECT_TIMEOUT + IO_TIMEOUT)
    }
    fn page_until(&self, after: u64, limit: usize, deadline: Instant) -> NetResult<RelayPage> {
        if limit == 0 || limit > MAX_RELAY_PAGE {
            return Err(NetError::Bounds);
        }
        let mut request = Vec::with_capacity(10);
        request.extend_from_slice(&after.to_be_bytes());
        request.extend_from_slice(&(limit as u16).to_be_bytes());
        let body = self.exchange(OP_PAGE, &request, deadline)?;
        if body.len() < 11 {
            return Err(NetError::Malformed);
        }
        let head = u64::from_be_bytes(body[..8].try_into().expect("bounded"));
        let more = match body[8] {
            0 => false,
            1 => true,
            _ => return Err(NetError::Malformed),
        };
        let count = u16::from_be_bytes(body[9..11].try_into().expect("bounded")) as usize;
        if count > limit {
            return Err(NetError::Malformed);
        }
        let mut records = Vec::with_capacity(count);
        let mut cursor = 11usize;
        for _ in 0..count {
            let end = cursor.checked_add(8).ok_or(NetError::Malformed)?;
            if end > body.len() {
                return Err(NetError::Malformed);
            }
            let position = u64::from_be_bytes(body[cursor..end].try_into().expect("bounded"));
            if position == 0 {
                return Err(NetError::Malformed);
            }
            cursor = end;
            let end = cursor.checked_add(4).ok_or(NetError::Malformed)?;
            if end > body.len() {
                return Err(NetError::Malformed);
            }
            let len = u32::from_be_bytes(body[cursor..end].try_into().expect("bounded")) as usize;
            cursor = end;
            let end = cursor.checked_add(len).ok_or(NetError::Malformed)?;
            if end > body.len() {
                return Err(NetError::Malformed);
            }
            let item = RelayItem::decode(&body[cursor..end]).map_err(|_| NetError::Malformed)?;
            records.push(PositionedItem { position, item });
            cursor = end;
        }
        if cursor != body.len()
            || (more && records.is_empty())
            || !records
                .iter()
                .zip(records.iter().skip(1))
                .all(|(a, b)| a.position < b.position)
        {
            return Err(NetError::Malformed);
        }
        let next = more.then(|| records.last().expect("nonempty").position);
        let page = RelayPage {
            head,
            next,
            records,
        };
        validate_page(&page, after, limit)?;
        Ok(page)
    }
    /// Fetch one exact retained relay position, or report its absence.
    pub fn fetch(&self, position: u64) -> NetResult<Option<PositionedItem>> {
        let after = position.checked_sub(1).ok_or(NetError::Bounds)?;
        let page = self.page(after, 1)?;
        Ok(page
            .records
            .into_iter()
            .find(|record| record.position == position))
    }
}

/// Validate the immutable, contiguous mailbox page contract before any effects.
fn validate_page(page: &RelayPage, after: u64, limit: usize) -> NetResult<()> {
    if limit == 0 || limit > MAX_RELAY_PAGE || page.records.len() > limit {
        return Err(NetError::Malformed);
    }
    // A standalone fetch beyond the retained head is a valid absence. A scan
    // separately refuses this as a rollback of its already retained cursor.
    if page.head < after {
        return if page.records.is_empty() && page.next.is_none() {
            Ok(())
        } else {
            Err(NetError::Malformed)
        };
    }
    let mut previous = after;
    for record in &page.records {
        if Some(record.position) != previous.checked_add(1) || record.position > page.head {
            return Err(NetError::Malformed);
        }
        previous = record.position;
    }
    if (previous < page.head && (page.records.is_empty() || page.next != Some(previous)))
        || (previous == page.head && page.next.is_some())
    {
        return Err(NetError::Malformed);
    }
    Ok(())
}

/// A completed catch-up pass through the first observed mailbox head. Items
/// appended during the pass wait for the next explicit scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanReport {
    /// First observed head, fully staged by this completed pass.
    pub head: u64,
    /// Durable cursor: the last position published in the items directory.
    pub cursor: u64,
    /// Items newly published during this pass; an exact rescan counts zero.
    pub scanned: usize,
}

/// Closed failures preserve committed evidence and the last durable cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanFailure {
    /// The relay refused, timed out, or answered noncanonically.
    Net(NetError),
    /// Retained item bytes or the contiguous local inventory are inconsistent.
    Corrupt,
    /// Local cursor or item storage failed. Reopen the exact directory.
    Storage,
    /// The source mailbox is damaged, foreign or busy.
    Source,
    /// The directory or a returned item belongs to another explicit namespace.
    Scope,
    /// A nonempty directory lacks the new namespace binding. Preserve it and
    /// select a new empty output directory; no automatic migration is safe.
    Legacy,
    /// Another scan or pull holds this directory's exclusive custody lock.
    Busy,
    /// A fixed retained-item or retained-byte budget would be exceeded.
    Capacity,
    /// The absolute scan/pull time budget elapsed. Progress remains resumable.
    Timeout,
}
impl core::fmt::Display for ScanFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ScanFailure {}

fn read_cursor(directory: &Path, uid: u32) -> std::result::Result<u64, ScanFailure> {
    let path = directory.join("cursor");
    if !custody::private_file_present(&path, uid, 8).map_err(|_| ScanFailure::Storage)? {
        return Ok(0);
    }
    let raw = custody::read_private_file(&path, uid, 8).map_err(|_| ScanFailure::Storage)?;
    let bytes = raw.try_into().map_err(|_| ScanFailure::Corrupt)?;
    let cursor = u64::from_be_bytes(bytes);
    if cursor > MAX_RELAY_ITEMS as u64 {
        return Err(ScanFailure::Capacity);
    }
    Ok(cursor)
}
fn publish_cursor(
    directory: &Path,
    handle: &File,
    cursor: u64,
    uid: u32,
) -> std::result::Result<(), ScanFailure> {
    let tmp = directory.join("cursor.tmp");
    // Only this guard owns the scratch file. Never unlink an arbitrary path.
    if custody::private_file_present(&tmp, uid, 8).map_err(|_| ScanFailure::Storage)? {
        fs::remove_file(&tmp).map_err(|_| ScanFailure::Storage)?;
    }
    let mut file = custody::create_private_file(&tmp).map_err(|_| ScanFailure::Storage)?;
    file.write_all(&cursor.to_be_bytes())
        .map_err(|_| ScanFailure::Storage)?;
    file.sync_all().map_err(|_| ScanFailure::Storage)?;
    fs::rename(&tmp, directory.join("cursor")).map_err(|_| ScanFailure::Storage)?;
    handle.sync_all().map_err(|_| ScanFailure::Storage)
}
fn item_path(items: &Path, position: u64) -> PathBuf {
    items.join(format!("{position:016x}.vhrelay"))
}

/// A bounded position-ordered source. Implementations must honor the absolute
/// deadline across every network read/write, not reset it for partial progress.
pub trait PageSource {
    /// Read one bounded page before the caller's operation deadline.
    fn source_page(
        &self,
        after: u64,
        limit: usize,
        deadline: Instant,
    ) -> std::result::Result<RelayPage, ScanFailure>;
}
impl PageSource for SocketRelay {
    fn source_page(
        &self,
        after: u64,
        limit: usize,
        deadline: Instant,
    ) -> std::result::Result<RelayPage, ScanFailure> {
        self.page_until(
            after,
            limit,
            deadline.min(Instant::now() + CONNECT_TIMEOUT + IO_TIMEOUT),
        )
        .map_err(ScanFailure::Net)
    }
}
impl PageSource for FileStore {
    fn source_page(
        &self,
        after: u64,
        limit: usize,
        deadline: Instant,
    ) -> std::result::Result<RelayPage, ScanFailure> {
        remaining(deadline).map_err(|_| ScanFailure::Timeout)?;
        let page = FileStore::page(self, after, limit).map_err(|_| ScanFailure::Source)?;
        remaining(deadline).map_err(|_| ScanFailure::Timeout)?;
        Ok(page)
    }
}
impl PageSource for Store {
    fn source_page(
        &self,
        after: u64,
        limit: usize,
        deadline: Instant,
    ) -> std::result::Result<RelayPage, ScanFailure> {
        remaining(deadline).map_err(|_| ScanFailure::Timeout)?;
        let page = Store::page(self, after, limit).map_err(|_| ScanFailure::Source)?;
        remaining(deadline).map_err(|_| ScanFailure::Timeout)?;
        Ok(page)
    }
}

/// Exclusive namespace-bound catch-up custody. Retain this guard across a scan
/// and consumption of staged items; dropping it releases the directory lock.
/// Filesystem barriers are synchronous and cannot be forcibly cancelled. Time
/// checks bound admission of further work after a slow filesystem call returns.
pub struct ScanDirectory {
    path: PathBuf,
    directory: File,
    items: File,
    _lock: File,
    uid: u32,
    namespace: RelayNamespace,
    cursor: u64,
    deadline: Instant,
    #[cfg(test)]
    fault: Option<PublicationFault>,
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum PublicationFault {
    PartialItem,
    ItemSynced,
    ItemPublished,
    ItemsSynced,
    CursorPublished,
}

impl ScanDirectory {
    /// Open or initialize an empty private directory for this explicit mailbox
    /// namespace. Nonempty legacy directories refuse without changing evidence.
    pub fn open(
        directory: &Path,
        namespace: RelayNamespace,
    ) -> std::result::Result<Self, ScanFailure> {
        let deadline = Instant::now() + SCAN_TIMEOUT;
        let path = custody::absolute(directory).map_err(|_| ScanFailure::Storage)?;
        let created = match fs::symlink_metadata(&path) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => return Err(ScanFailure::Storage),
        };
        let (dir, uid) =
            custody::ensure_private_directory(&path).map_err(|_| ScanFailure::Storage)?;
        let binding = path.join("namespace");
        let bound = custody::private_file_present(&binding, uid, SCAN_MAGIC.len() + 32)
            .map_err(|_| ScanFailure::Storage)?;
        if !bound {
            // A lock-only interrupted initialization has no mailbox data. All
            // older cursor/items directories remain untouched and unbound.
            for entry in fs::read_dir(&path).map_err(|_| ScanFailure::Storage)? {
                let entry = entry.map_err(|_| ScanFailure::Storage)?;
                if entry.file_name() != "lock" {
                    return Err(ScanFailure::Legacy);
                }
            }
        }
        let lock_path = path.join("lock");
        let lock = if bound {
            // A bound directory must retain its original lock inode. Never
            // recreate a missing lock while another process may still hold it.
            custody::open_private_file(&lock_path, uid, 0).map_err(|_| ScanFailure::Storage)?
        } else {
            match custody::create_private_file(&lock_path) {
                Ok(file) => file,
                Err(_) => custody::open_private_file(&lock_path, uid, 0)
                    .map_err(|_| ScanFailure::Storage)?,
            }
        };
        custody::acquire_exclusive(&lock).map_err(|error| match error {
            custody::Error::Busy => ScanFailure::Busy,
            _ => ScanFailure::Storage,
        })?;
        // Recheck under the lock: another initializer may have finished while
        // this caller was acquiring custody.
        if custody::private_file_present(&binding, uid, SCAN_MAGIC.len() + 32)
            .map_err(|_| ScanFailure::Storage)?
        {
            let raw = custody::read_private_file(&binding, uid, SCAN_MAGIC.len() + 32)
                .map_err(|_| ScanFailure::Storage)?;
            if raw.len() != SCAN_MAGIC.len() + 32 || !raw.starts_with(SCAN_MAGIC) {
                return Err(ScanFailure::Corrupt);
            }
            if &raw[SCAN_MAGIC.len()..] != namespace.as_bytes() {
                return Err(ScanFailure::Scope);
            }
        } else {
            for entry in fs::read_dir(&path).map_err(|_| ScanFailure::Storage)? {
                if entry.map_err(|_| ScanFailure::Storage)?.file_name() != "lock" {
                    return Err(ScanFailure::Legacy);
                }
            }
            let tmp = path.join("namespace.tmp");
            let mut file = custody::create_private_file(&tmp).map_err(|_| ScanFailure::Storage)?;
            file.write_all(SCAN_MAGIC)
                .and_then(|()| file.write_all(namespace.as_bytes()))
                .map_err(|_| ScanFailure::Storage)?;
            file.sync_all().map_err(|_| ScanFailure::Storage)?;
            fs::rename(&tmp, &binding).map_err(|_| ScanFailure::Storage)?;
            dir.sync_all().map_err(|_| ScanFailure::Storage)?;
        }
        let (items, items_uid) = custody::ensure_private_directory(&path.join("items"))
            .map_err(|_| ScanFailure::Storage)?;
        if items_uid != uid {
            return Err(ScanFailure::Storage);
        }
        dir.sync_all().map_err(|_| ScanFailure::Storage)?;
        if created {
            File::open(path.parent().ok_or(ScanFailure::Storage)?)
                .and_then(|parent| parent.sync_all())
                .map_err(|_| ScanFailure::Storage)?;
        }
        let cursor = read_cursor(&path, uid)?;
        let out = Self {
            path,
            directory: dir,
            items,
            _lock: lock,
            uid,
            namespace,
            cursor,
            deadline,
            #[cfg(test)]
            fault: None,
        };
        out.positions()?;
        Ok(out)
    }

    /// Refuse further scan/pull work after the one absolute operation budget.
    pub fn check_deadline(&self) -> std::result::Result<(), ScanFailure> {
        remaining(self.deadline)
            .map(|_| ())
            .map_err(|_| ScanFailure::Timeout)
    }

    /// Return the bounded contiguous committed positions after validating file
    /// custody and sizes. One published item beyond the cursor is permitted as
    /// interruption evidence; only the next scan can reconcile it.
    pub fn positions(&self) -> std::result::Result<Vec<u64>, ScanFailure> {
        self.check_deadline()?;
        let mut positions = Vec::new();
        let mut bytes = 0usize;
        let mut entries = 0usize;
        for entry in fs::read_dir(self.path.join("items")).map_err(|_| ScanFailure::Storage)? {
            self.check_deadline()?;
            entries += 1;
            if entries > MAX_RELAY_ITEMS + 1 {
                return Err(ScanFailure::Capacity);
            }
            let entry = entry.map_err(|_| ScanFailure::Storage)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ScanFailure::Corrupt)?;
            let handle = custody::open_private_file(&entry.path(), self.uid, MAX_ITEM_BYTES)
                .map_err(|_| ScanFailure::Storage)?;
            let length =
                usize::try_from(handle.metadata().map_err(|_| ScanFailure::Storage)?.len())
                    .map_err(|_| ScanFailure::Capacity)?;
            if name == "item.tmp" {
                continue;
            }
            let position = name
                .strip_suffix(".vhrelay")
                .and_then(|raw| u64::from_str_radix(raw, 16).ok())
                .filter(|position| *position > 0 && name == format!("{position:016x}.vhrelay"))
                .ok_or(ScanFailure::Corrupt)?;
            if position > MAX_RELAY_ITEMS as u64 || position > self.cursor + 1 {
                return Err(ScanFailure::Corrupt);
            }
            bytes = bytes
                .checked_add(length)
                .filter(|bytes| *bytes <= MAX_SCAN_BYTES)
                .ok_or(ScanFailure::Capacity)?;
            positions.push(position);
        }
        positions.sort_unstable();
        if positions
            .iter()
            .enumerate()
            .any(|(index, position)| *position != index as u64 + 1)
            || positions.len() < self.cursor as usize
        {
            return Err(ScanFailure::Corrupt);
        }
        positions.retain(|position| *position <= self.cursor);
        Ok(positions)
    }

    /// Read one committed item under retained custody with descriptor, size,
    /// canonical-envelope and namespace checks. No unbounded filesystem read.
    pub fn read(&self, position: u64) -> std::result::Result<RelayItem, ScanFailure> {
        self.check_deadline()?;
        if position == 0 || position > self.cursor {
            return Err(ScanFailure::Corrupt);
        }
        let raw = custody::read_private_file(
            &item_path(&self.path.join("items"), position),
            self.uid,
            MAX_ITEM_BYTES,
        )
        .map_err(|_| ScanFailure::Storage)?;
        let item = RelayItem::decode(&raw).map_err(|_| ScanFailure::Corrupt)?;
        if item.namespace() != self.namespace {
            return Err(ScanFailure::Scope);
        }
        self.check_deadline()?;
        Ok(item)
    }

    fn publish_item(&mut self, record: &PositionedItem) -> std::result::Result<bool, ScanFailure> {
        self.check_deadline()?;
        let encoded = record.item.encode().map_err(|_| ScanFailure::Corrupt)?;
        let items = self.path.join("items");
        let target = item_path(&items, record.position);
        let tmp = items.join("item.tmp");
        if custody::private_file_present(&target, self.uid, MAX_ITEM_BYTES)
            .map_err(|_| ScanFailure::Storage)?
        {
            let retained = custody::read_private_file(&target, self.uid, MAX_ITEM_BYTES)
                .map_err(|_| ScanFailure::Storage)?;
            if retained != encoded {
                return Err(ScanFailure::Corrupt);
            }
            // A prior interruption after rename still requires the directory
            // durability barrier before this run may advance its cursor.
            self.items.sync_all().map_err(|_| ScanFailure::Storage)?;
            return Ok(false);
        }
        if custody::private_file_present(&tmp, self.uid, MAX_ITEM_BYTES)
            .map_err(|_| ScanFailure::Storage)?
        {
            let retained = custody::read_private_file(&tmp, self.uid, MAX_ITEM_BYTES)
                .map_err(|_| ScanFailure::Storage)?;
            if !encoded.starts_with(&retained) {
                return Err(ScanFailure::Corrupt);
            }
            // Only a verified prefix of this exact retry is disposable scratch.
            fs::remove_file(&tmp).map_err(|_| ScanFailure::Storage)?;
        }
        let mut file = custody::create_private_file(&tmp).map_err(|_| ScanFailure::Storage)?;
        #[cfg(test)]
        if self.fault == Some(PublicationFault::PartialItem) {
            file.write_all(&encoded[..encoded.len() / 2])
                .map_err(|_| ScanFailure::Storage)?;
            return Err(ScanFailure::Storage);
        }
        file.write_all(&encoded).map_err(|_| ScanFailure::Storage)?;
        file.sync_all().map_err(|_| ScanFailure::Storage)?;
        #[cfg(test)]
        self.fail_at(PublicationFault::ItemSynced)?;
        // This exclusive guard is the sole publisher. Existing committed paths
        // were checked above and are never a recovery overwrite target.
        fs::rename(&tmp, &target).map_err(|_| ScanFailure::Storage)?;
        #[cfg(test)]
        self.fail_at(PublicationFault::ItemPublished)?;
        self.items.sync_all().map_err(|_| ScanFailure::Storage)?;
        #[cfg(test)]
        self.fail_at(PublicationFault::ItemsSynced)?;
        Ok(true)
    }

    #[cfg(test)]
    fn fail_at(&self, phase: PublicationFault) -> std::result::Result<(), ScanFailure> {
        if self.fault == Some(phase) {
            Err(ScanFailure::Storage)
        } else {
            Ok(())
        }
    }

    /// Stage the bounded immutable prefix through the first page's head. The
    /// guard and its deadline remain in force while the caller consumes items.
    pub fn scan(
        &mut self,
        source: &dyn PageSource,
        limit: usize,
    ) -> std::result::Result<ScanReport, ScanFailure> {
        if limit == 0 || limit > MAX_RELAY_PAGE {
            return Err(ScanFailure::Net(NetError::Bounds));
        }
        let mut target = None;
        let mut scanned = 0usize;
        loop {
            self.check_deadline()?;
            let page = source.source_page(self.cursor, limit, self.deadline)?;
            self.check_deadline()?;
            validate_page(&page, self.cursor, limit).map_err(ScanFailure::Net)?;
            if page.head < self.cursor {
                return Err(ScanFailure::Net(NetError::Malformed));
            }
            if page.head > MAX_RELAY_ITEMS as u64 {
                return Err(ScanFailure::Capacity);
            }
            if page
                .records
                .iter()
                .any(|record| record.item.namespace() != self.namespace)
            {
                return Err(ScanFailure::Scope);
            }
            let head = *target.get_or_insert(page.head);
            if page.head < head {
                return Err(ScanFailure::Net(NetError::Malformed));
            }
            for record in page
                .records
                .iter()
                .take_while(|record| record.position <= head)
            {
                scanned += usize::from(self.publish_item(record)?);
                publish_cursor(&self.path, &self.directory, record.position, self.uid)?;
                self.cursor = record.position;
                #[cfg(test)]
                self.fail_at(PublicationFault::CursorPublished)?;
            }
            if self.cursor == head {
                // Never report completion over unreconciled publication evidence
                // that the selected source no longer acknowledges.
                if custody::private_file_present(
                    &self.path.join("items/item.tmp"),
                    self.uid,
                    MAX_ITEM_BYTES,
                )
                .map_err(|_| ScanFailure::Storage)?
                    || custody::private_file_present(
                        &item_path(&self.path.join("items"), self.cursor + 1),
                        self.uid,
                        MAX_ITEM_BYTES,
                    )
                    .map_err(|_| ScanFailure::Storage)?
                {
                    return Err(ScanFailure::Corrupt);
                }
                self.check_deadline()?;
                return Ok(ScanReport {
                    head,
                    cursor: self.cursor,
                    scanned,
                });
            }
        }
    }
}

/// Scan one explicit namespace, retaining exclusive directory custody until
/// completion. Use `ScanDirectory` when consuming staged files afterward.
pub fn scan(
    directory: &Path,
    namespace: RelayNamespace,
    source: &dyn PageSource,
    limit: usize,
) -> std::result::Result<ScanReport, ScanFailure> {
    ScanDirectory::open(directory, namespace)?.scan(source, limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::{Limits, RelayNamespace};
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };
    use vhalla_private_kernel::{OperationId, OutboxKind};

    fn token() -> RelayToken {
        RelayToken::from_bytes([7; 32]).unwrap()
    }
    fn namespace() -> RelayNamespace {
        RelayNamespace::from_bytes([9; 32]).unwrap()
    }
    fn item(sequence: u64) -> RelayItem {
        RelayItem::new(
            namespace(),
            sequence,
            OperationId::from_bytes([sequence as u8; 16]).unwrap(),
            OutboxKind::Application,
            b"ciphertext",
        )
        .unwrap()
    }
    fn serve_store(store: Store, connections: u64) -> (SocketAddr, thread::JoinHandle<Result<()>>) {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || serve(listener, store, token(), Some(connections)));
        (addr, worker)
    }
    fn relay(addr: SocketAddr) -> SocketRelay {
        SocketRelay::new(addr, token())
    }
    pub(super) fn tempdir(name: &str) -> PathBuf {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        // The path stays absent; scan creates it as a 0700 private directory.
        std::env::temp_dir().join(format!(
            "vhalla-relay-net-{}-{}-{}-{name}",
            std::process::id(),
            time.as_nanos(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn loopback_submit_page_and_fetch_roundtrip() {
        let store = Store::new(
            namespace(),
            Limits {
                max_items: 8,
                max_bytes: 1024,
            },
        )
        .unwrap();
        let (addr, worker) = serve_store(store, 4);
        let client = relay(addr);
        let first = client.submit(&item(1)).unwrap();
        assert_eq!(first.position, 1);
        assert!(!first.duplicate);
        let retry = client.submit(&item(1)).unwrap();
        assert!(retry.duplicate);
        assert_eq!(retry.position, 1);
        client.submit(&item(2)).unwrap();
        let page = client.page(0, 8).unwrap();
        assert_eq!(page.head, 2);
        assert_eq!(
            page.records,
            vec![
                PositionedItem {
                    position: 1,
                    item: item(1)
                },
                PositionedItem {
                    position: 2,
                    item: item(2)
                }
            ]
        );
        assert_eq!(page.next, None);
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn wrong_token_is_denied_and_server_stays_up() {
        let store = Store::new(
            namespace(),
            Limits {
                max_items: 4,
                max_bytes: 1024,
            },
        )
        .unwrap();
        let (addr, worker) = serve_store(store, 2);
        let denied = SocketRelay::new(addr, RelayToken::from_bytes([8; 32]).unwrap());
        assert_eq!(denied.submit(&item(1)), Err(NetError::Denied));
        assert!(relay(addr).submit(&item(1)).is_ok());
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn conflict_capacity_and_scope_pass_through() {
        let store = Store::new(
            namespace(),
            Limits {
                max_items: 2,
                max_bytes: 1024,
            },
        )
        .unwrap();
        let (addr, worker) = serve_store(store, 4);
        let client = relay(addr);
        client.submit(&item(1)).unwrap();
        // The same operation identity with different bytes is a hard conflict.
        let changed = RelayItem::new(
            namespace(),
            2,
            item(1).operation(),
            OutboxKind::Application,
            b"other",
        )
        .unwrap();
        assert_eq!(client.submit(&changed), Err(NetError::Conflict));
        // A different sender's item may reuse the same sender-local sequence;
        // it lands at the next mailbox position, never in conflict.
        let foreign_sender = RelayItem::new(
            namespace(),
            1,
            OperationId::from_bytes([77; 16]).unwrap(),
            OutboxKind::Application,
            b"other",
        )
        .unwrap();
        assert_eq!(client.submit(&foreign_sender).unwrap().position, 2);
        assert_eq!(client.submit(&item(2)), Err(NetError::Capacity));
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn malformed_and_garbage_frames_do_not_wedge_the_service() {
        let store = Store::new(
            namespace(),
            Limits {
                max_items: 4,
                max_bytes: 1024,
            },
        )
        .unwrap();
        let (addr, worker) = serve_store(store, 3);
        // An unknown opcode with a valid token answers Bounds.
        let mut stream = TcpStream::connect(addr).unwrap();
        let mut body = token().as_bytes().to_vec();
        body.extend_from_slice(b"??");
        stream.write_all(&frame(0x7f, &body)).unwrap();
        let response = read_frame(&mut stream, MAX_RESPONSE, Instant::now() + IO_TIMEOUT).unwrap();
        assert_eq!(response[0], STATUS_BOUNDS);
        drop(stream);
        // A truncated write then close is dropped without killing the loop.
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(&u32::MAX.to_be_bytes()).unwrap();
        stream.write_all(&[0u8; 4]).unwrap();
        drop(stream);
        assert!(relay(addr).submit(&item(1)).is_ok());
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn foreign_namespace_items_are_refused_at_the_mailbox() {
        let store = Store::new(
            namespace(),
            Limits {
                max_items: 4,
                max_bytes: 1024,
            },
        )
        .unwrap();
        let (addr, worker) = serve_store(store, 1);
        let foreign = RelayItem::new(
            RelayNamespace::from_bytes([8; 32]).unwrap(),
            1,
            OperationId::from_bytes([1; 16]).unwrap(),
            OutboxKind::Application,
            b"x",
        )
        .unwrap();
        assert_eq!(relay(addr).submit(&foreign), Err(NetError::Scope));
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn scan_persists_cursor_resumes_and_detects_corruption() {
        let store = Store::new(
            namespace(),
            Limits {
                max_items: 8,
                max_bytes: 4096,
            },
        )
        .unwrap();
        let (addr, _worker) = serve_store(store, 9);
        let client = relay(addr);
        client.submit(&item(1)).unwrap();
        client.submit(&item(2)).unwrap();
        let dir = tempdir("cursor");
        let report = scan(&dir, namespace(), &client, 1).unwrap();
        assert_eq!(
            report,
            ScanReport {
                head: 2,
                cursor: 2,
                scanned: 2
            }
        );
        assert!(dir.join("items/0000000000000001.vhrelay").exists());
        // An exact rescan changes nothing and counts nothing.
        assert_eq!(scan(&dir, namespace(), &client, 8).unwrap().scanned, 0);
        client.submit(&item(3)).unwrap();
        let next = scan(&dir, namespace(), &client, 8).unwrap();
        assert_eq!((next.cursor, next.scanned, next.head), (3, 1, 3));
        // A pre-placed owner file at an unfetched sequence with different
        // bytes fails closed; the durable cursor never regresses.
        use std::os::unix::fs::PermissionsExt;
        let bogus = dir.join("items/0000000000000004.vhrelay");
        fs::write(&bogus, item(5).encode().unwrap()).unwrap();
        fs::set_permissions(&bogus, fs::Permissions::from_mode(0o600)).unwrap();
        client.submit(&item(4)).unwrap();
        assert_eq!(
            scan(&dir, namespace(), &client, 8),
            Err(ScanFailure::Corrupt)
        );
        assert_eq!(fs::read(dir.join("cursor")).unwrap(), 3u64.to_be_bytes());
    }

    #[test]
    fn truncated_wire_pages_resume_through_the_cursor() {
        let mut store = Store::new(
            namespace(),
            Limits {
                max_items: 32,
                max_bytes: 8 * 1024 * 1024,
            },
        )
        .unwrap();
        for sequence in 1..=20 {
            let big = RelayItem::new(
                namespace(),
                sequence,
                OperationId::from_bytes([sequence as u8; 16]).unwrap(),
                OutboxKind::Application,
                &vec![sequence as u8; MAX_RELAY_PAYLOAD],
            )
            .unwrap();
            store.put(big).unwrap();
        }
        // 20 x ~260 KiB exceeds the 4 MiB page budget; the wire truncates.
        let (addr, worker) = serve_store(store, 5);
        let client = relay(addr);
        let first = client.page(0, MAX_RELAY_PAGE).unwrap();
        assert!(first.records.len() < 20);
        assert_eq!(first.next, Some(first.records.last().unwrap().position));
        let dir = tempdir("truncated");
        let report = scan(&dir, namespace(), &client, MAX_RELAY_PAGE).unwrap();
        assert_eq!((report.cursor, report.scanned, report.head), (20, 20, 20));
        assert!(client.fetch(20).unwrap().is_some());
        assert!(client.fetch(21).unwrap().is_none());
        worker.join().unwrap().unwrap();
    }
}

#[cfg(test)]
#[path = "net_tests.rs"]
mod hardening_tests;
