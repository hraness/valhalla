//! A caller-selected authenticated transport sharing one mailbox protocol.
use super::{
    delivery,
    iroh::IrohRelay,
    net::{NetError, PageSource, ScanFailure},
    tls::TlsRelay,
    RelayItem, RelayNamespace, RelayPage, RelayReceipt,
};
use std::time::{Duration, Instant};
type Result<T> = std::result::Result<T, NetError>;
/// Exact selected transport. No automatic downgrade or fallback is performed.
#[derive(Clone)]
pub enum RelayClient {
    /// Explicit certificate-pinned TCP transport.
    Tls(TlsRelay),
    /// Public-key-pinned QUIC transport.
    Iroh(IrohRelay),
}
impl From<TlsRelay> for RelayClient {
    fn from(value: TlsRelay) -> Self {
        Self::Tls(value)
    }
}
impl From<IrohRelay> for RelayClient {
    fn from(value: IrohRelay) -> Self {
        Self::Iroh(value)
    }
}
macro_rules! selected { ($self:expr, $method:ident $(, $arg:expr)*) => { match $self { RelayClient::Tls(client) => client.$method($($arg),*), RelayClient::Iroh(client) => client.$method($($arg),*) } }; }
impl RelayClient {
    /// Exact namespace selected before connecting.
    pub fn namespace(&self) -> RelayNamespace {
        selected!(self, namespace)
    }
    /// Nonsecret transport trust commitment for retained delivery jobs.
    pub fn endpoint_id(&self) -> delivery::EndpointId {
        selected!(self, endpoint_id)
    }
    /// Submit already-encrypted immutable bytes.
    pub fn submit(&self, item: &RelayItem) -> Result<RelayReceipt> {
        selected!(self, submit, item)
    }
    /// Submit within an absolute deadline.
    pub fn submit_until(&self, item: &RelayItem, deadline: Instant) -> Result<RelayReceipt> {
        selected!(self, submit_until, item, deadline)
    }
    /// Read one bounded immutable page.
    pub fn page(&self, after: u64, limit: usize) -> Result<RelayPage> {
        selected!(self, page, after, limit)
    }
    /// Read one page within an absolute deadline.
    pub fn page_until(&self, after: u64, limit: usize, deadline: Instant) -> Result<RelayPage> {
        selected!(self, page_until, after, limit, deadline)
    }
    /// Wait for new retained items within the selected bounds.
    pub fn page_wait_until(
        &self,
        after: u64,
        limit: usize,
        wait: Duration,
        deadline: Instant,
    ) -> Result<RelayPage> {
        selected!(self, page_wait_until, after, limit, wait, deadline)
    }
    pub(super) fn token_matches(&self, token: &[u8; 32]) -> bool {
        selected!(self, token_matches, token)
    }
}
impl PageSource for RelayClient {
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
impl delivery::Transport for RelayClient {
    fn namespace(&self) -> RelayNamespace {
        self.namespace()
    }
    fn endpoint_id(&self) -> delivery::EndpointId {
        self.endpoint_id()
    }
    fn submit_until(&mut self, item: &RelayItem, deadline: Instant) -> Result<RelayReceipt> {
        RelayClient::submit_until(self, item, deadline)
    }
}
