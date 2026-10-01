//! Pinned public routing hints and a separate local transport identity.

use super::{
    catalog::{Hash, Hex},
    peer,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hraness_control_kit::{ErrorBody, ErrorCode};
use iroh::{Endpoint, EndpointAddr, RelayMap, RelayMode, RelayUrl, SecretKey};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Write,
    net::SocketAddr,
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use vhalla_custody::{self as custody, Owner};
use vhalla_direct_room::{PinnedGenesis, RoomId, SignedGenesis, MAX_GENESIS_BYTES};
use zeroize::Zeroizing;

pub(super) use vhalla_private_native::relay::iroh::IrohEndpoint as Source;
type Result<T> = std::result::Result<T, ErrorBody>;
const KEY_MAGIC: &[u8; 8] = b"VHDPKEY1";
const KEY_BYTES: usize = 40;
const LINK_PREFIX: &str = "valhalla://public/1/";
const MAX_LINK_BYTES: usize = 8192;

fn refused() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::PermissionDenied,
        "The network identity or its folder has changed; preserve it and restart the service.",
    )
}
fn usage() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::Usage,
        "Invalid public room link or peer address.",
    )
}

pub(super) fn address(source: &Source) -> Result<EndpointAddr> {
    source.validate().map_err(|_| usage())?;
    let mut address = EndpointAddr::new(source.endpoint_id.parse().map_err(|_| usage())?);
    if let Some(relay) = &source.relay_url {
        address = address.with_relay_url(relay.parse().map_err(|_| usage())?);
    }
    for ip in &source.addresses {
        address = address.with_ip_addr(*ip);
    }
    Ok(address)
}

fn relay_url(value: &str) -> Result<RelayUrl> {
    // Reuse the same endpoint policy for public and private transport hints.
    let source = Source {
        endpoint_id: SecretKey::from_bytes(&[1; 32]).public().to_string(),
        relay_url: Some(value.to_owned()),
        addresses: Vec::new(),
    };
    source.validate().map_err(|_| usage())?;
    value.parse().map_err(|_| usage())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Listen {
    pub(super) bind: SocketAddr,
    pub(super) relay_url: Option<String>,
    #[serde(default)]
    pub(super) relay_only: bool,
}
impl Default for Listen {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:48888".parse().expect("constant address"),
            relay_url: None,
            relay_only: false,
        }
    }
}
impl Listen {
    pub(super) fn validate(&self) -> Result<()> {
        if self.relay_only && self.relay_url.is_none() {
            return Err(usage());
        }
        if self.bind.ip().is_multicast()
            || matches!(self.bind, SocketAddr::V4(value) if value.ip().is_broadcast() || value.ip().is_link_local())
            || matches!(self.bind, SocketAddr::V6(value) if value.ip().is_unicast_link_local() || value.ip().to_ipv4_mapped().is_some() || value.scope_id() != 0 || value.flowinfo() != 0)
        {
            return Err(usage());
        }
        self.relay_url.as_deref().map(relay_url).transpose()?;
        Ok(())
    }
}

/// Separate from account, owner and room-author keys. The caller holds the
/// service lock before construction and retains it through endpoint shutdown.
pub(super) struct Identity {
    home: PathBuf,
    directory: File,
    file: File,
    owner: Owner,
    encoded: Zeroizing<[u8; KEY_BYTES]>,
    failed: AtomicBool,
}
impl Identity {
    pub(super) fn create_new(home: &Path) -> Result<Self> {
        let home = custody::absolute(home).map_err(|_| refused())?;
        let (directory, owner) = custody::open_private_directory(&home).map_err(|_| refused())?;
        let mut encoded = Zeroizing::new([0; KEY_BYTES]);
        encoded[..8].copy_from_slice(KEY_MAGIC);
        getrandom::fill(&mut encoded[8..]).map_err(|_| refused())?;
        if encoded[8..] == [0; 32] {
            return Err(refused());
        }
        let mut file =
            custody::create_private_file(&home.join("peer.key")).map_err(|_| refused())?;
        file.write_all(encoded.as_slice()).map_err(|_| refused())?;
        file.sync_all().map_err(|_| refused())?;
        directory.sync_all().map_err(|_| refused())?;
        let result = Self {
            home,
            directory,
            file,
            owner,
            encoded,
            failed: AtomicBool::new(false),
        };
        result.check()?;
        Ok(result)
    }
    pub(super) fn open(home: &Path) -> Result<Self> {
        let home = custody::absolute(home).map_err(|_| refused())?;
        let (directory, owner) = custody::open_private_directory(&home).map_err(|_| refused())?;
        let file = custody::open_private_file(&home.join("peer.key"), owner, KEY_BYTES)
            .map_err(|_| refused())?;
        let mut encoded = Zeroizing::new([0; KEY_BYTES]);
        file.read_exact_at(encoded.as_mut_slice(), 0)
            .map_err(|_| refused())?;
        if &encoded[..8] != KEY_MAGIC || encoded[8..] == [0; 32] {
            return Err(refused());
        }
        let result = Self {
            home,
            directory,
            file,
            owner,
            encoded,
            failed: AtomicBool::new(false),
        };
        result.check()?;
        Ok(result)
    }
    pub(super) fn check(&self) -> Result<()> {
        if self.failed.load(Ordering::Acquire) {
            return Err(refused());
        }
        self.check_inner()
            .inspect_err(|_| self.failed.store(true, Ordering::Release))
    }
    fn check_inner(&self) -> Result<()> {
        let (directory, owner) =
            custody::open_private_directory(&self.home).map_err(|_| refused())?;
        if owner != self.owner
            || owner != Owner::current().map_err(|_| refused())?
            || !custody::same_open_file(&directory, &self.directory).map_err(|_| refused())?
        {
            return Err(refused());
        }
        let current =
            custody::open_private_file(&self.home.join("peer.key"), self.owner, KEY_BYTES)
                .map_err(|_| refused())?;
        if !custody::same_open_file(&current, &self.file).map_err(|_| refused())? {
            return Err(refused());
        }
        let mut bytes = Zeroizing::new([0; KEY_BYTES]);
        self.file
            .read_exact_at(bytes.as_mut_slice(), 0)
            .map_err(|_| refused())?;
        if bytes
            .iter()
            .zip(self.encoded.iter())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            != 0
        {
            return Err(refused());
        }
        Ok(())
    }
    fn secret(&self) -> SecretKey {
        SecretKey::from_bytes(self.encoded[8..].try_into().expect("fixed key slice"))
    }
    pub(super) fn id(&self) -> Hash {
        Hex(*self.secret().public().as_bytes())
    }
    pub(super) async fn bind(&self, listen: &Listen) -> Result<Endpoint> {
        listen.validate()?;
        self.check()?;
        let relay = listen.relay_url.as_deref().map(relay_url).transpose()?;
        let mode = relay.map_or(RelayMode::Disabled, |url| {
            RelayMode::Custom(RelayMap::from_iter([url]))
        });
        let builder = peer::endpoint_builder()
            .secret_key(self.secret())
            .relay_mode(mode)
            .clear_ip_transports();
        let builder = if listen.relay_only {
            builder
        } else {
            builder.bind_addr(listen.bind).map_err(|_| usage())?
        };
        let endpoint = builder.bind().await.map_err(|_| {
            ErrorBody::new(
                ErrorCode::OwnerUnavailable,
                "Could not open the public peer listener.",
            )
        })?;
        if let Err(error) = self.check() {
            endpoint.close().await;
            return Err(error);
        }
        Ok(endpoint)
    }
}

/// A self-contained invitation pins signed genesis before contacting a source.
/// Routing hints confer no posting or owner rights and can be replaced later.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoomLink {
    pub(super) pin: Hash,
    pub(super) genesis: String,
    pub(super) source: Source,
}
impl RoomLink {
    pub(super) fn new(genesis: &PinnedGenesis, source: Source) -> Result<Self> {
        let link = Self {
            pin: Hex(*genesis.id().as_bytes()),
            genesis: URL_SAFE_NO_PAD.encode(genesis.encode()),
            source,
        };
        link.validate()?;
        Ok(link)
    }
    pub(super) fn validate(&self) -> Result<PinnedGenesis> {
        if self.genesis.len() > MAX_GENESIS_BYTES * 2 {
            return Err(usage());
        }
        address(&self.source)?;
        let bytes = URL_SAFE_NO_PAD.decode(&self.genesis).map_err(|_| usage())?;
        if URL_SAFE_NO_PAD.encode(&bytes) != self.genesis {
            return Err(usage());
        }
        SignedGenesis::decode(&bytes)
            .and_then(|g| g.verify_pin(RoomId::from_bytes(self.pin.0)))
            .map_err(|_| usage())
    }
    pub(super) fn encode(&self) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| usage())?;
        let link = format!("{LINK_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        if link.len() > MAX_LINK_BYTES {
            return Err(usage());
        }
        Ok(link)
    }
    pub(super) fn parse(link: &str) -> Result<Self> {
        if link.len() > MAX_LINK_BYTES {
            return Err(usage());
        }
        let encoded = link.strip_prefix(LINK_PREFIX).ok_or_else(usage)?;
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| usage())?;
        if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
            return Err(usage());
        }
        let result: Self = serde_json::from_slice(&bytes).map_err(|_| usage())?;
        result.validate()?;
        Ok(result)
    }
}

#[cfg(test)]
pub(super) fn source(endpoint: &Endpoint) -> Result<Source> {
    source_with_relay(endpoint, None)
}

pub(super) fn source_with_relay(
    endpoint: &Endpoint,
    configured_relay: Option<&str>,
) -> Result<Source> {
    let address = endpoint.addr();
    let source = Source {
        endpoint_id: endpoint.id().to_string(),
        relay_url: configured_relay
            .map(str::to_owned)
            .or_else(|| address.relay_urls().next().map(ToString::to_string)),
        addresses: address.ip_addrs().copied().collect(),
    };
    source.validate().map_err(|_| {
        ErrorBody::new(
            ErrorCode::OwnerUnavailable,
            "No usable peer address is available yet.",
        )
    })?;
    Ok(source)
}

#[cfg(test)]
#[path = "network_tests.rs"]
mod tests;
