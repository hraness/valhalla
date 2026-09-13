#![no_std]
#![forbid(unsafe_code)]
//! Reference policy only. It is NOT wired into the released Dioxus renderer.
extern crate alloc;
use alloc::{format, string::String};

pub const MAX_IPC_BYTES: usize = 81;
pub const MAX_ASSET_BYTES: usize = 512 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bounds,
    Origin,
    Replay,
    Encoding,
    Denied,
}

/// Exact release document origins, supplied by an adapter rather than page JSON.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin {
    Mac,
    Windows,
    Android,
}
impl Origin {
    pub const fn document(self) -> &'static str {
        match self {
            Self::Mac => "dioxus://index.html/",
            Self::Windows => "http://dioxus.index.html/",
            Self::Android => "https://dioxus.index.html/",
        }
    }
}
/// All external navigation is denied in the renderer. Rust router changes are
/// in-memory intentions, so neither route text nor a fragment needs navigation.
pub struct Navigation {
    origin: Origin,
    loaded: bool,
}
impl Navigation {
    pub const fn new(origin: Origin) -> Self {
        Self {
            origin,
            loaded: false,
        }
    }
    pub fn allow(&mut self, url: &str) -> bool {
        if !self.loaded && url == self.origin.document() {
            self.loaded = true;
            true
        } else {
            false
        }
    }
}

/// An asset is selected from trusted bundle bytes, never from a filesystem path
/// derived from an untrusted URI. Dynamic portraits have a separate typed producer.
pub struct Asset {
    pub path: &'static str,
    pub mime: &'static str,
    pub bytes: &'static [u8],
}
static ASSETS: &[Asset] = &[
    Asset {
        path: "/assets/app-a1b2.css",
        mime: "text/css; charset=utf-8",
        bytes: b"body{color:#fff;background:#171820}",
    },
    Asset {
        path: "/assets/icon-c3d4.svg",
        mime: "image/svg+xml",
        bytes: b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
    },
];
pub fn asset(method: &str, path: &str) -> Result<&'static Asset, Error> {
    if method != "GET" || path.len() > 256 {
        return Err(Error::Denied);
    }
    ASSETS
        .iter()
        .find(|entry| entry.path == path && entry.bytes.len() <= MAX_ASSET_BYTES)
        .ok_or(Error::Denied)
}

/// This parser models an application-intent boundary, not Dioxus's undocumented
/// JSON event format. Native IPC still needs upstream pre-decode interception.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Intent {
    ViewPost([u8; 32]),
    ProposeRead([u8; 32]),
    ProposeExternal(ExternalTarget),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalTarget {
    Documentation,
}
impl ExternalTarget {
    pub const fn url(self) -> &'static str {
        "https://vhalla.com/"
    }
}
pub struct Session {
    origin: Origin,
    nonce: [u8; 32],
    last: u64,
}
impl Session {
    /// `nonce` comes from native OS entropy; source origin must come from the
    /// audited platform callback, never a string the renderer supplies itself.
    pub const fn new(origin: Origin, nonce: [u8; 32]) -> Self {
        Self {
            origin,
            nonce,
            last: 0,
        }
    }
    pub fn receive(&mut self, source: &str, bytes: &[u8]) -> Result<Intent, Error> {
        if bytes.len() > MAX_IPC_BYTES {
            return Err(Error::Bounds);
        }
        if source != self.origin.document() {
            return Err(Error::Origin);
        }
        if bytes.len() < 49 || &bytes[..8] != b"VHUD\0\0\0\x01" || bytes[8..40] != self.nonce {
            return Err(Error::Encoding);
        }
        let sequence = u64::from_be_bytes(bytes[40..48].try_into().map_err(|_| Error::Encoding)?);
        if sequence <= self.last {
            return Err(Error::Replay);
        }
        let intent = match bytes[48] {
            0 | 1 if bytes.len() == 81 => {
                let id = bytes[49..].try_into().map_err(|_| Error::Encoding)?;
                if bytes[48] == 0 {
                    Intent::ViewPost(id)
                } else {
                    Intent::ProposeRead(id)
                }
            }
            2 if bytes.len() == 50 && bytes[49] == 0 => {
                Intent::ProposeExternal(ExternalTarget::Documentation)
            }
            _ => return Err(Error::Denied),
        };
        self.last = sequence;
        Ok(intent)
    }
    pub const fn last_sequence(&self) -> u64 {
        self.last
    }
}

/// Closed privileged effect token. There is intentionally no decode/from-intent
/// API. An OS-owned broker would mint this only after independent native consent.
/// This spike proves denial; it does not pretend renderer `isTrusted` is consent.
/// ```compile_fail
/// use vhalla_dioxus_boundary_spike::{EffectPermit,ExternalTarget};
/// let permit=EffectPermit {target:ExternalTarget::Documentation};
/// ```
/// ```compile_fail
/// use vhalla_dioxus_boundary_spike::{EffectPermit,Intent,ExternalTarget};
/// let permit:EffectPermit=Intent::ProposeExternal(ExternalTarget::Documentation).into();
/// ```
pub struct EffectPermit {
    target: ExternalTarget,
}
impl EffectPermit {
    pub const fn target(&self) -> ExternalTarget {
        self.target
    }
}
// Read proposals similarly require current exact social evidence and durable
// source-first publication in the broker. This module performs no effects.

/// Proposed release policy; needs actual WebView probes before promotion. A new
/// desktop edit server port requires a fresh document/CSP, not a widened wildcard.
pub fn desktop_csp(nonce: [u8; 32], edit_port: u16) -> Result<String, Error> {
    if edit_port == 0 || nonce == [0; 32] {
        return Err(Error::Bounds);
    }
    let mut token = String::with_capacity(64);
    for byte in nonce {
        use core::fmt::Write;
        let _ = write!(token, "{byte:02x}");
    }
    Ok(format!("default-src 'none'; script-src 'nonce-{token}'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self' ws://127.0.0.1:{edit_port}; object-src 'none'; base-uri 'none'; frame-src 'none'; frame-ancestors 'none'; form-action 'none'; media-src 'none'; worker-src 'none'"))
}
/// Web release policy requires an audited generated same-origin module loader.
/// wasm-unsafe-eval permits WebAssembly compilation, not JS eval/Function.
pub const WEB_CSP:&str="default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-src 'none'; frame-ancestors 'none'; form-action 'none'; worker-src 'none'";
