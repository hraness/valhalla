//! Explicit origin/format selection, shared by worker setup and native tests.
//! A profile supplies transport authority only; room and signing authority stay
//! inside the kernel. Credentials never participate in retained state bindings.
use sha2::{Digest, Sha256};
use vhalla_private_kernel::Context;
use vhalla_private_relay::{http_origin::HttpsOrigin, RelayNamespace, MAX_RELAY_ITEMS};
use zeroize::Zeroizing;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Encoded {
    format: u8,
    origin: String,
    namespace: String,
    capability: String,
    initial_cursor: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Mode {
    Loopback,
    Https,
}

pub(super) struct Selected {
    pub origin: String,
    pub namespace: RelayNamespace,
    pub capability: Zeroizing<String>,
    pub initial: u64,
    pub mode: Mode,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Invalid;

fn hex(raw: &str) -> Result<[u8; 32], Invalid> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Invalid);
    }
    let mut out = [0; 32];
    for (i, value) in out.iter_mut().enumerate() {
        *value = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).map_err(|_| Invalid)?;
    }
    if out == [0; 32] {
        return Err(Invalid);
    }
    Ok(out)
}

pub(super) fn canonical_loopback(origin: &str) -> bool {
    origin
        .strip_prefix("http://127.0.0.1:")
        .is_some_and(|port| {
            port.parse::<u16>()
                .is_ok_and(|n| !matches!(n, 0 | 80) && n.to_string() == port)
        })
}

pub(super) fn valid_origin(mode: Mode, origin: &str) -> bool {
    match mode {
        Mode::Loopback => canonical_loopback(origin),
        Mode::Https => HttpsOrigin::parse(origin).is_ok(),
    }
}

pub(super) fn select(
    bytes: &[u8],
    actual_origin: &str,
    secure_context: bool,
) -> Result<Selected, Invalid> {
    if bytes.len() > 4096 {
        return Err(Invalid);
    }
    let mut profile: Encoded = serde_json::from_slice(bytes).map_err(|_| Invalid)?;
    let capability = Zeroizing::new(std::mem::take(&mut profile.capability));
    hex(&capability)?;
    let mode = match profile.format {
        1 => Mode::Loopback,
        2 if secure_context => Mode::Https,
        _ => return Err(Invalid),
    };
    if profile.origin != actual_origin || !valid_origin(mode, &profile.origin) {
        return Err(Invalid);
    }
    let namespace = RelayNamespace::from_bytes(hex(&profile.namespace)?).map_err(|_| Invalid)?;
    let initial = profile.initial_cursor.parse::<u64>().map_err(|_| Invalid)?;
    if initial.to_string() != profile.initial_cursor || initial > MAX_RELAY_ITEMS as u64 {
        return Err(Invalid);
    }
    Ok(Selected {
        origin: profile.origin,
        namespace,
        capability,
        initial,
        mode,
    })
}

impl Selected {
    pub(super) fn binding(&self, context: Context) -> [u8; 32] {
        let mut h = Sha256::new();
        // Retain the exact old domain/bytes for format 1. HTTPS cannot reopen
        // that state, even if an external caller supplies matching metadata.
        h.update(match self.mode {
            Mode::Loopback => b"vhalla/browser-private-delivery-profile/v1\0",
            Mode::Https => b"vhalla/browser-private-delivery-profile/v2\0",
        });
        for b in [
            context.scope.room.as_bytes(),
            context.scope.anchor.as_bytes(),
            context.account.as_bytes(),
            context.device.as_bytes(),
        ] {
            h.update(b);
        }
        h.update(self.origin.as_bytes());
        h.update([0]);
        h.update(self.namespace.as_bytes());
        h.update(self.initial.to_be_bytes());
        h.finalize().into()
    }
}
