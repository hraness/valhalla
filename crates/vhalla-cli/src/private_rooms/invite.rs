//! One owner-private invite file per participant. The owner bundles a
//! confidential room offer with one enrolled relay credential; the recipient's
//! `private join --invite` turns it into a fresh member store, a delivery
//! profile and the encrypted admission request. The file is a bearer
//! capability shared privately, like a Tailcat address; it changes packaging,
//! never admission, custody or authority semantics.
use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::json;
use vhalla_identity::Identity;
use vhalla_private_kernel::{protocol::Key, ContactBootstrap};
use vhalla_private_native::client::{RoomCreation, RoomSession};
use vhalla_private_native::private_rooms::NativePrivateStore;
use vhalla_private_native::relay::{iroh::IrohEndpoint, net::RelayToken};

use super::{agent_delivery, files, Args, REFUSED};

/// Bundle byte bound: a 1024-byte offer plus one CA certificate and fixed
/// credential fields, hex encoded inside strict JSON.
const INVITE_LIMIT: usize = 192 * 1024;
const KIND: &str = "valhalla-private-invite";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    kind: String,
    version: u32,
    offer: String,
    relay: BundleRelay,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BundleRelay {
    namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca: Option<String>,
    token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    addresses: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport: Option<BundleTransport>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum BundleTransport {
    Iroh { endpoint: IrohEndpoint },
}

enum ParsedTransport {
    Tls {
        tls_name: String,
        ca: Vec<u8>,
        addresses: Vec<SocketAddr>,
    },
    Iroh {
        endpoint: IrohEndpoint,
    },
}

fn unhex(raw: &str, what: &str) -> Result<Vec<u8>, String> {
    if !raw.len().is_multiple_of(2)
        || raw.is_empty()
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!("invite {what} must be lowercase hexadecimal"));
    }
    Ok(raw
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect())
}

fn unhex32(raw: &str, what: &str) -> Result<[u8; 32], String> {
    unhex(raw, what)?
        .try_into()
        .map_err(|_| format!("invite {what} must be a full 32-byte value"))
}

struct Parsed {
    offer: Vec<u8>,
    namespace: String,
    token: [u8; 32],
    transport: ParsedTransport,
}

fn decode(raw: &[u8]) -> Result<Parsed, String> {
    let bundle: Bundle =
        serde_json::from_slice(raw).map_err(|_| "invite is not a canonical bundle")?;
    if bundle.kind != KIND || ![1, 2].contains(&bundle.version) {
        return Err("invite kind or version is not supported".into());
    }
    let offer = unhex(&bundle.offer, "offer")?;
    if offer.len() > super::OFFER_LIMIT {
        return Err("invite offer exceeds its bound".into());
    }
    let ns = vhalla_private_native::relay::RelayNamespace::from_bytes(super::unhex::<32>(
        &bundle.relay.namespace,
    )?)
    .map_err(|_| "invite namespace refused")?;
    let token = unhex32(&bundle.relay.token, "token")?;
    RelayToken::from_bytes(token).map_err(|_| "invite token refused")?;
    let transport = match (bundle.version, bundle.relay.transport) {
        (2, Some(BundleTransport::Iroh { endpoint })) => {
            let shape: serde_json::Value =
                serde_json::from_slice(raw).map_err(|_| "invite encoding refused")?;
            if ["tls_name", "ca", "addresses"]
                .iter()
                .any(|key| shape["relay"].get(*key).is_some())
            {
                return Err("iroh invite cannot carry TLS routing fields".into());
            }
            if bundle.relay.tls_name.is_some()
                || bundle.relay.ca.is_some()
                || bundle.relay.addresses.is_some()
            {
                return Err("iroh invite cannot carry TLS routing fields".into());
            }
            endpoint
                .validate()
                .map_err(|_| "invite iroh endpoint refused")?;
            ParsedTransport::Iroh { endpoint }
        }
        (1, None) => {
            let tls_name = bundle.relay.tls_name.ok_or("invite TLS name missing")?;
            if tls_name.is_empty()
                || tls_name.len() > 253
                || !tls_name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            {
                return Err("invite TLS name must be a plain DNS-style name".into());
            }
            let ca = unhex(&bundle.relay.ca.ok_or("invite CA missing")?, "CA")?;
            if ca.len() > 65536 {
                return Err("invite CA exceeds its bound".into());
            }
            let source = bundle.relay.addresses.ok_or("invite addresses missing")?;
            if !(1..=4).contains(&source.len()) {
                return Err("invite must carry one to four addresses".into());
            }
            let addresses = source
                .iter()
                .map(|text| {
                    text.parse::<SocketAddr>()
                        .map_err(|_| "invite address must be IP:PORT")
                })
                .collect::<Result<Vec<_>, _>>()?;
            vhalla_private_native::relay::tls::TlsRelay::new(
                addresses[0],
                &tls_name,
                ca.clone(),
                RelayToken::from_bytes(token).map_err(|_| "invite token refused")?,
                ns,
            )
            .map_err(|_| "invite TLS profile refused")?;
            ParsedTransport::Tls {
                tls_name,
                ca,
                addresses,
            }
        }
        _ => return Err("invite must select its versioned transport explicitly".into()),
    };
    Ok(Parsed {
        offer,
        namespace: bundle.relay.namespace,
        token,
        transport,
    })
}

/// `private invite`: validate the host material first, then mint the offer and
/// emit one bundle. A failure after minting is the same consumed operation the
/// standalone `offer` leaves. Host-side: the bundled material lives in the
/// host home, which remains a Unix surface.
#[cfg(unix)]
pub(super) async fn invite(args: &Args, room: &mut RoomSession) -> Result<(), String> {
    let material = crate::private_host::invite_material(
        Path::new(args.value("host")?),
        usize::try_from(args.number("credential")?).map_err(|_| "credential index bound")?,
    )?;
    let secret = room
        .create_contact_offer(args.operation()?, args.key("recipient")?, args.validity()?)
        .await
        .map_err(|_| REFUSED)?;
    let (version, relay) = match material.transport {
        crate::private_host::InviteTransport::Tls {
            tls_name,
            ca,
            addresses,
        } => (
            1,
            json!({
                "namespace": material.namespace, "tls_name": tls_name, "ca": super::hex(&ca),
                "token": super::hex(&material.token), "addresses": addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            }),
        ),
        crate::private_host::InviteTransport::Iroh { endpoint } => (
            2,
            json!({
                "namespace": material.namespace, "token": super::hex(&material.token),
                "transport": {"kind":"iroh", "endpoint": endpoint},
            }),
        ),
    };
    let bundle = json!({"kind": KIND, "version": version, "offer": super::hex(secret.confidential_bytes()), "relay": relay});
    args.output(&serde_json::to_vec_pretty(&bundle).map_err(|_| "invite encoding refused")?)
}

/// `private join --invite`: commit the new member store, lay down the delivery
/// profile and initialize it, then emit the encrypted admission request. The
/// store commit happens only after every pure input is verified; a later
/// failure is recovered through the granular commands, never by rerunning join
/// into the same store.
pub(super) async fn join(args: &Args, identity: Identity) -> Result<(), String> {
    let parsed = decode(&args.input("invite", INVITE_LIMIT, true)?)?;
    let account = Key::from_bytes(identity.public_key()).map_err(|_| REFUSED)?;
    let owner = args.key("owner")?;
    // A bad operation must not strand a newly committed member and delivery
    // profile before the request is created. Parse all scalar inputs first.
    let operation = args.operation()?;
    let validity = args.validity()?;
    let limits = args.limits()?;
    ContactBootstrap::inspect(&parsed.offer, owner, account, super::now()?).map_err(|_| REFUSED)?;
    let addr = match &parsed.transport {
        ParsedTransport::Iroh { .. } => {
            if args.flags.contains_key("addr") {
                return Err(
                    "iroh invite selects the peer identity; --addr is only for TLS invites".into(),
                );
            }
            None
        }
        ParsedTransport::Tls { addresses, .. } => Some(match args.flags.get("addr") {
            Some(value) => {
                let chosen: SocketAddr = value
                    .to_str()
                    .ok_or("invite address must be UTF-8")?
                    .parse()
                    .map_err(|_| "invite address must be IP:PORT")?;
                if !addresses.contains(&chosen) {
                    return Err("selected address is not one the invite advertises".into());
                }
                chosen
            }
            None => addresses[0],
        }),
    };
    let store = super::agent_setup::canonical_new_path(args.store()?, "member store")?;
    let delivery_dir = super::agent_setup::canonical_new_path(
        Path::new(args.value("delivery-dir")?),
        "delivery directory",
    )?;
    if store == delivery_dir {
        return Err("member store and delivery directory must use different new paths".into());
    }
    match std::fs::symlink_metadata(&delivery_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("delivery directory must be a new path".into()),
    }
    let output = super::agent_setup::canonical_new_path(
        Path::new(args.value("out")?),
        "admission request output",
    )?;
    if output == store || output == delivery_dir {
        return Err(
            "admission request output must differ from the member store and delivery directory"
                .into(),
        );
    }
    vhalla_custody::open_private_directory(output.parent().ok_or("output parent required")?)
        .map_err(|_| "admission request output parent must be owner-private 0700")?;
    match std::fs::symlink_metadata(&output) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("admission request output must be a new path".into()),
    }
    let creation = RoomCreation::from_contact(identity, &parsed.offer, owner, validity)
        .map_err(|_| REFUSED)?;
    creation.commit(&store, limits).await.map_err(|_| REFUSED)?;

    let identity =
        Identity::open(&args.identity).map_err(|_| "existing identity custody unavailable")?;
    let hint = NativePrivateStore::locate_context(&store).map_err(|_| REFUSED)?;
    let context = super::context(hint.as_bytes())?;
    let mut room = RoomSession::open(identity, &store, context)
        .await
        .map_err(|_| REFUSED)?;

    let (directory, _) =
        vhalla_custody::create_private_directory(&delivery_dir).map_err(|_| REFUSED)?;
    let token_path = delivery_dir.join("token.hex");
    let delivery_path = delivery_dir.join("delivery.json");
    files::write(
        &token_path,
        format!("{}\n", super::hex(&parsed.token)).as_bytes(),
    )?;
    let mut profile = json!({
        "version": 1,
        "context": {
            "room": super::hex(context.scope.room.as_bytes()),
            "anchor": super::hex(context.scope.anchor.as_bytes()),
            "account": super::hex(context.account.as_bytes()),
            "device": super::hex(context.device.as_bytes()),
        },
        "namespace": parsed.namespace,
        "token": token_path,
        "state": delivery_dir.join("delivery-state"),
        "max_jobs": 1024,
        "max_bytes": 67108864,
        "max_attempts": 20,
        "initial_backoff_secs": 5,
        "max_backoff_secs": 300,
        "emit_acceptance": true,
        "initial_cursor": 0,
    });
    match parsed.transport {
        ParsedTransport::Iroh { endpoint } => {
            profile["version"] = json!(4);
            profile["transport"] = json!({"kind":"iroh", "endpoint": endpoint});
        }
        ParsedTransport::Tls { tls_name, ca, .. } => {
            let ca_path = delivery_dir.join("ca.der");
            files::write(&ca_path, &ca)?;
            profile["addr"] = json!(addr.ok_or(REFUSED)?.to_string());
            profile["tls_name"] = json!(tls_name);
            profile["ca"] = json!(ca_path);
        }
    }
    files::write(
        &delivery_path,
        &serde_json::to_vec_pretty(&profile).map_err(|_| "delivery profile encoding refused")?,
    )?;
    agent_delivery::initialize(&delivery_path, context)?;
    directory.sync_all().map_err(|_| REFUSED)?;

    let result = room
        .contact_request(operation, &parsed.offer)
        .await
        .map_err(|_| REFUSED)?;
    // Recheck custody and use exclusive creation at publication; preflight
    // cannot prevent a later filesystem race or I/O failure.
    files::write(&output, result.bytes())
}
