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
    tls_name: String,
    ca: String,
    token: String,
    addresses: Vec<String>,
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
    tls_name: String,
    ca: Vec<u8>,
    token: [u8; 32],
    addresses: Vec<SocketAddr>,
}

fn decode(raw: &[u8]) -> Result<Parsed, String> {
    let bundle: Bundle =
        serde_json::from_slice(raw).map_err(|_| "invite is not a canonical bundle")?;
    if bundle.kind != KIND || bundle.version != 1 {
        return Err("invite kind or version is not supported".into());
    }
    let offer = unhex(&bundle.offer, "offer")?;
    if offer.len() > super::OFFER_LIMIT {
        return Err("invite offer exceeds its bound".into());
    }
    super::unhex::<32>(&bundle.relay.namespace)
        .map_err(|_| "invite namespace must be 64-digit hex")?;
    if bundle.relay.tls_name.is_empty()
        || bundle.relay.tls_name.len() > 253
        || !bundle
            .relay
            .tls_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err("invite TLS name must be a plain DNS-style name".into());
    }
    let ca = unhex(&bundle.relay.ca, "CA")?;
    if ca.len() > 65536 {
        return Err("invite CA exceeds its bound".into());
    }
    let token = unhex32(&bundle.relay.token, "token")?;
    if !(1..=4).contains(&bundle.relay.addresses.len()) {
        return Err("invite must carry one to four addresses".into());
    }
    let mut addresses = Vec::with_capacity(bundle.relay.addresses.len());
    for text in &bundle.relay.addresses {
        addresses.push(
            text.parse::<SocketAddr>()
                .map_err(|_| "invite address must be IP:PORT")?,
        );
    }
    Ok(Parsed {
        offer,
        namespace: bundle.relay.namespace,
        tls_name: bundle.relay.tls_name,
        ca,
        token,
        addresses,
    })
}

/// `private invite`: validate the host material first, then mint the offer and
/// emit one bundle. A failure after minting is the same consumed operation the
/// standalone `offer` leaves.
pub(super) async fn invite(args: &Args, room: &mut RoomSession) -> Result<(), String> {
    let material = crate::private_host::invite_material(
        Path::new(args.value("host")?),
        usize::try_from(args.number("credential")?).map_err(|_| "credential index bound")?,
    )?;
    let secret = room
        .create_contact_offer(args.operation()?, args.key("recipient")?, args.validity()?)
        .await
        .map_err(|_| REFUSED)?;
    let bundle = json!({
        "kind": KIND,
        "version": 1,
        "offer": super::hex(secret.confidential_bytes()),
        "relay": {
            "namespace": material.namespace,
            "tls_name": material.tls_name,
            "ca": super::hex(&material.ca),
            "token": super::hex(&material.token),
            "addresses": material.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        },
    });
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
    ContactBootstrap::inspect(&parsed.offer, owner, account, super::now()?).map_err(|_| REFUSED)?;
    let addr = match args.flags.get("addr") {
        Some(value) => {
            let chosen: SocketAddr = value
                .to_str()
                .ok_or("invite address must be UTF-8")?
                .parse()
                .map_err(|_| "invite address must be IP:PORT")?;
            if !parsed.addresses.contains(&chosen) {
                return Err("selected address is not one the invite advertises".into());
            }
            chosen
        }
        None => parsed.addresses[0],
    };
    let delivery_dir = super::agent_setup::canonical_new_path(
        Path::new(args.value("delivery-dir")?),
        "delivery directory",
    )?;
    if delivery_dir.exists() {
        return Err("delivery directory must be a new path".into());
    }
    let creation = RoomCreation::from_contact(identity, &parsed.offer, owner, args.validity()?)
        .map_err(|_| REFUSED)?;
    creation
        .commit(args.store()?, args.limits()?)
        .await
        .map_err(|_| REFUSED)?;

    let identity =
        Identity::open(&args.identity).map_err(|_| "existing identity custody unavailable")?;
    let hint = NativePrivateStore::locate_context(args.store()?).map_err(|_| REFUSED)?;
    let context = super::context(hint.as_bytes())?;
    let mut room = RoomSession::open(identity, args.store()?, context)
        .await
        .map_err(|_| REFUSED)?;

    let (directory, _) =
        vhalla_custody::create_private_directory(&delivery_dir).map_err(|_| REFUSED)?;
    let ca_path = delivery_dir.join("ca.der");
    let token_path = delivery_dir.join("token.hex");
    let delivery_path = delivery_dir.join("delivery.json");
    files::write(&ca_path, &parsed.ca)?;
    files::write(
        &token_path,
        format!("{}\n", super::hex(&parsed.token)).as_bytes(),
    )?;
    let profile = json!({
        "version": 1,
        "context": {
            "room": super::hex(context.scope.room.as_bytes()),
            "anchor": super::hex(context.scope.anchor.as_bytes()),
            "account": super::hex(context.account.as_bytes()),
            "device": super::hex(context.device.as_bytes()),
        },
        "namespace": parsed.namespace,
        "addr": addr.to_string(),
        "tls_name": parsed.tls_name,
        "ca": ca_path,
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
    files::write(
        &delivery_path,
        &serde_json::to_vec_pretty(&profile).map_err(|_| "delivery profile encoding refused")?,
    )?;
    agent_delivery::initialize(&delivery_path, context)?;
    directory.sync_all().map_err(|_| REFUSED)?;

    let result = room
        .contact_request(args.operation()?, &parsed.offer)
        .await
        .map_err(|_| REFUSED)?;
    args.output(result.bytes())
}
