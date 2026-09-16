//! Experimental social retrieval over the pinned paired channel. A provider
//! serves bounded signed pages of the records a requester lacks; the
//! requester pulls them through the same authenticated transport as paired
//! chat, so no new trust decision or discovery surface appears. Sync is a
//! pairwise operator action, not ambient replication: both sides choose a
//! peer, a realm, and a short serving window explicitly.
use std::io::Write;

use vhalla_discovery::Query;
use vhalla_identity::Identity;
use vhalla_native::{exchange_message, Delivery, Error as Transport, Event, Listener, Route};
use vhalla_retrieval::{ChannelScope, Provider, Request, Round, MAX_ATTEMPTS, MAX_KNOWN};
use vhalla_social::{OwnerId, RecordId};
use vhalla_social_store::Store;

use super::{commit, hex32, json, nonce, Args};

/// The directly pinned paired session's fixed authenticated context.
const CHANNEL: ChannelScope = ChannelScope {
    realm: vhalla_native::PAIRED_REALM,
    room: vhalla_native::PAIRED_ROOM,
    epoch: vhalla_native::PAIRED_EPOCH,
};

const USAGE: &str = "usage: vhalla social sync STORE REALM \
serve KEYDIR REQUESTER64 [LISTEN_IP] | \
pull KEYDIR PROVIDER64 ROUTE_ADDR EXPIRY [QUERY]";

/// `vhalla social sync STORE REALM serve|pull ...` — both directions pin the
/// exact peer application key; neither side accepts a stranger.
pub fn run(args: &Args, store: &mut Store) -> Result<String, String> {
    match args.get(0)? {
        "serve" => serve(args, store),
        "pull" => pull(args, store),
        _ => Err(USAGE.into()),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))
}

/// `sync serve STORE REALM serve KEYDIR REQUESTER64 [LISTEN_IP]` — print the
/// dialable route, then answer the pinned requester's signed frames with
/// bounded missing-record pages until the paired lifetime ends (~60s).
fn serve(args: &Args, store: &Store) -> Result<String, String> {
    let values = &args.values;
    if !(3..=4).contains(&values.len()) {
        return Err(USAGE.into());
    }
    let identity = Identity::open(&values[1]).map_err(|e| format!("identity: {e:?}"))?;
    let requester = hex32(&values[2])?;
    let listen = values.get(3).map(String::as_str).unwrap_or("127.0.0.1");
    let archive = store.archive();
    let key = identity.public_key();
    let owner = archive
        .records()
        .find(|record| {
            matches!(
                record.body(),
                vhalla_social::Body::OwnerGenesis { controller, .. } if *controller == key
            )
        })
        .map(|record| OwnerId::from_bytes(*record.id().as_bytes()))
        .ok_or("serving key has no owner genesis record in this archive")?;
    let now = args.now;
    runtime()?.block_on(async {
        let mut listener = Listener::bind_on(identity, requester, listen)
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "route {} {}",
            listener.route().address(),
            listener.route().expires_at()
        );
        std::io::stdout()
            .flush()
            .map_err(|e| format!("route output failed: {e}"))?;
        let mut provider: Option<Provider> = None;
        let mut pages = 0usize;
        let mut done = false;
        loop {
            let event = listener
                .next_serving(&mut |envelope| {
                    let page = match &mut provider {
                        Some(provider) => {
                            let request = Request::from_message(envelope, requester, CHANNEL, now)
                                .map_err(|_| Transport::Input("invalid sync request"))?;
                            if provider.refresh(request.clone()).is_err() {
                                // A different nonce opens a new bounded round.
                                *provider = Provider::new(request);
                            }
                            provider
                                .next(archive, owner, now)
                                .map_err(|_| Transport::Input("sync page unavailable"))?
                        }
                        slot @ None => {
                            let request = Request::from_message(envelope, requester, CHANNEL, now)
                                .map_err(|_| Transport::Input("invalid sync request"))?;
                            let mut pending = Provider::new(request);
                            let page = pending
                                .next(archive, owner, now)
                                .map_err(|_| Transport::Input("sync page unavailable"))?;
                            *slot = Some(pending);
                            page
                        }
                    };
                    done = page.provider_remaining() == 0;
                    Ok(page.encode())
                })
                .await;
            match event {
                Ok(Event::Message(_)) => {
                    pages += 1;
                    println!("served {pages}");
                    // The requester disconnects only after receiving the
                    // final page; waiting for that close proves the last
                    // response flushed before the listener is dropped.
                    if done {
                        let _ = listener.next().await;
                        break;
                    }
                }
                Ok(Event::Joined(session)) => println!("joined session={:032x}", session.0),
                Ok(Event::Disconnected) => println!("peer-closed"),
                Ok(Event::Rejected(error)) => println!("rejected {error}"),
                Err(Transport::Closed) => break,
                Err(error) => return Err(error.to_string()),
            }
            std::io::stdout()
                .flush()
                .map_err(|e| format!("serve output failed: {e}"))?;
        }
        Ok(json::object(vec![
            ("served", pages.to_string()),
            ("realm", json::id(&args.realm.0.to_be_bytes())),
        ]))
    })
}

/// `sync pull STORE REALM pull KEYDIR PROVIDER64 ROUTE_ADDR EXPIRY [QUERY]` —
/// disclose the bounded local inventory, then receive signed pages until the
/// provider reports none remain. Each accepted page commits durably, so an
/// interrupted pull resumes instead of restarting.
fn pull(args: &Args, store: &mut Store) -> Result<String, String> {
    let values = &args.values;
    if !(5..=6).contains(&values.len()) {
        return Err(USAGE.into());
    }
    let keydir = values[1].clone();
    let provider = hex32(&values[2])?;
    let expires_at: u64 = values[4].parse().map_err(|_| "invalid route expiry")?;
    let route = Route::parse(&values[3], expires_at).map_err(|e| e.to_string())?;
    let query = Query::parse(values.get(5).map(String::as_str).unwrap_or_default())
        .map_err(|e| format!("sync query: {e:?}"))?;
    let mut known: Vec<RecordId> = store.archive().records().map(|r| r.id()).collect();
    known.sort();
    known.dedup();
    known.truncate(MAX_KNOWN);
    let nonce_bytes = nonce()?;
    let request = Request::new(nonce_bytes, args.realm, query.clone(), None, known)
        .map_err(|_| "sync request")?;
    let mut round =
        Round::new(request.clone(), vec![provider], CHANNEL).map_err(|_| "sync round")?;
    let now = args.now;
    runtime()?.block_on(async {
        let mut body = request.encode();
        let mut pages = 0usize;
        loop {
            let delivery = page(&keydir, provider, &route, &body).await?;
            let mut candidate = store.archive().clone();
            round
                .receive(delivery.acknowledgment(), &mut candidate, now)
                .map_err(|_| {
                    "peer response failed sync admission; committed pages remain".to_owned()
                })?;
            commit(store, candidate)?;
            pages += 1;
            let stats = round.stats(provider).unwrap_or_default();
            if stats.provider_remaining == 0 || stats.attempts >= MAX_ATTEMPTS {
                break;
            }
            // Continuation is a fresh request frame under the same nonce: the
            // disclosed inventory now covers every committed page, so the
            // provider owes only records still missing — a page lost in flight
            // simply stays missing and is served again.
            let mut known: Vec<RecordId> = store.archive().records().map(|r| r.id()).collect();
            known.sort();
            known.dedup();
            known.truncate(MAX_KNOWN);
            body = Request::new(nonce_bytes, args.realm, query.clone(), None, known)
                .map_err(|_| "sync request")?
                .encode();
        }
        let stats = round.stats(provider).unwrap_or_default();
        Ok(json::object(vec![
            ("pages", pages.to_string()),
            ("attempts", stats.attempts.to_string()),
            ("bytes", stats.bytes.to_string()),
            ("accepted", stats.accepted.to_string()),
            ("duplicates", stats.duplicates.to_string()),
            ("failures", stats.failures.to_string()),
            ("remaining", stats.provider_remaining.to_string()),
            ("complete", (stats.provider_remaining == 0).to_string()),
        ]))
    })
}

/// One bounded request/response pair on a fresh paired connection. The
/// serving window is sixty seconds; a pull performs at most
/// `MAX_ATTEMPTS` sequential exchanges inside it.
async fn page(
    keydir: &str,
    provider: [u8; 32],
    route: &Route,
    body: &[u8],
) -> Result<Delivery, String> {
    let identity = Identity::open(keydir).map_err(|e| format!("identity: {e:?}"))?;
    exchange_message(identity, provider, route.clone(), body)
        .await
        .map_err(|e| e.to_string())
}
