//! Open candidate listing never grants authority or automatically dials a route.
use super::*;
use vhalla_public_protocol::discovery::{DiscoveryKind, DiscoveryRequest, PeerPage};
use web_sys::HtmlSelectElement;

pub(super) fn render(app: &App, available: bool, ready: bool) {
    let state = app.borrow();
    let select: HtmlSelectElement = state
        .document
        .get_element_by_id("discovered-peer")
        .unwrap()
        .unchecked_into();
    let previous = select.value();
    select.set_text_content(None);
    for bytes in &state.candidates {
        if let Ok(ad) = PeerAdvertisement::decode(bytes) {
            let claims = ad.unverified_claims();
            let option = state.document.create_element("option").unwrap();
            let _ = option.set_attribute("value", &hex(&claims.application_key));
            let routes = claims
                .endpoints
                .iter()
                .map(|e| e.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            option.set_text_content(Some(&format!(
                "{} · {routes}",
                hex(&claims.application_key)
            )));
            let _ = select.append_child(&option);
        }
    }
    if !previous.is_empty() {
        select.set_value(&previous);
    }
    select.set_disabled(!available || !ready || state.candidates.is_empty());
    for (id, enabled) in [
        ("discover-peers", !state.peers.is_empty()),
        ("select-discovered-peer", !state.candidates.is_empty()),
    ] {
        state
            .document
            .get_element_by_id(id)
            .unwrap()
            .unchecked_into::<HtmlButtonElement>()
            .set_disabled(!available || !ready || !enabled);
    }
}
async fn discover(app: &App, session: &Session) -> Result<(), String> {
    let (total, start) = {
        let state = app.borrow();
        (state.peers.len(), state.next_peer)
    };
    if total == 0 {
        return Err("Select one serving peer as a starting point for discovery.".into());
    }
    let mut candidates: Vec<Vec<u8>> = Vec::new();
    let mut sources = 0;
    let mut budget = READS_PER_ACTION;
    for offset in 0..total.min(2) {
        let index = (start + offset) % total;
        app.borrow_mut().next_peer = (index + 1) % total;
        status(
            app,
            "Reading independently signed candidates from a selected peer…",
        );
        let Ok((peer, route)) =
            super::activity::fresh_peer(app, session, index, false, &mut budget).await
        else {
            if app.borrow().failed {
                return Err("Peer selection changed. Reload before continuing.".into());
            }
            continue;
        };
        let mut generation = 0;
        let mut after = [0; 32];
        let mut answered = false;
        for _ in 0..2 {
            if budget == 0 {
                break;
            }
            budget -= 1;
            let request = DiscoveryRequest::new(
                transport::nonce().map_err(|_| "Browser randomness is unavailable.")?,
                DiscoveryKind::List {
                    generation,
                    after,
                    count: 16,
                },
            )
            .map_err(|_| "Could not construct discovery request.")?;
            let Ok(raw) =
                transport::discover(&route, session.client.network_id(), peer, request).await
            else {
                break;
            };
            let Ok(page) = PeerPage::decode(&raw) else {
                break;
            };
            if page
                .check_request(session.client.network_id(), request)
                .is_err()
            {
                break;
            }
            answered = true;
            let clock = now(app.borrow().clock_floor)?;
            for ad in page.advertisements() {
                let key = ad.unverified_claims().application_key;
                let raw = ad.encode();
                let selected = app
                    .borrow()
                    .peers
                    .iter()
                    .find(|bytes| {
                        PeerAdvertisement::decode(bytes)
                            .is_ok_and(|p| p.unverified_claims().application_key == key)
                    })
                    .cloned();
                let previous = candidates.iter().position(|bytes| {
                    PeerAdvertisement::decode(bytes)
                        .is_ok_and(|p| p.unverified_claims().application_key == key)
                });
                let retained = previous.map(|i| &candidates[i]).or(selected.as_ref());
                let anchor = retained
                    .map(|bytes| {
                        PeerAdvertisement::decode(bytes)
                            .and_then(|p| p.restore_sequence_anchor(session.client.network_id()))
                    })
                    .transpose();
                let Ok(anchor) = anchor else {
                    continue;
                };
                let same = retained.is_some_and(|bytes| bytes.as_slice() == raw.as_slice());
                let Ok(verified) = ad.verify(
                    &policy(session.client.network_id(), clock),
                    if same { None } else { anchor.as_ref() },
                ) else {
                    continue;
                };
                if !verified.claims().capabilities.contains(Capabilities::READ)
                    || !verified
                        .claims()
                        .endpoints
                        .iter()
                        .any(|e| e.scheme() == Scheme::Https)
                {
                    continue;
                }
                if let Some(index) = previous {
                    candidates[index] = raw;
                } else if candidates.len() < MAX_PEERS {
                    candidates.push(raw);
                }
            }
            if !page.has_more() || candidates.len() == MAX_PEERS {
                break;
            }
            generation = page.generation();
            after = page.next_after();
        }
        if answered {
            sources += 1;
        }
    }
    let clock = now(app.borrow().clock_floor)?;
    let peers = app.borrow().peers.clone();
    save_selection(app, session.head.scope(), &peers, clock).await?;
    let count = candidates.len();
    app.borrow_mut().candidates = candidates;
    if sources == 0 {
        return Err("Selected peers did not return a valid discovery page. Retry to rotate starting peers; your selected routes remain saved.".into());
    }
    status(
        app,
        &format!(
            "Found {count} independently signed candidates from {sources} selected peer views. Review a full key and route, then select it. No candidate route has been contacted automatically."
        ),
    );
    Ok(())
}
pub(super) fn bind_actions(app: &App) {
    bind(app, "discover-peers", |app| {
        launch(app.clone(), async move {
            let saved_session = { app.borrow_mut().session.take() };
            let result = if let Some(session) = saved_session {
                let result = discover(&app, &session).await;
                app.borrow_mut().session = Some(session);
                result
            } else {
                Err("Choose a verified network first.".into())
            };
            finish(&app, result);
        });
    });
    bind(app, "select-discovered-peer", |app| {
        let key = app
            .borrow()
            .document
            .get_element_by_id("discovered-peer")
            .unwrap()
            .unchecked_into::<HtmlSelectElement>()
            .value();
        let raw = app
            .borrow()
            .candidates
            .iter()
            .find(|bytes| {
                PeerAdvertisement::decode(bytes)
                    .is_ok_and(|ad| hex(&ad.unverified_claims().application_key) == key)
            })
            .cloned();
        launch(app.clone(), async move {
            let result = match raw {
                Some(raw) => add_peer(&app, raw).await,
                None => Err("Choose a discovered peer first.".into()),
            };
            finish(&app, result);
        });
    });
}
