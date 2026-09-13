//! Explicit native launcher. Never calls `dioxus_native::launch` or its defaults.
use crate::policy::{Registry, Resource, ResourcePolicy};
use blitz_dom::net::Resource as RenderResource;
use blitz_shell::{create_default_event_loop, BlitzShellEvent, WindowConfig};
use blitz_traits::{
    navigation::DummyNavigationProvider,
    net::{Body, BoxedHandler, Bytes, NetCallback, NetProvider, Request},
};
use dioxus::prelude::*;
use dioxus_native::{
    DioxusDocument, DioxusNativeApplication, DioxusNativeWindowRenderer, DocumentConfig,
    WindowAttributes,
};
use std::sync::{Arc, Mutex};
use winit::event_loop::EventLoopProxy;

struct Callback(EventLoopProxy<BlitzShellEvent>);
impl NetCallback<RenderResource> for Callback {
    fn call(&self, doc_id: usize, result: Result<RenderResource, Option<String>>) {
        if let Ok(data) = result {
            let _ = self
                .0
                .send_event(BlitzShellEvent::ResourceLoad { doc_id, data });
        }
    }
}
struct ClosedResources {
    policy: Mutex<ResourcePolicy>,
    callback: Arc<dyn NetCallback<RenderResource>>,
}
impl NetProvider<RenderResource> for ClosedResources {
    fn fetch(&self, doc_id: usize, request: Request, handler: BoxedHandler<RenderResource>) {
        let bytes = self.policy.lock().ok().and_then(|mut p| {
            p.request(
                request.method.as_str(),
                request.url.as_str(),
                matches!(request.body, Body::Empty),
                request.headers.is_empty(),
            )
            .ok()
        });
        // Drop the policy lock before synchronous parsing can request nested CSS
        // resources. Unknown URIs are denied without filesystem/network fallback.
        if let Some(bytes) = bytes {
            handler.bytes(
                doc_id,
                Bytes::copy_from_slice(&bytes),
                self.callback.clone(),
            );
        }
    }
}
fn fixture_registry() -> Result<Registry, Box<dyn std::error::Error>> {
    let mut entries = vec![Resource {
        uri: vhalla_dioxus_ui_spike::CLOSED_STYLE_URI.to_owned(),
        bytes: vhalla_dioxus_ui_spike::STYLE_BYTES.to_vec(),
    }];
    entries.extend(
        vhalla_dioxus_ui_spike::fixture_resources()
            .into_iter()
            .map(|(uri, bytes)| Resource { uri, bytes }),
    );
    Ok(Registry::new(entries)?)
}
fn closed_app() -> Element {
    let config = use_hook(|| vhalla_dioxus_ui_spike::fixture_config().with_embedded_stylesheet());
    rsx! { vhalla_dioxus_ui_spike::App {config} }
}
/// Launch the same U0 signed fixture screens. No identity or live transport is loaded.
/// DioxusNativeApplication inserts MemoryHistory before the first component build.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let registry = fixture_registry()?;
    let event_loop = create_default_event_loop::<BlitzShellEvent>();
    let proxy = event_loop.create_proxy();
    let provider = ClosedResources {
        policy: Mutex::new(ResourcePolicy::new(registry)),
        callback: Arc::new(Callback(proxy.clone())),
    };
    let vdom = VirtualDom::new(closed_app);
    let doc = DioxusDocument::new(
        vdom,
        DocumentConfig {
            base_url: Some("dioxus://index.html/".into()),
            net_provider: Some(Arc::new(provider)),
            navigation_provider: Some(Arc::new(DummyNavigationProvider)),
            html_parser_provider: None,
            ..Default::default()
        },
    );
    let renderer = DioxusNativeWindowRenderer::new();
    let config = WindowConfig::with_attributes(
        Box::new(doc),
        renderer,
        WindowAttributes::default().with_title("vhalla (valhalla) · closed native fixture"),
    );
    let mut application = DioxusNativeApplication::new(proxy, config);
    event_loop.run_app(&mut application)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blitz_traits::net::{DummyNetCallback, NetHandler, SharedCallback, Url};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Record(Arc<AtomicUsize>);
    impl NetHandler<RenderResource> for Record {
        fn bytes(self: Box<Self>, _: usize, bytes: Bytes, _: SharedCallback<RenderResource>) {
            self.0.fetch_add(bytes.len(), Ordering::Relaxed);
        }
    }
    #[test]
    fn actual_shared_fixture_registry_routes_only_registered_bytes() {
        let provider = ClosedResources {
            policy: Mutex::new(ResourcePolicy::new(fixture_registry().unwrap())),
            callback: Arc::new(DummyNetCallback),
        };
        let count = Arc::new(AtomicUsize::new(0));
        let style = Url::parse(vhalla_dioxus_ui_spike::CLOSED_STYLE_URI).unwrap();
        provider.fetch(1, Request::get(style), Box::new(Record(count.clone())));
        assert_eq!(
            count.load(Ordering::Relaxed),
            vhalla_dioxus_ui_spike::STYLE_BYTES.len()
        );
        for (uri, bytes) in vhalla_dioxus_ui_spike::fixture_resources() {
            let before = count.load(Ordering::Relaxed);
            provider.fetch(
                1,
                Request::get(Url::parse(&uri).unwrap()),
                Box::new(Record(count.clone())),
            );
            assert_eq!(count.load(Ordering::Relaxed) - before, bytes.len());
        }
        let before = count.load(Ordering::Relaxed);
        for uri in [
            "https://example.invalid/",
            "file:///tmp/owned-sentinel",
            "dioxus://index.html/assets/%2e%2e/sentinel",
            "dioxus://index.html/__file_dialog",
            "data:image/svg+xml,%3Cscript%3E",
        ] {
            provider.fetch(
                1,
                Request::get(Url::parse(uri).unwrap()),
                Box::new(Record(count.clone())),
            );
        }
        assert_eq!(count.load(Ordering::Relaxed), before);
    }
}
