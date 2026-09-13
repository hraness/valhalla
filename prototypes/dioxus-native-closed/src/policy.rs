use std::{collections::BTreeMap, sync::Arc};

pub const MAX_RESOURCES: usize = 16;
pub const MAX_RESOURCE_BYTES: usize = 64 * 1024;
pub const MAX_URI_BYTES: usize = 3 * MAX_RESOURCE_BYTES + 32;
pub const MAX_TOTAL_BYTES: usize = 512 * 1024;
pub const MAX_REQUESTS: usize = 4096;
pub const MAX_SERVED_BYTES: usize = 16 * 1024 * 1024;
const PORTRAIT_PREFIX: &str = "data:image/svg+xml,";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bounds,
    InvalidResource,
    Duplicate,
    Denied,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "closed resource policy: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Private fields and construction: UI consumers cannot register a new resource.
/// The launcher registers trusted compiled CSS and locally generated portrait bytes
/// once, before constructing the document. It never decodes a requested data URI.
pub(crate) struct Resource {
    pub(crate) uri: String,
    pub(crate) bytes: Vec<u8>,
}
pub(crate) struct Registry {
    entries: BTreeMap<String, Arc<[u8]>>,
}
impl Registry {
    pub(crate) fn new(resources: Vec<Resource>) -> Result<Self, Error> {
        if resources.is_empty() || resources.len() > MAX_RESOURCES {
            return Err(Error::Bounds);
        }
        let mut entries = BTreeMap::new();
        let mut total = 0usize;
        for resource in resources {
            if resource.uri.len() > MAX_URI_BYTES || resource.bytes.len() > MAX_RESOURCE_BYTES {
                return Err(Error::Bounds);
            }
            total = total
                .checked_add(resource.bytes.len())
                .ok_or(Error::Bounds)?;
            if total > MAX_TOTAL_BYTES {
                return Err(Error::Bounds);
            }
            let valid = if resource.uri.starts_with(PORTRAIT_PREFIX) {
                resource.uri == portrait_uri(&resource.bytes)
            } else {
                resource
                    .uri
                    .strip_prefix("dioxus://index.html/assets/")
                    .is_some_and(|path| {
                        !path.is_empty()
                            && !path.contains("..")
                            && path
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
                            && path.ends_with(".css")
                    })
            };
            if !valid {
                return Err(Error::InvalidResource);
            }
            if entries
                .insert(resource.uri, Arc::from(resource.bytes))
                .is_some()
            {
                return Err(Error::Duplicate);
            }
        }
        Ok(Self { entries })
    }
    fn get(&self, uri: &str) -> Option<Arc<[u8]>> {
        if uri.len() > MAX_URI_BYTES {
            return None;
        }
        self.entries.get(uri).cloned()
    }
}
fn portrait_uri(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut uri = String::with_capacity(PORTRAIT_PREFIX.len() + bytes.len() * 3);
    uri.push_str(PORTRAIT_PREFIX);
    for byte in bytes {
        write!(uri, "%{byte:02X}").expect("String write");
    }
    uri
}

/// Per-window finite allowance, never reset by a resource request. Unknown,
/// oversized, and malformed requests consume an attempt too. This is a resource
/// work bound, not a measured bound on every layout/parser CPU instruction.
pub(crate) struct ResourcePolicy {
    registry: Registry,
    remaining_requests: usize,
    remaining_bytes: usize,
}
impl ResourcePolicy {
    pub(crate) fn new(registry: Registry) -> Self {
        Self {
            registry,
            remaining_requests: MAX_REQUESTS,
            remaining_bytes: MAX_SERVED_BYTES,
        }
    }
    pub(crate) fn request(
        &mut self,
        method: &str,
        uri: &str,
        body_empty: bool,
        headers_empty: bool,
    ) -> Result<Arc<[u8]>, Error> {
        self.remaining_requests = self
            .remaining_requests
            .checked_sub(1)
            .ok_or(Error::Bounds)?;
        if method != "GET" || !body_empty || !headers_empty {
            return Err(Error::Denied);
        }
        let bytes = self.registry.get(uri).ok_or(Error::Denied)?;
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(bytes.len())
            .ok_or(Error::Bounds)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    const CSS: &str = "dioxus://index.html/assets/screen-a1b2.css";
    fn registry() -> Registry {
        Registry::new(vec![
            Resource {
                uri: CSS.into(),
                bytes: b"body {color: black}".to_vec(),
            },
            Resource {
                uri: portrait_uri(b"<svg/>"),
                bytes: b"<svg/>".to_vec(),
            },
        ])
        .unwrap()
    }
    #[test]
    fn exact_registered_bytes_only_no_path_or_data_decoder() {
        let mut p = ResourcePolicy::new(registry());
        assert_eq!(
            &*p.request("GET", CSS, true, true).unwrap(),
            b"body {color: black}"
        );
        assert_eq!(
            &*p.request("GET", &portrait_uri(b"<svg/>"), true, true)
                .unwrap(),
            b"<svg/>"
        );
        for uri in [
            "file:///tmp/owned-sentinel",
            "dioxus://index.html/tmp/owned-sentinel",
            "dioxus://index.html/assets/../../owned-sentinel",
            "dioxus://index.html/assets/%2e%2e/owned-sentinel",
            "dioxus://index.html/%FF",
            "dioxus://index.html/__file_dialog",
            "https://example.invalid/x.css",
            "data:image/svg+xml,%3Cscript%3E",
            "dioxus://index.html/assets/screen-a1b2.css?x=1",
        ] {
            assert_eq!(p.request("GET", uri, true, true), Err(Error::Denied));
        }
        assert_eq!(p.request("POST", CSS, true, true), Err(Error::Denied));
        assert_eq!(p.request("GET", CSS, false, true), Err(Error::Denied));
        assert_eq!(p.request("GET", CSS, true, false), Err(Error::Denied));
    }
    #[test]
    fn registration_enforces_individual_total_and_exact_key_bounds() {
        assert!(matches!(Registry::new(vec![]), Err(Error::Bounds)));
        assert!(matches!(
            Registry::new(vec![Resource {
                uri: CSS.into(),
                bytes: vec![0; MAX_RESOURCE_BYTES + 1]
            }]),
            Err(Error::Bounds)
        ));
        assert!(matches!(
            Registry::new(vec![
                Resource {
                    uri: CSS.into(),
                    bytes: vec![]
                },
                Resource {
                    uri: CSS.into(),
                    bytes: vec![]
                }
            ]),
            Err(Error::Duplicate)
        ));
        assert!(matches!(
            Registry::new(vec![Resource {
                uri: portrait_uri(b"<svg/>"),
                bytes: b"different".to_vec()
            }]),
            Err(Error::InvalidResource)
        ));
        assert!(matches!(
            Registry::new(
                (0..MAX_RESOURCES)
                    .map(|n| Resource {
                        uri: format!("dioxus://index.html/assets/{n}.css"),
                        bytes: vec![0; MAX_RESOURCE_BYTES]
                    })
                    .collect()
            ),
            Err(Error::Bounds)
        ));
    }
    #[test]
    fn denied_attempts_and_served_bytes_have_finite_allowances() {
        let mut p = ResourcePolicy::new(registry());
        for _ in 0..MAX_REQUESTS {
            assert_eq!(p.request("GET", "no", true, true), Err(Error::Denied));
        }
        assert_eq!(p.request("GET", CSS, true, true), Err(Error::Bounds));
        let r = Registry::new(vec![Resource {
            uri: CSS.into(),
            bytes: vec![0; MAX_RESOURCE_BYTES],
        }])
        .unwrap();
        let mut p = ResourcePolicy::new(r);
        for _ in 0..MAX_SERVED_BYTES / MAX_RESOURCE_BYTES {
            assert!(p.request("GET", CSS, true, true).is_ok());
        }
        assert_eq!(p.request("GET", CSS, true, true), Err(Error::Bounds));
    }
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]
        #[test]
        fn arbitrary_unknown_uris_never_select_bytes(uri in ".{0,2048}") {
            let mut p=ResourcePolicy::new(registry());
            if uri != CSS && uri != portrait_uri(b"<svg/>") {prop_assert_eq!(p.request("GET",&uri,true,true),Err(Error::Denied));}
        }
    }
}
