//! Execute the actual CLI helper body with bounded native-renderer metadata.
//! Actual dx invocation and compiled artifact qualification remain separate.
use std::collections::BTreeMap;
struct BuildRequest;
struct Dependency {
    name: String,
}
pub(crate) struct Package {
    features: BTreeMap<String, Vec<String>>,
    dependencies: Vec<Dependency>,
}
mod krates {
    pub(crate) mod cm {
        pub(crate) type Package = super::super::Package;
    }
}
struct Triple;
#[derive(Clone, Copy)]
enum Renderer {
    Native,
}
impl Renderer {
    fn feature_name(&self, _: &Triple) -> &str {
        "native"
    }
    fn autodetect_from_cargo_feature(feature: &str) -> Option<Self> {
        matches!(
            feature,
            "web" | "desktop" | "mobile" | "native" | "server" | "liveview"
        )
        .then_some(Self::Native)
    }
}
mod tracing {
    macro_rules! debug {
        ($($tokens:tt)*) => {
            ()
        };
    }
    pub(super) use debug;
}
include!("../upstream/dx-feature-helper.rs");
fn package(alias: bool) -> Package {
    let mut features = BTreeMap::from([("renderer".into(), vec!["dep:dioxus-native".into()])]);
    if alias {
        features.insert("native".into(), vec!["renderer".into()]);
    }
    Package {
        features,
        dependencies: vec![Dependency {
            name: "dioxus".into(),
        }],
    }
}
#[test]
fn missing_named_alias_triggers_broad_dependency_feature() {
    assert_eq!(
        BuildRequest::feature_for_platform_and_renderer(&package(false), &Triple, Renderer::Native),
        Some("dioxus/native".into())
    );
}
#[test]
fn named_native_alias_selects_closed_local_feature() {
    assert_eq!(
        BuildRequest::feature_for_platform_and_renderer(&package(true), &Triple, Renderer::Native),
        Some("native".into())
    );
}
