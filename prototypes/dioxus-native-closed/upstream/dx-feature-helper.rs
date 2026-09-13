// Extracted unchanged from DioxusLabs/dioxus v0.7.10 packages/cli/src/build/renderer.rs.
// MIT OR Apache-2.0. Tests supply lightweight metadata types and a no-effect logger.
impl BuildRequest {
    pub fn feature_for_platform_and_renderer(
        package: &krates::cm::Package,
        triple: &Triple,
        renderer: Renderer,
    ) -> Option<String> {
        // Try to find the feature that activates the dioxus feature for the given platform
        let dioxus_feature = renderer.feature_name(triple);

        let res = package.features.iter().find_map(|(key, features)| {
            // if the feature is just the name of the platform, we use that
            if key == dioxus_feature {
                tracing::debug!("Found feature {key} for renderer {renderer}");
                return Some(key.clone());
            }

            // Otherwise look for the feature that starts with dioxus/ or dioxus?/ and matches just the single platform
            // we are looking for.
            let mut dioxus_renderers_enabled = Vec::new();
            for feature in features {
                if let Some((_, after_dioxus)) = feature.split_once("dioxus") {
                    if let Some(dioxus_feature_enabled) =
                        after_dioxus.trim_start_matches('?').strip_prefix('/')
                    {
                        if Renderer::autodetect_from_cargo_feature(dioxus_feature_enabled).is_some()
                        {
                            dioxus_renderers_enabled.push(dioxus_feature_enabled.to_string());
                        }
                    }
                }
            }

            // If there is exactly one renderer enabled by this feature, we can use it
            if let [feature_name] = dioxus_renderers_enabled.as_slice() {
                if feature_name == dioxus_feature {
                    tracing::debug!(
                        "Found feature {key} for renderer {renderer} which enables dioxus/{renderer}"
                    );
                    return Some(key.clone());
                }
            }

            None
        });

        res.or_else(|| {
            let depends_on_dioxus = package.dependencies.iter().any(|dep| dep.name == "dioxus");
            if depends_on_dioxus {
                let fallback = format!("dioxus/{dioxus_feature}");
                tracing::debug!(
                    "Could not find explicit feature for renderer {renderer}, passing `fallback` instead"
                );
                Some(fallback)
            } else {
                None
            }
        })
    }
}
