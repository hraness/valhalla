# Contents

- `menubar/` contains the Valhalla menu bar on desktop-foundation's menu kit v2: a status line from `menubar-status.json` (room counts `vhalla menubar refresh` saves), the newest files in the outputs directory, Open at login, Updates & support, and Quit. `fixtures/` holds one menu snapshot per state, checked by `cargo test` and `companion lint-menu --strict`.
- `Cargo.toml` defines the desktop workspace shared by product adapters. It is deliberately separate from the root workspace so Tauri build dependencies never enter the protocol crates' Linux or WASM checks.
- The product-neutral menu-bar foundation lives in `hraness/desktop-foundation` and is pinned here by immutable tag; do not vendor or path-depend on it.

# Guidelines

- Keep the adapter thin. Identities, stores, and rooms remain the authorities; the menu-bar binary holds no privilege of its own and never opens an identity or store file. Its surfaces are the read-only outputs directory, the counts-only `menubar-status.json`, and an explicit human browser handoff to the fixed public Accounts support page. Pass no identity, email, session, or store data to that handoff.
- The binary must run unbundled. `cargo build` output is the artifact `vhalla menubar` spawns; `.app` packaging is an optional later gate, never a prerequisite. Nothing here requires signing or notarization.
- Persistence is desktop-foundation's LaunchAgent helper (`service`), reached through `vhalla-menubar install|uninstall|status|start` and `vhalla menubar …`. `vhalla menubar install` copies a build to `state_directory()/bin/`, retires the pre-0.8 `com.hraness.valhalla.menubar` plist only when it is byte-for-byte ours, then hands over to the copy. The helper never runs `launchctl`; the login item takes effect at next login. The local `.app` identity stays off unless `HRANESS_LOCAL_APP=1`. Keep `LIFECYCLE_MARKER` in step with the CLI's `MENUBAR_LIFECYCLE_MARKER`.
- Keep identities, paths, and environment values out of menu labels, tooltips, logs, and argv. File stems are the only user-facing text and are already bounded by the foundation.
- The host implements `dispatch_result` (typed outcomes — `Accepted` means requested, not completed) and `render_failed` (stderr diagnostics for safe render-error categories). The foundation owns model validation, snapshot cancellation, and refresh coalescing; the adapter adds no product state to any of them.
- Keep `desktop/target/` ignored.
- Build and test with `cargo build` / `cargo test` inside `desktop/`.
