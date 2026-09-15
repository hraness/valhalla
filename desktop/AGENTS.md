# Contents

- `menubar/` contains the Valhalla adapter: a thin binary that renders the agent outputs directory into a status-item menu. Agents drop descriptively named files into the outputs directory; the menu lists them newest-first with image thumbnails and open/reveal actions.
- `Cargo.toml` defines the desktop workspace shared by product adapters. It is deliberately separate from the root workspace so Tauri build dependencies never enter the protocol crates' Linux or WASM checks.
- The product-neutral menu-bar foundation lives in `hraness/desktop-foundation` and is pinned here by immutable tag; do not vendor or path-depend on it.

# Guidelines

- Keep the adapter thin. Identities, stores, and rooms remain the authorities; the menu-bar binary holds no privilege of its own and never opens an identity or store file. The only surface today is the read-only outputs directory.
- The binary must run unbundled. `cargo build` output is the artifact `vhalla menubar` spawns; `.app` packaging is an optional later gate, never a prerequisite. Nothing here requires signing or notarization.
- Persistence is `vhalla menubar install`: it copies a release build to `state_directory()/bin/` and registers a per-user `LaunchAgent` (`com.hraness.valhalla.menubar`, `gui/<uid>`, `RunAtLoad`). `uninstall` boots the agent out and removes both files. Both are idempotent, macOS-only, and need no privileges beyond the logged-in user's — no system daemon, no root.
- Keep identities, paths, and environment values out of menu labels, tooltips, logs, and argv. File stems are the only user-facing text and are already bounded by the foundation.
- The host implements `dispatch_result` (typed outcomes — `Accepted` means requested, not completed) and `render_failed` (stderr diagnostics for safe render-error categories). The foundation owns model validation, snapshot cancellation, and refresh coalescing; the adapter adds no product state to any of them.
- Keep `desktop/target/` ignored.
- Build and test with `cargo build` / `cargo test` inside `desktop/`.
