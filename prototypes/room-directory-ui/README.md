# vhalla rooms: shared Dioxus room-directory companion

Disposable R5 reference, not an installed client. One Rust `App` renders the
room directory, literal search, room detail, owner account, and room creation
screens. A `RoomServices` trait injects the projection source; the
`fixture_app` launch wrapper constructs the demonstration corpus. No
application JavaScript or TypeScript is authored.

The companion is deliberately low-authority. Screens consume
`vhalla-rooms-app` projections — directory rows, account summaries, quotes and
pending markers — and never see a registry, journal, private key or consensus
type. A room claim is submitted as a canonical `BatchBody` of already-signed
record bytes through `RoomServices::submit`; the hosted node assembles it
against the live frontier, and the screen surfaces the marker's resolution:
queued, in flight, committed, name taken (collision) or not admitted
(rejected). UI projections grant no host authority — no arbitrary filesystem
paths, URLs, shell commands or network endpoints cross the boundary.

`NodeServices` (unix-only) adapts the real `vhalla_rooms_app::Service`: a read
replica that absorbs the node's committed journal bundles under canonical
certificate verification and drops `*.body` files into the node's intake.
`FixtureServices` fabricates the same contract in-session for SSR tests and
the demonstration launchers. The app crate is split so web renderers consume
portable projection DTOs without the unix filesystem machinery.

## Run

```console
$ cargo run --features desktop --bin vhalla-rooms-desktop   # native window
$ dx serve --features web --bin vhalla-rooms-web            # browser (needs dioxus-cli)
```

Both launchers mount the fixture corpus. Wiring `NodeServices` to a live
`vhalla rooms node` replica is a deployment choice made by the embedding CLI.

## Verify

```console
$ cargo test            # six SSR tests: every route, pending states, not-found
$ cargo clippy --all-targets -- -D warnings
```

Browser (`wasm32`) compilation is CI-deferred; `dioxus-web` only builds for
the wasm target.
