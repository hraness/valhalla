# Experimental upstream patch

The adjacent `libp2p-webrtc-websys` source is the crates.io **0.5.0** release,
whose `.cargo_vcs_info.json` identifies rust-libp2p commit
`7171dce2f90c05ba7892d4ba926abb1881db27c7`, path `transports/webrtc-websys`.
The package manifest and original source notices are preserved. `LICENSE` is
the [upstream root MIT license at that commit](https://github.com/libp2p/rust-libp2p/blob/7171dce2f90c05ba7892d4ba926abb1881db27c7/LICENSE).
The unused package-local lock and registry `.cargo-ok` marker were omitted;
the enclosing experiment owns its exact dependency lock.

The original registry archive SHA-256 is
`a4599b0cb5869694f38b024e431565b1624dddb2cb873f359c5cda392427784c`.
A byte comparison confirmed that the package manifest matches the release and
only the two Rust files below differ.

Only two Rust files differ from the release:

1. `src/stream/poll_data_channel.rs`: when the final shared callback owner drops,
   detach `onopen`, `onbufferedamountlow`, `onclose` and `onmessage` before the
   corresponding Rust `Closure`s are destroyed. Earlier clone drops do nothing.
   **Do not close the raw data channel here**: that more aggressive experiment
   caused an 8 KiB exchange to time out and was discarded.
2. `src/connection.rs`: the private `RtcPeerConnection` wrapper clears
   `ondatachannel` and closes in Drop, including paths that fail/cancel before a
   `Connection` exists. The existing `Connection::drop` remains in place.

These changes remove the observed callback-after-drop error in the tested
browser path. They are experimental, not independently reviewed or an upstream
release. Revisit them before any long-lived or public transport promotion. The
16 KiB read cap, overflow rejection and all protocol bytes remain unchanged.
