# Rooms seed validator on Railway (or any platform with a public TCP
# endpoint, a mounted volume and Docker builds). Builds vhalla from this
# repository, then runs `rooms node` against a home it scaffolds once
# from environment on the mounted volume, so the journal and WAL survive
# redeploys. deploy/rooms-seed/README.md covers the platform steps.

FROM rust:slim-bookworm AS build
WORKDIR /src
# codegen-units 16 keeps the thin-LTO link inside small-builder memory.
ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake perl \
 && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release --locked -p vhalla-cli \
      --no-default-features \
      --features experimental-rooms-node

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/vhalla /usr/local/bin/vhalla
COPY deploy/rooms-seed/start.sh /usr/local/bin/start.sh
RUN chmod 755 /usr/local/bin/vhalla /usr/local/bin/start.sh
CMD ["/usr/local/bin/start.sh"]
