# Private-room relay host on Railway (or any platform with a public TCP
# endpoint, a mounted volume and Docker builds). Builds vhalla from this
# repository, then runs the relay's loopback listener behind a small TCP
# bridge so the host never binds a wildcard address. deploy/railway/README.md
# covers the platform steps.

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
      --features experimental-network,experimental-sync,experimental-rooms-tui,experimental-public,experimental-private

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends socat ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/vhalla /usr/local/bin/vhalla
COPY deploy/railway/start.sh /usr/local/bin/start.sh
RUN chmod 755 /usr/local/bin/vhalla /usr/local/bin/start.sh
CMD ["/usr/local/bin/start.sh"]
