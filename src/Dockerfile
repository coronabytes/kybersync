# syntax=docker/dockerfile:1.7
# kybersync-server: zero-knowledge storage for encrypted blobs + commit log.

FROM rust:1-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p kybersync-server \
    && cp target/release/kybersync-server /kybersync-server \
    && mkdir -p /data-empty

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /kybersync-server /usr/local/bin/kybersync-server
COPY --from=build --chown=65532:65532 /data-empty /data
ENV KYBERSYNC_LISTEN=0.0.0.0:8443 \
    KYBERSYNC_STORAGE=fs \
    KYBERSYNC_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8443
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["/usr/local/bin/kybersync-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/kybersync-server"]
