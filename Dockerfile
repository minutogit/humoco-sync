# syntax=docker/dockerfile:1
# Multi-stage build for humoco-sync-server (BuildKit context `humoco-proto` -> ../../humoco-proto)
FROM rust:1.86-bookworm AS builder

WORKDIR /workspace/humoco-sync/rust
COPY --from=humoco-proto Cargo.toml /workspace/humoco-proto/
COPY --from=humoco-proto src /workspace/humoco-proto/src
COPY rust/Cargo.toml rust/Cargo.lock ./
COPY rust/src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home humoco

WORKDIR /var/lib/humoco-sync
COPY --from=builder /workspace/humoco-sync/rust/target/release/humoco-sync-server /usr/local/bin/humoco-sync-server
COPY config.example.toml /etc/humoco-sync/config.example.toml

RUN mkdir -p /var/lib/humoco-sync/data \
    && chown -R humoco:humoco /var/lib/humoco-sync \
    && chmod 0700 /var/lib/humoco-sync/data \
    && chmod 0755 /etc/humoco-sync \
    && chmod 0644 /etc/humoco-sync/config.example.toml
USER humoco

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -sf http://127.0.0.1:8080/sync.php?info >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/humoco-sync-server"]
CMD ["serve", "--config", "/etc/humoco-sync/config.toml", "--bind", "0.0.0.0:8080"]
