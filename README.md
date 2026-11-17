# `humoco-sync` — HuMoCo Sync Server (Rust & PHP)

**`humoco-sync`** provides two wire-compatible server implementations for privacy-preserving, zero-knowledge synchronization in the **Human Money (HuMoCo)** ecosystem:

1. **`php/` (`sync.php`)** — Zero-dependency PHP ($\ge 8.1$ + `ext-sodium`, `hash('sha3-256')`) single-file drop-in + `lock_handler.php` for shared web hosting and small friend circles.
2. **`rust/` (`humoco-sync-server`)** — High-performance, `#![forbid(unsafe_code)]`, async Rust daemon (`axum` + `tokio` + `redb`) built for public community hosting, VPS deployments, hybrid friend+public operation, storage pool isolation, quota profiles, and web/API self-service.

Both servers implement the exact protocol defined in [`SPEC.md`](SPEC.md), so **Human Money App** treats them identically.

---

## Quick Start: Rust Daemon

```bash
cd rust
cargo build --release
./target/release/humoco-sync-server generate-config --admin-pubkey <64-hex-pubkey> --data-dir d-0000000000000000 > ../config.toml
./target/release/humoco-sync-server serve --config ../config.toml
```

See [`config.example.toml`](config.example.toml) and [`docker/`](docker/) for production setups with Caddy Auto-HTTPS or `systemd`.

---

## Quick Start: PHP (Shared Hosting)

Upload the contents of `php/` (or export the pre-configured ZIP directly from **Settings → Own Sync Service** in `human-money-app`) to any PHP $\ge 8.1$ webspace with `ext-sodium`. For local development:

```bash
./php/start-sync-server.sh
```

---

## Unified Integration Tests

Run the blackbox `curl` protocol suite against the Rust daemon, PHP, or both:

```bash
./tests/run.sh --target rust
./tests/run.sh --target both --allow-missing-php
```

Run Rust unit and integration tests (including hybrid mode, pool isolation, priority media eviction, Zero-PII email opt-in, redeem codes, and graceful downgrade):

```bash
cd rust && cargo test
```
