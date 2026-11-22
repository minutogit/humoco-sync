# `humoco-sync` — HuMoCo Sync & Lock Server (Rust & PHP)

**`humoco-sync`** provides two wire-compatible server implementations for zero-knowledge comfort synchronization (encrypted backups, marketplace/media, contact cards, WoT distribution, async payments) and the **launch Blind Collision Lock Registry** (`LockCommittee`) in the **Human Money (HuMoCo)** ecosystem:

1. **`php/` (`sync.php`)** — Zero-dependency PHP ($\ge 8.1$ + `ext-sodium`, `hash('sha3-256')`) drop-in (`sync.php`, `lock_handler.php`, lazy-loaded `lock_rotation.php`) for shared web hosting and small friend circles, keeping infrastructure decentralized without server admin overhead.
2. **`rust/` (`humoco-sync-server`)** — High-performance, `#![forbid(unsafe_code)]`, async Rust daemon (`axum` + `tokio` + `redb`) built for public community hosting, VPS deployments, hybrid friend+public operation, storage pool isolation, quota profiles, and web/API self-service.

Both servers implement the exact protocol defined in [`SPEC.md`](SPEC.md), so **Human Money App** treats them identically. Note that the Rust daemon links sibling [`../humoco-proto`](../humoco-proto) via relative path (`../../humoco-proto` in `rust/Cargo.toml`).

See also [`AGENTS.md`](AGENTS.md), [`formal/README.md`](formal/README.md) (TLA+ proofs), [`docs/security/DESIGN_INTENT_TRIAGE.md`](docs/security/DESIGN_INTENT_TRIAGE.md), and [`prompts/AUDIT_LOOP.md`](prompts/AUDIT_LOOP.md).

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

## Unified Integration Tests & Hoster Benchmark

Run the blackbox `curl` protocol suite against the Rust daemon, PHP, or both, plus the PHP concurrency/rollback/inode suite and shared-hoster measurement tool:

```bash
./tests/run.sh --target rust
./tests/run.sh --target both --allow-missing-php
./tests/test_php_locks.sh
./tests/measure_hoster.sh --url https://hoster.example/sync.php --admin-sk <64-hex-sk> --out report.md
```

Run Rust unit and integration tests (including hybrid mode, pool isolation, priority media eviction, Zero-PII email opt-in, redeem codes, and graceful downgrade):

```bash
cd rust && cargo test
```
