# Project Status: `humoco-sync`

**Version:** `v0.1.0`  
**Last Updated:** 2026-11-15

## Overview
`humoco-sync` is the 6th repository in the HuMoCo ecosystem, housing both the lightweight PHP sync script (`php/`) and the high-performance Rust sync daemon (`rust/humoco-sync-server`), unified under [`SPEC.md`](SPEC.md) and verified by a shared blackbox integration test suite (`tests/run.sh`).

## Task Progress

| ID | Task | Status | Notes |
|---|---|---|---|
| `SYNC-005` | Raise PHP `card`/`wot` defaults to `512 KiB` & harmonize `HEAD` headers (`X-Channel-Max-Bytes`, `ETag`, `X-Drop-Authorized`) across PHP & Rust (`SPEC.md`) | ✅ **Done** | PHP `card`/`wot` defaults at `512 KiB` + unified `HEAD` headers across PHP/Rust/`SPEC.md`; 39/39 Rust blackbox assertions (`tests/run.sh --target rust`), 4/4 Rust integration tests, and `clippy` (0 warnings) passed (PHP CLI not installed locally) |
| `SYNC-001` | Extract `php/` from `human-money-app`, author `SPEC.md`, add `DELETE ?account` | ✅ **Done** | Single source of truth for PHP & Rust |
| `SYNC-002` | Rust Daemon Core (`axum`, `tokio`, `redb`, RAM rate-limiter, streaming `PUT`, Prio-3 eviction, Hybrid separation) | ✅ **Done** | `#![forbid(unsafe_code)]`, 100% `sync.php` wire parity (both `/sync.php` & `/sync`), pure-public `drop_pub` synthesis |
| `SYNC-003` | Quota Profiles, Storage Pool Isolation, Anti-Spam Gates (Zero-PII Email HMAC, Codes, PoW), Built-in Web UI & Admin API | ✅ **Done** | `/register`, `/admin`, `/api/v1/admin/*`, `XChaCha20-Poly1305` optional email cipher, `downgrade_grace_days` |
| `SYNC-004` | Deployment Packaging (`Dockerfile`, `docker-compose.yml` with Caddy, `systemd` unit, `config.example.toml`) & Blackbox Suite | ✅ **Done** | 37/37 blackbox HTTP assertions passed (`tests/run.sh --target rust`), 4/4 Rust integration tests passed, `clippy` 0 warnings |
