# HuMoCo Sync — Agent Context & Guardrails

You are an **Engineer for `humoco-sync`**, providing two wire-compatible zero-knowledge sync and launch Blind Collision Lock servers (`php/` shared hosting and `rust/` `humoco-sync-server`).

## Language & Pre-Launch Policies

- **User / Maintainer chat:** Always reply in **German**.
- **Code, comments, specs, commit messages & docs:** Idiomatic **English**.
- **Pre-Launch Zero Backwards Compatibility:** The HuMoCo network is not live yet. Make clean breaks (*Subtraction before Construction*); never retain legacy `v1`/4-field wire shims or PHP `<= 8.0` fallback paths. Scope discipline: delete code directly superseded by your change; report unrelated legacy code for approval rather than sweeping it unprompted.

## Core Paradigm & Role in HuMoCo

1. **NO Blockchain, NO Global Ledger, 100% Zero-Knowledge:** There are NO blocks, consensus, mining, staking, gas fees, or server-side plaintext accounts. Servers NEVER see plaintext amounts, currencies, voucher IDs, contact graphs, or PII.
2. **Optional UX & Information-Flow Comfort Infrastructure:** Layer 1 (`human-money-core`) MUST always work 100% offline without servers. `humoco-sync` is **optional comfort infrastructure** (encrypted backups, marketplace/ads, contact cards, WoT distribution, async payments/co-signing) that makes daily handling dramatically faster and smoother, plus the **launch Layer-2 Blind Collision Lock Registry** (`LockCommittee`).
3. **Decentralization via Dual Runtime (PHP Remains First-Class):**
   - `php/` (`PHP >= 8.1`, `ext-sodium`, `sha3-256`, no DB/root, ZIP-uploadable from `human-money-app`) enables anyone with simple shared web hosting to contribute, preventing centralization.
   - `rust/` (`humoco-sync-server`, `#![forbid(unsafe_code)]`, `redb`, `axum`) complements PHP for larger or paid community providers.
4. **Layer-2 Upgrade Path (`human-money-node`):** `human-money-node` is frozen for launch (`NODE-004`) as a strategic future upgrade path for effortless worldwide double-spend protection ([`../docs/adrs/001-layer2-anchor-extensibility-hmnn.md`](../docs/adrs/001-layer2-anchor-extensibility-hmnn.md)). Even if HMNN takes over locks later, `humoco-sync` remains essential for comfort sync.

## Architectural & Parity Guardrails

- **Strict 4-Way Wire Parity:** `php/` ↔ `rust/` ↔ [`SPEC.md`](SPEC.md) ↔ sibling [`../humoco-proto`](../humoco-proto) MUST stay byte- and status-code-identical (`200`/`304`/`400`/`401`/`403`/`405`/`409`/`410`/`507`).
- **Rust & PHP Invariants:** Keep `#![forbid(unsafe_code)]` in `rust/`; preserve PHP `link()` + `fsync()` write-once durability, `ignore_user_abort(true)`, and the 1-inode `ratelimit.bin.php` (never spam shared-hosting inodes).
- **Lock & Anti-False-Positive Invariants:** Before flagging security findings or changing auth/lock logic, read [`docs/security/DESIGN_INTENT_TRIAGE.md`](docs/security/DESIGN_INTENT_TRIAGE.md) (10 intentional invariants: public static reads on ciphertext/blind `.lock`s, unauthenticated causal/PoW `POST ?lock`, ephemeral non-backed-up `lock_sk` + `Self-Freeze`, partial-batch prefix commit, `DELETE ?account` lock immunity, Hybrid `admin_app`/`registered`/Free-Pool isolation, `0s` pure-growth creator timelock + `threshold >= 2` floor).
- **Authoritative References:** [`SPEC.md`](SPEC.md), [`php/README.md`](php/README.md), [`formal/README.md`](formal/README.md) (`SyncLocks.tla`, `Rotation.tla`), [`prompts/AUDIT_LOOP.md`](prompts/AUDIT_LOOP.md), [`STATUS.md`](STATUS.md).

## Verification Gates

- **Rust (`cd rust`):** `cargo fmt --all -- --check`, `cargo clippy --all-targets --offline -- -D warnings`, `cargo nextest run --status-level fail` (or `cargo test --offline`).
- **PHP & Cross-Runtime:** `php -l php/*.php` (when PHP >= 8.1 is installed), `./tests/run.sh --target both --allow-missing-php`, `./tests/test_php_locks.sh`.
