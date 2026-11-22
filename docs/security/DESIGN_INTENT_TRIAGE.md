# Post-Audit Design-Intent & False-Positive Triage

> **Mandatory Second-Pass Filter:** This triage step MUST be executed at the end of every AI audit run, *after* candidate findings are identified and *before* any code modifications or implementation commits are made.

---

## 🎯 Purpose & Threat-Model Realities

Automated AI security auditors often evaluate backend HTTP/storage servers using generic web-API or centralized database heuristics (e.g., assuming user accounts own plaintext data on the server, expecting session-authenticated reads, or treating unauthenticated lock submission endpoints as missing auth).

In **`humoco-sync`**, the security model is a **100% blind, zero-knowledge encrypted drop and blind collision lock registry** implemented in wire parity across `php/` and `rust/`:
* **Zero Plaintext Knowledge:** Client slots (`card`, `wot`, `backup`, `post`), media blobs, and 605-byte `LockEntry` records carry zero unencrypted amounts, currencies, identities, or PII.
* **Two Wire-Equivalent Runtimes (`SPEC.md`):** Shared-hosting PHP ($\ge 8.1$) and the `#![forbid(unsafe_code)]` Rust daemon (`redb` + `axum`) share one canonical HTTP wire specification and must stay parity-aligned without legacy compatibility branches.
* **Byzantine Lock Safety vs. Static Public Reads:** Public static reads maximize scalability and caching while write-once lock admission, anti-amnesia self-freeze, and 3-phase committee rotation (`SyncLocks.tla`, `Rotation.tla`) defend against server equivocation and rollback.

Blindly "fixing" intentional zero-knowledge, static-read, partial-batch, or anti-amnesia properties breaks protocol parity and double-spend protection.

---

## 📚 Required Reference Materials

Before triaging findings, the auditor MUST inspect:
1. [`SPEC.md`](../../SPEC.md) — Canonical HTTP wire protocol shared identically by PHP and Rust (`v1.2`).
2. [`README.md`](../../README.md) — Dual-runtime architecture, quick start, and unified blackbox/hoster test entry points.
3. [`STATUS.md`](../../STATUS.md) — Implemented milestones (`SYNC-001`–`SYNC-013`, `S01`–`S09` audit sweep, and TLA+ V3 verification).
4. [`php/README.md`](../../php/README.md) — Shared-hosting PHP >= 8.1 invariants, 1-inode rate limiter, and `.htaccess` hardening.
5. [`formal/README.md`](../../formal/README.md) — Formal TLA+ safety and liveness proofs (`SyncLocks.tla`, `Rotation.tla`).
6. [`AGENTS.md`](../../AGENTS.md) (and optional workspace [`../AGENTS.md`](../../../AGENTS.md)) — Zero-knowledge comfort & lock server guardrails, PHP↔Rust parity, and Pre-Launch Zero-Compat policy.

---

## 🏛️ Key Intentional Architectural Invariants (v0.1.4+)

Auditors must evaluate candidate findings against these 10 non-negotiable architectural invariants:

### 1. Zero-Knowledge Public Static Reads (`GET <read_url>/...`)
- **Invariant:** Static delivery of encrypted slots (`<id>[_<prefix>].<ch>.bin`), encrypted media blobs (`<blob_id>.media.bin`), blind 605-byte `.lock` entries, `/anchors/<anchor_id>.bin`, `revocation.json`, and friends-only `index.json` (`ETag` / `304 Not Modified`) is intentionally unauthenticated so standard static web servers (Apache/Nginx/Caddy) can serve reads without invoking PHP.
- **Rule:** Flagging unauthenticated `GET <read_url>/...` reads on client-side AEAD-encrypted blobs or blind lock hashes as broken access control is a `[FALSE POSITIVE / MISINTERPRETATION]`.

### 2. Unauthenticated `POST ?lock` & Zero-Write WAF Probe Admission (`SPEC.md` §6.2–§6.4)
- **Invariant:** `POST ?lock`, `GET ?lock_selftest`, and `GET ?lock_freeze` intentionally do not require member Ed25519 session headers so any PoS recipient can submit causal lock batches (`CausalOutputProof` + `HUMOCO_LOCK_POW_V1` + 1-child-per-output + valid `GenesisTicket` on bucket creation) or execute a zero-write signed WAF probe.
- **Rule:** Flagging `POST ?lock` for lacking member `X-Drop-Signature` headers is an `[INTENTIONAL DESIGN REQUIREMENT]`. *(By contrast, bypassing causal/PoW/ticket checks, mutating disk/DB state during a WAF probe, or lacking IP rate limiting remain `[CONFIRMED VULNERABILITY]`.)*

### 3. Ephemeral Non-Backed-Up `lock_sk` & Anti-Amnesia Self-Freeze (`SPEC.md` §6.1, §6.4)
- **Invariant:** `lock_sk` lives strictly inside `<data_dir>` (`SERVER_META["lock_key"]` in Rust `redb`; `<data_dir>/.lock_key.php` formatted with `<?php __halt_compiler(); ?>` in PHP) and is never placed in `config.toml`, `config.php`, or external backups. When a valid self-signed `known_head_receipt` is ahead of or diverges from local bucket state, the server intentionally marks the bucket permanently `409 bucket_self_frozen` to prevent silent rollback equivocation.
- **Rule:** Flagging the deliberate non-backup of `lock_sk` or permanent `409 bucket_self_frozen` on verified rollback evidence as a durability bug or self-DoS is an `[INTENTIONAL DESIGN REQUIREMENT]`. *(Unsigned/forged receipts triggering freeze or direct HTTP exposure of `.lock_key.php` remain `[CONFIRMED VULNERABILITY]`.)*

### 4. Partial-Batch Conflict Prefix Commit (`SPEC.md` §6.4)
- **Invariant:** During a sequential `POST ?lock` batch (`1..=64` entries), if entry `idx` hits an existing slot with differing `wire_bytes[0..597]`, valid ancestor entries `0..idx` are intentionally committed, entry `idx` returns `ConflictSeen` + `competing_entry`, and entries `> idx` are aborted.
- **Rule:** Flagging the commitment of valid prefix entries `0..idx` prior to a conflicting entry `idx` as "non-atomic batch execution" is an `[INTENTIONAL DESIGN REQUIREMENT]`.

### 5. Hybrid Mode Isolation, Friends-Only `index.json` & `HEAD` `200 OK` Semantics (`SPEC.md` §2.3, §4)
- **Invariant:** `PUT ?members&channel=<ch>` prunes and replaces only `admin_app` memberships (never touching `registered` users); `registered` accounts are excluded from `index.json` to prevent pubkey enumeration; `is_free_pool = true` profiles share `max_free_pool_mb` isolation; and `HEAD /sync.php` intentionally returns `200 OK` with `X-Drop-Authorized: false` (never `403`) for valid non-member pubkeys.
- **Rule:** Flagging `HEAD /sync.php` returning `200 OK` for unauthorized pubkeys or the omission of `registered` slots from `index.json` is an `[INTENTIONAL DESIGN REQUIREMENT]`.

### 6. Zero-PII Email Verification & Authenticated Self-Deletion (`SPEC.md` §4.4–§4.5)
- **Invariant:** For `free` accounts with `store_contact_email = false`, email addresses are never stored in plaintext — only `HMAC-SHA256(canonical_email, server_pepper)` is persisted to enforce one free account per email and enable email-confirmed `/register/delete-confirm`. Unauthenticated web deletion by pubkey `R` alone is forbidden because contacts know `slot_id = R`.
- **Rule:** Flagging HMAC-only email retention or refusing unauthenticated deletion by `R` alone is an `[INTENTIONAL DESIGN REQUIREMENT]`.

### 7. `DELETE ?account` Lock-Channel Immunity & Quarterly Retention GC (`SPEC.md` §6)
- **Invariant:** `DELETE ?account` wipes user slots, media blobs, and memberships while intentionally preserving committed Lock Channel entries and buckets until `retain_until_quarter + 30d` so double-spend evidence cannot be erased by the offender (lock entries hold zero PII, amounts, or identities).
- **Rule:** Flagging retained `.lock` / `LOCK_CONFLICTS` / `/anchors/<id>.bin` data after `DELETE ?account` as a GDPR/account-wipe omission is an `[INTENTIONAL DESIGN REQUIREMENT]`.

### 8. 0-Second Pure-Growth Creator Timelock vs. 72-Hour Rotation Timelock (`SYNC-010`/`SYNC-012`)
- **Invariant:** `effective_proposal_timelock_secs` permits `0s` timelock ONLY when `initiator == Creator`, `guarantor_mig_pubs` is empty, AND `is_pure_committee_growth` holds (`N=1 -> 2/3` pure server additions without removing or replacing any existing server); all other rotations enforce the full `72h` (`259200s`) timelock, `30d` creator-inactivity guarantor takeover, and `threshold >= 2` floor.
- **Rule:** Flagging `0s` timelock on creator-only pure-growth committees without guarantors as a missing timelock is an `[INTENTIONAL DESIGN REQUIREMENT]`. *(Allowing `0s` on shrinks, server replacements, non-empty `guarantor_mig_pubs`, or guarantor proposals remains `[CONFIRMED VULNERABILITY]`.)*

### 9. Fixed 1-Inode PHP Rate Limiter & Proxy-Safe Member Exemption (`php/README.md`)
- **Invariant:** `php/sync.php` uses a fixed 65,564-byte single-file 4,096-bucket hash table (`ratelimit.bin.php` under `flock`) to prevent shared-hosting inode exhaustion, and exempts valid Ed25519-signed member requests from IP failure throttling (enforcing per-pubkey limits instead) to avoid Cloudflare/CGNAT lockouts.
- **Rule:** Flagging hash-bucket collisions in `ratelimit.bin.php` or proxy-safe Ed25519 member IP exemption as a design bug is an `[INTENTIONAL DESIGN REQUIREMENT]`.

### 10. Strict PHP >= 8.1 Baseline & Zero-Compat Policy (`SPEC.md` §0, `AGENTS.md`)
- **Invariant:** PHP <= 8.0 is explicitly unsupported due to `fsync()` durability guarantees, and obsolete protocol formats (such as the old 4-field `HUMOCO-LOCK-DELEGATE-V1`) are permanently removed without compatibility shims.
- **Rule:** Flagging missing PHP <= 8.0 fallbacks or deleted legacy protocol versions as regressions is a `[FALSE POSITIVE / MISINTERPRETATION]`.

---

## 🔍 The 4-Step Triage Questionnaire

For **every** candidate finding produced during an audit pass, answer these four questions:

### 1. Zero-Knowledge & Threat-Boundary Analysis
* **Question:** Does the finding permit unauthenticated/unauthorized mutation, equivocation, rollback bypass, PII/key leakage (`lock_sk`, `admin` tokens, email plaintext), SSRF/XSS/CSRF, quota starvation, or PHP↔Rust wire divergence — or does it only observe public ciphertext/blind hashes?
* **Rule:** Public static exposure of client-encrypted slots or blind 605-byte `.lock` entries is intentional; breaking cryptographic admission, isolation, or server-side key secrecy is a real defect.

### 2. Double-Spend & Byzantine Safety
* **Question:** Would applying the suggested fix weaken anti-amnesia (`lock_sk` / `Self-Freeze`), partial-batch `ConflictSeen` reporting, `DELETE ?account` lock immunity, `72h` rotation timelocks, or TLA+ quorum intersection invariants?
* **Rule:** Never relax lock durability, rollback detection, or committee rotation constraints to satisfy generic CRUD assumptions.

### 3. Established Specification Check
* **Question:** Is the behavior explicitly specified in `SPEC.md` (`v1.2`), `php/README.md`, `formal/README.md` (`SyncLocks.tla`/`Rotation.tla`), or `STATUS.md` (`SYNC-001`–`SYNC-013`)?
* **Rule:** Behavior mandated by `SPEC.md` and formally verified in `formal/` is `[INTENTIONAL DESIGN REQUIREMENT]`.

### 4. Dual-Runtime Parity & Functional Trade-Off Evaluation
* **Question:** Would the change break wire parity between `php/` and `rust/`, exhaust shared-hosting inodes, or reintroduce legacy compatibility shims?
* **Rule:** Maintain strict PHP↔Rust↔`SPEC.md` parity and zero-compat hygiene across both runtimes.

---

## 🏷️ Triage Classification Outcomes

Classify every candidate finding into one of three outcomes:

### Outcome A: `[CONFIRMED VULNERABILITY]`
* **Definition:** A genuine security, concurrency, atomicity, crypto-admission, quota-isolation, web/CSRF/XSS, or PHP↔Rust wire-parity defect backed by exact code evidence.
* **Action:** Include in the verified findings list, cluster by root cause, and resolve via Fail-First TDD + full Rust/PHP/blackbox verification.

### Outcome B: `[INTENTIONAL DESIGN REQUIREMENT]`
* **Definition:** Behavior flagged by generic server heuristics that is explicitly required by `SPEC.md`, zero-knowledge blind storage, anti-amnesia lock safety, Hybrid isolation, or shared-hosting inode constraints.
* **Action:**
  1. **DO NOT MODIFY** the operational logic.
  2. **Preserve / Clarify Comments:** Add or retain a concise comment explaining *why* the behavior is intentional if helpful.
  3. **Verify Invariant Tests:** Confirm `rust/tests/integration_tests.rs`, `tests/run.sh`, or `tests/test_php_locks.sh` covers the invariant.

### Outcome C: `[FALSE POSITIVE / MISINTERPRETATION]`
* **Definition:** The candidate finding relies on a misread transaction/validation guard, assumes server-side plaintext decryption, or flags missing backward compatibility for deleted pre-launch protocol versions.
* **Action:** Discard the finding with a concise evidence-based rationale.

---

## 📋 Triage Report Template

Include this summary when documenting triage decisions in `prompts/reports/` or review summaries:

```markdown
### Post-Audit Design-Intent Triage Summary

| Finding ID | Suspected CWE | Triage Outcome | Rationale / Architectural Requirement | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| SYNC-S01-01 | CWE-306 | `[INTENTIONAL DESIGN REQUIREMENT]` | `POST ?lock` intentionally accepts unauthenticated PoS batches gated by `CausalOutputProof`, `HUMOCO_LOCK_POW_V1`, and `GenesisTicket` (`SPEC.md` §6.4). | Preserved; audited proof & PoW checks instead. |
| SYNC-S03-02 | CWE-459 | `[INTENTIONAL DESIGN REQUIREMENT]` | `DELETE ?account` preserves Lock Channel entries until `retain_until_quarter + 30d` so offenders cannot erase double-spend evidence (`SPEC.md` §6). | Preserved; verified user slot/media wipe only. |
| SYNC-S04-03 | CWE-284 | `[FALSE POSITIVE / MISINTERPRETATION]` | Static `<read_url>/<id>.<ch>.bin` reads return client-side AEAD ciphertext; confidentiality does not rely on HTTP read auth. | Discarded as false positive. |
| SYNC-S07-04 | CWE-362 | `[INTENTIONAL DESIGN REQUIREMENT]` | `0s` rotation timelock is strictly gated on `Creator` + empty `guarantor_mig_pubs` + `lock_is_pure_committee_growth` (`SYNC-012`). | Invariant verified across PHP & Rust. |
```
