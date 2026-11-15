# HuMoCo Sync Protocol Specification (`humoco-sync` v1.1)

This document defines the canonical HTTP wire protocol shared identically by the lightweight PHP implementation (`php/sync.php`) and the high-performance Rust daemon (`rust/humoco-sync-server`). Clients (`human-money-app`) interact with both servers identically.

---

## 1. Endpoints & Route Compatibility

Both `/sync.php` and `/sync` accept identical query parameters and HTTP methods. Static reads are served under `<read_url>` (`<base_url>/<data_dir>`).

| Operation | Method & Route | Auth Scope |
|---|---|---|
| Server discovery | `GET /sync.php?info` | Public (IP rate-limited) |
| Slot capability & ETag check | `HEAD /sync.php` | Member pubkey header |
| Upload binary slot or media | `PUT /sync.php` | Member Ed25519 signature |
| Delete slot or media | `DELETE /sync.php` | Member Ed25519 signature |
| Delete entire account & blobs | `DELETE /sync.php?account` | Account Ed25519 signature |
| Update friend member list | `PUT /sync.php?members&channel=<ch>` | Admin Ed25519 signature |
| Fetch storage dashboard | `GET /sync.php?status` | Admin Ed25519 signature |
| Publish or clear revocation | `PUT /sync.php?revoke` | Admin Ed25519 signature |
| Static catalog (friends only) | `GET <read_url>/index.json` | Public |
| Static revocation notice | `GET <read_url>/revocation.json` | Public |
| Static encrypted slot | `GET <read_url>/<id>[_<prefix>].<ch>.bin` | Public |
| Static encrypted media blob | `GET <read_url>/<blob_id>.media.bin` | Public |

Any unrecognized method/query combination on `/sync.php` returns `405 Method Not Allowed` with `Allow: GET, HEAD, PUT, DELETE, POST`.

---

## 2. Cryptographic Headers & Canonical Signed Messages

All cryptographic identifiers use **lowercase hexadecimal** strings:
- `X-Drop-Pubkey`: 64 lowercase hex chars (32-byte Ed25519 verifying key).
- `X-Drop-Timestamp`: Unix epoch seconds (must be within $\pm 60$ seconds of server time).
- `X-Drop-Nonce`: 32 lowercase hex chars (16 random bytes; single-use within a 120s window, `409 Conflict` on replay).
- `X-Drop-Signature`: 128 lowercase hex chars (64-byte detached Ed25519 signature).
- `X-Channel`: `[a-z0-9_]{1,32}` (`card`, `wot`, `backup`, `post`, `media`).
- `X-Drop-Prefix` *(optional, standard channels only)*: `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`, no `--` (`400`/`403` otherwise; disallowed on `media`).
- `X-Media-Id` *(required on `PUT media`, optional on `DELETE media`)*: 64 lowercase hex chars.

Empty body SHA-256 hex digest: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

### 2.1 Member Requests (`HUMOCO-DROP-REQ-V1`)

1. **Standard channel (`PUT` / `DELETE`):**
   ```text
   HUMOCO-DROP-REQ-V1\n<METHOD>\n<channel>\n<prefix_or_empty>\n<timestamp>\n<nonce>\n<sha256_hex(raw_body)>
   ```
2. **Media channel (`PUT`):**
   ```text
   HUMOCO-DROP-REQ-V1\nPUT\nmedia:<media_id>\n\n<timestamp>\n<nonce>\n<sha256_hex(raw_body)>
   ```
3. **Media channel (`DELETE`):**
   - Single blob (`X-Media-Id` provided): `media:<media_id>`
   - All user media blobs (`X-Media-Id` omitted): `media`
   ```text
   HUMOCO-DROP-REQ-V1\nDELETE\n<media_target>\n\n<timestamp>\n<nonce>\n<sha256_hex('')>
   ```
4. **Full account & data wipe (`DELETE ?account`):**
   ```text
   HUMOCO-DROP-REQ-V1\nDELETE_ACCOUNT\n\n<timestamp>\n<nonce>\n<sha256_hex('')>
   ```

### 2.2 Admin Requests (`HUMOCO-DROP-ADMIN-V1` & `HUMOCO-DROP-REVOKE-V1`)

1. **`PUT ?members&channel=<ch>`:**
   ```text
   HUMOCO-DROP-ADMIN-V1\nPUT_MEMBERS\n<channel>\n<timestamp>\n<nonce>\n<sha256_hex(raw_body)>
   ```
   Body JSON: `{"pubkeys": ["<64-hex>", ...]}`.
2. **`GET ?status`:**
   ```text
   HUMOCO-DROP-ADMIN-V1\nSTATUS\n\n<timestamp>\n<nonce>\n<sha256_hex('')>
   ```
3. **`PUT ?revoke`:**
   ```text
   HUMOCO-DROP-ADMIN-V1\nPUT_REVOKE\n<timestamp>\n<nonce>\n<sha256_hex(raw_body)>
   ```
   Inner notice signature (`HUMOCO-DROP-REVOKE-V1`):
   ```text
   HUMOCO-DROP-REVOKE-V1\n<drop_pub>\n<issued_at>\n<effective_at>\n<rep_write>\n<rep_read>\n<rep_pub>\n<reason>
   ```

---

## 3. Channel Priorities, Quotas & Eviction

- **Priority 1 (`backup`, `post`, `wot`)** and **Priority 2 (`card`)**: Protected. When storage quota is tight, uploading Prio 1/2 slots automatically evicts the oldest **Priority 3 (`media`)** blobs via LRU before returning `507 Insufficient Storage`.
- **Priority 3 (`media`)**: Ephemeral encrypted image blobs (`max_user_count`, `max_user_bytes`, `max_channel_mb`). Ownership is tracked per `media_id` (`403` if another pubkey attempts overwrite/delete). Never included in `index.json`.

---

## 4. Hybrid Mode Invariants (Rust Daemon)

The Rust server supports `admin_app` (friends managed via App `PUT ?members`) and `registered` (public/paid users via `/register` or `/api/v1/admin`) simultaneously:

1. **Authorization Isolation:** `PUT ?members&channel=<ch>` replaces and prunes **only** `admin_app` memberships for `<ch>`. It NEVER modifies or deletes `registered` users or their slots/media.
2. **Privacy & Scalability of `index.json`:** Only `admin_app` slots (capped at `max_members`, e.g. 300) appear in `<read_url>/index.json`. Public/paid `registered` users rely on $O(1)$ `slot_id` direct fetches (`<read_url>/<id>[_<prefix>].<ch>.bin`), keeping `index.json` tiny and preventing enumeration of public user pubkeys.
3. **Storage Pool Isolation:** Profiles flagged `is_free_pool = true` share `max_free_pool_mb`. Free-tier spam can never starve `friends` (`admin_app`) or paid (`pro`) accounts.
4. **Zero-PII Email Verification:** For `free` accounts with `store_contact_email = false`, email addresses are NEVER persisted in plaintext — only `HMAC-SHA256(canonical_email, server_pepper)` is stored to enforce one free account per email and enable verified web self-deletion.
5. **Authenticated Self-Deletion:** Unauthenticated web deletion by pubkey `R` alone is forbidden (since contacts know `slot_id = R`). Accounts may only be deleted via Ed25519-signed `DELETE /sync.php?account`, email-confirmed `/register/delete-confirm`, or Admin authorization.

---

## 5. Rust Public Web & Admin Extensions

When enabled via configuration (`mode.enable_public_registration` / `mode.enable_builtin_ui`):

- `GET /register?key=<R>` — Self-service onboarding, status check, code redemption, and verified deletion UI.
- `POST /register/email` / `GET /register/confirm?token=...` — Double-Opt-In Zero-PII activation.
- `POST /register/redeem` — Redeem invite or paid upgrade code (`INVITE-*` / `PRO-*`).
- `POST /register/pow` / `POST /register/open` — Browser SHA-256 PoW or open registration (subject to `/24` & `/48` daily subnet caps).
- `POST /register/delete-request` / `GET /register/delete-confirm?token=...` — Email-verified self-deletion.
- `GET /admin` — Built-in web admin dashboard (Argon2id token auth, `HttpOnly; SameSite=Strict` session + CSRF protection).
- `/api/v1/admin/*` — Bearer-authenticated JSON API for billing/voucher automation (`GET /stats`, `GET /users/:pubkey`, `POST /users/:pubkey/profile`, `DELETE /users/:pubkey`, `POST /codes`).
