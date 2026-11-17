# HuMoCo Sync Protocol Specification (`humoco-sync` v1.2)

This document defines the canonical HTTP wire protocol shared identically by the lightweight PHP implementation (`php/sync.php`, `php/lock_handler.php`) and the high-performance Rust daemon (`rust/humoco-sync-server`). Clients (`human-money-core` / `human-money-app`) interact with both servers identically.

## 0. Runtime Prerequisites

- **PHP Shared-Hosting (`php/`):** Requires **PHP >= 8.1** (`fsync()` durability requirement), core **`ext-sodium`**, and SHA3-256 support in `hash()` (`hash('sha3-256', ...)`). Older PHP versions (`<= 8.0`, EOL) are unsupported; no legacy fallback paths exist.
- **Rust Daemon (`rust/`):** `#![forbid(unsafe_code)]`, `redb` ACID storage, zero external daemon dependencies.

---

## 1. Endpoints & Route Compatibility

Both `/sync.php` and `/sync` accept identical query parameters and HTTP methods. Static reads are served under `<read_url>` (`<base_url>/<data_dir>`).

| Operation | Method & Route | Auth Scope |
|---|---|---|
| Server discovery | `GET /sync.php?info` | Public (IP rate-limited) |
| Slot capability & ETag check | `HEAD /sync.php` | Member pubkey header (`X-Drop-Authorized`) |
| Upload binary slot or media | `PUT /sync.php` | Member Ed25519 signature |
| Delete slot or media | `DELETE /sync.php` | Member Ed25519 signature |
| Delete entire account & blobs | `DELETE /sync.php?account` | Account Ed25519 signature |
| Update friend member list | `PUT /sync.php?members&channel=<ch>` | Admin Ed25519 signature |
| Fetch storage dashboard | `GET /sync.php?status` | Admin Ed25519 signature |
| Publish or clear revocation | `PUT /sync.php?revoke` | Admin Ed25519 signature |
| Delegate server `lock_pub` | `PUT /sync.php?lock_delegate` | Admin Ed25519 signature (`HUMOCO-DROP-ADMIN-V1`) |
| Fetch cached lock selftest report | `GET /sync.php?lock_selftest` | Public (IP rate-limited, signed by `lock_sk`) |
| Re-run lock selftest live | `POST /sync.php?lock_selftest` | Admin Ed25519 signature (`HUMOCO-DROP-ADMIN-V1`) |
| Issue offline GenesisTicket | `POST /sync.php?lock_ticket` | Member/Registered/Admin `HUMOCO-DROP-REQ-V1` or server ticket PoW |
| Submit lock batch or WAF probe | `POST /sync.php?lock` | Public (IP rate-limited; cryptographic causal & PoW admission) |
| Inspect rotation / freeze state | `GET /sync.php?lock_freeze&anchor_id=<64-hex>` | Public (IP rate-limited) |
| Submit pre-freeze, proposal, veto, heartbeat | `POST /sync.php?lock_freeze` | Authority / holder per Concept §5.4 |
| Target union import & `ImportAck` | `POST /sync.php?lock_import` | Public (IP rate-limited; verifies `>= Q_old` snapshots & timelock) |
| Sign or finalize `MigrationCert` commit | `POST /sync.php?lock_commit` | Public (IP rate-limited; verifies all `ImportAck`s / chain) |
| Static catalog (friends only) | `GET <read_url>/index.json` | Public |
| Static revocation notice | `GET <read_url>/revocation.json` | Public |
| Static anchor chain discovery manifest | `GET /anchors/<anchor_id>.bin` (or `<read_url>/anchors/<anchor_id>.bin`) | Public (`ETag` / `304 Not Modified`) |
| Static encrypted slot | `GET <read_url>/<id>[_<prefix>].<ch>.bin` | Public |
| Static encrypted media blob | `GET <read_url>/<blob_id>.media.bin` | Public |
| Static blind collision lock entry | `GET <read_url>/locks/<YYYY-QN>/<bucket_hex64>/<file_hex64>.lock` | Public (with `ETag` / `304 Not Modified`) |

Any unrecognized method/query combination on `/sync.php` returns `405 Method Not Allowed` with `Allow: GET, HEAD, PUT, DELETE, POST`.

---

## 2. Cryptographic Headers & Canonical Signed Messages

All cryptographic identifiers use **lowercase hexadecimal** strings:
- `X-Drop-Pubkey`: 64 lowercase hex chars (32-byte Ed25519 verifying key).
- `X-Drop-Timestamp`: Unix epoch seconds (must be within $\pm 60$ seconds of server time).
- `X-Drop-Nonce`: 32 lowercase hex chars (16 random bytes; single-use within a 120s window, `409 Conflict` on replay).
- `X-Drop-Signature`: 128 lowercase hex chars (64-byte detached Ed25519 signature).
- `X-Channel`: `[a-z0-9_]{1,32}` (`card`, `wot`, `backup`, `post`, `media`, `lock`). Note: `lock` uses `PUT ?members&channel=lock` for friend Genesis-Ticket authorization and `POST ?lock_ticket` / `POST ?lock` instead of binary `PUT` slots.
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
4. **`PUT ?lock_delegate`:**
   ```text
   HUMOCO-DROP-ADMIN-V1\nPUT_LOCK_DELEGATE\n<timestamp>\n<nonce>\n<sha256_hex(raw_body)>
   ```
5. **`POST ?lock_selftest`:**
   ```text
   HUMOCO-DROP-ADMIN-V1\nPOST_LOCK_SELFTEST\n<timestamp>\n<nonce>\n<sha256_hex(raw_body)>
   ```
6. **`POST ?lock_ticket` (when using Member / Registered / Admin Ed25519 auth):**
   ```text
   HUMOCO-DROP-REQ-V1\nPOST\nlock_ticket\n\n<timestamp>\n<nonce>\n<sha256_hex(raw_body)>
   ```

### 2.3 Canonical `HEAD` Capability & Conditional `GET` Headers

Both `php/sync.php` and `rust/humoco-sync-server` respond identically to `HEAD /sync.php` (`HEAD /sync`):

- **Request Headers:** `X-Drop-Pubkey` (required, 64-hex); optional `X-Channel`, `X-Drop-Prefix` (disallowed on `media`), and `X-Media-Id`. Invalid header syntax returns `400 Bad Request`.
- **Response (`200 OK`, `Cache-Control: no-store`):**
  - `X-Drop-Authorized`: `true` or `false` (valid non-member pubkeys receive `200 OK` with `X-Drop-Authorized: false`, not `403`).
  - `X-Drop-Channels` *(when member)*: comma-separated authorized channels.
  - `X-Channel-Max-Bytes`, `X-Channel-Ttl-Days` *(if `ttl_days > 0`)*, `X-Slot-Occupied` (`true|false`), and `ETag` (`"<sha256_hex>"`, when slot exists and is owned by `X-Drop-Pubkey`) *(when authorized/configured and `X-Channel` is provided)*.
  - `X-Media-Count`, `X-Media-Bytes`, plus `X-Media-Max-Count` and `X-Media-Max-Bytes` *(when authorized)*.
- **Static Conditional Reads (`GET <read_url>/...`):** Servers emit `ETag: "<sha256_hex>"` and return `304 Not Modified` when `If-None-Match` matches. Default PHP quotas align `card` and `wot` at `524288` bytes (512 KiB).

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

---

## 6. Lock Channel & Blind Collision Registry (`SYNC-006a`)

The Lock Channel provides a blind, write-once, voucher-pinned collision registry (`slot -> LockEntry`) without server-to-server communication. All hash primitives in Section 6 use raw SHA-256 unless explicitly specified as SHA3-256 (for L1 P2PKH ephemeral key hash matching), and all binary JSON encodings use lowercase hexadecimal.

### 6.1 Key Lifecycle, Anti-Amnesia & Delegation (`HUMOCO-LOCK-DELEGATE-V1`)

1. **Local Lock Keypair (`lock_sk`, `lock_pub`):**
   - Generated once using CSPRNG in the server's data directory (`SERVER_META["lock_key"]` in Rust `redb`; `<data_dir>/.lock_key.php` in PHP formatted as `<?php __halt_compiler(); ?>` + 64 raw keypair bytes, protected by `.htaccess` dotfile denial).
   - **NEVER** stored in `config.toml`, `config.php`, or external backups. Loss of `<data_dir>` destroys `lock_sk` permanently so a rolled-back/wiped server can never reuse its old `lock_pub`.
2. **Admin Delegation (`PUT /sync.php?lock_delegate`):**
   - Signed outer envelope: `HUMOCO-DROP-ADMIN-V1\nPUT_LOCK_DELEGATE\n<ts>\n<nonce>\n<sha256_hex(body)>` by `admin_pubkey`.
   - Body JSON:
     ```json
     {
       "admin_pub": "<64-hex>",
       "lock_pub": "<64-hex>",
       "issued_at": 1794916800,
       "sig": "<128-hex>"
     }
     ```
   - `sig` is the Ed25519 signature by `admin_sk` over the UTF-8 message:
     ```text
     HUMOCO-LOCK-DELEGATE-V1\n<admin_pub>\n<lock_pub>\n<issued_at>
     ```
   - Server verifies `admin_pub == configured admin_pubkey`, `lock_pub == local lock_pub`, non-zero `issued_at`, and `sig`. Returns `200 OK` with the persisted delegation object.
3. **Extended `GET /sync.php?info` Payload:**
   Returns existing fields plus `lock`:
   ```json
   {
     "drop_pub": "<64-hex>",
     "read_url": "<resolved_read_url>",
     "register_url": null,
     "channels": ["card", "wot", "backup", "post", "media", "lock"],
     "revocation": null,
     "lock": {
       "lock_pub": "<64-hex>",
       "delegation": { "admin_pub": "<64-hex>", "lock_pub": "<64-hex>", "issued_at": 1794916800, "sig": "<128-hex>" },
       "max_retention_quarter": 8159,
       "max_inodes": 50000,
       "used_inodes": 0,
       "inode_warning": false,
       "pow_base_bits": 8,
       "allow_pow_tickets": false,
       "selftest": { "...": "cached SelftestReport signed by lock_sk" }
     }
   }
   ```
   `inode_warning` becomes `true` when `used_inodes * 100 >= max_inodes * 80`. When `used_inodes >= max_inodes`, `POST ?lock_ticket` rejects new anchor buckets with `507 Insufficient Storage` while writes inside already-created active buckets continue until filesystem capacity.

### 6.2 Selftest (`GET|POST /sync.php?lock_selftest`) & External Probe

1. **`SelftestReport` Schema (signed by `lock_sk`):**
   ```json
   {
     "runtime": "rust",
     "checked_at": 1794916800,
     "lock_pub": "<64-hex>",
     "php_version": null,
     "checks": {
       "ext_sodium": "not_applicable",
       "sha3_256": "pass",
       "atomic_link_eexist": "not_applicable",
       "fsync": "pass",
       "ignore_user_abort": "not_applicable",
       "storage_writable": "pass",
       "inode_budget": "pass",
       "fastcgi_finish_request": "not_applicable"
     },
     "free_inodes": 1000000,
     "all_passed": true,
     "sig": "<128-hex>"
   }
   ```
   Check values are strictly `"pass"`, `"fail"`, or `"not_applicable"`. `all_passed` is `true` iff every applicable check (`"pass"` / `"fail"`) is `"pass"` and `free_inodes` > 0 (or non-zero capacity).
   `sig` signs:
   ```text
   HUMOCO-LOCK-SELFTEST-V1\n<runtime>\n<checked_at>\n<lock_pub>\n<all_passed_0_or_1>\n<sha256_hex(canonical_checks_line)>
   ```
   where `canonical_checks_line` is `<ext_sodium>,<sha3_256>,<atomic_link_eexist>,<fsync>,<ignore_user_abort>,<storage_writable>,<inode_budget>,<fastcgi_finish_request>,<free_inodes>`.
   - `GET /sync.php?lock_selftest`: public, returns cached `SelftestReport` (generated at startup/first access) with `200 OK` JSON.
   - `POST /sync.php?lock_selftest`: admin-signed (`HUMOCO-DROP-ADMIN-V1`), runs all checks live, persists and returns the refreshed `SelftestReport`.
2. **Zero-Write WAF Probe (`POST /sync.php?lock`):**
   Clients evaluating a candidate server send:
   ```json
   {
     "probe": true,
     "client_nonce": "<64-hex>"
   }
   ```
   Server performs **zero** disk/DB mutations and returns `200 OK`:
   ```json
   {
     "probe_ok": true,
     "lock_pub": "<64-hex>",
     "client_nonce": "<64-hex>",
     "server_time": 1794916800,
     "sig": "<128-hex>"
   }
   ```
   where `sig` is the Ed25519 signature by `lock_sk` over:
   ```text
   HUMOCO-LOCK-PROBE-V1\n<lock_pub>\n<client_nonce>\n<server_time>
   ```

### 6.3 Quarter Encoding, Retention Invariant & Canonical Domain Tags

1. **Quarter Encoding (`u16`):**
   - `quarter = year * 4 + (q - 1)` where `year` $\in [2020, 9999]$ and `q` $\in \{1, 2, 3, 4\}$.
   - Formatted directory segment `<YYYY-QN>`: `format!("{year:04}-Q{q}")` (e.g., `2031-Q2` $\leftrightarrow$ `8125`).
   - UTC quarter mapping of Unix timestamp `ts_ms` (`u64`): convert `ts_ms / 1000` to Gregorian UTC `(year, month, day)`, set `q = (month - 1) / 3 + 1`.
   - `retention_covers(deletable_at_ms, retain_until_quarter)`: `true` iff `quarter_of_timestamp_ms(deletable_at_ms)` yields `Some(req)` with `retain_until_quarter >= req`.
   - **Physical Deletion Threshold:** Bucket directory `locks/<YYYY-QN>/<bucket_hex64>/` (or all bucket records in Rust) may ONLY be purged once `now_secs >= quarter_end_exclusive_secs(retain_until_quarter) + 30 * 86_400`, where `quarter_end_exclusive_secs` is the first Unix second of the following quarter (`00:00:00Z`). Deletion is strictly bucket-wise. `DELETE ?account`, storage quota exhaustion, and inode exhaustion **never** purge active lock buckets.

2. **Migration Seed & Anchor Manifest Identity:**
   - Migration key seed per anchor set:
     `mig_seed = HMAC-SHA256(key = master_seed, msg = b"HUMOCO_ANCHOR_MIG_SEED_V1:" || anchor_nonce)`
   - `NominatedBy` canonical bytes: `0x00` for `Creator`; `0x01 || idx: u8` for `Guarantor(idx)`.
   - `ServerEntry` canonical bytes (`encode_server_entry`):
     `(write_url.len() as u16).to_le_bytes() || write_url_utf8 || (read_url.len() as u16).to_le_bytes() || read_url_utf8 || admin_pub (32B) || lock_pub (32B) || nominated_by_bytes`.
   - `AnchorManifest` canonical `anchor_id` (`SHA-256`, always computed over Genesis Rev-1 layout):
     ```text
     SHA-256(
       b"HUMOCO_ANCHOR_MANIFEST_V1\0" (26B)
       || 1u64.to_le_bytes() (8B)
       || [threshold: u8] (1B)
       || [servers.len() as u8] (1B)
       || concat(encode_server_entry(s) for s in servers)
       || (successors.len() as u16).to_le_bytes() (2B)
       || concat(encode_server_entry(s) for s in successors)
       || creator_mig_pub (32B)
       || [guarantor_mig_pubs.len() as u8] (1B)
       || concat(g for g in guarantor_mig_pubs)
       || issued_at_ms.to_le_bytes() (8B)
       || retain_until_quarter.to_le_bytes() (2B)
     )
     ```
     Committee bounds: `1 <= servers.len() <= 5`, `1 <= threshold <= servers.len()`, and `2 * threshold > servers.len()`. `anchor_id` equals the L1 genesis header field `voucher.layer2_anchor`.

3. **Slots, Per-Server File Paths & Cryptographic Domain Separators (all `SHA-256`):**
   - `slot` (canonical across all servers of an anchor set):
     `SHA-256(b"HUMOCO_SYNC_SLOT_V1" || anchor_id (32B) || ds_tag_bytes (32B))`
     where `ds_tag_bytes` is `decode_bs58_32(init.t_id)` at `depth == 0`, and `decode_bs58_32(tx.trap_data.ds_tag)` at `depth >= 1`.
   - `bucket` (`B_S`, per server):
     `SHA-256(b"HUMOCO_SYNC_BUCKET_V1" || anchor_id (32B) || lock_pub (32B))`
   - `file_S` (per-server disk/read filename):
     `SHA-256(b"HUMOCO_SYNC_FILE_V1" || slot (32B) || lock_pub (32B))`
   - `GenesisTicket` signature preimage (Ed25519 by `S.lock_sk`):
     `SHA-256(b"HUMOCO_GENESIS_TICKET_V1" || anchor_id (32B) || retain_until_quarter.to_le_bytes() (2B) || issued_at.to_le_bytes() (8B) || lock_pub (32B))`
   - `depth = 0` root migration authorization (`root_mig_sig`, Ed25519 by `creator_mig_sk`, verified against `manifest.authority.creator_mig_pub`):
     `SHA-256(b"HUMOCO_ROOT_MIG_AUTH_V1" || anchor_id (32B) || root_slot (32B) || genesis_pubkey (32B))`
   - `CausalOutputProof` signature preimage (Ed25519 by `sender_pubkey`, verified against parent's `receiver_pubkey_hash` for `output_branch == 0` or `change_pubkey_hash` for `output_branch == 1`):
     ```text
     SHA-256(
       b"HUMOCO_CAUSAL_OUTPUT_V1" (23B)
       || anchor_id (32B)
       || slot (32B)
       || parent_slot (32B)
       || [output_branch: u8] (1B)
       || depth.to_le_bytes() (4B)
       || child_lock (32B)
       || sender_pubkey (32B)
       || receiver_pubkey_hash (32B)
       || [has_change: u8] (1B)
       || change_pubkey_hash_or_zeros (32B)
     )
     ```
     *(Preimage length: fixed 253 bytes. When `change_pubkey_hash` is `None`, `has_change = 0x00` and the trailing 32 bytes are `[0u8; 32]`.)*
   - **Depth-Progressive Proof-of-Work (`HUMOCO_LOCK_POW_V1`):**
     `pow_hash = SHA-256(b"HUMOCO_LOCK_POW_V1" || slot (32B) || child_lock (32B) || depth.to_le_bytes() (4B) || pow_nonce.to_le_bytes() (8B))`
     Required leading zero bits in `pow_hash`:
     `required_bits = min(24, pow_base_bits + (depth / 16) * 2)` (default `pow_base_bits = 8`).

### 6.4 Pro-Hop AEAD Payload & Canonical `LockEntry` Wire Layout (Fixed `605` Bytes)

1. **Pro-Hop AEAD (`XChaCha20-Poly1305`):**
   - Key: `hop_aead_key = SHA-256(b"HUMOCO_HOP_AEAD_KEY_V1" || anchor_id (32B) || ds_tag_bytes (32B) || sender_pubkey (32B))`
   - Deterministic 24-byte nonce (guarantees identical ciphertext when two honest terminals lock the exact same L1 transaction, without `(key, nonce)` reuse across distinct `child_lock`s):
     `hop_aead_nonce = SHA-256(b"HUMOCO_HOP_AEAD_NONCE_V1" || anchor_id (32B) || ds_tag_bytes (32B) || child_lock (32B) || layer2_signature (64B))[0..24]`
   - AAD (96 bytes): `slot (32B) || child_lock (32B) || sender_pubkey (32B)`
   - Plaintext (fixed **225 bytes**, little-endian integers):
     - `flags`: `u8` (1B; bit `0` = `is_genesis`, bit `1` = `has_privacy_guard`, bits `2..7` = `0`)
     - `l2_voucher_id`: `[u8; 32]` (32B; SHA3-256 raw L2 voucher container ID)
     - `trap_r`: `[u8; 32]` (32B; all-zeros when `is_genesis`)
     - `trap_s`: `[u8; 32]` (32B; all-zeros when `is_genesis`)
     - `privacy_guard_hash`: `[u8; 32]` (32B; all-zeros when `!has_privacy_guard`)
     - `encrypted_timestamp_le`: `[u8; 16]` (16B)
     - `created_at_ms_le`: `[u8; 8]` (8B)
     - `deletable_at_ms_le`: `[u8; 8]` (8B; `0` on spend hops where `tx.deletable_at` is absent, actual ms on genesis)
     - `layer2_signature`: `[u8; 64]` (64B)
   - `encrypted_payload` (fixed **265 bytes**): `hop_aead_nonce (24B) || ciphertext_and_poly1305_tag (225 + 16 = 241B)`.

2. **Canonical `LockEntry` Binary Wire Format (Fixed `605` Bytes):**
   Every lock entry stored on disk and transmitted in batches/responses is encoded as exactly **605 bytes** (`magic = b"HMLK"`, `version = 1`):

   | Offset | Size | Field | Notes |
   |---|---|---|---|
   | `0..4` | 4 | `magic` | ASCII `b"HMLK"` |
   | `4..5` | 1 | `version` | `1u8` |
   | `5..37` | 32 | `slot` | Set-canonical slot ID |
   | `37..69` | 32 | `parent_slot` | `[0u8; 32]` if `depth == 0`, else parent `slot` |
   | `69..70` | 1 | `output_branch` | `0u8` (receiver output; mandatory on `depth == 0`) or `1u8` (split change output) |
   | `70..74` | 4 | `depth` | `u32` LE (`0` for L1 `init`, `parent.depth + 1` for spends) |
   | `74..106` | 32 | `child_lock` | 32B decoded `tx.t_id` |
   | `106..138` | 32 | `sender_pubkey` | 32B `tx.sender_ephemeral_pub` |
   | `138..170` | 32 | `receiver_pubkey_hash` | 32B decoded `tx.receiver_ephemeral_pub_hash` |
   | `170..171` | 1 | `has_change` | `0u8` or `1u8` |
   | `171..203` | 32 | `change_pubkey_hash` | 32B decoded `tx.change_ephemeral_pub_hash` (zeros if `has_change == 0`) |
   | `203..267` | 64 | `causal_sig` | Ed25519 signature by `sender_pubkey` over `CausalOutputProof` |
   | `267..268` | 1 | `has_root_mig_sig` | `1u8` iff `depth == 0`, else `0u8` |
   | `268..332` | 64 | `root_mig_sig` | Ed25519 signature by `creator_mig_sk` (`HUMOCO_ROOT_MIG_AUTH_V1`), zeros if `depth > 0` |
   | `332..597` | 265 | `encrypted_payload` | `nonce (24B) || XChaCha20-Poly1305 ciphertext + tag (241B)` |
   | `597..605` | 8 | `pow_nonce` | `u64` LE solving `HUMOCO_LOCK_POW_V1` |

   - **Canonical Identity Prefix & `entry_hash`:**
     The leading **597 bytes** (`wire_bytes[0..597]`) define the lock identity excluding `pow_nonce`:
     `entry_hash = SHA-256(b"HUMOCO_LOCK_ENTRY_V1" || wire_bytes[0..597])`
   - **Idempotency & Conflict Definition:**
     - Slot exists and stored `wire_bytes[0..597] == incoming.wire_bytes[0..597]` → **idempotent `FirstWrite`**.
     - Slot exists and stored `wire_bytes[0..597] != incoming.wire_bytes[0..597]` → **`ConflictSeen`** (returning the existing 605-byte `LockEntry`).

### 6.5 Genesis-Ticket Endpoint (`POST /sync.php?lock_ticket`)

- **Authorization:** Request carries standard `X-Drop-Pubkey`, `X-Drop-Timestamp`, `X-Drop-Nonce`, `X-Drop-Signature` (`HUMOCO-DROP-REQ-V1\nPOST\nlock_ticket\n\n<ts>\n<nonce>\n<sha256_hex(raw_body)>`) for either:
  1. configured `admin_pubkey`,
  2. an `admin_app` member on channel `lock`, or
  3. an active `registered` user whose account is not downgraded/disabled.
  *(If server config enables `allow_pow_tickets = true`, an unauthenticated request carrying `pow_timestamp` (`|now - pow_timestamp| <= 300`) and `pow_nonce: u64` satisfying `leading_zero_bits(SHA-256(b"HUMOCO_LOCK_TICKET_POW_V1" || anchor_id (32B) || retain_until_quarter_le (2B) || pow_timestamp_le (8B) || pow_nonce_le (8B))) >= lock_ticket_pow_bits` is also accepted; the server records `SHA-256(pow_tuple)` in the 120s replay table to reject PoW replays.)*
- **Request JSON:**
  ```json
  {
    "anchor_id": "<64-hex>",
    "retain_until_quarter": 8125,
    "pow_timestamp": null,
    "pow_nonce": null
  }
  ```
- **Checks:** `retain_until_quarter <= lock_max_retention_quarter` (else `400 Bad Request` / `422`), `used_inodes < lock_max_inodes` (else `507 Insufficient Storage`), bucket not frozen.
- **Response (`200 OK`):**
  ```json
  {
    "ticket": {
      "anchor_id": "<64-hex>",
      "retain_until_quarter": 8125,
      "issued_at": 1794916800,
      "lock_pub": "<64-hex>",
      "sig": "<128-hex>"
    }
  }
  ```

### 6.6 Lock Batch Endpoint (`POST /sync.php?lock`), Receipts & Rollback Self-Freeze

1. **Bucket Head Chain (`write_seq`, `bucket_head`):**
   - Initialized on bucket creation:
     `bucket_head_0 = SHA-256(b"HUMOCO_BUCKET_INIT_V1" || bucket (32B) || retain_until_quarter.to_le_bytes() (2B))`, `write_seq = 0`.
   - Advanced atomically on each **newly** committed slot (`FirstWrite` that created a new slot, never on idempotent retries):
     `write_seq_new = write_seq_old + 1`
     `bucket_head_new = SHA-256(b"HUMOCO_BUCKET_STEP_V1" || bucket_head_old (32B) || write_seq_new.to_le_bytes() (8B) || slot (32B) || entry_hash (32B))`

2. **`LockReceipt` Schema & Signing Digest:**
   ```json
   {
     "kind": "first_write",
     "lock_pub": "<64-hex>",
     "bucket": "<64-hex>",
     "slot": "<64-hex>",
     "child_lock": "<64-hex>",
     "entry_hash": "<64-hex>",
     "retain_until_quarter": 8125,
     "write_seq": 1,
     "bucket_head": "<64-hex>",
     "recipient_nonce": "<64-hex>",
     "sig": "<128-hex>"
   }
   ```
   `kind` is strictly `"first_write"` (`0u8`) or `"conflict_seen"` (`1u8`).
   `sig` signs:
   ```text
   SHA-256(
     b"HUMOCO_LOCK_RECEIPT_V1" (22B)
     || [kind_byte: u8] (1B)
     || lock_pub (32B)
     || bucket (32B)
     || slot (32B)
     || child_lock (32B)
     || entry_hash (32B)
     || retain_until_quarter.to_le_bytes() (2B)
     || write_seq.to_le_bytes() (8B)
     || bucket_head (32B)
     || recipient_nonce (32B)
   )
   ```

3. **Batch Request JSON (`POST /sync.php?lock`):**
   ```json
   {
     "anchor_id": "<64-hex>",
     "bucket": "<64-hex>",
     "recipient_nonce": "<64-hex>",
     "entries": ["<1210-hex (605 bytes)>", "..."],
     "manifest": { "...": "AnchorManifest JSON, required if bucket does not yet exist" },
     "genesis_ticket": { "...": "GenesisTicket JSON, required if bucket does not yet exist" },
     "known_head_receipt": { "...": "Optional LockReceipt JSON from this server" }
   }
   ```
   Bounds: `1 <= entries.len() <= 64`, non-zero `recipient_nonce`, each entry hex decodes to exactly 605 bytes.

4. **Server Validation & Execution Order (Single Atomic `redb` Write Tx / PHP Lock+Link):**
   1. **Rollback Check (before writes):** If `known_head_receipt` is supplied, verify its `lock_pub == S.lock_pub`, `bucket == request.bucket`, `sig` valid over `HUMOCO_LOCK_RECEIPT_V1`. (Unsigned or forged receipts are rejected with `400`/`401` and **never** freeze a bucket.) If the bucket exists and either `known.write_seq > local.write_seq` or (`known.write_seq == local.write_seq && known.bucket_head != local.bucket_head`), OR if `known_head_receipt` carries a valid signature for this bucket when the bucket is missing altogether: **immediately mark the bucket self-frozen (`BUCKET_SELF_FROZEN`)** and return **`409 Conflict`** (`{"error": "bucket_self_frozen", "bucket": "<64-hex>"}`).
   2. **Frozen Check:** If bucket is already frozen (rotation or self-frozen), return `409 Conflict` (`{"error": "bucket_self_frozen" | "epoch_frozen", ...}`).
   3. **Bucket Creation (if absent):** Require valid `manifest` (`manifest.revision == 1`, `manifest.rev1_anchor_id() == anchor_id`, `manifest.servers` contains `S.lock_pub`, `bucket == derive_bucket(anchor_id, S.lock_pub)`), valid `genesis_ticket` (`ticket.anchor_id == anchor_id`, valid `S.lock_sk` signature), `ticket.retain_until_quarter == manifest.retain_until_quarter`, `retain_until_quarter <= lock_max_retention_quarter`, and `used_inodes < lock_max_inodes`. Persist immutable `(anchor_id, retain_until_quarter, creator_mig_pub, bucket_head_0, write_seq = 0)`.
   4. **Sequential Batch Entry Processing (`for idx, entry in entries`):**
      - Parse 605-byte `LockEntry` (`magic == "HMLK"`, `version == 1`, valid `output_branch <= 1`).
      - Verify PoW (`HUMOCO_LOCK_POW_V1`).
      - Verify causal authorization:
        - If `depth == 0`: `parent_slot == [0u8; 32]`, `output_branch == 0`, `has_root_mig_sig == 1`, verify `root_mig_sig` against bucket's `creator_mig_pub` and `causal_sig` against `sender_pubkey`.
        - If `depth >= 1`: `has_root_mig_sig == 0`; load `parent` at `parent_slot` (from persisted bucket OR earlier committed entry `< idx` in this batch); require `depth == parent.depth + 1`; check `SHA3-256(entry.sender_pubkey) == parent.receiver_pubkey_hash` (for `output_branch == 0`) or `Some(SHA3-256(entry.sender_pubkey)) == parent.change_pubkey_hash` (for `output_branch == 1`); verify `causal_sig` against `entry.sender_pubkey`; check 1-child-slot-per-output rule: if `(parent_slot, output_branch)` already maps to `existing_slot != entry.slot`, reject with `409 Conflict` (`output_branch_already_claimed`).
      - Write-Once check on `entry.slot`:
        - **Absent:** Persist `entry`, record `(parent_slot, output_branch) -> entry.slot`, increment `write_seq` and advance `bucket_head` via `HUMOCO_BUCKET_STEP_V1`, sign `FirstWrite` `LockReceipt` (using current `write_seq`, `bucket_head`, `retain_until_quarter`, `recipient_nonce`), append to `results`.
        - **Present with identical `wire_bytes[0..597]`:** Idempotent retry — sign `FirstWrite` `LockReceipt` with current bucket `(write_seq, bucket_head)` and `recipient_nonce`, append to `results`.
        - **Present with differing `wire_bytes[0..597]`:** **Partial-batch conflict!** Commit all earlier entries `< idx`, do **not** write `idx` or any `> idx`, sign `ConflictSeen` `LockReceipt` carrying the **stored existing** `child_lock` and `entry_hash`, include `competing_entry_hex` (the stored 605 bytes), and stop processing the batch (`conflict_index = idx`).

5. **Batch Response JSON (`200 OK`):**
   ```json
   {
     "status": "ok",
     "bucket": "<64-hex>",
     "retain_until_quarter": 8125,
     "receipts": [
       { "kind": "first_write", "...": "LockReceipt JSON" }
     ],
     "conflict": null
   }
   ```
   When a conflict occurred at `idx`:
   ```json
   {
     "status": "conflict",
     "bucket": "<64-hex>",
     "retain_until_quarter": 8125,
     "receipts": [
       { "kind": "first_write", "...": "committed prefix entries 0..idx" }
     ],
     "conflict": {
       "entry_index": 1,
       "slot": "<64-hex>",
       "receipt": { "kind": "conflict_seen", "...": "LockReceipt JSON" },
       "competing_entry": "<1210-hex (605 bytes)>"
     }
   }
   ```
   Note: The prefix `0..idx` returns `"first_write"` receipts in `receipts` (true committed ancestors); the leaf conflict at `idx` returns `conflict.receipt` (`"conflict_seen"`) and `conflict.competing_entry`, and **no** entries `> idx` are executed.

---

## 7. Committee Rotation, Timelock, Veto & Anchor Discovery (`SYNC-007`)

### 7.1 Bucket Freeze States & Revocation

1. **Planned Server Move (Fall A / `PUT ?revoke`):** When a server revocation notice is active (`GET ?revoke` / `revocation.json`), `POST ?lock_ticket`, `POST ?lock`, and `?lock_freeze` / `?lock_import` / `?lock_commit` fail closed with **`410 Gone`** carrying the signed `SyncRevocationNotice` (`"revocation": { ... }`). Existing static `.lock` blobs remain readable unless decommissioned.
2. **Pre-Proposal Freeze (`pre_proposal_frozen`, TTL `1800 s`):** Temporarily halts `POST ?lock` (`409 Conflict` with `"error": "pre_proposal_frozen"` and `"expires_at"`). Automatically reverts to `Active` on any request once `now >= expires_at` (`LÜCKE-04c`), preventing indefinite Freeze-DoS without an accepted proposal.
3. **Epoch Freeze (`409 epoch_frozen`):** After `MigrationCert` commit removes an old server from the active committee, it responds to `POST ?lock` with **`409 Conflict`**:
   ```json
   {
     "error": "epoch_frozen",
     "bucket": "<64-hex>",
     "current_revision": 2,
     "latest_manifest": { "...": "verified AnchorManifest JSON incl. migration_chain" }
   }
   ```

### 7.2 Rotation Endpoints

1. **`GET /sync.php?lock_freeze&anchor_id=<64-hex>`:** Returns current freeze state, `active_manifest`, `last_creator_activity_secs`, `voted_proposal`, and signed `SnapshotExport` (when frozen).
2. **`POST /sync.php?lock_freeze` (`{"action": ...}`):**
   - `pre_freeze`: Freezes active bucket with TTL `lock.pre_freeze_ttl_secs` (`1800 s`) and returns non-permanent `SnapshotExport`.
   - `heartbeat`: Verifies `CreatorHeartbeat` (`HUMOCO_CREATOR_HB_V1`) against `creator_mig_pub` and updates `last_creator_activity_secs`.
   - `propose`: Enforces `voted_proposal[from_rev]` uniqueness (re-returns idempotently if identical digest, `409 Conflict` on differing proposal), authority/standby authorization, `CREATOR_INACTIVITY_TAKEOVER_SECS` (`30 d`) for `ProposalInitiator::Guarantor`, nomination binding (`humoco_proto::verify_nomination_binding`), binds `frozen_at = now` for the `72 h` (`259200 s`) timelock, permanently freezes the bucket, and returns signed `SnapshotExport` (`HUMOCO_FREEZE_SNAP_V1` + `HUMOCO_FREEZE_STATE_V1`).
   - `veto`: Before `timelock` expiry, verifies `MigrationVeto` (`HUMOCO_MIGRATION_VETO_V1`) from an authority distinct from the proposer, blacklists `proposal_hash`, clears `voted_proposal[from_rev]`, and unfreezes the bucket back to `Active`.
3. **`POST /sync.php?lock_import`:** Target server in `proposal.new_servers` verifies `active_manifest.verify_anchor_id(&anchor_id)`, `retain_until_quarter` invariance, `72 h` timelock elapsed against both `proposal.proposed_at` and `>= Q_old` snapshot `frozen_at` timestamps, nomination binding, and executes `humoco_proto::resolve_import_union`:
   - Preserves every single-entry slot and resolves conflicting slots with a verified `QuorumCertificate` across historical committees `1..=from_rev`.
   - Conflicting entries lacking a QC stay `CONFLICT([A, B, ...])` (`LOCK_CONFLICTS` table; future `POST ?lock` returns `ConflictSeen` carrying the competing wire entry, while valid children of surviving branches remain unblocked).
   - Signs and returns `ImportAck` (`HUMOCO_IMPORT_ACK_V1`) committing `imported_state_hash` (`HUMOCO_IMPORT_STATE_V1`).
4. **`POST /sync.php?lock_commit` (`{"action": ...}`):**
   - `sign_commit`: Verifies `import_acks` cover every member of `proposal.new_servers` with identical `imported_state_hash`, then returns this server's `CommitteeSignature` (`HUMOCO_MIGRATION_CERT_V1`).
   - `finalize`: Verifies completed `new_manifest.verify_anchor_id(&anchor_id)`, stores `new_manifest` for `/anchors/<anchor_id>.bin`, transitions active committee members back to `Active` (except `SelfFrozen`), and marks retired servers `EpochFrozen`.
5. **Static Discovery (`GET /anchors/<anchor_id>.bin` and `<read_url>/anchors/<anchor_id>.bin`):** Serves the latest verified `AnchorManifest` JSON with `ETag` and `Cache-Control: no-cache`, purged only during bucket retention GC (`Quartalsende + 30 d`).
