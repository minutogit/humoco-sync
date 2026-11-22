# HuMoCo Sync Service (`humoco-sync/php`)

The **HuMoCo PHP Sync Service** is an ultra-lightweight, zero-dependency PHP script for privacy-preserving, zero-knowledge synchronization (backups, marketplace listings/media, contact cards, Web of Trust sync, async dual-delivery payments) and the **launch Blind Collision Lock Channel** (`LockCommittee`) in the decentralized **Human Money (HuMoCo)** ecosystem. It runs on ordinary PHP $\ge 8.1$ shared web hosting with zero database or daemon setup so anyone with simple webspace can contribute and prevent centralization.

---

## 1. Architecture & Security Invariants

* **Zero Dependencies:** Pure PHP (>= 8.1 with core `ext-sodium` and `hash('sha3-256')`, required for durable `fsync()`). No Composer, no SQL or SQLite database, no background daemons, and no external extensions. PHP 7.4 and 8.0 are unsupported (EOL).
* **Zero Plaintext Knowledge:** The server operator, hoster, and network observers see only encrypted binary blobs (`SlotBlob` / `PostBoxEntry` / `.hmcbackup`). The server cannot decrypt contact cards, marketplace listings, trust lists, or messages.
* **Strict 64-Hex Ed25519 Request Signatures:** Every mutating request is signed with detached Ed25519 signatures validated via `sodium_crypto_sign_verify_detached`:
  - **Private Sync Services:** Members sign with a stealth key derived via ECDH + `HUMOCO_DROP_STEALTH_SEED_V1` ($P$).
  - **Public Sync Services:** Users sign with a deterministic registration key ($R$) derived from mnemonic + provider canonical URL.
* **Direct Static Reads (Zero PHP overhead on reads):** Clients poll `<read_url>/index.json` and `<read_url>/<pubkey64>.<channel>.bin` directly via static web server delivery (Apache / Nginx / Caddy), completely bypassing PHP execution.
* **Fixed 1-Inode IP Rate Limiter (`ratelimit.bin.php`):** A single 65,564-byte file with 4,096 buckets (16 bytes each) handles IP lockout under `flock`. It never allocates extra files, preventing inode exhaustion on shared web hosting.
* **Proxy-Safe Member Exemption:** Authenticated Ed25519-signed requests bypass IP failure throttling (avoiding Cloudflare/Carrier-NAT lockout) and are rate-limited per pubkey via a dedicated token bucket.

---

## 2. Directory Structure

```
php/
├── sync.php             # Core API endpoint
├── lock_handler.php     # Blind Lock channel handler (Write-Once link()+fsync(), ?lock_ticket, ?lock, GC)
├── lock_rotation.php    # Lazy-loaded 3-phase committee rotation (?lock_freeze, ?lock_import, ?lock_commit)
├── config.php           # Server configuration (admin pubkey, storage limits, channels, lock budget)
├── .htaccess            # Hardening: directory indexing off, internal files & lock handlers protected
├── .state.php           # Internal server state (salt, admin pubkey, nonces)
├── ratelimit.bin.php    # Fixed 64 KiB 1-inode rate limiter storage
├── members.<ch>.php     # Authorized member pubkey lists per channel (incl. members.lock.php)
├── robots.txt           # Crawling prevention (User-agent: * / Disallow: /)
├── index.html           # Empty blank landing page
├── README.md            # Installation and documentation
└── start-sync-server.sh # Local dev server runner (PHP >= 8.1)
```

`<data_dir>` contains:
- `index.json`: Public catalog of published slots (`[{"id": "<pubkey64>", "channel": "<ch>", "mtime": <int>, "size": <int>, "etag": "<sha256>"}]`).
- `revocation.json`: Optional signed `SyncRevocationNotice` served statically on planned server moves.
- `<pubkey64>.<channel>.bin`: Encrypted binary slot files.
- `<blob_id>.media.bin`: Encrypted Priority-3 media blobs (excluded from `index.json`).
- `.lock_key.php`: Server-generated Ed25519 lock signing key (`<?php __halt_compiler(); ?>`), isolated from slot state.
- `locks/<YYYY-QN>/<B_S>/<file_S>.lock`: Immutable 605-byte write-once lock entries served statically with immutable cache headers.
- `anchors/<anchor_id>.bin`: Latest finalized `AnchorManifest` JSON for committee rotation discovery.
- `.locks_meta/`: Internal bucket metadata, rotation state, nonces, and inode counters (denied via `.htaccess`).

---

## 3. Configuration Reference (`config.php`)

```php
<?php // config.php – adjust to your needs
return [
    'admin_pubkey'         => '0000000000000000000000000000000000000000000000000000000000000000', // 64-hex Ed25519 VerifyingKey (D_ed)
    'data_dir'             => 'd-0000000000000000', // deterministic directory name, part of read_url
    'register_url'         => null,                 // optional registration URL for public sync services
    'max_members'          => 300,                  // max pubkeys per channel list
    'max_total_storage_mb' => 2048,                 // total quota across all channels (soft warning at 80%, hard 507 at 100%)
    'max_user_storage_mb'  => 25,                   // total quota per member across all channels (min 10 MB)

    // Set to true (or export HUMOCO_DISABLE_RATE_LIMIT=1 in env) to disable the IP rate limiter
    // for local multi-wallet development and testing. Keep false in production.
    'disable_rate_limit'   => false,

    'channels' => [
        'card'   => ['max_bytes' => 524288,  'ttl_days' => 30],
        'wot'    => ['max_bytes' => 524288,  'ttl_days' => 30],
        'backup' => ['max_bytes' => 5242880, 'ttl_days' => 180],
        'post'   => ['max_bytes' => 524288,  'ttl_days' => 21],
        'media'  => [
            'max_bytes'      => 524288,  // max 512 KB per encrypted image blob
            'max_user_count' => 12,      // max 12 images per member
            'max_user_bytes' => 6291456, // max 6 MB total media per member
            'max_channel_mb' => 512,     // max 512 MB across all media blobs
            'ttl_days'       => 90,      // 90 days retention
        ],
    ],

    // Lock channel settings (SPEC.md Section 6)
    'lock' => [
        'enabled'               => true,
        'max_retention_quarter' => 8159,  // 2039-Q4
        'max_inodes'            => 50000, // 80% soft warning in ?info, hard 507 on new tickets at 100%
        'max_buckets'           => 50000, // hard cap on tracked rotation/lock buckets
        'pow_base_bits'         => 8,
        'allow_pow_tickets'     => false,
        'ticket_pow_bits'       => 16,
    ],
];
```

---

## 4. API Protocol & Endpoints

All mutating requests must use custom HTTP headers:

| Method & Route | Required Headers | Description |
|---|---|---|
| `GET sync.php?info` | – | Self-description: returns `drop_pub`, `read_url`, `register_url`, `channels`, `revocation`, and `lock` metadata. |
| `HEAD sync.php` | `X-Drop-Pubkey` *(optional: `X-Channel`, `X-Drop-Prefix`, `X-Media-Id`)* | Capability check: returns `200 OK` with `X-Drop-Authorized: true\|false`, `X-Drop-Channels`, `X-Channel-Max-Bytes`, `X-Channel-Ttl-Days`, `X-Slot-Occupied`, `ETag`, and `X-Media-*` headers (`400` on invalid header syntax). |
| `PUT sync.php` | `X-Drop-Pubkey`, `X-Channel`, `X-Drop-Timestamp`, `X-Drop-Nonce`, `X-Drop-Signature`, optional `If-Match`, optional `X-Media-Id` | Raw binary slot or media upload. Enforces content length, replay nonce, `If-Match` concurrency, and quota/LRU eviction. |
| `DELETE sync.php` | `X-Drop-Pubkey`, `X-Channel`, `X-Drop-Timestamp`, `X-Drop-Nonce`, `X-Drop-Signature` | Member slot or media deletion (`X-Media-Id`). |
| `DELETE sync.php?account` | `X-Drop-Pubkey`, `X-Drop-Timestamp`, `X-Drop-Nonce`, `X-Drop-Signature` | Wipes caller slots, media blobs, and memberships (Lock Channel entries stay immune until `retain_until_quarter + 30d`). |
| `PUT sync.php?members&channel=<name>` | `X-Drop-Pubkey`, `X-Drop-Timestamp`, `X-Drop-Nonce`, `X-Drop-Signature`, Body: `{"pubkeys": [...]}` | Admin updates member list (`card`, `wot`, `backup`, `post`, `media`, `lock`). |
| `PUT sync.php?admin_config` | `X-Drop-Pubkey`, `X-Drop-Timestamp`, `X-Drop-Nonce`, `X-Drop-Signature`, Body: `{"max_total_storage_mb": ..., "max_members": ..., "max_user_storage_mb": ...}` | Admin updates storage and member limits live and returns updated status JSON. |
| `PUT sync.php?revoke` | `X-Drop-Pubkey`, `X-Drop-Timestamp`, `X-Drop-Nonce`, `X-Drop-Signature`, Body: signed `SyncRevocationNotice` or clear JSON | Admin publishes or clears `<read_url>/revocation.json` (`410 Gone` enforcement on locks). |
| `GET sync.php?status` | `X-Drop-Pubkey`, `X-Drop-Timestamp`, `X-Drop-Nonce`, `X-Drop-Signature` | Admin dashboard status (used bytes, quotas, slot counts). |
| `GET/POST sync.php?lock_selftest` | *(POST requires Admin headers)* | Runs / returns signed PHP 8.1+ lock readiness report (`ext-sodium`, `sha3-256`, `link()`, `fsync()`, inode budget). |
| `PUT sync.php?lock_delegate` | Admin headers + `HUMOCO-LOCK-DELEGATE-V1` JSON | Persists admin delegation binding `S.lock_pub` to `admin_pubkey`. |
| `POST sync.php?lock_ticket` | Member `lock` headers or PoW | Issues signed offline `GenesisTicket` for `anchor_id`. |
| `POST sync.php?lock` | *(Unauthenticated PoS / WAF probe)* | Blind write-once lock batch (`FirstWrite` / `ConflictSeen` receipt, or zero-write WAF probe). |
| `GET/POST sync.php?lock_freeze` | – | 3-phase committee rotation Phase 1 (`pre_freeze`, `propose`, `veto`, `heartbeat`, snapshot export). |
| `POST sync.php?lock_import` | – | Rotation Phase 2 on new committee servers (timelock + union import -> `ImportAck`). |
| `POST sync.php?lock_commit` | – | Rotation Phase 3 (`sign_commit` + `finalize` -> `/anchors/<anchor_id>.bin`). |
