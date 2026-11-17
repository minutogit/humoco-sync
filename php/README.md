# HuMoCo Sync-Dienst (`humoco-sync`)

The **HuMoCo Sync-Dienst** is an ultra-lightweight, zero-dependency PHP script designed for privacy-preserving, asynchronous contact card exchange, Web of Trust synchronization, encrypted off-site backups, and dual-delivery peer-to-peer messaging (payments, co-signing, attestations) in the decentralized **Human Money (HuMoCo)** ecosystem.

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
tools/humoco-sync/
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
- `index.json`: Public catalog of published slots (`[{"id": "<pubkey64>", "channel": "<ch>", "mtime": <int>, "size": <int>, "etag": "<sha256>"}]`)
- `<pubkey64>.<channel>.bin`: Encrypted binary slot files.
- `.lock_key.php`: Server-generated Ed25519 lock signing key (`<?php __halt_compiler(); ?>`), isolated from slot state.
- `locks/<YYYY-QN>/<B_S>/<file_S>.lock`: Immutable 605-byte write-once lock entries served statically with immutable cache headers.
- `anchors/<anchor_id>.bin`: Latest finalized `AnchorManifest` JSON for committee rotation discovery.
- `.locks_meta/`: Internal bucket metadata, rotation state, nonces, and inode counters (denied via `.htaccess`).

---

## 3. Configuration Reference (`config.php`)

```php
<?php
return [
    // 64-hex lowercase Ed25519 VerifyingKey of the sync admin
    'admin_pubkey'         => '0000000000000000000000000000000000000000000000000000000000000000',

    // Deterministic directory name, part of read_url
    'data_dir'             => 'd-0000000000000000',

    // Optional URL where new users can register on public sync services
    'register_url'         => null,

    // Maximum number of member public keys per channel
    'max_members'          => 300,

    // Total storage quota in megabytes across all channels
    'max_total_storage_mb' => 256,

    // Configured channels: max byte sizes and retention TTL
    'channels' => [
        'card'   => ['max_bytes' => 524288,  'ttl_days' => 30],
        'wot'    => ['max_bytes' => 524288,  'ttl_days' => 30],
        'backup' => ['max_bytes' => 5242880, 'ttl_days' => 180],
        'post'   => ['max_bytes' => 524288,  'ttl_days' => 21],
    ],

    // Lock channel settings (SPEC.md Section 6)
    'lock' => [
        'enabled'               => true,
        'max_retention_quarter' => 8159,
        'max_inodes'            => 50000,
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
| `GET sync.php?info` | – | Self-description: returns `drop_pub`, `read_url`, `register_url`, `channels`, and `lock` metadata. |
| `HEAD sync.php` | `X-Drop-Pubkey` *(optional: `X-Channel`, `X-Drop-Prefix`, `X-Media-Id`)* | Capability check: returns `200 OK` with `X-Drop-Authorized: true\|false`, `X-Drop-Channels`, `X-Channel-Max-Bytes`, `X-Channel-Ttl-Days`, `X-Slot-Occupied`, `ETag`, and `X-Media-*` headers (`400` on invalid header syntax). |
| `PUT sync.php` | `X-Drop-Pubkey`, `X-Channel`, `X-Drop-Timestamp`, `X-Drop-Nonce`, `X-Drop-Signature`, optional `If-Match` | Raw binary slot upload. Enforces content length, replay nonce, `If-Match` concurrency, and global quota. |
| `DELETE sync.php` | `X-Drop-Pubkey`, `X-Channel`, `X-Drop-Timestamp`, `X-Drop-Nonce`, `X-Drop-Signature` | Member slot deletion. |
| `PUT sync.php?members&channel=<name>` | `X-Drop-Pubkey`, `X-Drop-Timestamp`, `X-Drop-Nonce`, `X-Drop-Signature`, Body: `{"pubkeys": [...]}` | Admin updates member list (`card`, `wot`, `backup`, `post`, `media`, `lock`). |
| `GET sync.php?status` | `X-Drop-Pubkey`, `X-Drop-Timestamp`, `X-Drop-Nonce`, `X-Drop-Signature` | Admin dashboard status (used bytes, quotas, slot counts). |
| `GET/POST sync.php?lock_selftest` | *(POST requires Admin headers)* | Runs / returns signed PHP 8.1+ lock readiness report (`ext-sodium`, `sha3-256`, `link()`, `fsync()`, inode budget). |
| `PUT sync.php?lock_delegate` | Admin headers + `HUMOCO-LOCK-DELEGATE-V1` JSON | Persists admin delegation binding `S.lock_pub` to `admin_pubkey`. |
| `POST sync.php?lock_ticket` | Member `lock` headers or PoW | Issues signed offline `GenesisTicket` for `anchor_id`. |
| `POST sync.php?lock` | *(Unauthenticated PoS / WAF probe)* | Blind write-once lock batch (`FirstWrite` / `ConflictSeen` receipt, or zero-write WAF probe). |
| `GET/POST sync.php?lock_freeze` | – | 3-phase committee rotation Phase 1 (`pre_freeze`, `propose`, `veto`, `heartbeat`, snapshot export). |
| `POST sync.php?lock_import` | – | Rotation Phase 2 on new committee servers (timelock + union import -> `ImportAck`). |
| `POST sync.php?lock_commit` | – | Rotation Phase 3 (`sign_commit` + `finalize` -> `/anchors/<anchor_id>.bin`). |
