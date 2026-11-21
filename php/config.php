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

    // Lock channel settings (SPEC.md Section 6, Concept Sections 5 & 6)
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
