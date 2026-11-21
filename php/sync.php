<?php
/**
 * HuMoCo Sync-Dienst – Hardened Privacy-Preserving HTTP Sync v1.2.0 (Multi-Channel + Lock Channel)
 *
 * Requirements: PHP >= 8.1 with ext-sodium and hash('sha3-256'), zero database, zero Composer.
 * Strictly enforces 64-hex lowercase Ed25519 signatures, 1-inode rate limiting,
 * atomic index rebuilds, and isolated Write-Once Lock Channel routing.
 */

if (PHP_VERSION_ID < 80100) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "PHP >= 8.1 is required.\n";
    exit;
}
if (!function_exists('sodium_crypto_sign_verify_detached') || !in_array('sha3-256', hash_algos(), true)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "PHP ext-sodium and sha3-256 hash support are required.\n";
    exit;
}

// Load configuration
$configFile = __DIR__ . '/config.php';
if (PHP_SAPI === 'cli-server') {
    $envConfig = getenv('HUMOCO_SYNC_CONFIG');
    if ($envConfig !== false && $envConfig !== '') {
        $configFile = $envConfig;
    }
}

if (!is_file($configFile)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Configuration file missing.\n";
    exit;
}

$config = require $configFile;
if (!is_array($config)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Invalid configuration format.\n";
    exit;
}

$disableRateLimit = !empty($config['disable_rate_limit'])
    || getenv('HUMOCO_DISABLE_RATE_LIMIT') === '1'
    || (isset($_SERVER['HUMOCO_DISABLE_RATE_LIMIT']) && $_SERVER['HUMOCO_DISABLE_RATE_LIMIT'] === '1');

$channels = isset($config['channels']) && is_array($config['channels']) ? $config['channels'] : [];
$maxTotalStorageMb = isset($config['max_total_storage_mb']) ? (int)$config['max_total_storage_mb'] : 2048;
$maxTotalBytes = isset($config['max_total_bytes']) ? (int)$config['max_total_bytes'] : ($maxTotalStorageMb * 1024 * 1024);
$softLimitBytes = (int)floor($maxTotalBytes * 0.8);

// Resolve data directory
$dataDirSetting = isset($config['data_dir']) && is_string($config['data_dir']) ? $config['data_dir'] : 'data';
$trimmedDataDir = trim($dataDirSetting, "/\\");
if ($dataDirSetting === ''
    || strpos($dataDirSetting, "\0") !== false
    || strpos($dataDirSetting, '..') !== false
    || $trimmedDataDir === ''
    || $trimmedDataDir === '.'
    || $trimmedDataDir === 'anchors'
    || $trimmedDataDir === 'sync'
) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Invalid data directory path.\n";
    exit;
}

if ($dataDirSetting !== '' && ($dataDirSetting[0] === '/' || $dataDirSetting[0] === '\\' || (strlen($dataDirSetting) > 2 && $dataDirSetting[1] === ':'))) {
    $dataDir = $dataDirSetting;
} else {
    $dataDir = dirname($configFile) . DIRECTORY_SEPARATOR . $dataDirSetting;
}

if (!is_dir($dataDir)) {
    if (!mkdir($dataDir, 0755, true) && !is_dir($dataDir)) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Failed to create data directory.\n";
        exit;
    }
}

function sync_atomic_write(string $path, string $bytes): bool {
    $dir = dirname($path);
    if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) {
        return false;
    }
    $tmp = $dir . DIRECTORY_SEPARATOR . '.tmp.' . basename($path) . '.' . getmypid() . '.' . bin2hex(random_bytes(4));
    $fp = @fopen($tmp, 'xb');
    if ($fp === false) {
        return false;
    }
    $written = fwrite($fp, $bytes);
    $ok = ($written === strlen($bytes)) && fflush($fp) && fsync($fp);
    fclose($fp);
    if (!$ok || !@rename($tmp, $path)) {
        @unlink($tmp);
        return false;
    }
    return true;
}

$dataHtaccess = $dataDir . DIRECTORY_SEPARATOR . '.htaccess';
if (!file_exists($dataHtaccess)) {
    $htaccessContent = "# Disable PHP execution and script handlers in data directory\n"
        . "Options -Indexes\n\n"
        . "<IfModule mod_php7.c>\n"
        . "    php_flag engine off\n"
        . "</IfModule>\n"
        . "<IfModule mod_php.c>\n"
        . "    php_flag engine off\n"
        . "</IfModule>\n\n"
        . "<IfModule mod_mime.c>\n"
        . "    RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .phps .cgi .pl .py\n"
        . "    RemoveType .php .phtml .php3 .php4 .php5 .php7 .phps .cgi .pl .py\n"
        . "    AddType application/octet-stream .bin .lock\n"
        . "    AddType application/json .json\n"
        . "</IfModule>\n\n"
        . "# Deny direct access to lock and temporary files\n"
        . "<FilesMatch \"^(\\..*|.*\\.tmp.*|.*\\.lockdir.*)\">\n"
        . "    <IfModule mod_authz_core.c>\n"
        . "        Require all denied\n"
        . "    </IfModule>\n"
        . "<IfModule !mod_authz_core.c>\n"
        . "        Order allow,deny\n"
        . "        Deny from all\n"
        . "    </IfModule>\n"
        . "</FilesMatch>\n";
    @sync_atomic_write($dataHtaccess, $htaccessContent);
}

// Dispatch Lock Channel & static cli-server routes strictly BEFORE global .lock acquisition (§6.9)
require_once __DIR__ . '/lock_handler.php';
lock_maybe_handle_request($config, $configFile, $dataDir, $dataDirSetting, $disableRateLimit);

// Global flock on .lock in script directory across all standard channel requests
$lockFile = dirname($configFile) . DIRECTORY_SEPARATOR . '.lock';
$lockFp = fopen($lockFile, 'c+');
if ($lockFp === false) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Failed to open lock file.\n";
    exit;
}
if (!flock($lockFp, LOCK_EX)) {
    fclose($lockFp);
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Failed to acquire lock.\n";
    exit;
}

// Response helper
function sync_respond($statusCode, $lockFp, $message = null, array $headers = []) {
    if ($lockFp !== null && is_resource($lockFp)) {
        flock($lockFp, LOCK_UN);
        fclose($lockFp);
    }
    http_response_code($statusCode);
    foreach ($headers as $k => $v) {
        header($k . ': ' . $v);
    }
    if ($message !== null && $message !== '') {
        if (!isset($headers['Content-Type'])) {
            header('Content-Type: text/plain; charset=utf-8');
        }
        echo $message . "\n";
    }
    exit;
}

// Verify Ed25519 detached signature
function verify_ed25519_detached($sigHex, $message, $pubkeyHex) {
    if (strlen($sigHex) !== 128 || !ctype_xdigit($sigHex)) {
        return false;
    }
    if (strlen($pubkeyHex) !== 64 || !ctype_xdigit($pubkeyHex)) {
        return false;
    }
    $sigBytes = hex2bin(strtolower($sigHex));
    $pkBytes = hex2bin(strtolower($pubkeyHex));
    if ($sigBytes === false || $pkBytes === false) {
        return false;
    }
    try {
        return sodium_crypto_sign_verify_detached($sigBytes, $message, $pkBytes);
    } catch (\Throwable $e) {
        return false;
    }
}

function sync_is_int_timestamp($raw): bool {
    return is_string($raw) && preg_match('/\A-?[0-9]{1,19}\z/', $raw) === 1;
}

function sync_read_bounded_body(int $maxBytes, $lockFp, array $commonHeaders, string $tooLargeMsg = 'Payload Too Large'): string {
    if (isset($_SERVER['CONTENT_LENGTH'])) {
        $clRaw = trim((string)$_SERVER['CONTENT_LENGTH']);
        if (preg_match('/\A[0-9]+\z/', $clRaw) === 1 && (int)$clRaw > $maxBytes) {
            sync_respond(413, $lockFp, $tooLargeMsg, $commonHeaders);
        }
    }
    $inputFp = fopen('php://input', 'rb');
    if ($inputFp === false) {
        sync_respond(500, $lockFp, 'Internal Server Error', $commonHeaders);
    }
    $rawBody = '';
    $bytesRead = 0;
    while (!feof($inputFp)) {
        $chunk = fread($inputFp, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $bytesRead += strlen($chunk);
        if ($bytesRead > $maxBytes) {
            fclose($inputFp);
            sync_respond(413, $lockFp, $tooLargeMsg, $commonHeaders);
        }
        $rawBody .= $chunk;
    }
    fclose($inputFp);
    return $rawBody;
}

function sync_normalize_etag_token(string $raw): string {
    $t = trim($raw);
    if (str_starts_with($t, 'W/')) {
        $t = substr($t, 2);
    }
    return trim($t, "\" \t\n\r\0\x0B");
}

function sync_check_put_preconditions(?string $currentEtag, $lockFp, string $stateFile, array &$state, array $commonHeaders): void {
    if (isset($_SERVER['HTTP_IF_NONE_MATCH'])) {
        $rawInm = (string)$_SERVER['HTTP_IF_NONE_MATCH'];
        $matched = false;
        foreach (explode(',', $rawInm) as $part) {
            $cand = trim($part);
            if ($cand === '') {
                continue;
            }
            if ($cand === '*') {
                $matched = ($currentEtag !== null);
                break;
            }
            $norm = sync_normalize_etag_token($cand);
            if ($currentEtag !== null && $norm !== '' && hash_equals($currentEtag, $norm)) {
                $matched = true;
                break;
            }
        }
        if ($matched) {
            sync_save_and_respond(412, $lockFp, $stateFile, $state, 'Precondition Failed', array_merge($commonHeaders, [
                'ETag' => '"' . $currentEtag . '"',
            ]));
        }
    }

    if (isset($_SERVER['HTTP_IF_MATCH'])) {
        $ifMatch = sync_normalize_etag_token((string)$_SERVER['HTTP_IF_MATCH']);
        if ($ifMatch === 'none' || $ifMatch === '') {
            if ($currentEtag !== null) {
                sync_save_and_respond(412, $lockFp, $stateFile, $state, 'Precondition Failed', array_merge($commonHeaders, [
                    'ETag' => '"' . $currentEtag . '"',
                ]));
            }
        } else {
            if ($currentEtag === null || !hash_equals($currentEtag, $ifMatch)) {
                $etagHeaderVal = ($currentEtag !== null) ? '"' . $currentEtag . '"' : '""';
                sync_save_and_respond(412, $lockFp, $stateFile, $state, 'Precondition Failed', array_merge($commonHeaders, [
                    'ETag' => $etagHeaderVal,
                ]));
            }
        }
    }
}

function contains_control_chars($str) {
    return preg_match('/[\x00-\x1f\x7f]/', (string)$str) === 1;
}

function is_sync_url_valid($url) {
    if (!is_string($url) || $url === '' || strlen($url) > 2048) {
        return false;
    }
    if (preg_match('/[\x00-\x20\x7f]/', $url) === 1) {
        return false;
    }
    if (str_starts_with($url, 'https://')) {
        $host = parse_url($url, PHP_URL_HOST);
        return is_string($host) && $host !== '';
    }
    return preg_match('/\Ahttp:\/\/(?:127\.0\.0\.1|localhost|\[::1\])(?::[0-9]{1,5})?(?:\/|\z)/i', $url) === 1;
}

function build_revocation_canonical_message(array $notice) {
    $dropPub = isset($notice['drop_pub']) ? strtolower((string)$notice['drop_pub']) : '';
    $issuedAt = isset($notice['issued_at']) ? (string)(int)$notice['issued_at'] : '0';
    $effectiveAt = isset($notice['effective_at']) ? (string)(int)$notice['effective_at'] : '0';
    $rep = isset($notice['replacement']) && is_array($notice['replacement']) ? $notice['replacement'] : null;
    $repWrite = ($rep !== null && isset($rep['write_url'])) ? (string)$rep['write_url'] : '';
    $repRead = ($rep !== null && isset($rep['read_url'])) ? (string)$rep['read_url'] : '';
    $repPub = ($rep !== null && isset($rep['drop_pub'])) ? strtolower((string)$rep['drop_pub']) : '';
    $reason = isset($notice['reason']) && $notice['reason'] !== null ? (string)$notice['reason'] : '';

    return "HUMOCO-DROP-REVOKE-V1\n"
        . $dropPub . "\n"
        . $issuedAt . "\n"
        . $effectiveAt . "\n"
        . $repWrite . "\n"
        . $repRead . "\n"
        . $repPub . "\n"
        . $reason;
}

function respond_if_revoked(array $state, $now, $lockFp, array $commonHeaders, $isHead = false) {
    if (!isset($state['revocation']) || !is_array($state['revocation'])) {
        return;
    }
    $body = $isHead ? null : json_encode([
        'error'      => 'This sync service has been revoked',
        'revocation' => $state['revocation'],
    ], JSON_UNESCAPED_SLASHES);
    $headers = $isHead
        ? $commonHeaders
        : array_merge($commonHeaders, ['Content-Type' => 'application/json; charset=utf-8']);
    sync_respond(410, $lockFp, $body, $headers);
}

function resolve_own_sync_urls(array $config, $dataDirSetting) {
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
        || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https');
    $scheme = $isHttps ? 'https' : 'http';
    $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost');
    $scriptName = isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '/sync.php';
    $scriptDir = rtrim(dirname($scriptName), '/\\');
    $writeUrl = $scheme . '://' . $host . $scriptName;
    if (isset($config['read_url']) && is_string($config['read_url']) && $config['read_url'] !== '') {
        $readUrl = $config['read_url'];
    } else {
        $readUrl = $scheme . '://' . $host . ($scriptDir !== '' ? $scriptDir : '') . '/' . $dataDirSetting;
    }
    return [$writeUrl, $readUrl];
}

// Extract and validate optional sub-mailbox prefix from X-Drop-Prefix header
function extract_and_validate_prefix() {
    if (!isset($_SERVER['HTTP_X_DROP_PREFIX'])) {
        return '';
    }
    $prefix = trim((string)$_SERVER['HTTP_X_DROP_PREFIX']);
    if ($prefix === '') {
        return '';
    }
    if (strlen($prefix) > 63) {
        return false;
    }
    if (strpos($prefix, '--') !== false) {
        return false;
    }
    if (!preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $prefix)) {
        return false;
    }
    return $prefix;
}

// Build slot filename for standard channel
function build_slot_filename($pubkey, $prefix, $channel) {
    return $pubkey . ($prefix !== '' ? '_' . $prefix : '') . '.' . $channel . '.bin';
}

// Parse slot filename into id, prefix, and channel
function parse_slot_filename($basename) {
    if (!preg_match('/^([0-9a-f]{64})(?:_([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))?\.([a-z0-9_]{1,32})\.bin$/', $basename, $matches)) {
        return null;
    }
    $prefix = isset($matches[2]) ? $matches[2] : '';
    if ($prefix !== '' && strpos($prefix, '--') !== false) {
        return null;
    }
    return [
        'id'      => $matches[1],
        'prefix'  => $prefix,
        'channel' => $matches[3],
    ];
}

// Load and manage .state.php
$stateFile = dirname($configFile) . DIRECTORY_SEPARATOR . '.state.php';
$now = time();
$state = [];
$stateNeedsSave = false;

if (file_exists($stateFile)) {
    $rawState = file_get_contents($stateFile);
    if ($rawState !== false && strlen($rawState) > 28) {
        $jsonState = substr($rawState, 28);
        $state = json_decode($jsonState, true);
        if (!is_array($state)) {
            $state = [];
            $stateNeedsSave = true;
        }
    } else {
        $stateNeedsSave = true;
    }
} else {
    $stateNeedsSave = true;
}

if (!isset($state['pepper']) || !is_string($state['pepper']) || strlen($state['pepper']) !== 32) {
    $state['pepper'] = bin2hex(random_bytes(16));
    $stateNeedsSave = true;
}
$cfgAdminPub = (isset($config['admin_pubkey']) && is_string($config['admin_pubkey'])) ? strtolower(trim($config['admin_pubkey'])) : '';
if (preg_match('/\A[0-9a-f]{64}\z/', $cfgAdminPub) === 1) {
    if (!isset($state['admin_pubkey']) || $state['admin_pubkey'] !== $cfgAdminPub) {
        $state['admin_pubkey'] = $cfgAdminPub;
        $stateNeedsSave = true;
    }
} elseif (!isset($state['admin_pubkey']) || !is_string($state['admin_pubkey']) || preg_match('/\A[0-9a-f]{64}\z/', $state['admin_pubkey']) !== 1) {
    $state['admin_pubkey'] = str_repeat('0', 64);
    $stateNeedsSave = true;
}
if (!isset($state['nonces']) || !is_array($state['nonces'])) {
    $state['nonces'] = [];
    $stateNeedsSave = true;
}
if (!isset($state['member_buckets']) || !is_array($state['member_buckets'])) {
    $state['member_buckets'] = [];
    $stateNeedsSave = true;
}
if (!isset($state['media_blobs']) || !is_array($state['media_blobs'])) {
    $state['media_blobs'] = [];
    $stateNeedsSave = true;
}
if (!isset($state['used_bytes'])) {
    $totalUsed = 0;
    $existingBins = glob($dataDir . DIRECTORY_SEPARATOR . '*.*.bin');
    if ($existingBins !== false) {
        foreach ($existingBins as $bf) {
            $sz = filesize($bf);
            if ($sz !== false) {
                $totalUsed += $sz;
            }
        }
    }
    $state['used_bytes'] = $totalUsed;
    $stateNeedsSave = true;
}

$maxMembers = isset($config['max_members']) ? (int)$config['max_members'] : 300;
$maxUserStorageMb = isset($config['max_user_storage_mb']) ? (int)$config['max_user_storage_mb'] : 25;
if (isset($state['admin_config']) && is_array($state['admin_config'])) {
    if (isset($state['admin_config']['max_total_storage_mb'])) {
        $maxTotalStorageMb = (int)$state['admin_config']['max_total_storage_mb'];
        $maxTotalBytes = $maxTotalStorageMb * 1024 * 1024;
        $softLimitBytes = (int)floor($maxTotalBytes * 0.8);
    }
    if (isset($state['admin_config']['max_members'])) {
        $maxMembers = (int)$state['admin_config']['max_members'];
    }
    if (isset($state['admin_config']['max_user_storage_mb'])) {
        $maxUserStorageMb = (int)$state['admin_config']['max_user_storage_mb'];
    }
}
$maxUserBytesLimit = $maxUserStorageMb * 1024 * 1024;


// Prune nonces older than 120 seconds
foreach ($state['nonces'] as $n => $ts) {
    if ($ts < $now - 120) {
        unset($state['nonces'][$n]);
    }
}

// Prune member buckets idle for over 3600 seconds
foreach ($state['member_buckets'] as $pk => $b) {
    if (isset($b[0]) && $b[0] < $now - 3600) {
        unset($state['member_buckets'][$pk]);
    }
}

function save_state($stateFile, array $state): bool {
    $encoded = json_encode($state, JSON_UNESCAPED_SLASHES);
    if ($encoded === false) {
        return false;
    }
    return sync_atomic_write($stateFile, "<?php __halt_compiler(); ?>\n" . $encoded);
}

function sync_save_and_respond($statusCode, $lockFp, $stateFile, array $state, $message = null, array $headers = []): never {
    if (!save_state($stateFile, $state)) {
        sync_respond(500, $lockFp, 'Internal Server Error: Failed to persist state', []);
    }
    sync_respond($statusCode, $lockFp, $message, $headers);
}

function sync_check_member_ratelimit($disableRateLimit, $lockFp, $stateFile, array &$state, $pubkey, $now, array $commonHeaders): void {
    if (!empty($disableRateLimit)) {
        return;
    }
    if (!isset($state['member_buckets'][$pubkey])) {
        $state['member_buckets'][$pubkey] = [$now, 15.0];
    }
    $mb = &$state['member_buckets'][$pubkey];
    $elapsedMb = max(0, $now - $mb[0]);
    $mb[1] = min(15.0, $mb[1] + $elapsedMb * 0.25);
    $mb[0] = $now;
    if ($mb[1] < 1.0) {
        save_state($stateFile, $state);
        sync_respond(429, $lockFp, 'Too Many Requests', array_merge($commonHeaders, ['Retry-After' => '4']));
    }
    $mb[1] -= 1.0;
}

if ($stateNeedsSave) {
    save_state($stateFile, $state);
}

// 1-Inode IP rate limiter file
$rlFp = null;
$ipBucketIdx = 0;
$bucket = ['ipTag' => 0, 'lastTs' => $now, 'tokens' => 30.0, 'failCount' => 0];

if (!$disableRateLimit) {
    $rlFile = dirname($configFile) . DIRECTORY_SEPARATOR . 'ratelimit.bin.php';
    $rlFp = fopen($rlFile, 'c+b');
    if ($rlFp === false) {
        sync_respond(500, $lockFp, 'Internal Server Error: Rate limit store failure');
    }
    $rlSize = fstat($rlFp)['size'];
    if ($rlSize < 65564) {
        fseek($rlFp, 0);
        fwrite($rlFp, "<?php __halt_compiler(); ?>\n" . str_repeat("\0", 65536));
        fflush($rlFp);
    }

    $clientIp = isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '127.0.0.1';
    $ipHash = hash_hmac('sha256', $clientIp, gmdate('Y-m-d') . '|' . $state['pepper'], true);
    $ipBucketIdx = unpack('V', substr($ipHash, 0, 4))[1] & 4095;
    $ipBucketTag = unpack('V', substr($ipHash, 4, 4))[1];
    if ($ipBucketTag === 0) {
        $ipBucketTag = 1;
    }

    fseek($rlFp, 28 + $ipBucketIdx * 16);
    $rawBucket = fread($rlFp, 16);
    if ($rawBucket !== false && strlen($rawBucket) === 16) {
        $bucket = unpack('VipTag/VlastTs/ftokens/VfailCount', $rawBucket);
    } else {
        $bucket = ['ipTag' => 0, 'lastTs' => 0, 'tokens' => 30.0, 'failCount' => 0];
    }

    if ($bucket['ipTag'] !== $ipBucketTag) {
        $bucket = ['ipTag' => $ipBucketTag, 'lastTs' => $now, 'tokens' => 30.0, 'failCount' => 0];
    } else {
        $elapsed = max(0, $now - $bucket['lastTs']);
        if ($bucket['failCount'] >= 10 && $elapsed >= 900) {
            $bucket['failCount'] = 0;
        }
        $bucket['tokens'] = min(30.0, $bucket['tokens'] + $elapsed * 0.5);
        if ($bucket['failCount'] < 10) {
            $bucket['lastTs'] = $now;
        }
    }
}

function write_ip_bucket($rlFp, $idx, array $bucket) {
    global $disableRateLimit;
    if (!empty($disableRateLimit) || $rlFp === null) {
        return;
    }
    fseek($rlFp, 28 + $idx * 16);
    fwrite($rlFp, pack('VVfV', $bucket['ipTag'], $bucket['lastTs'], (float)$bucket['tokens'], (int)$bucket['failCount']));
    fflush($rlFp);
}

function ip_is_locked(array $bucket, $now) {
    global $disableRateLimit;
    if (!empty($disableRateLimit)) {
        return false;
    }
    return $bucket['failCount'] >= 10 && ($now - $bucket['lastTs'] < 900);
}

function sync_fail_ip_and_respond($statusCode, $lockFp, $message, array $commonHeaders) {
    global $disableRateLimit, $rlFp, $ipBucketIdx, $bucket, $now;
    if (empty($disableRateLimit)) {
        if (ip_is_locked($bucket, $now)) {
            sync_respond(429, $lockFp, 'Too Many Requests', array_merge($commonHeaders, ['Retry-After' => '900']));
        }
        $bucket['failCount'] = min(100, $bucket['failCount'] + 1);
        if ($bucket['failCount'] >= 10) {
            $bucket['lastTs'] = $now;
        }
        write_ip_bucket($rlFp, $ipBucketIdx, $bucket);
    }
    sync_respond($statusCode, $lockFp, $message, $commonHeaders);
}

// Rebuild index.json atomically
function rebuild_index($dataDir, array $channels) {
    $binFiles = glob($dataDir . DIRECTORY_SEPARATOR . '*.*.bin');
    $indexEntries = [];
    if ($binFiles !== false) {
        foreach ($binFiles as $file) {
            $base = basename($file);
            $parsed = parse_slot_filename($base);
            if ($parsed === null) {
                continue;
            }
            $ch = $parsed['channel'];
            if ($ch === 'media') {
                continue;
            }
            if (!isset($channels[$ch])) {
                continue;
            }
            clearstatcache(true, $file);
            $mtime = filemtime($file);
            $size = filesize($file);
            if ($mtime === false || $size === false) {
                continue;
            }
            $etag = hash_file('sha256', $file);
            $entry = [
                'id'      => $parsed['id'],
                'channel' => $ch,
                'mtime'   => $mtime,
                'size'    => $size,
                'etag'    => $etag,
            ];
            if ($parsed['prefix'] !== '') {
                $entry['prefix'] = $parsed['prefix'];
            }
            $indexEntries[] = $entry;
        }
    }

    usort($indexEntries, function ($a, $b) {
        $c = strcmp($a['channel'], $b['channel']);
        if ($c !== 0) {
            return $c;
        }
        $c = strcmp($a['id'], $b['id']);
        if ($c !== 0) {
            return $c;
        }
        $pa = isset($a['prefix']) ? $a['prefix'] : '';
        $pb = isset($b['prefix']) ? $b['prefix'] : '';
        return strcmp($pa, $pb);
    });

    $indexFile = $dataDir . DIRECTORY_SEPARATOR . 'index.json';
    $indexPayload = json_encode($indexEntries, JSON_UNESCAPED_SLASHES);
    if ($indexPayload !== false) {
        sync_atomic_write($indexFile, $indexPayload);
    }
}

// Lazy prune expired slots
function lazy_prune_slots($dataDir, array $channels, array &$state, $now) {
    $binFiles = glob($dataDir . DIRECTORY_SEPARATOR . '*.*.bin');
    if ($binFiles === false || empty($binFiles)) {
        return;
    }
    $changed = false;
    foreach ($binFiles as $file) {
        $base = basename($file);
        $parsed = parse_slot_filename($base);
        if ($parsed === null) {
            continue;
        }
        $id = $parsed['id'];
        $ch = $parsed['channel'];
        if (!isset($channels[$ch]['ttl_days'])) {
            continue;
        }
        $ttlDays = (int)$channels[$ch]['ttl_days'];
        if ($ttlDays <= 0) {
            continue;
        }
        clearstatcache(true, $file);
        $mtime = filemtime($file);
        if ($mtime !== false && ($now - $mtime > $ttlDays * 86400)) {
            $size = filesize($file);
            @unlink($file);
            if ($size !== false) {
                $state['used_bytes'] = max(0, $state['used_bytes'] - $size);
            }
            if ($ch === 'media') {
                if (isset($state['media_blobs'][$id])) {
                    unset($state['media_blobs'][$id]);
                }
            } else {
                $changed = true;
            }
        }
    }
    // Clean up any entries in $state['media_blobs'] whose file <data_dir>/<id>.media.bin no longer exists on disk
    if (isset($state['media_blobs']) && is_array($state['media_blobs'])) {
        foreach ($state['media_blobs'] as $mId => $mInfo) {
            $mPath = $dataDir . DIRECTORY_SEPARATOR . $mId . '.media.bin';
            if (!file_exists($mPath)) {
                $mSize = isset($mInfo['size']) ? (int)$mInfo['size'] : 0;
                $state['used_bytes'] = max(0, $state['used_bytes'] - $mSize);
                unset($state['media_blobs'][$mId]);
            }
        }
    }
    if ($changed) {
        rebuild_index($dataDir, $channels);
    }
}

// Helper: evict oldest media blobs when higher-priority channels need space
function evict_oldest_media_for_space($dataDir, array &$state, $neededBytes, $maxTotalBytes): bool {
    if ($state['used_bytes'] + $neededBytes <= $maxTotalBytes) {
        return true;
    }
    if (!isset($state['media_blobs']) || !is_array($state['media_blobs']) || empty($state['media_blobs'])) {
        return false;
    }

    $candidates = [];
    $evictableTotal = 0;
    foreach ($state['media_blobs'] as $blobId => $blobInfo) {
        $mFile = $dataDir . DIRECTORY_SEPARATOR . $blobId . '.media.bin';
        $sz = isset($blobInfo['size']) ? (int)$blobInfo['size'] : 0;
        if (file_exists($mFile)) {
            $realSz = filesize($mFile);
            if ($realSz !== false) {
                $sz = $realSz;
            }
        }
        $evictableTotal += $sz;
        $candidates[$blobId] = [
            'mtime' => isset($blobInfo['mtime']) ? (int)$blobInfo['mtime'] : 0,
            'size'  => $sz,
        ];
    }
    // Fail atomically without deleting any media if evicting all media still cannot fit
    if (($state['used_bytes'] - $evictableTotal) + $neededBytes > $maxTotalBytes) {
        return false;
    }

    uksort($candidates, function ($ka, $kb) use ($candidates) {
        $cmp = $candidates[$ka]['mtime'] <=> $candidates[$kb]['mtime'];
        return $cmp !== 0 ? $cmp : strcmp((string)$ka, (string)$kb);
    });

    foreach ($candidates as $blobId => $meta) {
        if ($state['used_bytes'] + $neededBytes <= $maxTotalBytes) {
            break;
        }
        $mFile = $dataDir . DIRECTORY_SEPARATOR . $blobId . '.media.bin';
        if (file_exists($mFile)) {
            @unlink($mFile);
        }
        $state['used_bytes'] = max(0, $state['used_bytes'] - $meta['size']);
        unset($state['media_blobs'][$blobId]);
    }
    return $state['used_bytes'] + $neededBytes <= $maxTotalBytes;
}

// Helper: enforce per-user storage budget with Priority-3 media eviction
function ensure_user_quota_with_media_eviction($dataDir, array &$state, $pubkey, $newSize, $maxUserBytesLimit, $skipSlotBase = null, $skipMediaId = null) {
    if ($maxUserBytesLimit <= 0) {
        return true;
    }
    $userNonMedia = 0;
    $userFiles = glob($dataDir . DIRECTORY_SEPARATOR . $pubkey . '*.bin');
    if ($userFiles !== false) {
        foreach ($userFiles as $uf) {
            $base = basename($uf);
            if ($skipSlotBase !== null && $base === $skipSlotBase) {
                continue;
            }
            $parsed = parse_slot_filename($base);
            if ($parsed !== null && $parsed['id'] === $pubkey && $parsed['channel'] !== 'media') {
                $sz = filesize($uf);
                if ($sz !== false) {
                    $userNonMedia += $sz;
                }
            }
        }
    }
    if ($userNonMedia + $newSize > $maxUserBytesLimit) {
        return false;
    }

    $userMedia = [];
    $userMediaBytes = 0;
    if (isset($state['media_blobs']) && is_array($state['media_blobs'])) {
        foreach ($state['media_blobs'] as $mId => $mInfo) {
            if (isset($mInfo['owner']) && $mInfo['owner'] === $pubkey) {
                if ($skipMediaId !== null && $mId === $skipMediaId) {
                    continue;
                }
                $mFile = $dataDir . DIRECTORY_SEPARATOR . $mId . '.media.bin';
                $mSz = isset($mInfo['size']) ? (int)$mInfo['size'] : 0;
                if (file_exists($mFile)) {
                    $realSz = filesize($mFile);
                    if ($realSz !== false) {
                        $mSz = $realSz;
                    }
                }
                $userMediaBytes += $mSz;
                $userMedia[$mId] = [
                    'mtime' => isset($mInfo['mtime']) ? (int)$mInfo['mtime'] : 0,
                    'size'  => $mSz,
                ];
            }
        }
    }
    if ($userNonMedia + $userMediaBytes + $newSize <= $maxUserBytesLimit) {
        return true;
    }

    uksort($userMedia, function ($ka, $kb) use ($userMedia) {
        $cmp = $userMedia[$ka]['mtime'] <=> $userMedia[$kb]['mtime'];
        return $cmp !== 0 ? $cmp : strcmp((string)$ka, (string)$kb);
    });
    foreach ($userMedia as $victimId => $meta) {
        if ($userNonMedia + $userMediaBytes + $newSize <= $maxUserBytesLimit) {
            break;
        }
        $mFile = $dataDir . DIRECTORY_SEPARATOR . $victimId . '.media.bin';
        if (file_exists($mFile)) {
            @unlink($mFile);
        }
        $userMediaBytes -= $meta['size'];
        $state['used_bytes'] = max(0, $state['used_bytes'] - $meta['size']);
        unset($state['media_blobs'][$victimId]);
    }
    return ($userNonMedia + $userMediaBytes + $newSize) <= $maxUserBytesLimit;
}

// Helper: build admin status JSON payload
function build_admin_status_payload($dataDir, array $channels, array $state, $maxTotalBytes, $softLimitBytes, $maxMembers, $maxUserBytesLimit) {
    $slotCounts = [];
    $totalSlotCount = 0;
    foreach (array_keys($channels) as $ch) {
        if ($ch === 'media') {
            $c = isset($state['media_blobs']) && is_array($state['media_blobs']) ? count($state['media_blobs']) : 0;
        } else {
            $files = glob($dataDir . DIRECTORY_SEPARATOR . '*.' . $ch . '.bin');
            $c = ($files !== false) ? count($files) : 0;
        }
        $slotCounts[$ch] = $c;
        $totalSlotCount += $c;
    }

    return [
        'used_bytes'       => $state['used_bytes'],
        'max_bytes'        => $maxTotalBytes,
        'soft_limit_bytes' => $softLimitBytes,
        'soft_warning'     => ($state['used_bytes'] >= $softLimitBytes),
        'slot_count'       => $totalSlotCount,
        'channel_counts'   => $slotCounts,
        'admin_pubkey'     => $state['admin_pubkey'],
        'max_members'      => $maxMembers,
        'max_user_bytes'   => $maxUserBytesLimit,
    ];
}

$commonHeaders = [];

// Load members for a channel
function load_channel_members($configFile, $channel) {
    $mFile = dirname($configFile) . DIRECTORY_SEPARATOR . 'members.' . $channel . '.php';
    if (!file_exists($mFile)) {
        if ($channel === 'media') {
            $mFile = dirname($configFile) . DIRECTORY_SEPARATOR . 'members.card.php';
            if (!file_exists($mFile)) {
                return [];
            }
        } else {
            return [];
        }
    }
    $raw = file_get_contents($mFile);
    if ($raw === false || strlen($raw) <= 28) {
        return [];
    }
    $json = substr($raw, 28);
    $data = json_decode($json, true);
    if (!is_array($data) || !isset($data['pubkeys']) || !is_array($data['pubkeys'])) {
        return [];
    }
    return $data['pubkeys'];
}

$method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper($_SERVER['REQUEST_METHOD']) : '';

// =========================================================================
// ROUTE 1: GET sync.php?info
// =========================================================================
if ($method === 'GET' && isset($_GET['info']) && count($_GET) === 1) {
    if (!$disableRateLimit) {
        if (ip_is_locked($bucket, $now)) {
            sync_respond(429, $lockFp, 'Too Many Requests', array_merge($commonHeaders, ['Retry-After' => '900']));
        }
        if ($bucket['tokens'] < 1.0) {
            write_ip_bucket($rlFp, $ipBucketIdx, $bucket);
            sync_respond(429, $lockFp, 'Too Many Requests', array_merge($commonHeaders, ['Retry-After' => '2']));
        }
        $bucket['tokens'] -= 1.0;
        write_ip_bucket($rlFp, $ipBucketIdx, $bucket);
    }

    list(, $readUrl) = resolve_own_sync_urls($config, $dataDirSetting);
    $lockInfo = lock_get_info_payload($config, $configFile, $dataDir, $now);
    $infoChannels = array_keys($channels);
    if ($lockInfo !== null && !in_array('lock', $infoChannels, true)) {
        $infoChannels[] = 'lock';
    }

    $infoResponse = [
        'drop_pub'     => $state['admin_pubkey'],
        'read_url'     => $readUrl,
        'register_url' => isset($config['register_url']) ? $config['register_url'] : null,
        'channels'     => $infoChannels,
        'revocation'   => (isset($state['revocation']) && is_array($state['revocation'])) ? $state['revocation'] : null,
        'lock'         => $lockInfo,
    ];

    sync_respond(200, $lockFp, json_encode($infoResponse, JSON_UNESCAPED_SLASHES), array_merge($commonHeaders, [
        'Content-Type'  => 'application/json; charset=utf-8',
        'Cache-Control' => 'no-store',
    ]));
}

// =========================================================================
// ROUTE 2: HEAD sync.php
// =========================================================================
if ($method === 'HEAD' && empty($_GET)) {
    if (!$disableRateLimit && ip_is_locked($bucket, $now)) {
        sync_respond(429, $lockFp, null, array_merge($commonHeaders, ['Retry-After' => '900']));
    }
    respond_if_revoked($state, $now, $lockFp, $commonHeaders, true);

    $pubkey = isset($_SERVER['HTTP_X_DROP_PUBKEY']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_PUBKEY'])) : '';
    if (!preg_match('/\A[0-9a-f]{64}\z/', $pubkey)) {
        if (!$disableRateLimit) {
            $bucket['failCount'] = min(100, $bucket['failCount'] + 1);
            if ($bucket['failCount'] >= 10) {
                $bucket['lastTs'] = $now;
            }
            write_ip_bucket($rlFp, $ipBucketIdx, $bucket);
        }
        sync_respond(400, $lockFp, null, $commonHeaders);
    }

    $lockCfg = lock_cfg($config);
    $channelRaw = isset($_SERVER['HTTP_X_CHANNEL']) ? trim((string)$_SERVER['HTTP_X_CHANNEL']) : '';
    $channel = ($channelRaw !== '') ? $channelRaw : null;
    if ($channel !== null && (!preg_match('/\A[a-z0-9_]{1,32}\z/', $channel) || (!isset($channels[$channel]) && !($channel === 'lock' && $lockCfg['enabled'])))) {
        sync_respond(400, $lockFp, null, $commonHeaders);
    }

    $prefix = extract_and_validate_prefix();
    if ($prefix === false || ($channel === 'media' && $prefix !== '')) {
        sync_respond(400, $lockFp, null, $commonHeaders);
    }

    $mediaIdRaw = isset($_SERVER['HTTP_X_MEDIA_ID']) ? strtolower(trim((string)$_SERVER['HTTP_X_MEDIA_ID'])) : '';
    $mediaId = ($mediaIdRaw !== '') ? $mediaIdRaw : null;
    if ($mediaId !== null && !preg_match('/\A[0-9a-f]{64}\z/', $mediaId)) {
        sync_respond(400, $lockFp, null, $commonHeaders);
    }

    if (!$disableRateLimit) {
        write_ip_bucket($rlFp, $ipBucketIdx, $bucket);
    }

    $allowedChannels = [];
    foreach ($channels as $chName => $_chCfg) {
        $chMembers = load_channel_members($configFile, (string)$chName);
        if (in_array($pubkey, $chMembers, true)) {
            $allowedChannels[] = (string)$chName;
        }
    }
    if ($lockCfg['enabled']) {
        $lockMembers = load_channel_members($configFile, 'lock');
        if (($state['admin_pubkey'] !== '' && hash_equals($state['admin_pubkey'], $pubkey)) || in_array($pubkey, $lockMembers, true)) {
            $allowedChannels[] = 'lock';
        }
    }

    $authorized = ($channel !== null)
        ? in_array($channel, $allowedChannels, true)
        : !empty($allowedChannels);

    $mediaTtlDays = isset($channels['media']['ttl_days']) ? (int)$channels['media']['ttl_days'] : 90;
    $usedCount = 0;
    $usedBytes = 0;
    if (isset($state['media_blobs']) && is_array($state['media_blobs'])) {
        foreach ($state['media_blobs'] as $mId => $mInfo) {
            $mFile = $dataDir . DIRECTORY_SEPARATOR . $mId . '.media.bin';
            if (!file_exists($mFile)) {
                continue;
            }
            clearstatcache(true, $mFile);
            $mTime = filemtime($mFile);
            if ($mTime === false || ($mediaTtlDays > 0 && ($now - $mTime > $mediaTtlDays * 86400))) {
                continue;
            }
            if (isset($mInfo['owner']) && $mInfo['owner'] === $pubkey) {
                $usedCount++;
                $usedBytes += isset($mInfo['size']) ? (int)$mInfo['size'] : 0;
            }
        }
    }

    $respHeaders = array_merge($commonHeaders, [
        'Cache-Control'     => 'no-store',
        'X-Drop-Authorized' => $authorized ? 'true' : 'false',
    ]);

    if (!empty($allowedChannels)) {
        $respHeaders['X-Drop-Channels'] = implode(',', $allowedChannels);

        if ($channel !== null && isset($channels[$channel])) {
            $respHeaders['X-Channel-Max-Bytes'] = (string)$channels[$channel]['max_bytes'];
            $ttlDays = isset($channels[$channel]['ttl_days']) ? (int)$channels[$channel]['ttl_days'] : 30;
            if ($ttlDays > 0) {
                $respHeaders['X-Channel-Ttl-Days'] = (string)$ttlDays;
            }

            if ($channel === 'media') {
                if ($mediaId !== null) {
                    $mediaOccupied = false;
                    $mediaEtag = null;
                    if (isset($state['media_blobs'][$mediaId])) {
                        $mediaFile = $dataDir . DIRECTORY_SEPARATOR . $mediaId . '.media.bin';
                        if (file_exists($mediaFile)) {
                            clearstatcache(true, $mediaFile);
                            $mTime = filemtime($mediaFile);
                            if ($mTime !== false && ($mediaTtlDays <= 0 || ($now - $mTime <= $mediaTtlDays * 86400))) {
                                $mediaOccupied = true;
                                if (isset($state['media_blobs'][$mediaId]['owner']) && $state['media_blobs'][$mediaId]['owner'] === $pubkey) {
                                    $hashVal = hash_file('sha256', $mediaFile);
                                    if ($hashVal !== false) {
                                        $mediaEtag = $hashVal;
                                    }
                                }
                            }
                        }
                    }
                    $respHeaders['X-Slot-Occupied'] = $mediaOccupied ? 'true' : 'false';
                    if ($mediaEtag !== null) {
                        $respHeaders['ETag'] = '"' . $mediaEtag . '"';
                    }
                }
            } else {
                $slotPath = $dataDir . DIRECTORY_SEPARATOR . build_slot_filename($pubkey, $prefix, $channel);
                $occupied = false;
                $slotEtag = null;
                if (file_exists($slotPath)) {
                    clearstatcache(true, $slotPath);
                    $mtime = filemtime($slotPath);
                    if ($mtime !== false && ($ttlDays <= 0 || ($now - $mtime <= $ttlDays * 86400))) {
                        $occupied = true;
                        $hashVal = hash_file('sha256', $slotPath);
                        if ($hashVal !== false) {
                            $slotEtag = $hashVal;
                        }
                    }
                }
                $respHeaders['X-Slot-Occupied'] = $occupied ? 'true' : 'false';
                if ($slotEtag !== null) {
                    $respHeaders['ETag'] = '"' . $slotEtag . '"';
                }
            }
        }

        if (isset($channels['media'])) {
            $respHeaders['X-Media-Max-Count'] = (string)(isset($channels['media']['max_user_count']) ? (int)$channels['media']['max_user_count'] : 12);
            $cfgMediaMaxUserBytes = isset($channels['media']['max_user_bytes']) ? (int)$channels['media']['max_user_bytes'] : 6291456;
            $respHeaders['X-Media-Max-Bytes'] = (string)min($maxUserBytesLimit, $cfgMediaMaxUserBytes);
        }
    }

    $respHeaders['X-Media-Count'] = (string)$usedCount;
    $respHeaders['X-Media-Bytes'] = (string)$usedBytes;

    sync_respond(200, $lockFp, null, $respHeaders);
}

// =========================================================================
// ROUTE 3: PUT sync.php?members&channel=<name> (Admin Update Member Pubkeys)
// =========================================================================
if ($method === 'PUT' && isset($_GET['members']) && empty(array_diff(array_keys($_GET), ['members', 'channel']))) {
    $channel = (isset($_GET['channel']) && is_string($_GET['channel']) && $_GET['channel'] !== '')
        ? $_GET['channel']
        : (isset($_SERVER['HTTP_X_CHANNEL']) ? (string)$_SERVER['HTTP_X_CHANNEL'] : '');
    if (!preg_match('/\A[a-z0-9_]{1,32}\z/', $channel) || (!isset($channels[$channel]) && $channel !== 'lock')) {
        sync_respond(404, $lockFp, 'Not Found', $commonHeaders);
    }

    $adminPub = isset($_SERVER['HTTP_X_DROP_PUBKEY']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_PUBKEY'])) : '';
    $timestampRaw = isset($_SERVER['HTTP_X_DROP_TIMESTAMP']) ? trim((string)$_SERVER['HTTP_X_DROP_TIMESTAMP']) : '';
    $nonce = isset($_SERVER['HTTP_X_DROP_NONCE']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_NONCE'])) : '';
    $signature = isset($_SERVER['HTTP_X_DROP_SIGNATURE']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_SIGNATURE'])) : '';

    if ($adminPub === '' || !sync_is_int_timestamp($timestampRaw) || !preg_match('/\A[0-9a-f]{64}\z/', $adminPub) || !preg_match('/\A[0-9a-f]{32}\z/', $nonce) || !preg_match('/\A[0-9a-f]{128}\z/', $signature)) {
        sync_fail_ip_and_respond(400, $lockFp, 'Bad Request: Invalid headers', $commonHeaders);
    }
    $timestamp = (int)$timestampRaw;

    if (!hash_equals($state['admin_pubkey'], $adminPub)) {
        sync_fail_ip_and_respond(403, $lockFp, 'Forbidden: Unauthorized admin pubkey', $commonHeaders);
    }
    if (abs($now - $timestamp) > 60) {
        sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Timestamp outside allowed window', $commonHeaders);
    }

    $rawInput = sync_read_bounded_body(8 * 1024 * 1024, $lockFp, $commonHeaders, 'Payload Too Large: Members list exceeds 8 MiB limit');
    $canonicalMsg = "HUMOCO-DROP-ADMIN-V1\nPUT_MEMBERS\n{$channel}\n{$timestamp}\n{$nonce}\n" . hash('sha256', $rawInput);

    if (!verify_ed25519_detached($signature, $canonicalMsg, $adminPub)) {
        sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Invalid admin signature', $commonHeaders);
    }

    if (isset($state['nonces'][$nonce])) {
        sync_respond(409, $lockFp, 'Conflict: Replay detected', $commonHeaders);
    }
    $state['nonces'][$nonce] = $now;

    $bodyData = json_decode($rawInput, true);
    if (!is_array($bodyData) || !isset($bodyData['pubkeys']) || !is_array($bodyData['pubkeys'])) {
        sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: Expected pubkeys array', $commonHeaders);
    }

    $deduped = [];
    foreach ($bodyData['pubkeys'] as $pk) {
        if (!is_string($pk) || !preg_match('/\A[0-9a-f]{64}\z/', $pk)) {
            sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: Invalid pubkey format (must be 64 lowercase hex)', $commonHeaders);
        }
        $deduped[strtolower($pk)] = true;
    }
    $newMemberPubkeys = array_keys($deduped);
    if (count($newMemberPubkeys) > $maxMembers) {
        sync_save_and_respond(507, $lockFp, $stateFile, $state, 'Insufficient Storage: Exceeds max_members limit', $commonHeaders);
    }
    sort($newMemberPubkeys);

    $membersFile = dirname($configFile) . DIRECTORY_SEPARATOR . 'members.' . $channel . '.php';
    $membersJson = json_encode(['pubkeys' => $newMemberPubkeys], JSON_UNESCAPED_SLASHES);
    if ($membersJson === false || !sync_atomic_write($membersFile, "<?php __halt_compiler(); ?>\n" . $membersJson)) {
        sync_save_and_respond(500, $lockFp, $stateFile, $state, 'Internal Server Error: Failed to write members file', $commonHeaders);
    }

    // Prune slots for this channel if pubkey is no longer a member (lock channel never prunes lock files)
    if ($channel !== 'lock') {
        $memberSet = array_flip($newMemberPubkeys);
        $existingSlots = glob($dataDir . DIRECTORY_SEPARATOR . '*.' . $channel . '.bin');
        if ($existingSlots !== false) {
            foreach ($existingSlots as $sFile) {
                $bName = basename($sFile);
                $parsed = parse_slot_filename($bName);
                if ($parsed !== null && $parsed['channel'] === $channel) {
                    if (!isset($memberSet[$parsed['id']])) {
                        $sz = filesize($sFile);
                        @unlink($sFile);
                        if ($sz !== false) {
                            $state['used_bytes'] = max(0, $state['used_bytes'] - $sz);
                        }
                    }
                }
            }
        }

        if ($channel === 'card' || $channel === 'media') {
            $effectiveMediaSet = array_flip(load_channel_members($configFile, 'media'));
            if (isset($state['media_blobs']) && is_array($state['media_blobs'])) {
                foreach ($state['media_blobs'] as $mId => $mInfo) {
                    $owner = isset($mInfo['owner']) ? $mInfo['owner'] : '';
                    if (!isset($effectiveMediaSet[$owner])) {
                        $mFile = $dataDir . DIRECTORY_SEPARATOR . $mId . '.media.bin';
                        if (file_exists($mFile)) {
                            $sz = filesize($mFile);
                            @unlink($mFile);
                            if ($sz !== false) {
                                $state['used_bytes'] = max(0, $state['used_bytes'] - $sz);
                            }
                        } else {
                            $sz = isset($mInfo['size']) ? (int)$mInfo['size'] : 0;
                            $state['used_bytes'] = max(0, $state['used_bytes'] - $sz);
                        }
                        unset($state['media_blobs'][$mId]);
                    }
                }
            }
        }

        lazy_prune_slots($dataDir, $channels, $state, $now);
        rebuild_index($dataDir, $channels);
    }

    sync_save_and_respond(200, $lockFp, $stateFile, $state, json_encode([
        'status'  => 'ok',
        'channel' => $channel,
        'members' => count($newMemberPubkeys),
    ], JSON_UNESCAPED_SLASHES), array_merge($commonHeaders, [
        'Content-Type' => 'application/json; charset=utf-8',
    ]));
}

// =========================================================================
// ROUTE 4: PUT sync.php?revoke (Admin Publish or Clear Revocation Notice)
// =========================================================================
if ($method === 'PUT' && isset($_GET['revoke']) && count($_GET) === 1) {
    $adminPub = isset($_SERVER['HTTP_X_DROP_PUBKEY']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_PUBKEY'])) : '';
    $timestampRaw = isset($_SERVER['HTTP_X_DROP_TIMESTAMP']) ? trim((string)$_SERVER['HTTP_X_DROP_TIMESTAMP']) : '';
    $nonce = isset($_SERVER['HTTP_X_DROP_NONCE']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_NONCE'])) : '';
    $signature = isset($_SERVER['HTTP_X_DROP_SIGNATURE']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_SIGNATURE'])) : '';

    if ($adminPub === '' || !sync_is_int_timestamp($timestampRaw) || !preg_match('/\A[0-9a-f]{64}\z/', $adminPub) || !preg_match('/\A[0-9a-f]{32}\z/', $nonce) || !preg_match('/\A[0-9a-f]{128}\z/', $signature)) {
        sync_fail_ip_and_respond(400, $lockFp, 'Bad Request: Invalid headers', $commonHeaders);
    }
    $timestamp = (int)$timestampRaw;

    if (!hash_equals($state['admin_pubkey'], $adminPub)) {
        sync_fail_ip_and_respond(403, $lockFp, 'Forbidden: Unauthorized admin pubkey', $commonHeaders);
    }
    if (abs($now - $timestamp) > 60) {
        sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Timestamp outside allowed window', $commonHeaders);
    }

    $rawInput = sync_read_bounded_body(64 * 1024, $lockFp, $commonHeaders, 'Payload Too Large: Revocation payload exceeds 64 KiB limit');
    $canonicalMsg = "HUMOCO-DROP-ADMIN-V1\nPUT_REVOKE\n{$timestamp}\n{$nonce}\n" . hash('sha256', $rawInput);

    if (!verify_ed25519_detached($signature, $canonicalMsg, $adminPub)) {
        sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Invalid admin signature', $commonHeaders);
    }

    if (isset($state['nonces'][$nonce])) {
        sync_respond(409, $lockFp, 'Conflict: Replay detected', $commonHeaders);
    }
    $state['nonces'][$nonce] = $now;

    $bodyData = json_decode($rawInput, true);
    if ($bodyData === null && trim($rawInput) !== 'null') {
        sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: Invalid revocation JSON', $commonHeaders);
    }

    $revocationFile = $dataDir . DIRECTORY_SEPARATOR . 'revocation.json';

    // Clear revocation when payload is null or effective_at is null/0 or clear=true or revoked=false
    $shouldClear = ($bodyData === null)
        || (is_array($bodyData) && !empty($bodyData['clear']))
        || (is_array($bodyData) && array_key_exists('revoked', $bodyData) && $bodyData['revoked'] === false)
        || (is_array($bodyData) && (!isset($bodyData['effective_at']) || $bodyData['effective_at'] === null || $bodyData['effective_at'] === 0));
    if ($shouldClear) {
        $state['revocation'] = null;
        if (file_exists($revocationFile)) {
            @unlink($revocationFile);
        }
        sync_save_and_respond(200, $lockFp, $stateFile, $state, json_encode(['status' => 'ok', 'revoked' => false], JSON_UNESCAPED_SLASHES), array_merge($commonHeaders, [
            'Content-Type' => 'application/json; charset=utf-8',
        ]));
    }

    if (!is_array($bodyData) || !isset($bodyData['issued_at']) || !is_int($bodyData['issued_at']) || $bodyData['issued_at'] <= 0) {
        sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: Invalid issued_at', $commonHeaders);
    }
    $issuedAt = $bodyData['issued_at'];

    if (isset($state['revocation']['issued_at']) && $issuedAt <= (int)$state['revocation']['issued_at']) {
        sync_save_and_respond(409, $lockFp, $stateFile, $state, 'Conflict: Stale issued_at', $commonHeaders);
    }

    if (!isset($bodyData['effective_at']) || !is_int($bodyData['effective_at']) || $bodyData['effective_at'] <= 0) {
        sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: Invalid effective_at', $commonHeaders);
    }
    $effectiveAt = $bodyData['effective_at'];

    $rawNoticeDropPub = $bodyData['drop_pub'] ?? null;
    if (!is_string($rawNoticeDropPub) || preg_match('/\A[0-9a-fA-F]{64}\z/', $rawNoticeDropPub) !== 1) {
        sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: Notice drop_pub mismatch', $commonHeaders);
    }
    $noticeDropPub = strtolower($rawNoticeDropPub);
    if (!hash_equals($state['admin_pubkey'], $noticeDropPub)) {
        sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: Notice drop_pub mismatch', $commonHeaders);
    }

    $reason = null;
    if (isset($bodyData['reason']) && $bodyData['reason'] !== null) {
        if (!is_string($bodyData['reason']) || strlen($bodyData['reason']) > 200 || contains_control_chars($bodyData['reason'])) {
            sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: Invalid reason', $commonHeaders);
        }
        if ($bodyData['reason'] !== '') {
            $reason = $bodyData['reason'];
        }
    }

    $replacement = null;
    if (isset($bodyData['replacement']) && $bodyData['replacement'] !== null) {
        if (!is_array($bodyData['replacement'])) {
            sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: Invalid replacement', $commonHeaders);
        }
        $repWrite = $bodyData['replacement']['write_url'] ?? null;
        $repRead = $bodyData['replacement']['read_url'] ?? null;
        $rawRepPub = $bodyData['replacement']['drop_pub'] ?? null;
        if (!is_sync_url_valid($repWrite)
            || !is_sync_url_valid($repRead)
            || !is_string($rawRepPub)
            || preg_match('/\A[0-9a-fA-F]{64}\z/', $rawRepPub) !== 1
        ) {
            sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: Invalid replacement fields', $commonHeaders);
        }
        $repPub = strtolower($rawRepPub);
        list($ownWriteUrl, $ownReadUrl) = resolve_own_sync_urls($config, $dataDirSetting);
        $normOwnWrite = strtolower(rtrim($ownWriteUrl, '/'));
        $normOwnRead = strtolower(rtrim($ownReadUrl, '/'));
        $normRepWrite = strtolower(rtrim($repWrite, '/'));
        $normRepRead = strtolower(rtrim($repRead, '/'));
        if ($normRepWrite === $normOwnWrite || $normRepRead === $normOwnRead || $normRepWrite === $normOwnRead || $normRepRead === $normOwnWrite) {
            sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: Self-redirect replacement is not allowed', $commonHeaders);
        }
        $replacement = [
            'write_url' => $repWrite,
            'read_url'  => $repRead,
            'drop_pub'  => $repPub,
        ];
    }

    $rawNoticeSig = $bodyData['signature'] ?? null;
    if (!is_string($rawNoticeSig) || preg_match('/\A[0-9a-fA-F]{128}\z/', $rawNoticeSig) !== 1) {
        sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: Invalid notice signature format', $commonHeaders);
    }
    $noticeSig = strtolower($rawNoticeSig);

    $cleanNotice = [
        'drop_pub'     => $noticeDropPub,
        'issued_at'    => $issuedAt,
        'effective_at' => $effectiveAt,
        'reason'       => $reason,
        'replacement'  => $replacement,
        'signature'    => $noticeSig,
    ];

    $noticeCanonical = build_revocation_canonical_message($cleanNotice);
    if (!verify_ed25519_detached($noticeSig, $noticeCanonical, $state['admin_pubkey'])) {
        sync_save_and_respond(403, $lockFp, $stateFile, $state, 'Forbidden: Invalid notice signature', $commonHeaders);
    }

    $revJson = json_encode($cleanNotice, JSON_UNESCAPED_SLASHES);
    if ($revJson === false || !sync_atomic_write($revocationFile, $revJson)) {
        sync_save_and_respond(500, $lockFp, $stateFile, $state, 'Internal Server Error: Failed to write revocation.json', $commonHeaders);
    }

    $state['revocation'] = $cleanNotice;
    sync_save_and_respond(200, $lockFp, $stateFile, $state, $revJson, array_merge($commonHeaders, [
        'Content-Type' => 'application/json; charset=utf-8',
    ]));
}

// =========================================================================
// ROUTE 4b: PUT sync.php?admin_config (Admin Update Storage & Member Quotas)
// =========================================================================
if ($method === 'PUT' && isset($_GET['admin_config']) && count($_GET) === 1) {
    $adminPub = isset($_SERVER['HTTP_X_DROP_PUBKEY']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_PUBKEY'])) : '';
    $timestampRaw = isset($_SERVER['HTTP_X_DROP_TIMESTAMP']) ? trim((string)$_SERVER['HTTP_X_DROP_TIMESTAMP']) : '';
    $nonce = isset($_SERVER['HTTP_X_DROP_NONCE']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_NONCE'])) : '';
    $signature = isset($_SERVER['HTTP_X_DROP_SIGNATURE']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_SIGNATURE'])) : '';

    if ($adminPub === '' || !sync_is_int_timestamp($timestampRaw) || !preg_match('/\A[0-9a-f]{64}\z/', $adminPub) || !preg_match('/\A[0-9a-f]{32}\z/', $nonce) || !preg_match('/\A[0-9a-f]{128}\z/', $signature)) {
        sync_fail_ip_and_respond(400, $lockFp, 'Bad Request: Invalid headers', $commonHeaders);
    }
    $timestamp = (int)$timestampRaw;

    if (!hash_equals($state['admin_pubkey'], $adminPub)) {
        sync_fail_ip_and_respond(403, $lockFp, 'Forbidden: Unauthorized admin pubkey', $commonHeaders);
    }
    if (abs($now - $timestamp) > 60) {
        sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Timestamp outside allowed window', $commonHeaders);
    }

    $rawInput = sync_read_bounded_body(16 * 1024, $lockFp, $commonHeaders, 'Payload Too Large: Admin config exceeds 16 KiB limit');
    $canonicalMsg = "HUMOCO-DROP-ADMIN-V1\nPUT_ADMIN_CONFIG\n\n{$timestamp}\n{$nonce}\n" . hash('sha256', $rawInput);
    if (!verify_ed25519_detached($signature, $canonicalMsg, $adminPub)) {
        sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Invalid admin signature', $commonHeaders);
    }

    if (isset($state['nonces'][$nonce])) {
        sync_respond(409, $lockFp, 'Conflict: Replay detected', $commonHeaders);
    }
    $state['nonces'][$nonce] = $now;

    $bodyData = json_decode($rawInput, true);
    if (!is_array($bodyData)
        || !isset($bodyData['max_total_storage_mb'], $bodyData['max_members'], $bodyData['max_user_storage_mb'])
        || !is_int($bodyData['max_total_storage_mb'])
        || !is_int($bodyData['max_members'])
        || !is_int($bodyData['max_user_storage_mb'])) {
        sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: Invalid admin_config JSON', $commonHeaders);
    }

    $reqTotalMb = $bodyData['max_total_storage_mb'];
    $reqMembers = $bodyData['max_members'];
    $reqUserMb  = $bodyData['max_user_storage_mb'];

    if ($reqMembers < 1 || $reqMembers > 100000) {
        sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: max_members must be between 1 and 100000', $commonHeaders);
    }
    if ($reqUserMb < 10) {
        sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: max_user_storage_mb must be at least 10 MB', $commonHeaders);
    }
    if ($reqTotalMb < $reqUserMb || $reqTotalMb > 10485760) {
        sync_save_and_respond(400, $lockFp, $stateFile, $state, 'Bad Request: max_total_storage_mb must be between max_user_storage_mb and 10485760 MB', $commonHeaders);
    }

    $state['admin_config'] = [
        'max_total_storage_mb' => $reqTotalMb,
        'max_members'          => $reqMembers,
        'max_user_storage_mb'  => $reqUserMb,
    ];
    $maxTotalStorageMb = $reqTotalMb;
    $maxTotalBytes     = $maxTotalStorageMb * 1024 * 1024;
    $softLimitBytes    = (int)floor($maxTotalBytes * 0.8);
    $maxMembers        = $reqMembers;
    $maxUserStorageMb  = $reqUserMb;
    $maxUserBytesLimit = $maxUserStorageMb * 1024 * 1024;

    lazy_prune_slots($dataDir, $channels, $state, $now);

    $statusData = build_admin_status_payload($dataDir, $channels, $state, $maxTotalBytes, $softLimitBytes, $maxMembers, $maxUserBytesLimit);
    sync_save_and_respond(200, $lockFp, $stateFile, $state, json_encode($statusData, JSON_UNESCAPED_SLASHES), array_merge($commonHeaders, [
        'Content-Type'  => 'application/json; charset=utf-8',
        'Cache-Control' => 'no-store',
    ]));
}

// =========================================================================
// ROUTE 5: GET sync.php?status (Admin Storage Dashboard Info)
// =========================================================================
if ($method === 'GET' && isset($_GET['status']) && count($_GET) === 1) {
    $adminPub = isset($_SERVER['HTTP_X_DROP_PUBKEY']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_PUBKEY'])) : '';
    $timestampRaw = isset($_SERVER['HTTP_X_DROP_TIMESTAMP']) ? trim((string)$_SERVER['HTTP_X_DROP_TIMESTAMP']) : '';
    $nonce = isset($_SERVER['HTTP_X_DROP_NONCE']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_NONCE'])) : '';
    $signature = isset($_SERVER['HTTP_X_DROP_SIGNATURE']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_SIGNATURE'])) : '';

    if ($adminPub === '' || !sync_is_int_timestamp($timestampRaw) || !preg_match('/\A[0-9a-f]{64}\z/', $adminPub) || !preg_match('/\A[0-9a-f]{32}\z/', $nonce) || !preg_match('/\A[0-9a-f]{128}\z/', $signature)) {
        sync_fail_ip_and_respond(400, $lockFp, 'Bad Request: Invalid headers', $commonHeaders);
    }
    $timestamp = (int)$timestampRaw;

    if (!hash_equals($state['admin_pubkey'], $adminPub)) {
        sync_fail_ip_and_respond(403, $lockFp, 'Forbidden: Unauthorized admin pubkey', $commonHeaders);
    }
    if (abs($now - $timestamp) > 60) {
        sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Timestamp outside allowed window', $commonHeaders);
    }

    $canonicalMsg = "HUMOCO-DROP-ADMIN-V1\nSTATUS\n\n{$timestamp}\n{$nonce}\n" . hash('sha256', '');
    if (!verify_ed25519_detached($signature, $canonicalMsg, $adminPub)) {
        sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Invalid admin signature', $commonHeaders);
    }

    if (isset($state['nonces'][$nonce])) {
        sync_respond(409, $lockFp, 'Conflict: Replay detected', $commonHeaders);
    }
    $state['nonces'][$nonce] = $now;

    lazy_prune_slots($dataDir, $channels, $state, $now);

    $statusData = build_admin_status_payload($dataDir, $channels, $state, $maxTotalBytes, $softLimitBytes, $maxMembers, $maxUserBytesLimit);

    sync_save_and_respond(200, $lockFp, $stateFile, $state, json_encode($statusData, JSON_UNESCAPED_SLASHES), array_merge($commonHeaders, [
        'Content-Type'  => 'application/json; charset=utf-8',
        'Cache-Control' => 'no-store',
    ]));
}

// =========================================================================
// ROUTE 6: PUT sync.php (Member Raw Binary Upload)
// =========================================================================
if ($method === 'PUT' && empty($_GET)) {
    respond_if_revoked($state, $now, $lockFp, $commonHeaders);
    $channel = isset($_SERVER['HTTP_X_CHANNEL']) ? trim((string)$_SERVER['HTTP_X_CHANNEL']) : '';
    if (!preg_match('/\A[a-z0-9_]{1,32}\z/', $channel) || !isset($channels[$channel])) {
        sync_respond(404, $lockFp, 'Not Found', $commonHeaders);
    }

    $prefix = extract_and_validate_prefix();
    if ($prefix === false || ($channel === 'media' && $prefix !== '')) {
        sync_fail_ip_and_respond(400, $lockFp, 'Bad Request: Invalid X-Drop-Prefix', $commonHeaders);
    }
    if ($channel !== 'media' && isset($_SERVER['HTTP_X_MEDIA_ID']) && trim((string)$_SERVER['HTTP_X_MEDIA_ID']) !== '') {
        sync_fail_ip_and_respond(400, $lockFp, 'Bad Request: X-Media-Id is only valid on media channel', $commonHeaders);
    }

    $channelCfg = $channels[$channel];
    $maxBytes = (int)$channelCfg['max_bytes'];

    $pubkey = isset($_SERVER['HTTP_X_DROP_PUBKEY']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_PUBKEY'])) : '';
    $timestampRaw = isset($_SERVER['HTTP_X_DROP_TIMESTAMP']) ? trim((string)$_SERVER['HTTP_X_DROP_TIMESTAMP']) : '';
    $nonce = isset($_SERVER['HTTP_X_DROP_NONCE']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_NONCE'])) : '';
    $signature = isset($_SERVER['HTTP_X_DROP_SIGNATURE']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_SIGNATURE'])) : '';

    if ($timestampRaw === '' || !sync_is_int_timestamp($timestampRaw) || !preg_match('/\A[0-9a-f]{32}\z/', $nonce) || !preg_match('/\A[0-9a-f]{128}\z/', $signature) || !preg_match('/\A[0-9a-f]{64}\z/', $pubkey)) {
        sync_fail_ip_and_respond(400, $lockFp, 'Bad Request: Invalid auth headers', $commonHeaders);
    }
    $timestamp = (int)$timestampRaw;
    if (abs($now - $timestamp) > 60) {
        sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Timestamp outside allowed window', $commonHeaders);
    }

    $channelMembers = load_channel_members($configFile, $channel);
    if (!in_array($pubkey, $channelMembers, true)) {
        sync_fail_ip_and_respond(403, $lockFp, 'Forbidden: Pubkey is not an authorized member', $commonHeaders);
    }

    $rawBody = sync_read_bounded_body($maxBytes, $lockFp, $commonHeaders);

    if (strlen($rawBody) === 0) {
        sync_respond(400, $lockFp, 'Bad Request: Empty payload', $commonHeaders);
    }

    if ($channel === 'media') {
        $mediaId = isset($_SERVER['HTTP_X_MEDIA_ID']) ? strtolower(trim((string)$_SERVER['HTTP_X_MEDIA_ID'])) : '';
        if (!preg_match('/\A[0-9a-f]{64}\z/', $mediaId)) {
            sync_fail_ip_and_respond(400, $lockFp, 'Bad Request: Missing or invalid X-Media-Id', $commonHeaders);
        }
        $canonicalMsg = "HUMOCO-DROP-REQ-V1\nPUT\nmedia:{$mediaId}\n\n{$timestamp}\n{$nonce}\n" . hash('sha256', $rawBody);
    } else {
        $canonicalMsg = "HUMOCO-DROP-REQ-V1\nPUT\n{$channel}\n{$prefix}\n{$timestamp}\n{$nonce}\n" . hash('sha256', $rawBody);
    }

    if (!verify_ed25519_detached($signature, $canonicalMsg, $pubkey)) {
        sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Invalid request signature', $commonHeaders);
    }

    // Authenticated request: does NOT increment IP failCount! Enforce per-member token bucket
    sync_check_member_ratelimit($disableRateLimit, $lockFp, $stateFile, $state, $pubkey, $now, $commonHeaders);

    if (isset($state['nonces'][$nonce])) {
        sync_save_and_respond(409, $lockFp, $stateFile, $state, 'Conflict: Replay detected', $commonHeaders);
    }
    $state['nonces'][$nonce] = $now;

    lazy_prune_slots($dataDir, $channels, $state, $now);

    if ($channel === 'media') {
        // Ownership check
        if (isset($state['media_blobs'][$mediaId]) && $state['media_blobs'][$mediaId]['owner'] !== $pubkey) {
            sync_save_and_respond(403, $lockFp, $stateFile, $state, 'Forbidden: Media blob owned by another member', $commonHeaders);
        }

        $mediaFile = $dataDir . DIRECTORY_SEPARATOR . $mediaId . '.media.bin';
        $currentMediaEtag = null;
        if (isset($state['media_blobs'][$mediaId]) && file_exists($mediaFile)) {
            $hashVal = hash_file('sha256', $mediaFile);
            if ($hashVal !== false) {
                $currentMediaEtag = $hashVal;
            }
        }
        sync_check_put_preconditions($currentMediaEtag, $lockFp, $stateFile, $state, $commonHeaders);

        $newSize = strlen($rawBody);
        $oldBlobSize = 0;
        if (isset($state['media_blobs'][$mediaId])) {
            $oldBlobSize = (int)$state['media_blobs'][$mediaId]['size'];
        }
        $delta = $newSize - $oldBlobSize;

        // Pre-compute non-evictable channel & global usage so 507 never needlessly evicts user media
        $maxUserCount = isset($channelCfg['max_user_count']) ? (int)$channelCfg['max_user_count'] : 12;
        $maxUserBytes = min($maxUserBytesLimit, isset($channelCfg['max_user_bytes']) ? (int)$channelCfg['max_user_bytes'] : 6291456);
        $maxChannelMb = isset($channelCfg['max_channel_mb']) ? (int)$channelCfg['max_channel_mb'] : 100;
        $maxChannelBytes = $maxChannelMb * 1024 * 1024;
        if ($maxUserCount < 1 || $newSize > $maxUserBytes) {
            sync_save_and_respond(507, $lockFp, $stateFile, $state, 'Insufficient Storage: Member media quota exceeded', $commonHeaders);
        }
        $otherChannelMediaBytes = 0;
        $userEvictableMediaBytes = 0;
        if (isset($state['media_blobs']) && is_array($state['media_blobs'])) {
            foreach ($state['media_blobs'] as $mId => $mInfo) {
                $mSize = isset($mInfo['size']) ? (int)$mInfo['size'] : 0;
                if (isset($mInfo['owner']) && $mInfo['owner'] === $pubkey && $mId !== $mediaId) {
                    $userEvictableMediaBytes += $mSize;
                } elseif ($mId !== $mediaId) {
                    $otherChannelMediaBytes += $mSize;
                }
            }
        }
        if (($otherChannelMediaBytes + $newSize) > $maxChannelBytes) {
            sync_save_and_respond(507, $lockFp, $stateFile, $state, 'Insufficient Storage: Media channel quota exceeded', $commonHeaders);
        }
        if (($state['used_bytes'] - $userEvictableMediaBytes) + $delta > $maxTotalBytes) {
            sync_save_and_respond(507, $lockFp, $stateFile, $state, 'Insufficient Storage: Global sync quota exceeded', $commonHeaders);
        }

        if (!ensure_user_quota_with_media_eviction($dataDir, $state, $pubkey, $newSize, $maxUserBytesLimit, null, $mediaId)) {
            sync_save_and_respond(507, $lockFp, $stateFile, $state, 'Insufficient Storage: Account total quota exceeded', $commonHeaders);
        }

        // Compute member's current media count & bytes (excluding $mediaId if overwriting own existing blob)
        // and total channel media bytes across all $state['media_blobs']
        $userCount = 0;
        $userBytes = 0;
        $channelMediaBytes = 0;
        if (isset($state['media_blobs']) && is_array($state['media_blobs'])) {
            foreach ($state['media_blobs'] as $mId => $mInfo) {
                $mSize = isset($mInfo['size']) ? (int)$mInfo['size'] : 0;
                $channelMediaBytes += $mSize;
                if (isset($mInfo['owner']) && $mInfo['owner'] === $pubkey) {
                    if ($mId !== $mediaId) {
                        $userCount++;
                        $userBytes += $mSize;
                    }
                }
            }
        }

        // Check per-member limits
        if (($userCount + 1) > $maxUserCount || ($userBytes + $newSize) > $maxUserBytes) {
            sync_save_and_respond(507, $lockFp, $stateFile, $state, 'Insufficient Storage: Member media quota exceeded', $commonHeaders);
        }

        // Check channel limit
        if (($channelMediaBytes + $delta) > $maxChannelBytes) {
            sync_save_and_respond(507, $lockFp, $stateFile, $state, 'Insufficient Storage: Media channel quota exceeded', $commonHeaders);
        }

        // Check global limit
        if ($state['used_bytes'] + $delta > $maxTotalBytes) {
            sync_save_and_respond(507, $lockFp, $stateFile, $state, 'Insufficient Storage: Global sync quota exceeded', $commonHeaders);
        }

        $mediaFile = $dataDir . DIRECTORY_SEPARATOR . $mediaId . '.media.bin';
        if (!sync_atomic_write($mediaFile, $rawBody)) {
            sync_save_and_respond(500, $lockFp, $stateFile, $state, 'Internal Server Error: Failed to write media blob', $commonHeaders);
        }

        $state['media_blobs'][$mediaId] = [
            'owner' => $pubkey,
            'size'  => $newSize,
            'mtime' => $now,
        ];
        $state['used_bytes'] = max(0, $state['used_bytes'] + $delta);
        if (!save_state($stateFile, $state)) {
            sync_respond(500, $lockFp, 'Internal Server Error: Failed to persist state', $commonHeaders);
        }

        $newEtag = hash('sha256', $rawBody);
        sync_respond(200, $lockFp, json_encode([
            'status'  => 'ok',
            'channel' => 'media',
            'bytes'   => $newSize,
            'etag'    => $newEtag,
        ], JSON_UNESCAPED_SLASHES), array_merge($commonHeaders, [
            'Content-Type' => 'application/json; charset=utf-8',
            'ETag'         => '"' . $newEtag . '"',
        ]));
    }

    // Standard slot channels (card, wot, backup, post)
    $slotFile = $dataDir . DIRECTORY_SEPARATOR . build_slot_filename($pubkey, $prefix, $channel);
    $currentEtag = null;
    $oldSize = 0;
    if (file_exists($slotFile)) {
        clearstatcache(true, $slotFile);
        $mtime = filemtime($slotFile);
        $ttlDays = (int)$channelCfg['ttl_days'];
        if ($mtime !== false && ($ttlDays <= 0 || ($now - $mtime <= $ttlDays * 86400))) {
            $currentEtag = hash_file('sha256', $slotFile);
            $sz = filesize($slotFile);
            $oldSize = ($sz !== false) ? $sz : 0;
        }
    }

    sync_check_put_preconditions($currentEtag, $lockFp, $stateFile, $state, $commonHeaders);

    // Verify lock signing key availability (anti-amnesia) BEFORE evicting media or committing slot
    try {
        $lockKeys = lock_load_or_init_keys($dataDir);
    } catch (LockAbort $e) {
        sync_save_and_respond($e->status, $lockFp, $stateFile, $state, $e->getMessage(), $commonHeaders);
    }

    // Hard quota check with active priority eviction of oldest media blobs
    $newSize = strlen($rawBody);
    $delta = $newSize - $oldSize;
    $totalAllMediaBytes = 0;
    if (isset($state['media_blobs']) && is_array($state['media_blobs'])) {
        foreach ($state['media_blobs'] as $mId => $mInfo) {
            $mFile = $dataDir . DIRECTORY_SEPARATOR . $mId . '.media.bin';
            $mSz = isset($mInfo['size']) ? (int)$mInfo['size'] : 0;
            if (file_exists($mFile)) {
                $realSz = filesize($mFile);
                if ($realSz !== false) {
                    $mSz = $realSz;
                }
            }
            $totalAllMediaBytes += $mSz;
        }
    }
    if (($state['used_bytes'] - $totalAllMediaBytes) + $delta > $maxTotalBytes) {
        sync_save_and_respond(507, $lockFp, $stateFile, $state, 'Insufficient Storage: Global sync quota exceeded', $commonHeaders);
    }

    $slotBaseName = build_slot_filename($pubkey, $prefix, $channel);
    if (!ensure_user_quota_with_media_eviction($dataDir, $state, $pubkey, $newSize, $maxUserBytesLimit, $slotBaseName, null)) {
        sync_save_and_respond(507, $lockFp, $stateFile, $state, 'Insufficient Storage: Account total quota exceeded', $commonHeaders);
    }
    if ($state['used_bytes'] + $delta > $maxTotalBytes) {
        if (!evict_oldest_media_for_space($dataDir, $state, $delta, $maxTotalBytes)) {
            sync_save_and_respond(507, $lockFp, $stateFile, $state, 'Insufficient Storage: Global sync quota exceeded', $commonHeaders);
        }
    }

    if (!sync_atomic_write($slotFile, $rawBody)) {
        sync_save_and_respond(500, $lockFp, $stateFile, $state, 'Internal Server Error: Failed to write slot', $commonHeaders);
    }

    $state['used_bytes'] = max(0, $state['used_bytes'] + $delta);
    rebuild_index($dataDir, $channels);
    if (!save_state($stateFile, $state)) {
        sync_respond(500, $lockFp, 'Internal Server Error: Failed to persist state', $commonHeaders);
    }

    $newEtag = hash('sha256', $rawBody);
    $ackPrefixJson = ($prefix !== '') ? $prefix : null;
    $ackMsg = "HUMOCO-SLOT-ACK-V1\n{$lockKeys['pkHex']}\n{$pubkey}\n{$prefix}\n{$channel}\n{$newEtag}\n{$now}";
    $ackSig = bin2hex(sodium_crypto_sign_detached($ackMsg, $lockKeys['sk64']));
    sync_respond(200, $lockFp, json_encode([
        'status'   => 'ok',
        'channel'  => $channel,
        'bytes'    => $newSize,
        'etag'     => $newEtag,
        'slot_ack' => [
            'lock_pub'  => $lockKeys['pkHex'],
            'pubkey'    => $pubkey,
            'prefix'    => $ackPrefixJson,
            'channel'   => $channel,
            'etag'      => $newEtag,
            'timestamp' => $now,
            'sig'       => $ackSig,
        ],
    ], JSON_UNESCAPED_SLASHES), array_merge($commonHeaders, [
        'Content-Type' => 'application/json; charset=utf-8',
        'ETag'         => '"' . $newEtag . '"',
    ]));
}

// =========================================================================
// ROUTE 6b: DELETE sync.php?account (Full Account & Data Wipe)
// =========================================================================
if ($method === 'DELETE' && isset($_GET['account']) && count($_GET) === 1) {
    $pubkey = isset($_SERVER['HTTP_X_DROP_PUBKEY']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_PUBKEY'])) : '';
    $timestampRaw = isset($_SERVER['HTTP_X_DROP_TIMESTAMP']) ? trim((string)$_SERVER['HTTP_X_DROP_TIMESTAMP']) : '';
    $nonce = isset($_SERVER['HTTP_X_DROP_NONCE']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_NONCE'])) : '';
    $signature = isset($_SERVER['HTTP_X_DROP_SIGNATURE']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_SIGNATURE'])) : '';

    if ($timestampRaw === '' || !sync_is_int_timestamp($timestampRaw) || !preg_match('/\A[0-9a-f]{32}\z/', $nonce) || !preg_match('/\A[0-9a-f]{128}\z/', $signature) || !preg_match('/\A[0-9a-f]{64}\z/', $pubkey)) {
        sync_fail_ip_and_respond(400, $lockFp, 'Bad Request: Invalid auth headers', $commonHeaders);
    }
    $timestamp = (int)$timestampRaw;
    if (abs($now - $timestamp) > 60) {
        sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Timestamp outside allowed window', $commonHeaders);
    }

    $canonicalMsg = "HUMOCO-DROP-REQ-V1\nDELETE_ACCOUNT\n\n{$timestamp}\n{$nonce}\n" . hash('sha256', '');
    if (!verify_ed25519_detached($signature, $canonicalMsg, $pubkey)) {
        sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Invalid request signature', $commonHeaders);
    }

    sync_check_member_ratelimit($disableRateLimit, $lockFp, $stateFile, $state, $pubkey, $now, $commonHeaders);

    if (isset($state['nonces'][$nonce])) {
        sync_save_and_respond(409, $lockFp, $stateFile, $state, 'Conflict: Replay detected', $commonHeaders);
    }
    $state['nonces'][$nonce] = $now;

    $deletedAnySlot = false;
    $existingBins = glob($dataDir . DIRECTORY_SEPARATOR . '*.*.bin');
    if ($existingBins !== false) {
        foreach ($existingBins as $file) {
            $base = basename($file);
            $parsed = parse_slot_filename($base);
            if ($parsed !== null && $parsed['id'] === $pubkey && $parsed['channel'] !== 'media') {
                $sz = filesize($file);
                @unlink($file);
                if ($sz !== false) {
                    $state['used_bytes'] = max(0, $state['used_bytes'] - $sz);
                }
                $deletedAnySlot = true;
            }
        }
    }

    if (isset($state['media_blobs']) && is_array($state['media_blobs'])) {
        foreach ($state['media_blobs'] as $mId => $mInfo) {
            if (isset($mInfo['owner']) && $mInfo['owner'] === $pubkey) {
                $mFile = $dataDir . DIRECTORY_SEPARATOR . $mId . '.media.bin';
                if (file_exists($mFile)) {
                    $sz = filesize($mFile);
                    @unlink($mFile);
                    if ($sz !== false) {
                        $state['used_bytes'] = max(0, $state['used_bytes'] - $sz);
                    }
                } else {
                    $sz = isset($mInfo['size']) ? (int)$mInfo['size'] : 0;
                    $state['used_bytes'] = max(0, $state['used_bytes'] - $sz);
                }
                unset($state['media_blobs'][$mId]);
            }
        }
    }

    if ($deletedAnySlot) {
        rebuild_index($dataDir, $channels);
    }

    sync_save_and_respond(200, $lockFp, $stateFile, $state, json_encode([
        'status'          => 'ok',
        'deleted_account' => $pubkey,
    ], JSON_UNESCAPED_SLASHES), array_merge($commonHeaders, [
        'Content-Type' => 'application/json; charset=utf-8',
    ]));
}

// =========================================================================
// ROUTE 7: DELETE sync.php (Member Slot or Media Delete)
// =========================================================================
if ($method === 'DELETE' && empty($_GET)) {
    respond_if_revoked($state, $now, $lockFp, $commonHeaders);
    $channel = isset($_SERVER['HTTP_X_CHANNEL']) ? trim((string)$_SERVER['HTTP_X_CHANNEL']) : '';
    if (!preg_match('/\A[a-z0-9_]{1,32}\z/', $channel) || !isset($channels[$channel])) {
        sync_respond(404, $lockFp, 'Not Found', $commonHeaders);
    }

    $prefix = extract_and_validate_prefix();
    if ($prefix === false || ($channel === 'media' && $prefix !== '')) {
        sync_fail_ip_and_respond(400, $lockFp, 'Bad Request: Invalid X-Drop-Prefix', $commonHeaders);
    }

    $pubkey = isset($_SERVER['HTTP_X_DROP_PUBKEY']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_PUBKEY'])) : '';
    $timestampRaw = isset($_SERVER['HTTP_X_DROP_TIMESTAMP']) ? trim((string)$_SERVER['HTTP_X_DROP_TIMESTAMP']) : '';
    $nonce = isset($_SERVER['HTTP_X_DROP_NONCE']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_NONCE'])) : '';
    $signature = isset($_SERVER['HTTP_X_DROP_SIGNATURE']) ? strtolower(trim((string)$_SERVER['HTTP_X_DROP_SIGNATURE'])) : '';

    if ($timestampRaw === '' || !sync_is_int_timestamp($timestampRaw) || !preg_match('/\A[0-9a-f]{32}\z/', $nonce) || !preg_match('/\A[0-9a-f]{128}\z/', $signature) || !preg_match('/\A[0-9a-f]{64}\z/', $pubkey)) {
        sync_fail_ip_and_respond(400, $lockFp, 'Bad Request: Invalid auth headers', $commonHeaders);
    }
    $timestamp = (int)$timestampRaw;
    if (abs($now - $timestamp) > 60) {
        sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Timestamp outside allowed window', $commonHeaders);
    }

    $channelMembers = load_channel_members($configFile, $channel);
    $isMember = in_array($pubkey, $channelMembers, true);

    if ($channel === 'media') {
        $mediaId = isset($_SERVER['HTTP_X_MEDIA_ID']) ? strtolower(trim((string)$_SERVER['HTTP_X_MEDIA_ID'])) : '';
        if ($mediaId !== '') {
            if (!preg_match('/\A[0-9a-f]{64}\z/', $mediaId)) {
                sync_fail_ip_and_respond(400, $lockFp, 'Bad Request: Invalid X-Media-Id', $commonHeaders);
            }
            $canonicalMsg = "HUMOCO-DROP-REQ-V1\nDELETE\nmedia:{$mediaId}\n\n{$timestamp}\n{$nonce}\n" . hash('sha256', '');
        } else {
            $canonicalMsg = "HUMOCO-DROP-REQ-V1\nDELETE\nmedia\n\n{$timestamp}\n{$nonce}\n" . hash('sha256', '');
        }

        if (!verify_ed25519_detached($signature, $canonicalMsg, $pubkey)) {
            sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Invalid request signature', $commonHeaders);
        }

        if (!$isMember) {
            $ownsAny = false;
            if (isset($state['media_blobs']) && is_array($state['media_blobs'])) {
                foreach ($state['media_blobs'] as $mInfo) {
                    if (isset($mInfo['owner']) && $mInfo['owner'] === $pubkey) {
                        $ownsAny = true;
                        break;
                    }
                }
            }
            if (!$ownsAny) {
                sync_fail_ip_and_respond(404, $lockFp, 'Not Found', $commonHeaders);
            }
        }

        sync_check_member_ratelimit($disableRateLimit, $lockFp, $stateFile, $state, $pubkey, $now, $commonHeaders);

        if (isset($state['nonces'][$nonce])) {
            sync_save_and_respond(409, $lockFp, $stateFile, $state, 'Conflict: Replay detected', $commonHeaders);
        }
        $state['nonces'][$nonce] = $now;

        if ($mediaId !== '') {
            if (isset($state['media_blobs'][$mediaId])) {
                if ($state['media_blobs'][$mediaId]['owner'] !== $pubkey) {
                    sync_save_and_respond(403, $lockFp, $stateFile, $state, 'Forbidden: Media blob owned by another member', $commonHeaders);
                }
                $mFile = $dataDir . DIRECTORY_SEPARATOR . $mediaId . '.media.bin';
                if (file_exists($mFile)) {
                    $sz = filesize($mFile);
                    @unlink($mFile);
                    if ($sz !== false) {
                        $state['used_bytes'] = max(0, $state['used_bytes'] - $sz);
                    }
                } else {
                    $sz = isset($state['media_blobs'][$mediaId]['size']) ? (int)$state['media_blobs'][$mediaId]['size'] : 0;
                    $state['used_bytes'] = max(0, $state['used_bytes'] - $sz);
                }
                unset($state['media_blobs'][$mediaId]);
            } else {
                $mFile = $dataDir . DIRECTORY_SEPARATOR . $mediaId . '.media.bin';
                if (file_exists($mFile)) {
                    $sz = filesize($mFile);
                    @unlink($mFile);
                    if ($sz !== false) {
                        $state['used_bytes'] = max(0, $state['used_bytes'] - $sz);
                    }
                }
            }
            sync_save_and_respond(200, $lockFp, $stateFile, $state, json_encode([
                'status'  => 'ok',
                'channel' => 'media',
            ], JSON_UNESCAPED_SLASHES), array_merge($commonHeaders, [
                'Content-Type' => 'application/json; charset=utf-8',
            ]));
        } else {
            // Delete all media blobs where owner === pubkey
            if (isset($state['media_blobs']) && is_array($state['media_blobs'])) {
                foreach ($state['media_blobs'] as $mId => $mInfo) {
                    if (isset($mInfo['owner']) && $mInfo['owner'] === $pubkey) {
                        $mFile = $dataDir . DIRECTORY_SEPARATOR . $mId . '.media.bin';
                        if (file_exists($mFile)) {
                            $sz = filesize($mFile);
                            @unlink($mFile);
                            if ($sz !== false) {
                                $state['used_bytes'] = max(0, $state['used_bytes'] - $sz);
                            }
                        } else {
                            $sz = isset($mInfo['size']) ? (int)$mInfo['size'] : 0;
                            $state['used_bytes'] = max(0, $state['used_bytes'] - $sz);
                        }
                        unset($state['media_blobs'][$mId]);
                    }
                }
            }
            sync_save_and_respond(200, $lockFp, $stateFile, $state, json_encode([
                'status'  => 'ok',
                'channel' => 'media',
            ], JSON_UNESCAPED_SLASHES), array_merge($commonHeaders, [
                'Content-Type' => 'application/json; charset=utf-8',
            ]));
        }
    }

    // Standard slot channels
    $slotFile = $dataDir . DIRECTORY_SEPARATOR . build_slot_filename($pubkey, $prefix, $channel);
    $slotExists = file_exists($slotFile);

    $canonicalMsg = "HUMOCO-DROP-REQ-V1\nDELETE\n{$channel}\n{$prefix}\n{$timestamp}\n{$nonce}\n" . hash('sha256', '');
    if (!verify_ed25519_detached($signature, $canonicalMsg, $pubkey)) {
        sync_fail_ip_and_respond(401, $lockFp, 'Unauthorized: Invalid request signature', $commonHeaders);
    }

    if (!$isMember && !$slotExists) {
        sync_fail_ip_and_respond(404, $lockFp, 'Not Found', $commonHeaders);
    }

    sync_check_member_ratelimit($disableRateLimit, $lockFp, $stateFile, $state, $pubkey, $now, $commonHeaders);

    if (isset($state['nonces'][$nonce])) {
        sync_save_and_respond(409, $lockFp, $stateFile, $state, 'Conflict: Replay detected', $commonHeaders);
    }
    $state['nonces'][$nonce] = $now;

    if ($slotExists) {
        $sz = filesize($slotFile);
        @unlink($slotFile);
        if ($sz !== false) {
            $state['used_bytes'] = max(0, $state['used_bytes'] - $sz);
        }
        rebuild_index($dataDir, $channels);
    }

    sync_save_and_respond(200, $lockFp, $stateFile, $state, json_encode([
        'status'  => 'ok',
        'channel' => $channel,
    ], JSON_UNESCAPED_SLASHES), array_merge($commonHeaders, [
        'Content-Type' => 'application/json; charset=utf-8',
    ]));
}

header('Allow: GET, HEAD, PUT, DELETE, POST');
sync_respond(405, $lockFp, 'Method Not Allowed', $commonHeaders);
