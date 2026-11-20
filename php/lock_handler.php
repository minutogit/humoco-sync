<?php
/**
 * HuMoCo Lock Channel Handler (SPEC.md Section 6, Concept Sections 5 & 6).
 * Strictly isolated from .state.php, global .lock, rebuild_index(), and media logic.
 */

const LOCK_KEY_HEADER = "<?php http_response_code(403); __halt_compiler(); ?>\n";
const LOCK_ENTRY_WIRE_LEN = 605;
const LOCK_ENTRY_ID_LEN = 597;
const LOCK_MAX_CHAIN_LEN = 64;
const LOCK_SHA3_ABC_KAT = '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532';

final class LockAbort extends \RuntimeException {
    public function __construct(public readonly int $status, string $msg, public readonly array $extra = []) { parent::__construct($msg); }
}
function lock_fail(int $code, string $msg, array $extra = []): never { throw new LockAbort($code, $msg, $extra); }
function lock_ok(int $code, mixed $data, bool $noStore = false): never {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    if ($noStore) header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_SLASHES) . "\n";
    exit;
}
function lock_cfg(array $config): array {
    $l = isset($config['lock']) && is_array($config['lock']) ? $config['lock'] : [];
    return [
        'enabled' => array_key_exists('enabled', $l) ? (bool)$l['enabled'] : true,
        'max_retention_quarter' => (int)($l['max_retention_quarter'] ?? 8159),
        'max_inodes' => max(1, (int)($l['max_inodes'] ?? 50000)),
        'pow_base_bits' => (int)($l['pow_base_bits'] ?? 8),
        'allow_pow_tickets' => !empty($l['allow_pow_tickets']),
        'ticket_pow_bits' => (int)($l['ticket_pow_bits'] ?? 16),
        'pre_freeze_ttl_secs' => max(1, (int)($l['pre_freeze_ttl_secs'] ?? 1800)),
        'proposal_timelock_secs' => (int)($l['proposal_timelock_secs'] ?? 259200),
        'creator_inactivity_secs' => (int)($l['creator_inactivity_secs'] ?? 2592000),
    ];
}
function lock_hex_bytes(mixed $val, int $bytes): ?string {
    if (!is_string($val) || strlen($val) !== $bytes * 2 || !preg_match('/^[0-9a-f]+$/', $val)) return null;
    $raw = hex2bin($val);
    return ($raw !== false && strlen($raw) === $bytes) ? $raw : null;
}
function lock_verify_sig(string $pk32, string $sig64, string $msg): bool {
    if (strlen($pk32) !== 32 || strlen($sig64) !== 64) return false;
    try { return sodium_crypto_sign_verify_detached($sig64, $msg, $pk32); }
    catch (\Throwable) { return false; }
}
function lock_sign(string $sk64, string $msg): string { return sodium_crypto_sign_detached($msg, $sk64); }
function lock_zero_bits(string $h32): int {
    $z = 0;
    for ($i = 0; $i < 32; $i++) {
        $b = ord($h32[$i]);
        if ($b === 0) { $z += 8; continue; }
        for ($k = 7; $k >= 0; $k--) { if (($b & (1 << $k)) !== 0) break 2; $z++; }
    }
    return $z;
}
function lock_decode_quarter(int $q): ?array {
    if ($q < 0) return null;
    $year = intdiv($q, 4);
    return ($year < 2020 || $year > 9999) ? null : [$year, ($q % 4) + 1];
}
function lock_format_quarter(int $q): ?string {
    $d = lock_decode_quarter($q);
    return $d === null ? null : sprintf('%04d-Q%d', $d[0], $d[1]);
}
function lock_purge_after_secs(int $q): ?int {
    $d = lock_decode_quarter($q);
    if ($d === null) return null;
    [$y, $qn] = $d;
    $ny = ($qn === 4) ? $y + 1 : $y;
    $nm = ($qn === 4) ? 1 : ($qn * 3 + 1);
    return (new DateTimeImmutable(sprintf('%04d-%02d-01 00:00:00', $ny, $nm), new DateTimeZone('UTC')))->getTimestamp() + 30 * 86400;
}
function lock_paths(string $dataDir): array {
    $meta = $dataDir . '/.locks_meta';
    foreach ([$dataDir . '/locks', $dataDir . '/anchors', $meta, "$meta/buckets", "$meta/rotations"] as $d) {
        if (!is_dir($d) && !mkdir($d, 0755, true) && !is_dir($d)) lock_fail(500, 'Failed to create lock directory');
    }
    $ht = $meta . '/.htaccess';
    if (!file_exists($ht)) {
        @file_put_contents($ht, "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n");
    }
    return ['locks' => $dataDir . '/locks', 'anchors' => $dataDir . '/anchors', 'meta' => $meta];
}
function lock_atomic_write(string $path, string $bytes): bool {
    $dir = dirname($path);
    if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) return false;
    $tmp = $dir . '/.tmp.' . basename($path) . '.' . getmypid() . '.' . bin2hex(random_bytes(4));
    $fp = @fopen($tmp, 'xb');
    if ($fp === false) return false;
    $ok = fwrite($fp, $bytes) === strlen($bytes) && fflush($fp) && fsync($fp);
    fclose($fp);
    if (!$ok || !@rename($tmp, $path)) { @unlink($tmp); return false; }
    return true;
}
function lock_with_lock(string $lockDir, callable $fn): mixed {
    $start = microtime(true);
    while (!@mkdir($lockDir, 0700)) {
        clearstatcache(true, $lockDir);
        if (is_dir($lockDir)) {
            $mt = @filemtime($lockDir);
            if ($mt !== false && (time() - $mt) > 45) { @rmdir($lockDir); continue; }
        }
        if ((microtime(true) - $start) > 6.0) lock_fail(503, 'Lock busy timeout');
        usleep(random_int(1500, 12000));
    }
    try { return $fn(); } finally { @rmdir($lockDir); }
}
function lock_read_json(string $path): ?array {
    clearstatcache(true, $path);
    $raw = @file_get_contents($path);
    if ($raw === false || $raw === '') return null;
    $d = json_decode($raw, true);
    return is_array($d) ? $d : null;
}
function lock_has_existing_buckets(array $p): bool {
    if (count(glob($p['meta'] . '/buckets/*.json') ?: []) > 0) return true;
    foreach (glob($p['locks'] . '/*', GLOB_ONLYDIR) ?: [] as $qd) {
        if (count(glob($qd . '/*', GLOB_ONLYDIR) ?: []) > 0) return true;
    }
    return false;
}

function lock_load_or_init_keys(string $dataDir): array {
    $p = lock_paths($dataDir);
    $keyPath = $dataDir . '/.lock_key.php';
    $hdrLen = strlen(LOCK_KEY_HEADER);
    $readKey = static function () use ($keyPath, $hdrLen): ?array {
        clearstatcache(true, $keyPath);
        $raw = @file_get_contents($keyPath);
        if ($raw === false || strlen($raw) !== $hdrLen + 64 || !str_starts_with($raw, LOCK_KEY_HEADER)) return null;
        $sk64 = substr($raw, $hdrLen, 64);
        $pk32 = sodium_crypto_sign_publickey_from_secretkey($sk64);
        return ['sk64' => $sk64, 'pk32' => $pk32, 'pkHex' => bin2hex($pk32)];
    };
    if (file_exists($keyPath)) return $readKey() ?? lock_fail(500, 'Corrupted .lock_key.php');
    if (lock_has_existing_buckets($p)) lock_fail(500, 'Anti-amnesia halt: lock buckets exist without .lock_key.php');
    $kp = sodium_crypto_sign_keypair();
    $payload = LOCK_KEY_HEADER . sodium_crypto_sign_secretkey($kp);
    $tmp = $dataDir . '/.tmp.lockkey.' . getmypid() . '.' . bin2hex(random_bytes(4));
    $fp = @fopen($tmp, 'xb');
    if ($fp === false) lock_fail(500, 'Failed to allocate .lock_key.php');
    $wrote = fwrite($fp, $payload) === strlen($payload) && fflush($fp) && fsync($fp);
    fclose($fp);
    if (!$wrote) { @unlink($tmp); lock_fail(500, 'Failed to flush .lock_key.php'); }
    $linked = @link($tmp, $keyPath);
    if (!$linked) {
        clearstatcache(true, $tmp);
        $st = @stat($tmp);
        if (is_array($st) && (($st['nlink'] ?? 0) >= 2)) $linked = true;
    }
    @unlink($tmp);
    return $readKey() ?? lock_fail(500, 'Failed to read initialized .lock_key.php');
}

function lock_used_inodes_get(array $p): int {
    $raw = @file_get_contents($p['meta'] . '/used_inodes.txt');
    return ($raw !== false && is_numeric(trim($raw))) ? max(0, (int)trim($raw)) : 0;
}

function lock_used_inodes_add(array $p, int $delta): int {
    if ($delta === 0) return lock_used_inodes_get($p);
    return lock_with_lock($p['meta'] . '/.inodes.lockdir', static function () use ($p, $delta): int {
        $next = max(0, lock_used_inodes_get($p) + $delta);
        lock_atomic_write($p['meta'] . '/used_inodes.txt', (string)$next);
        return $next;
    });
}

function lock_ip_ratelimit_allow(array $p, bool $disable): bool {
    if ($disable) return true;
    $pepFile = $p['meta'] . '/pepper.bin';
    $pep = @file_get_contents($pepFile);
    if ($pep === false || strlen($pep) !== 16) { $pep = random_bytes(16); lock_atomic_write($pepFile, $pep); }
    $rlFile = $p['meta'] . '/ratelimit.bin.php';
    return lock_with_lock($p['meta'] . '/.rl.lockdir', static function () use ($rlFile, $pep): bool {
        $fp = @fopen($rlFile, 'c+b');
        if ($fp === false) return true;
        if ((fstat($fp)['size'] ?? 0) < 65564) { fseek($fp, 0); fwrite($fp, "<?php __halt_compiler(); ?>\n" . str_repeat("\0", 65536)); }
        $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');
        $h = hash_hmac('sha256', $ip, gmdate('Y-m-d') . '|' . $pep, true);
        $idx = unpack('V', substr($h, 0, 4))[1] & 4095;
        $tag = unpack('V', substr($h, 4, 4))[1] ?: 1;
        $now = time();
        fseek($fp, 28 + $idx * 16);
        $raw = fread($fp, 16);
        $b = ($raw !== false && strlen($raw) === 16) ? unpack('VipTag/VlastTs/ftokens/VfailCount', $raw) : ['ipTag' => 0, 'lastTs' => $now, 'tokens' => 60.0, 'failCount' => 0];
        if ($b['ipTag'] !== $tag) $b = ['ipTag' => $tag, 'lastTs' => $now, 'tokens' => 60.0, 'failCount' => 0];
        else { $b['tokens'] = min(60.0, $b['tokens'] + max(0, $now - $b['lastTs']) * 2.0); $b['lastTs'] = $now; }
        $allow = $b['tokens'] >= 1.0;
        if ($allow) $b['tokens'] -= 1.0;
        fseek($fp, 28 + $idx * 16);
        fwrite($fp, pack('VVfV', $b['ipTag'], $b['lastTs'], (float)$b['tokens'], (int)$b['failCount']));
        fflush($fp);
        fclose($fp);
        return $allow;
    });
}

function lock_consume_nonce(array $p, string $nonceKey, int $ttlSecs, int $now): bool {
    return lock_with_lock($p['meta'] . '/.nonces.lockdir', static function () use ($p, $nonceKey, $ttlSecs, $now): bool {
        $nf = $p['meta'] . '/nonces.json';
        $map = lock_read_json($nf) ?? [];
        foreach ($map as $k => $exp) { if ((int)$exp <= $now) unset($map[$k]); }
        if (isset($map[$nonceKey]) && (int)$map[$nonceKey] > $now) return false;
        $map[$nonceKey] = $now + $ttlSecs;
        lock_atomic_write($nf, json_encode($map, JSON_UNESCAPED_SLASHES));
        return true;
    });
}

function lock_build_selftest(string $dataDir, array $cfg, array $keys, int $now): array {
    $p = lock_paths($dataDir);
    $extSodium = (function_exists('sodium_crypto_sign_detached') && function_exists('sodium_crypto_sign_verify_detached')) ? 'pass' : 'fail';
    $sha3 = (in_array('sha3-256', hash_algos(), true) && hash('sha3-256', 'abc') === LOCK_SHA3_ABC_KAT) ? 'pass' : 'fail';
    $fsyncOk = 'fail'; $linkOk = 'fail'; $probeW = 'fail';
    $t1 = $p['meta'] . '/.st1.' . getmypid(); $t2 = $p['meta'] . '/.st2.' . getmypid(); $tl = $p['meta'] . '/.stl.' . getmypid();
    @unlink($t1); @unlink($t2); @unlink($tl);
    $fp = @fopen($t1, 'xb');
    if ($fp !== false) {
        $w = fwrite($fp, 'kat1') === 4 && fflush($fp);
        $fs = $w && function_exists('fsync') && fsync($fp);
        fclose($fp);
        $fsyncOk = $fs ? 'pass' : 'fail'; $probeW = $w ? 'pass' : 'fail';
        if (@file_put_contents($t2, 'kat2') === 4 && @link($t1, $tl) && !@link($t2, $tl) && @file_get_contents($tl) === 'kat1') $linkOk = 'pass';
    }
    @unlink($t1); @unlink($t2); @unlink($tl);
    @ignore_user_abort(true);
    $abortOk = (ignore_user_abort() === 1) ? 'pass' : 'fail';
    $used = lock_used_inodes_get($p); $free = max(0, $cfg['max_inodes'] - $used);
    $inodeOk = ($free > 0) ? 'pass' : 'fail';
    $fastcgi = function_exists('fastcgi_finish_request') ? 'pass' : 'not_applicable';
    $checks = ['ext_sodium' => $extSodium, 'sha3_256' => $sha3, 'atomic_link_eexist' => $linkOk, 'fsync' => $fsyncOk, 'ignore_user_abort' => $abortOk, 'storage_writable' => $probeW, 'inode_budget' => $inodeOk, 'fastcgi_finish_request' => $fastcgi];
    $allPassed = ($free > 0) && !in_array('fail', $checks, true);
    $line = implode(',', array_values($checks)) . ',' . $free;
    $msg = "HUMOCO-LOCK-SELFTEST-V1\nphp\n{$now}\n{$keys['pkHex']}\n" . ($allPassed ? '1' : '0') . "\n" . hash('sha256', $line);
    $report = ['runtime' => 'php', 'checked_at' => $now, 'lock_pub' => $keys['pkHex'], 'php_version' => PHP_VERSION, 'checks' => $checks, 'free_inodes' => $free, 'all_passed' => $allPassed, 'sig' => bin2hex(lock_sign($keys['sk64'], $msg))];
    lock_atomic_write($p['meta'] . '/selftest.json', json_encode($report, JSON_UNESCAPED_SLASHES));
    return $report;
}

function lock_get_info_payload(array $config, string $configFile, string $dataDir, int $now): ?array {
    if (PHP_VERSION_ID < 80100) return null;
    $cfg = lock_cfg($config);
    if (!$cfg['enabled']) return null;
    try {
        $p = lock_paths($dataDir); $keys = lock_load_or_init_keys($dataDir);
        $selftest = lock_read_json($p['meta'] . '/selftest.json') ?? lock_build_selftest($dataDir, $cfg, $keys, $now);
        $del = lock_read_json($p['meta'] . '/delegation.json');
        $used = lock_used_inodes_get($p);
        return ['lock_pub' => $keys['pkHex'], 'delegation' => $del, 'max_retention_quarter' => $cfg['max_retention_quarter'], 'max_inodes' => $cfg['max_inodes'], 'used_inodes' => $used, 'inode_warning' => ($used * 100 >= $cfg['max_inodes'] * 80), 'pow_base_bits' => $cfg['pow_base_bits'], 'allow_pow_tickets' => $cfg['allow_pow_tickets'], 'selftest' => $selftest];
    } catch (LockAbort) { return null; }
}

function lock_is_valid_url(mixed $url): bool {
    if (!is_string($url) || $url === '' || strlen($url) > 2048) return false;
    if (!str_starts_with($url, 'https://') && !str_starts_with($url, 'http://')) return false;
    return preg_match('/[\x00-\x20\x7f]/', $url) !== 1;
}

function lock_encode_server(array $s, int $gCount): ?string {
    $wu = $s['write_url'] ?? null; $ru = $s['read_url'] ?? null;
    $ap = lock_hex_bytes($s['admin_pub'] ?? null, 32); $lp = lock_hex_bytes($s['lock_pub'] ?? null, 32);
    $nb = $s['nominated_by'] ?? null;
    if (!is_string($wu) || $wu === '' || strlen($wu) > 2048 || !is_string($ru) || $ru === '' || strlen($ru) > 2048 || $ap === null || $lp === null) return null;
    if ($nb === 'creator') $nbBytes = "\x00";
    elseif (is_array($nb) && isset($nb['guarantor']) && is_int($nb['guarantor']) && $nb['guarantor'] >= 0 && $nb['guarantor'] < $gCount) $nbBytes = "\x01" . chr($nb['guarantor']);
    else return null;
    return $ap . $lp . $nbBytes;
}

function lock_validate_committee(array $servers, int $q): ?array {
    $n = count($servers);
    if ($n < 1 || $n > 5 || $q < 1 || $q > $n || (2 * $q <= $n)) return null;
    $seen = [];
    foreach ($servers as $s) {
        $lp = $s['lock_pub'] ?? '';
        if (lock_hex_bytes($lp, 32) === null || isset($seen[$lp])) return null;
        $seen[$lp] = true;
    }
    return ['members' => array_keys($seen), 'threshold' => $q];
}

function lock_rev1_anchor_id(array $m): ?string {
    if (($m['revision'] ?? 0) !== 1 || !empty($m['migration_chain'] ?? []) || !is_int($m['issued_at_ms'] ?? null) || $m['issued_at_ms'] <= 0) return null;
    $q = $m['retain_until_quarter'] ?? null;
    if (!is_int($q) || lock_decode_quarter($q) === null) return null;
    $auth = $m['authority'] ?? null; $cMig = lock_hex_bytes($auth['creator_mig_pub'] ?? null, 32); $gPubs = $auth['guarantor_mig_pubs'] ?? null;
    if ($cMig === null || !is_array($gPubs) || count($gPubs) > 32) return null;
    $gBin = ''; $seenAuth = [$cMig => true];
    foreach ($gPubs as $gp) { $gb = lock_hex_bytes($gp, 32); if ($gb === null || isset($seenAuth[$gb])) return null; $seenAuth[$gb] = true; $gBin .= $gb; }
    $gCnt = count($gPubs); $srvs = $m['servers'] ?? []; $succs = $m['successors'] ?? [];
    if (!is_array($srvs) || !is_array($succs) || lock_validate_committee($srvs, (int)($m['threshold'] ?? 0)) === null) return null;
    $sBin = ''; $activePks = [];
    foreach ($srvs as $s) { $enc = lock_encode_server($s, $gCnt); if ($enc === null) return null; $sBin .= $enc; $activePks[$s['lock_pub']] = true; }
    $suBin = ''; $suPks = [];
    foreach ($succs as $s) {
        $enc = lock_encode_server($s, $gCnt);
        if ($enc === null || isset($activePks[$s['lock_pub']]) || isset($suPks[$s['lock_pub']])) return null;
        $suPks[$s['lock_pub']] = true; $suBin .= $enc;
    }
    return hash('sha256', "HUMOCO_ANCHOR_MANIFEST_V1\0" . pack('P', 1) . chr((int)$m['threshold']) . chr(count($srvs)) . $sBin . pack('v', count($succs)) . $suBin . $cMig . chr($gCnt) . $gBin . pack('P', $m['issued_at_ms']) . pack('v', $q), true);
}

function lock_parse_entry(string $wireHex): ?array {
    $wire = lock_hex_bytes($wireHex, LOCK_ENTRY_WIRE_LEN);
    if ($wire === null || substr($wire, 0, 4) !== 'HMLK' || ord($wire[4]) !== 1) return null;
    $ob = ord($wire[69]); $depth = unpack('V', substr($wire, 70, 4))[1];
    $hasChange = ord($wire[170]); $hasRoot = ord($wire[267]);
    if ($ob > 1 || ($hasChange !== 0 && $hasChange !== 1) || ($hasRoot !== 0 && $hasRoot !== 1)) return null;
    $parentSlot = substr($wire, 37, 32); $zeros32 = str_repeat("\0", 32);
    if ($hasChange === 0 && substr($wire, 171, 32) !== $zeros32) return null;
    if ($hasRoot === 0 && (substr($wire, 268, 64) !== str_repeat("\0", 64) || $depth === 0)) return null;
    if ($hasRoot === 1 && $depth !== 0) return null;
    if ($depth === 0 && ($parentSlot !== $zeros32 || $ob !== 0)) return null;
    if ($depth > 0 && $parentSlot === $zeros32) return null;
    $idBytes = substr($wire, 0, LOCK_ENTRY_ID_LEN);
    return [
        'wire' => $wire, 'hex' => $wireHex, 'idBytes' => $idBytes, 'entryHash' => hash('sha256', 'HUMOCO_LOCK_ENTRY_V1' . $idBytes, true),
        'slot' => substr($wire, 5, 32), 'parentSlot' => $parentSlot, 'ob' => $ob, 'depth' => $depth,
        'childLock' => substr($wire, 74, 32), 'senderPub' => substr($wire, 106, 32), 'recvHash' => substr($wire, 138, 32),
        'hasChange' => $hasChange, 'changeHash' => $hasChange === 1 ? substr($wire, 171, 32) : null,
        'causalSig' => substr($wire, 203, 64), 'rootMigSig' => $hasRoot === 1 ? substr($wire, 268, 64) : null, 'powNonceLe' => substr($wire, 597, 8),
    ];
}

function lock_verify_entry(array $e, string $anchor32, string $creatorMig32, int $powBaseBits, ?array $parent): ?string {
    $reqBits = min(24, $powBaseBits + intdiv($e['depth'], 16) * 2);
    if (lock_zero_bits(hash('sha256', 'HUMOCO_LOCK_POW_V1' . $e['slot'] . $e['childLock'] . pack('V', $e['depth']) . $e['powNonceLe'], true)) < $reqBits) return 'Insufficient lock entry proof-of-work';
    $ch = $e['changeHash'] ?? str_repeat("\0", 32);
    $cDig = hash('sha256', 'HUMOCO_CAUSAL_OUTPUT_V1' . $anchor32 . $e['slot'] . $e['parentSlot'] . chr($e['ob']) . pack('V', $e['depth']) . $e['childLock'] . $e['senderPub'] . $e['recvHash'] . chr($e['hasChange']) . $ch, true);
    if (!lock_verify_sig($e['senderPub'], $e['causalSig'], $cDig)) return 'Invalid causal_sig';
    if ($e['depth'] === 0) {
        if ($parent !== null || $e['rootMigSig'] === null) return 'Invalid depth 0 root entry';
        return lock_verify_sig($creatorMig32, $e['rootMigSig'], hash('sha256', 'HUMOCO_ROOT_MIG_AUTH_V1' . $anchor32 . $e['slot'] . $e['senderPub'], true)) ? null : 'Invalid root_mig_sig';
    }
    if ($parent === null || $parent['slot'] !== $e['parentSlot'] || $e['depth'] !== $parent['depth'] + 1) return 'Causal parent mismatch';
    $expHash = ($e['ob'] === 0) ? $parent['recvHash'] : $parent['changeHash'];
    return ($expHash !== null && hash('sha3-256', $e['senderPub'], true) === $expHash) ? null : 'Sender key does not match parent output';
}

function lock_verify_receipt(array $r, string $expectedLock32, string $expectedBucket32): bool {
    $kStr = $r['kind'] ?? null;
    if ($kStr === 'first_write') $kb = 0; elseif ($kStr === 'conflict_seen') $kb = 1; else return false;
    $lp = lock_hex_bytes($r['lock_pub'] ?? null, 32); $bk = lock_hex_bytes($r['bucket'] ?? null, 32);
    $sl = lock_hex_bytes($r['slot'] ?? null, 32); $cl = lock_hex_bytes($r['child_lock'] ?? null, 32);
    $eh = lock_hex_bytes($r['entry_hash'] ?? null, 32); $bh = lock_hex_bytes($r['bucket_head'] ?? null, 32);
    $rn = lock_hex_bytes($r['recipient_nonce'] ?? null, 32); $sig = lock_hex_bytes($r['sig'] ?? null, 64);
    $q = $r['retain_until_quarter'] ?? null; $ws = $r['write_seq'] ?? null;
    if ($lp !== $expectedLock32 || $bk !== $expectedBucket32 || $sl === null || $cl === null || $eh === null || $bh === null || $rn === null || $sig === null || !is_int($q) || lock_decode_quarter($q) === null || !is_int($ws) || $ws < 0) return false;
    return lock_verify_sig($lp, $sig, hash('sha256', 'HUMOCO_LOCK_RECEIPT_V1' . chr($kb) . $lp . $bk . $sl . $cl . $eh . pack('v', $q) . pack('P', $ws) . $bh . $rn, true));
}

function lock_sign_receipt(string $sk64, string $pk32, string $bucket32, int $q, string $nonce32, array $pending): array {
    $kb = ($pending['kind'] === 'first_write') ? 0 : 1;
    $dig = hash('sha256', 'HUMOCO_LOCK_RECEIPT_V1' . chr($kb) . $pk32 . $bucket32 . $pending['slot'] . $pending['childLock'] . $pending['entryHash'] . pack('v', $q) . pack('P', $pending['writeSeq']) . $pending['head'] . $nonce32, true);
    return ['kind' => $pending['kind'], 'lock_pub' => bin2hex($pk32), 'bucket' => bin2hex($bucket32), 'slot' => bin2hex($pending['slot']), 'child_lock' => bin2hex($pending['childLock']), 'entry_hash' => bin2hex($pending['entryHash']), 'retain_until_quarter' => $q, 'write_seq' => $pending['writeSeq'], 'bucket_head' => bin2hex($pending['head']), 'recipient_nonce' => bin2hex($nonce32), 'sig' => bin2hex(lock_sign($sk64, $dig))];
}

function lock_check_revoked(string $dataDir): void {
    $rev = lock_read_json($dataDir . '/revocation.json');
    if ($rev !== null) lock_fail(410, 'This sync service has been revoked', ['revocation' => $rev]);
}

function lock_auth_admin(string $adminPubHex, array $p, string $action, string $rawBody, int $now): void {
    $pk = strtolower(trim((string)($_SERVER['HTTP_X_DROP_PUBKEY'] ?? ''))); $tsRaw = $_SERVER['HTTP_X_DROP_TIMESTAMP'] ?? '';
    $nonce = strtolower(trim((string)($_SERVER['HTTP_X_DROP_NONCE'] ?? ''))); $sig = strtolower(trim((string)($_SERVER['HTTP_X_DROP_SIGNATURE'] ?? '')));
    if ($pk === '' || !is_numeric($tsRaw) || !preg_match('/^[0-9a-f]{64}$/', $pk) || !preg_match('/^[0-9a-f]{32}$/', $nonce) || !preg_match('/^[0-9a-f]{128}$/', $sig)) lock_fail(400, 'Missing or invalid auth headers');
    if ($adminPubHex === '' || !hash_equals($adminPubHex, $pk)) lock_fail(403, 'Admin pubkey required');
    $ts = (int)$tsRaw; if (abs($now - $ts) > 60) lock_fail(401, 'Timestamp outside allowed window');
    if (!lock_verify_sig(hex2bin($pk), hex2bin($sig), "HUMOCO-DROP-ADMIN-V1\n{$action}\n{$ts}\n{$nonce}\n" . hash('sha256', $rawBody))) lock_fail(401, 'Invalid admin signature');
    if (!lock_consume_nonce($p, "admin:{$nonce}", 120, $now)) lock_fail(409, 'Nonce already used');
}

function lock_read_members(string $configFile): array {
    $raw = @file_get_contents(dirname($configFile) . '/members.lock.php');
    if ($raw === false || strlen($raw) <= 28) return [];
    $d = json_decode(substr($raw, 28), true);
    return (is_array($d) && isset($d['pubkeys']) && is_array($d['pubkeys'])) ? $d['pubkeys'] : [];
}

function lock_auto_expire_pre_freeze(array &$b, int $now): bool {
    if (is_array($b['freeze_state']) && isset($b['freeze_state']['pre_proposal']) && $now >= (int)$b['freeze_state']['pre_proposal']['expires_at']) {
        $b['freeze_state'] = 'active';
        return true;
    }
    return false;
}

function lock_handle_ticket(array $cfg, array $keys, string $configFile, string $dataDir, string $adminPubHex, int $now): never {
    lock_check_revoked($dataDir);
    $p = lock_paths($dataDir); $rawBody = (string)file_get_contents('php://input');
    $req = strlen($rawBody) <= 16384 ? json_decode($rawBody, true) : null;
    $a32 = is_array($req) ? lock_hex_bytes($req['anchor_id'] ?? null, 32) : null; $q = is_array($req) ? ($req['retain_until_quarter'] ?? null) : null;
    if ($a32 === null || !is_int($q) || lock_decode_quarter($q) === null) lock_fail(400, 'Invalid lock_ticket JSON');
    if ($q > $cfg['max_retention_quarter']) lock_fail(422, 'Requested retain_until_quarter exceeds server lock.max_retention_quarter');

    if (isset($_SERVER['HTTP_X_DROP_PUBKEY']) || isset($_SERVER['HTTP_X_DROP_TIMESTAMP']) || isset($_SERVER['HTTP_X_DROP_NONCE']) || isset($_SERVER['HTTP_X_DROP_SIGNATURE'])) {
        $pk = strtolower(trim((string)($_SERVER['HTTP_X_DROP_PUBKEY'] ?? ''))); $tsRaw = $_SERVER['HTTP_X_DROP_TIMESTAMP'] ?? '';
        $nonce = strtolower(trim((string)($_SERVER['HTTP_X_DROP_NONCE'] ?? ''))); $sig = strtolower(trim((string)($_SERVER['HTTP_X_DROP_SIGNATURE'] ?? '')));
        if ($pk === '' || !is_numeric($tsRaw) || !preg_match('/^[0-9a-f]{64}$/', $pk) || !preg_match('/^[0-9a-f]{32}$/', $nonce) || !preg_match('/^[0-9a-f]{128}$/', $sig)) lock_fail(400, 'Missing or invalid auth headers');
        if (abs($now - (int)$tsRaw) > 60) lock_fail(401, 'Timestamp outside allowed window');
        if (!lock_verify_sig(hex2bin($pk), hex2bin($sig), "HUMOCO-DROP-REQ-V1\nPOST\nlock_ticket\n\n" . (int)$tsRaw . "\n{$nonce}\n" . hash('sha256', $rawBody))) lock_fail(401, 'Invalid request signature');
        if (!lock_consume_nonce($p, "req:{$nonce}", 120, $now)) lock_fail(409, 'Nonce already used');
        if (!($adminPubHex !== '' && hash_equals($adminPubHex, $pk)) && !in_array($pk, lock_read_members($configFile), true)) lock_fail(403, 'Account is not authorized for lock tickets');
    } else {
        if (!$cfg['allow_pow_tickets']) lock_fail(401, 'Authentication required for lock_ticket');
        $pts = $req['pow_timestamp'] ?? null; $pn = $req['pow_nonce'] ?? null;
        if (!is_int($pts) || !is_int($pn)) lock_fail(400, 'Missing pow_timestamp or pow_nonce');
        if (abs($now - $pts) > 300) lock_fail(401, 'Ticket PoW timestamp outside allowed 300s window');
        if (lock_zero_bits(hash('sha256', 'HUMOCO_LOCK_TICKET_POW_V1' . $a32 . pack('v', $q) . pack('P', $pts) . pack('P', $pn), true)) < $cfg['ticket_pow_bits']) lock_fail(422, 'Insufficient lock_ticket proof-of-work');
        if (!lock_consume_nonce($p, "tpow:{$req['anchor_id']}:{$q}:{$pts}:{$pn}", 600, $now)) lock_fail(409, 'Ticket PoW replay rejected');
    }

    $bHex = hash('sha256', 'HUMOCO_SYNC_BUCKET_V1' . $a32 . $keys['pk32']);
    $b = lock_read_json($p['meta'] . "/buckets/{$bHex}.json");
    if ($b !== null) { lock_auto_expire_pre_freeze($b, $now); if (is_array($b['freeze_state'])) lock_fail(409, (string)array_key_first($b['freeze_state'])); }
    if (lock_used_inodes_get($p) >= $cfg['max_inodes']) lock_fail(507, 'Lock inode budget exhausted');
    $dig = hash('sha256', 'HUMOCO_GENESIS_TICKET_V1' . $a32 . pack('v', $q) . pack('P', $now) . $keys['pk32'], true);
    lock_ok(200, ['ticket' => ['anchor_id' => $req['anchor_id'], 'retain_until_quarter' => $q, 'issued_at' => $now, 'lock_pub' => $keys['pkHex'], 'sig' => bin2hex(lock_sign($keys['sk64'], $dig))]]);
}

function lock_handle_batch(array $cfg, array $keys, string $dataDir, int $now): never {
    lock_check_revoked($dataDir);
    $p = lock_paths($dataDir); $raw = (string)file_get_contents('php://input');
    if (strlen($raw) > 262144) lock_fail(413, 'Lock payload too large');
    $req = json_decode($raw, true);
    if (!is_array($req)) lock_fail(400, 'Invalid lock JSON');

    if (($req['probe'] ?? false) === true) {
        $cn = trim((string)($req['client_nonce'] ?? '')); $nb = lock_hex_bytes($cn, 32);
        if ($nb === null || $nb === str_repeat("\0", 32)) lock_fail(400, 'Invalid probe client_nonce');
        lock_ok(200, ['probe_ok' => true, 'lock_pub' => $keys['pkHex'], 'client_nonce' => $cn, 'server_time' => $now, 'sig' => bin2hex(lock_sign($keys['sk64'], "HUMOCO-LOCK-PROBE-V1\n{$keys['pkHex']}\n{$cn}\n{$now}"))]);
    }

    $a32 = lock_hex_bytes($req['anchor_id'] ?? null, 32); $b32 = lock_hex_bytes($req['bucket'] ?? null, 32);
    $rn32 = lock_hex_bytes($req['recipient_nonce'] ?? null, 32); $rawEntries = $req['entries'] ?? null;
    if ($a32 === null || $b32 === null || $rn32 === null || $rn32 === str_repeat("\0", 32) || !is_array($rawEntries) || count($rawEntries) < 1 || count($rawEntries) > 64) lock_fail(400, 'Invalid lock batch request JSON');
    if ($b32 !== hash('sha256', 'HUMOCO_SYNC_BUCKET_V1' . $a32 . $keys['pk32'], true)) lock_fail(400, 'bucket does not match derive_bucket(anchor_id, lock_pub)');

    $entries = [];
    foreach ($rawEntries as $eh) { $entries[] = (is_string($eh) ? lock_parse_entry($eh) : null) ?? lock_fail(400, 'Invalid LockEntry wire hex'); }
    $kr = $req['known_head_receipt'] ?? null;
    if ($kr !== null && (!is_array($kr) || !lock_verify_receipt($kr, $keys['pk32'], $b32))) lock_fail(401, 'Invalid signature on known_head_receipt');

    $bHex = bin2hex($b32); $aHex = bin2hex($a32);
    $bFile = $p['meta'] . "/buckets/{$bHex}.json"; $rFile = $p['meta'] . "/rotations/{$aHex}.json";

    $result = lock_with_lock($p['meta'] . "/buckets/{$bHex}.lockdir", static function () use ($cfg, $keys, $p, $req, $entries, $kr, $a32, $b32, $aHex, $bHex, $bFile, $rFile, $now): array {
        $b = lock_read_json($bFile);
        if ($kr !== null) {
            if ($b === null) {
                $tomb = ['anchor_id' => $aHex, 'retain_until_quarter' => $kr['retain_until_quarter'], 'creator_mig_pub' => str_repeat('00', 32), 'write_seq' => $kr['write_seq'], 'bucket_head' => $kr['bucket_head'], 'freeze_state' => ['self_frozen' => ['frozen_at' => $now, 'reason' => 'Rollback detected on missing bucket']], 'slots' => [], 'conflicts' => [], 'output_claims' => []];
                lock_atomic_write($bFile, json_encode($tomb, JSON_UNESCAPED_SLASHES));
                return ['code' => 409, 'body' => ['error' => 'bucket_self_frozen', 'bucket' => $bHex]];
            }
            if ((int)$kr['write_seq'] > (int)$b['write_seq'] || ((int)$kr['write_seq'] === (int)$b['write_seq'] && $kr['bucket_head'] !== $b['bucket_head'])) {
                $b['freeze_state'] = ['self_frozen' => ['frozen_at' => $now, 'reason' => 'Rollback detected against known_head_receipt']];
                lock_atomic_write($bFile, json_encode($b, JSON_UNESCAPED_SLASHES));
                return ['code' => 409, 'body' => ['error' => 'bucket_self_frozen', 'bucket' => $bHex]];
            }
        }
        if ($b !== null) {
            $changed = lock_auto_expire_pre_freeze($b, $now); $fs = $b['freeze_state'];
            if (is_array($fs)) {
                if (isset($fs['self_frozen'])) return ['code' => 409, 'body' => ['error' => 'bucket_self_frozen', 'bucket' => $bHex]];
                if (isset($fs['pre_proposal'])) return ['code' => 409, 'body' => ['error' => 'pre_proposal_frozen', 'bucket' => $bHex, 'expires_at' => $fs['pre_proposal']['expires_at']]];
                if (isset($fs['permanent_proposal'])) { $pp = $fs['permanent_proposal']; return ['code' => 409, 'body' => ['error' => 'proposal_frozen', 'bucket' => $bHex, 'from_rev' => $pp['from_rev'], 'proposal_hash' => $pp['proposal_hash'], 'effective_at' => $pp['effective_at']]]; }
                if (isset($fs['epoch_frozen'])) return ['code' => 409, 'body' => ['error' => 'epoch_frozen', 'bucket' => $bHex, 'current_revision' => $fs['epoch_frozen']['committed_rev'], 'latest_manifest' => lock_read_json($p['anchors'] . "/{$aHex}.bin")]];
            }
            if ($changed) lock_atomic_write($bFile, json_encode($b, JSON_UNESCAPED_SLASHES));
        } else {
            $m = $req['manifest'] ?? null; $t = $req['genesis_ticket'] ?? null;
            if (!is_array($m) || !is_array($t)) lock_fail(400, 'Missing AnchorManifest or GenesisTicket for initial bucket creation');
            if (lock_rev1_anchor_id($m) !== $a32) lock_fail(400, 'Manifest rev1_anchor_id mismatch');
            $comm = lock_validate_committee($m['servers'], (int)$m['threshold']);
            if ($comm === null || !in_array($keys['pkHex'], $comm['members'], true)) lock_fail(400, 'This server lock_pub is not in manifest committee');
            $q = (int)$m['retain_until_quarter']; $tSig = lock_hex_bytes($t['sig'] ?? null, 64); $tIss = $t['issued_at'] ?? null;
            $tDig = is_int($tIss) && $tIss > 0 ? hash('sha256', 'HUMOCO_GENESIS_TICKET_V1' . $a32 . pack('v', $q) . pack('P', $tIss) . $keys['pk32'], true) : '';
            if (($t['anchor_id'] ?? '') !== $aHex || ($t['lock_pub'] ?? '') !== $keys['pkHex'] || ($t['retain_until_quarter'] ?? -1) !== $q || $tSig === null || $tDig === '' || !lock_verify_sig($keys['pk32'], $tSig, $tDig)) lock_fail(401, 'Invalid or mismatched GenesisTicket');
            if ($q > $cfg['max_retention_quarter']) lock_fail(422, 'Manifest retain_until_quarter exceeds server limit');
            if (lock_used_inodes_get($p) >= $cfg['max_inodes']) lock_fail(507, 'Lock inode budget exhausted');
            $b = ['anchor_id' => $aHex, 'retain_until_quarter' => $q, 'creator_mig_pub' => $m['authority']['creator_mig_pub'], 'write_seq' => 0, 'bucket_head' => hash('sha256', 'HUMOCO_BUCKET_INIT_V1' . $b32 . pack('v', $q)), 'freeze_state' => 'active', 'slots' => [], 'conflicts' => [], 'output_claims' => []];
            lock_atomic_write($bFile, json_encode($b, JSON_UNESCAPED_SLASHES));
            if (!file_exists($rFile)) lock_atomic_write($rFile, json_encode(['active_manifest' => $m, 'last_creator_activity_secs' => min($now, intdiv((int)$m['issued_at_ms'], 1000)), 'voted_proposals_by_rev' => [], 'vetoed_proposal_hashes' => [], 'imported_proposal' => null], JSON_UNESCAPED_SLASHES));
            if (!file_exists($p['anchors'] . "/{$aHex}.bin")) lock_atomic_write($p['anchors'] . "/{$aHex}.bin", json_encode($m, JSON_UNESCAPED_SLASHES));
        }

        $q = (int)$b['retain_until_quarter']; $qStr = lock_format_quarter($q); $slotDir = $p['locks'] . "/{$qStr}/{$bHex}";
        if (!is_dir($slotDir) && !mkdir($slotDir, 0755, true) && !is_dir($slotDir)) lock_fail(500, 'Failed to create slot dir');
        $preSeq = (int)$b['write_seq']; $preHead = (string)$b['bucket_head'];
        $cMig32 = hex2bin($b['creator_mig_pub']); $batchAcc = []; $batchClaims = []; $pending = []; $conflict = null; $addedInodes = 0;

        foreach ($entries as $idx => $e) {
            $slotHex = bin2hex($e['slot']); $pSlotHex = bin2hex($e['parentSlot']); $parents = [];
            if ($e['depth'] >= 1) {
                if (isset($batchAcc[$pSlotHex])) $parents = [$batchAcc[$pSlotHex]];
                elseif (isset($b['slots'][$pSlotHex])) { $pr = @file_get_contents("{$slotDir}/" . $b['slots'][$pSlotHex] . '.lock'); if ($pr !== false) $parents = [lock_parse_entry(bin2hex($pr))]; }
                elseif (isset($b['conflicts'][$pSlotHex])) { foreach ($b['conflicts'][$pSlotHex] as $ch) $parents[] = lock_parse_entry($ch); }
                else return ['code' => 422, 'body' => ['error' => 'Missing causal parent lock entry']];
            }
            if ($e['depth'] === 0) {
                $err = lock_verify_entry($e, $a32, $cMig32, $cfg['pow_base_bits'], null);
                if ($err !== null) return ['code' => 422, 'body' => ['error' => $err]];
            } else {
                $okP = false; foreach ($parents as $cand) { if ($cand !== null && lock_verify_entry($e, $a32, $cMig32, $cfg['pow_base_bits'], $cand) === null) { $okP = true; break; } }
                if (!$okP) return ['code' => 422, 'body' => ['error' => 'Causal validation failed against parent']];
                $claimK = "{$pSlotHex}:{$e['ob']}"; $claimed = $batchClaims[$claimK] ?? ($b['output_claims'][$claimK] ?? null);
                if ($claimed !== null && $claimed !== $slotHex) return ['code' => 409, 'body' => ['error' => 'output_branch_already_claimed', 'parent_slot' => $pSlotHex, 'output_branch' => $e['ob']]];
            }
            if (isset($b['conflicts'][$slotHex])) {
                $comp = null;
                foreach ($b['conflicts'][$slotHex] as $ch) {
                    $cand = lock_parse_entry($ch);
                    if ($cand !== null && ($comp === null || $cand['idBytes'] !== $e['idBytes'])) { $comp = $cand; if ($cand['idBytes'] !== $e['idBytes']) break; }
                }
                if ($comp === null) lock_fail(500, 'Empty or corrupted conflict group');
                $conflict = [$idx, $slotHex, ['kind' => 'conflict_seen', 'slot' => $comp['slot'], 'childLock' => $comp['childLock'], 'entryHash' => $comp['entryHash'], 'writeSeq' => (int)$b['write_seq'], 'head' => hex2bin($b['bucket_head'])], $comp['hex']];
                break;
            }
            $fileHex = hash('sha256', 'HUMOCO_SYNC_FILE_V1' . $e['slot'] . $keys['pk32']);
            $slotPath = "{$slotDir}/{$fileHex}.lock"; $tmp = "{$slotDir}/.tmp.{$fileHex}." . getmypid() . '.' . bin2hex(random_bytes(4));
            $fp = @fopen($tmp, 'xb'); if ($fp === false) lock_fail(500, 'Failed to allocate temp slot file');
            $okW = fwrite($fp, $e['wire']) === LOCK_ENTRY_WIRE_LEN && fflush($fp) && fsync($fp); fclose($fp);
            if (!$okW) { @unlink($tmp); lock_fail(500, 'Failed to flush temp slot file'); }
            $linked = @link($tmp, $slotPath);
            if (!$linked) { clearstatcache(true, $tmp); $st = @stat($tmp); if (is_array($st) && (($st['nlink'] ?? 0) >= 2)) $linked = true; }
            @unlink($tmp);
            clearstatcache(true, $slotPath); $disk = @file_get_contents($slotPath);
            if ($disk === false || strlen($disk) !== LOCK_ENTRY_WIRE_LEN) lock_fail(500, 'Read-back verification failed');

            $stored = lock_parse_entry(bin2hex($disk));
            if (substr($disk, 0, LOCK_ENTRY_ID_LEN) === $e['idBytes']) {
                if (!isset($b['slots'][$slotHex])) {
                    $b['slots'][$slotHex] = $fileHex;
                    if ($e['depth'] >= 1) $b['output_claims']["{$pSlotHex}:{$e['ob']}"] = $slotHex;
                    $addedInodes++; $b['write_seq'] = (int)$b['write_seq'] + 1;
                    $b['bucket_head'] = hash('sha256', 'HUMOCO_BUCKET_STEP_V1' . hex2bin($b['bucket_head']) . pack('P', (int)$b['write_seq']) . $e['slot'] . $e['entryHash']);
                }
                if ($e['depth'] >= 1) $batchClaims["{$pSlotHex}:{$e['ob']}"] = $slotHex;
                $batchAcc[$slotHex] = $stored;
                $pending[] = ['kind' => 'first_write', 'slot' => $stored['slot'], 'childLock' => $stored['childLock'], 'entryHash' => $e['entryHash'], 'writeSeq' => (int)$b['write_seq'], 'head' => hex2bin($b['bucket_head'])];
            } else {
                $conflict = [$idx, $slotHex, ['kind' => 'conflict_seen', 'slot' => $stored['slot'], 'childLock' => $stored['childLock'], 'entryHash' => $stored['entryHash'], 'writeSeq' => (int)$b['write_seq'], 'head' => hex2bin($b['bucket_head'])], $stored['hex']];
                break;
            }
        }
        if ($addedInodes > 0) {
            $curB = lock_read_json($bFile);
            if ($curB === null || (int)$curB['write_seq'] !== $preSeq || (string)$curB['bucket_head'] !== $preHead) {
                $b['freeze_state'] = ['self_frozen' => ['frozen_at' => $now, 'reason' => 'Branched bucket hash-chain detected (self-freeze)']];
                lock_atomic_write($bFile, json_encode($b, JSON_UNESCAPED_SLASHES));
                return ['code' => 409, 'body' => ['error' => 'bucket_self_frozen', 'bucket' => $bHex]];
            }
            if (!lock_atomic_write($bFile, json_encode($b, JSON_UNESCAPED_SLASHES))) lock_fail(500, 'Failed to persist bucket metadata');
            $rb = lock_read_json($bFile);
            if ($rb === null || (int)$rb['write_seq'] !== (int)$b['write_seq'] || $rb['bucket_head'] !== $b['bucket_head']) {
                $b['freeze_state'] = ['self_frozen' => ['frozen_at' => $now, 'reason' => 'Bucket metadata read-back divergence (self-freeze)']];
                lock_atomic_write($bFile, json_encode($b, JSON_UNESCAPED_SLASHES));
                return ['code' => 409, 'body' => ['error' => 'bucket_self_frozen', 'bucket' => $bHex]];
            }
            lock_used_inodes_add($p, $addedInodes);
        }
        return ['code' => 200, 'retain' => $q, 'pending' => $pending, 'conflict' => $conflict];
    });

    if ($result['code'] !== 200) lock_ok($result['code'], $result['body']);
    $receipts = [];
    foreach ($result['pending'] as $pr) $receipts[] = lock_sign_receipt($keys['sk64'], $keys['pk32'], $b32, $result['retain'], $rn32, $pr);
    $confDto = null;
    if ($result['conflict'] !== null) {
        [$ci, $cSlotHex, $cPend, $cWire] = $result['conflict'];
        $confDto = ['entry_index' => $ci, 'slot' => $cSlotHex, 'receipt' => lock_sign_receipt($keys['sk64'], $keys['pk32'], $b32, $result['retain'], $rn32, $cPend), 'competing_entry' => $cWire];
    }
    lock_ok(200, ['status' => $confDto ? 'conflict' : 'ok', 'bucket' => $bHex, 'retain_until_quarter' => $result['retain'], 'receipts' => $receipts, 'conflict' => $confDto]);
}

function lock_run_gc(string $dataDir, int $now): array {
    $p = lock_paths($dataDir); $purgedB = 0; $purgedInodes = 0;
    foreach (glob($p['meta'] . '/buckets/*.json') ?: [] as $bf) {
        $b = lock_read_json($bf); if ($b === null) continue;
        $q = (int)($b['retain_until_quarter'] ?? 0); $thr = lock_purge_after_secs($q);
        if ($thr === null || $now < $thr) continue;
        $bHex = basename($bf, '.json'); $qStr = lock_format_quarter($q); $aHex = (string)($b['anchor_id'] ?? '');
        lock_with_lock($p['meta'] . "/buckets/{$bHex}.lockdir", static function () use ($bf, $p, $qStr, $bHex, $aHex, $now, $thr, &$purgedB, &$purgedInodes): void {
            $b2 = lock_read_json($bf); if ($b2 === null || $now < $thr) return;
            $dir = $p['locks'] . "/{$qStr}/{$bHex}"; $removed = count($b2['slots'] ?? []) + count($b2['conflicts'] ?? []);
            if (is_dir($dir)) { foreach (glob("{$dir}/*") ?: [] as $f) @unlink($f); @rmdir($dir); }
            @unlink($bf);
            if ($aHex !== '') { @unlink($p['meta'] . "/rotations/{$aHex}.json"); @unlink($p['anchors'] . "/{$aHex}.bin"); }
            $purgedB++; $purgedInodes += $removed;
        });
        @rmdir($p['locks'] . "/{$qStr}");
    }
    if ($purgedInodes > 0) lock_used_inodes_add($p, -$purgedInodes);
    return [$purgedB, $purgedInodes];
}

function lock_serve_static(string $filePath, string $ctype, string $cacheCtrl): never {
    clearstatcache(true, $filePath);
    $bytes = is_file($filePath) ? @file_get_contents($filePath) : false;
    if ($bytes === false) { http_response_code(404); exit; }
    $etag = '"' . hash('sha256', $bytes) . '"';
    $inm = isset($_SERVER['HTTP_IF_NONE_MATCH']) ? trim((string)$_SERVER['HTTP_IF_NONE_MATCH']) : '';
    header('ETag: ' . $etag); header('Cache-Control: ' . $cacheCtrl);
    if ($inm === $etag || trim($inm, '" ') === trim($etag, '"')) { http_response_code(304); exit; }
    header('Content-Type: ' . $ctype); header('Content-Length: ' . strlen($bytes));
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') echo $bytes;
    exit;
}

function lock_maybe_handle_cli_router(string $dataDir, string $dataDirSetting, string $configFile): void {
    if (PHP_SAPI !== 'cli-server') return;
    $path = (string)(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/');
    if (str_contains($path, '..') || str_contains($path, '\\') || str_contains($path, "\0")) { http_response_code(404); exit; }
    if (preg_match('#/(?:\.[^/]*|config\.php|lock_handler\.php|lock_rotation\.php|ratelimit\.bin\.php|members\.[^/]+\.php)$#', $path) || str_contains($path, '/.locks_meta/')) { http_response_code(403); exit; }
    $m = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    $baseData = trim(str_replace('\\', '/', $dataDirSetting), '/');
    if (preg_match('#^/anchors/([0-9a-f]{64})\.bin$#', $path, $mx) || ($baseData !== '' && preg_match('#^/' . preg_quote($baseData, '#') . '/anchors/([0-9a-f]{64})\.bin$#', $path, $mx))) {
        if ($m !== 'GET' && $m !== 'HEAD') { http_response_code(405); header('Allow: GET, HEAD'); exit; }
        lock_serve_static($dataDir . '/anchors/' . $mx[1] . '.bin', 'application/json', 'no-cache');
    }
    if ($baseData !== '' && preg_match('#^/' . preg_quote($baseData, '#') . '/locks/(\d{4}-Q[1-4])/([0-9a-f]{64})/([0-9a-f]{64})\.lock$#', $path, $lx)) {
        if ($m !== 'GET' && $m !== 'HEAD') { http_response_code(405); header('Allow: GET, HEAD'); exit; }
        lock_serve_static($dataDir . "/locks/{$lx[1]}/{$lx[2]}/{$lx[3]}.lock", 'application/octet-stream', 'public, max-age=31536000, immutable');
    }
    if ($baseData !== '' && preg_match('#^/' . preg_quote($baseData, '#') . '/([^/]+)$#', $path, $dx)) {
        if ($m !== 'GET' && $m !== 'HEAD') { http_response_code(405); exit; }
        $fn = $dx[1];
        lock_serve_static($dataDir . '/' . $fn, str_ends_with($fn, '.json') ? 'application/json' : 'application/octet-stream', str_ends_with($fn, '.media.bin') ? 'public, max-age=60' : 'no-cache');
    }
    $docRoot = dirname($configFile);
    if ($path === '/' || $path === '/index.html') {
        if (is_file($docRoot . '/index.html')) lock_serve_static($docRoot . '/index.html', 'text/html; charset=utf-8', 'no-cache');
        http_response_code(200); exit;
    }
    if ($path === '/robots.txt') lock_serve_static($docRoot . '/robots.txt', 'text/plain; charset=utf-8', 'no-cache');
    if ($path !== '/sync.php' && $path !== '/sync') { http_response_code(404); exit; }
}

function lock_maybe_handle_request(array $config, string $configFile, string $dataDir, string $dataDirSetting, bool $disableRateLimit): void {
    if (PHP_VERSION_ID < 80100) { http_response_code(500); header('Content-Type: application/json'); echo "{\"error\":\"PHP >= 8.1 required\"}\n"; exit; }
    lock_maybe_handle_cli_router($dataDir, $dataDirSetting, $configFile);
    $method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    $isLockRoute = isset($_GET['lock_selftest']) || isset($_GET['lock_delegate']) || isset($_GET['lock_ticket'])
        || isset($_GET['lock']) || isset($_GET['lock_freeze']) || isset($_GET['lock_import']) || isset($_GET['lock_commit']) || isset($_GET['__anchor']);
    if (!$isLockRoute) return;
    try {
        if (isset($_GET['__anchor']) && preg_match('/^([0-9a-f]{64})\.bin$/', (string)$_GET['__anchor'], $mx)) lock_serve_static($dataDir . '/anchors/' . $mx[1] . '.bin', 'application/json', 'no-cache');
        @ignore_user_abort(true); @set_time_limit(30);
        $cfg = lock_cfg($config);
        if (!$cfg['enabled']) lock_fail(404, 'Lock channel is disabled');
        $p = lock_paths($dataDir);
        if (!lock_ip_ratelimit_allow($p, $disableRateLimit)) { header('Retry-After: 2'); lock_fail(429, 'IP rate limit exceeded'); }
        $keys = lock_load_or_init_keys($dataDir);
        $adminPub = isset($config['admin_pubkey']) ? strtolower(trim((string)$config['admin_pubkey'])) : '';
        $now = time();
        register_shutdown_function(static function () use ($dataDir): void {
            if (function_exists('fastcgi_finish_request')) @fastcgi_finish_request();
            elseif (random_int(1, 100) !== 1) return;
            try { lock_run_gc($dataDir, time()); } catch (\Throwable) {}
        });
        if ($method === 'GET' && isset($_GET['lock_selftest'])) lock_ok(200, lock_read_json($p['meta'] . '/selftest.json') ?? lock_build_selftest($dataDir, $cfg, $keys, $now), true);
        if ($method === 'POST' && isset($_GET['lock_selftest'])) { lock_auth_admin($adminPub, $p, 'POST_LOCK_SELFTEST', (string)file_get_contents('php://input'), $now); lock_ok(200, lock_build_selftest($dataDir, $cfg, $keys, $now), true); }
        if ($method === 'PUT' && isset($_GET['lock_delegate'])) {
            $raw = (string)file_get_contents('php://input');
            lock_auth_admin($adminPub, $p, 'PUT_LOCK_DELEGATE', $raw, $now);
            $del = json_decode($raw, true);
            $wu = $del['write_url'] ?? null;
            $ru = $del['read_url'] ?? null;
            if (!is_array($del) || strtolower((string)($del['admin_pub'] ?? '')) !== $adminPub || strtolower((string)($del['lock_pub'] ?? '')) !== $keys['pkHex'] || !lock_is_valid_url($wu) || !lock_is_valid_url($ru) || !is_int($del['issued_at'] ?? null) || $del['issued_at'] <= 0) lock_fail(400, 'Invalid lock delegation payload');
            $sig = lock_hex_bytes($del['sig'] ?? null, 64);
            if ($sig === null || !lock_verify_sig(hex2bin($adminPub), $sig, "HUMOCO-LOCK-DELEGATE-V1\n{$adminPub}\n{$keys['pkHex']}\n{$wu}\n{$ru}\n{$del['issued_at']}")) lock_fail(401, 'Invalid lock delegation signature');
            lock_atomic_write($p['meta'] . '/delegation.json', json_encode($del, JSON_UNESCAPED_SLASHES));
            lock_ok(200, $del);
        }
        if ($method === 'POST' && isset($_GET['lock_ticket'])) lock_handle_ticket($cfg, $keys, $configFile, $dataDir, $adminPub, $now);
        if ($method === 'POST' && isset($_GET['lock'])) lock_handle_batch($cfg, $keys, $dataDir, $now);
        if (isset($_GET['lock_freeze']) || isset($_GET['lock_import']) || isset($_GET['lock_commit'])) {
            require_once __DIR__ . '/lock_rotation.php';
            if (($method === 'GET' || $method === 'POST') && isset($_GET['lock_freeze'])) lock_handle_freeze($method, $cfg, $keys, $dataDir, $now);
            if ($method === 'POST' && isset($_GET['lock_import'])) lock_handle_import($cfg, $keys, $dataDir, $now);
            if ($method === 'POST' && isset($_GET['lock_commit'])) lock_handle_commit($cfg, $keys, $dataDir, $now);
        }
        header('Allow: GET, HEAD, PUT, DELETE, POST');
        lock_fail(405, 'Method Not Allowed');
    } catch (LockAbort $e) {
        http_response_code($e->status); header('Content-Type: application/json; charset=utf-8'); header('Cache-Control: no-store');
        echo json_encode(array_merge(['error' => $e->getMessage()], $e->extra), JSON_UNESCAPED_SLASHES) . "\n";
        exit;
    }
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    $opts = getopt('', ['gc', 'config:', 'now:']);
    if (isset($opts['gc'])) {
        $cfgFile = (string)($opts['config'] ?? (__DIR__ . '/config.php'));
        $cfg = require $cfgFile;
        $dd = (string)($cfg['data_dir'] ?? 'data');
        $dir = ($dd !== '' && ($dd[0] === '/' || $dd[0] === '\\')) ? $dd : (dirname($cfgFile) . '/' . $dd);
        [$pb, $pi] = lock_run_gc($dir, isset($opts['now']) ? (int)$opts['now'] : time());
        echo "purged_buckets={$pb} purged_inodes={$pi}\n";
    }
}
