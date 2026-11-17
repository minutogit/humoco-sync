<?php
/**
 * HuMoCo Lock Committee 3-Phase Rotation & Union Import Handler (SPEC.md Section 7, Concept Section 5.4).
 * Loaded lazily by lock_handler.php only when ?lock_freeze, ?lock_import, or ?lock_commit is called.
 */

function lock_encode_server_list(array $list, int $gCount): ?string {
    $out = '';
    foreach ($list as $s) {
        $enc = is_array($s) ? lock_encode_server($s, $gCount) : null;
        if ($enc === null) return null;
        $out .= pack('N', strlen($enc)) . $enc;
    }
    return $out;
}

function lock_proposal_digest(array $prop): ?string {
    $aid = lock_hex_bytes($prop['anchor_id'] ?? null, 32);
    if ($aid === null || !is_int($prop['from_rev'] ?? null) || !is_int($prop['to_rev'] ?? null) || !is_int($prop['new_threshold'] ?? null)
        || !is_int($prop['retain_until_quarter'] ?? null) || !is_int($prop['proposed_at'] ?? null) || $prop['proposed_at'] <= 0) return null;
    $init = $prop['initiator'] ?? null;
    $k = $init['kind'] ?? null;
    if ($k === 'creator') $initBytes = "\x00";
    elseif ($k === 'guarantor' && is_int($init['guarantor_index'] ?? null)) $initBytes = "\x01" . chr($init['guarantor_index']);
    elseif ($k === 'holder_standby') $initBytes = "\x02";
    else return null;
    $srvs = $prop['new_servers'] ?? [];
    $succs = $prop['new_successors'] ?? [];
    if (!is_array($srvs) || !is_array($succs) || count($srvs) > 5) return null;
    $sBin = '';
    foreach ($srvs as $s) { $e = lock_encode_server($s, 32); if ($e === null) return null; $sBin .= $e; }
    $suBin = '';
    foreach ($succs as $s) { $e = lock_encode_server($s, 32); if ($e === null) return null; $suBin .= $e; }
    $pre = 'HUMOCO_MIGRATION_PROP_V1' . $aid . pack('P', $prop['from_rev']) . pack('P', $prop['to_rev']) . chr($prop['new_threshold'])
        . chr(count($srvs)) . $sBin . pack('v', count($succs)) . $suBin . pack('v', $prop['retain_until_quarter']) . pack('P', $prop['proposed_at']) . $initBytes;
    return hash('sha256', $pre, true);
}

function lock_check_role_nomination(mixed $role, array $prev, array $prop): bool {
    $matchRole = static fn(array $list): array => array_values(array_filter($list, static fn($s) => ($s['nominated_by'] ?? null) === $role));
    $prevA = $matchRole($prev['servers']);
    $newA = $matchRole($prop['new_servers']);
    if (count($newA) > count($prevA)) return false;
    $prevSu = $matchRole($prev['successors']);
    $newSu = $matchRole($prop['new_successors']);
    $prevSet = [];
    foreach ($prevA as $s) $prevSet[$s['lock_pub']] = true;
    $added = array_values(array_filter($newA, static fn($s) => !isset($prevSet[$s['lock_pub']])));
    if (count($added) > count($prevSu)) return false;
    foreach ($added as $i => $s) {
        if (lock_encode_server($s, 32) !== lock_encode_server($prevSu[$i], 32)) return false;
    }
    $rem = array_slice($prevSu, count($added));
    if (lock_encode_server_list($newSu, 32) !== lock_encode_server_list($rem, 32)) return false;
    return !(count($newA) < count($prevA) && count($rem) > 0);
}

function lock_verify_proposal(array $prop, string $anchor32, array $prev): bool {
    if (($prop['anchor_id'] ?? '') !== bin2hex($anchor32) || ($prop['from_rev'] ?? 0) !== ($prev['revision'] ?? 0)
        || ($prop['to_rev'] ?? 0) !== ($prev['revision'] ?? 0) + 1 || ($prop['retain_until_quarter'] ?? -1) !== ($prev['retain_until_quarter'] ?? -2)) return false;
    $gPubs = $prev['authority']['guarantor_mig_pubs'] ?? [];
    $gCnt = count($gPubs);
    $newSrvs = $prop['new_servers'] ?? [];
    $newSucc = $prop['new_successors'] ?? [];
    $comm = lock_validate_committee($newSrvs, (int)($prop['new_threshold'] ?? 0));
    if ($comm === null) return false;
    $activeMap = array_flip($comm['members']);
    $succMap = [];
    foreach ($newSrvs as $s) { if (lock_encode_server($s, $gCnt) === null) return false; }
    foreach ($newSucc as $s) {
        if (lock_encode_server($s, $gCnt) === null || isset($activeMap[$s['lock_pub']]) || isset($succMap[$s['lock_pub']])) return false;
        $succMap[$s['lock_pub']] = true;
    }
    $digest = lock_proposal_digest($prop);
    if ($digest === null) return false;
    $init = $prop['initiator'];
    $pSigHex = $prop['proposer_sig'] ?? null;
    $cosigs = $prop['guarantor_cosigs'] ?? [];
    if (!is_array($cosigs)) return false;
    $signedG = [];
    $seenCosig = [];
    if ($init['kind'] === 'creator') {
        $sig = lock_hex_bytes($pSigHex, 64);
        $cpk = lock_hex_bytes($prev['authority']['creator_mig_pub'], 32);
        if ($sig === null || $cpk === null || !lock_verify_sig($cpk, $sig, $digest)) return false;
    } elseif ($init['kind'] === 'guarantor') {
        $gi = $init['guarantor_index'];
        $sig = lock_hex_bytes($pSigHex, 64);
        $gpk = isset($gPubs[$gi]) ? lock_hex_bytes($gPubs[$gi], 32) : null;
        if ($sig === null || $gpk === null || !lock_verify_sig($gpk, $sig, $digest)) return false;
        $signedG[$gi] = true;
    } else {
        if ($pSigHex !== null || !empty($cosigs)) return false;
        if ((int)$prop['new_threshold'] !== (int)$prev['threshold'] || count($newSrvs) !== count($prev['servers'])) return false;
        if (lock_encode_server_list($newSrvs, $gCnt) === lock_encode_server_list($prev['servers'], $gCnt)) return false;
        $pool = $prev['successors'];
        foreach ($prev['servers'] as $i => $oldS) {
            if (lock_encode_server($newSrvs[$i], $gCnt) === lock_encode_server($oldS, $gCnt)) continue;
            $pos = null;
            foreach ($pool as $pi => $cand) { if ($cand['nominated_by'] === $oldS['nominated_by']) { $pos = $pi; break; } }
            if ($pos === null) return false;
            $exp = $pool[$pos];
            array_splice($pool, $pos, 1);
            if (lock_encode_server($newSrvs[$i], $gCnt) !== lock_encode_server($exp, $gCnt)) return false;
        }
        return lock_encode_server_list($newSucc, $gCnt) === lock_encode_server_list($pool, $gCnt);
    }
    foreach ($cosigs as $cs) {
        $gi = $cs['guarantor_index'] ?? -1;
        $sig = lock_hex_bytes($cs['sig'] ?? null, 64);
        $gpk = (is_int($gi) && isset($gPubs[$gi])) ? lock_hex_bytes($gPubs[$gi], 32) : null;
        if (!is_int($gi) || isset($seenCosig[$gi]) || $sig === null || $gpk === null || !lock_verify_sig($gpk, $sig, $digest)) return false;
        $seenCosig[$gi] = true;
        $signedG[$gi] = true;
    }
    for ($gi = 0; $gi < $gCnt; $gi++) {
        if (!isset($signedG[$gi]) && !lock_check_role_nomination(['guarantor' => $gi], $prev, $prop)) return false;
    }
    if ($init['kind'] !== 'creator' && !lock_check_role_nomination('creator', $prev, $prop)) return false;
    if (count($signedG) < $gCnt && $gCnt > 0) {
        $pCnt = count(array_filter($prev['servers'], static fn($s) => $s['nominated_by'] === 'creator'));
        $nCnt = count(array_filter($newSrvs, static fn($s) => $s['nominated_by'] === 'creator'));
        if ($nCnt > $pCnt) return false;
    }
    return true;
}

function lock_verify_import_acks(array $acks, array $newComm, string $a32, string $pHash32, int $toRev, string $ish32, int $q): bool {
    if (count($acks) !== count($newComm['members'])) return false;
    $aHex = bin2hex($a32);
    $pHashHex = bin2hex($pHash32);
    $ishHex = bin2hex($ish32);
    $newSet = array_flip($newComm['members']);
    $seen = [];
    foreach ($acks as $ack) {
        $lph = $ack['lock_pub'] ?? '';
        $lp = lock_hex_bytes($lph, 32);
        $sig = lock_hex_bytes($ack['sig'] ?? null, 64);
        if ($lp === null || $sig === null || !isset($newSet[$lph]) || isset($seen[$lph])
            || ($ack['anchor_id'] ?? '') !== $aHex || ($ack['proposal_hash'] ?? '') !== $pHashHex
            || ($ack['to_rev'] ?? 0) !== $toRev || ($ack['imported_state_hash'] ?? '') !== $ishHex
            || ($ack['retain_until_quarter'] ?? -1) !== $q || !is_int($ack['acked_at'] ?? null) || $ack['acked_at'] <= 0) return false;
        $dig = hash('sha256', 'HUMOCO_IMPORT_ACK_V1' . $a32 . $pHash32 . pack('P', $toRev) . $ish32 . pack('v', $q) . $lp . pack('P', $ack['acked_at']), true);
        if (!lock_verify_sig($lp, $sig, $dig)) return false;
        $seen[$lph] = true;
    }
    return true;
}

function lock_verify_manifest_chain(array $m, string $expectedAnchor32): ?array {
    $rev = $m['revision'] ?? 0;
    $chain = $m['migration_chain'] ?? null;
    if (!is_int($rev) || $rev < 1 || !is_array($chain) || count($chain) > LOCK_MAX_CHAIN_LEN) return null;
    if ($rev === 1) {
        if (!empty($chain) || lock_rev1_anchor_id($m) !== $expectedAnchor32) return null;
        return [lock_validate_committee($m['servers'], (int)$m['threshold'])];
    }
    if (count($chain) !== $rev - 1) return null;
    $gen = $chain[0]['genesis_manifest'] ?? null;
    if (!is_array($gen) || lock_rev1_anchor_id($gen) !== $expectedAnchor32) return null;
    $comms = [lock_validate_committee($gen['servers'], (int)$gen['threshold'])];
    $cur = $gen;
    foreach ($chain as $idx => $cert) {
        if ($idx > 0 && ($cert['genesis_manifest'] ?? null) !== null) return null;
        $prop = $cert['proposal'] ?? null;
        $ish = lock_hex_bytes($cert['imported_state_hash'] ?? null, 32);
        if (!is_array($prop) || $ish === null || ($cert['anchor_id'] ?? '') !== bin2hex($expectedAnchor32) || !lock_verify_proposal($prop, $expectedAnchor32, $cur)) return null;
        $pHash = lock_proposal_digest($prop);
        $newC = lock_validate_committee($prop['new_servers'], (int)$prop['new_threshold']);
        if ($newC === null || !lock_verify_import_acks($cert['import_acks'] ?? [], $newC, $expectedAnchor32, $pHash, (int)$prop['to_rev'], $ish, (int)$prop['retain_until_quarter'])) return null;
        $prevC = $comms[count($comms) - 1];
        $prevSet = array_flip($prevC['members']);
        $cDig = hash('sha256', 'HUMOCO_MIGRATION_CERT_V1' . $expectedAnchor32 . $pHash . pack('P', $prop['to_rev']) . $ish, true);
        $cSeen = [];
        foreach (($cert['commit_sigs'] ?? []) as $cs) {
            $lp = lock_hex_bytes($cs['lock_pub'] ?? null, 32);
            $sig = lock_hex_bytes($cs['sig'] ?? null, 64);
            if ($lp === null || $sig === null || !isset($prevSet[$cs['lock_pub']]) || isset($cSeen[$cs['lock_pub']]) || !is_int($cs['committed_at'] ?? null) || $cs['committed_at'] <= 0 || !lock_verify_sig($lp, $sig, $cDig)) return null;
            $cSeen[$cs['lock_pub']] = true;
        }
        if (count($cSeen) < $prevC['threshold']) return null;
        $cur = ['revision' => $prop['to_rev'], 'threshold' => $prop['new_threshold'], 'servers' => $prop['new_servers'], 'successors' => $prop['new_successors'], 'authority' => $cur['authority'], 'issued_at_ms' => $prop['proposed_at'] * 1000, 'retain_until_quarter' => $cur['retain_until_quarter']];
        $comms[] = $newC;
    }
    $gCnt = count($m['authority']['guarantor_mig_pubs'] ?? []);
    if ($cur['revision'] !== $rev || $cur['threshold'] !== $m['threshold'] || lock_encode_server_list($cur['servers'], $gCnt) !== lock_encode_server_list($m['servers'], $gCnt)
        || lock_encode_server_list($cur['successors'], $gCnt) !== lock_encode_server_list($m['successors'], $gCnt)
        || ($cur['authority']['creator_mig_pub'] ?? '') !== ($m['authority']['creator_mig_pub'] ?? '')
        || ($cur['authority']['guarantor_mig_pubs'] ?? []) !== ($m['authority']['guarantor_mig_pubs'] ?? [])
        || $cur['retain_until_quarter'] !== $m['retain_until_quarter']) return null;
    return $comms;
}

function lock_freeze_state_hash(string $a32, int $fromRev, array $entries, array $conflicts): string {
    $sItems = [];
    foreach ($entries as $e) $sItems[] = [$e['slot'], $e['entryHash']];
    usort($sItems, static fn($a, $b) => strcmp($a[0], $b[0]) ?: strcmp($a[1], $b[1]));
    $cItems = [];
    foreach ($conflicts as $grp) {
        $hs = []; $sl32 = null;
        foreach ($grp as $e) {
            $sl32 = $sl32 ?? $e['slot'];
            if ($e['slot'] !== $sl32) lock_fail(400, 'Conflict slot mismatch');
            $hs[] = $e['entryHash'];
        }
        if ($sl32 === null) lock_fail(400, 'Empty conflict group');
        usort($hs, 'strcmp');
        $cItems[] = [$sl32, array_values(array_unique($hs))];
    }
    usort($cItems, static fn($a, $b) => strcmp($a[0], $b[0]));
    $pre = 'HUMOCO_FREEZE_STATE_V1' . $a32 . pack('P', $fromRev) . pack('P', count($sItems));
    foreach ($sItems as [$s, $eh]) $pre .= $s . $eh;
    $pre .= pack('P', count($cItems));
    foreach ($cItems as [$s, $hs]) {
        $pre .= $s . pack('P', count($hs));
        foreach ($hs as $h) $pre .= $h;
    }
    return hash('sha256', $pre, true);
}

function lock_export_snapshot(array $keys, array $p, array $b, string $bucketHex, int $fromRev, bool $perm, ?string $propHash32, int $frozenAt, ?int $expiresAt): array {
    $qStr = lock_format_quarter((int)$b['retain_until_quarter']);
    $entriesHex = []; $entries = [];
    foreach (($b['slots'] ?? []) as $fileHex) {
        $raw = @file_get_contents($p['locks'] . "/{$qStr}/{$bucketHex}/{$fileHex}.lock");
        if ($raw === false || strlen($raw) !== LOCK_ENTRY_WIRE_LEN) lock_fail(500, 'Corrupted stored lock entry');
        $h = bin2hex($raw);
        $entriesHex[] = $h;
        $entries[] = lock_parse_entry($h);
    }
    $confGroupsHex = array_values($b['conflicts'] ?? []);
    $conflicts = array_map(static fn($g) => array_map('lock_parse_entry', $g), $confGroupsHex);
    $a32 = hex2bin($b['anchor_id']);
    $stHash = lock_freeze_state_hash($a32, $fromRev, $entries, $conflicts);
    $snapPre = 'HUMOCO_FREEZE_SNAP_V1' . $a32 . hex2bin($bucketHex) . pack('P', $fromRev) . pack('v', (int)$b['retain_until_quarter'])
        . pack('P', (int)$b['write_seq']) . hex2bin($b['bucket_head']) . $stHash . chr($perm ? 1 : 0)
        . ($propHash32 !== null ? "\x01" . $propHash32 : "\x00") . pack('P', $frozenAt) . pack('P', $expiresAt ?? 0) . $keys['pk32'];
    return [
        'snapshot' => [
            'anchor_id' => $b['anchor_id'], 'bucket' => $bucketHex, 'from_rev' => $fromRev, 'retain_until_quarter' => (int)$b['retain_until_quarter'],
            'write_seq' => (int)$b['write_seq'], 'bucket_head' => $b['bucket_head'], 'state_hash' => bin2hex($stHash), 'permanent' => $perm,
            'proposal_hash' => $propHash32 !== null ? bin2hex($propHash32) : null, 'frozen_at' => $frozenAt, 'expires_at' => $expiresAt,
            'lock_pub' => $keys['pkHex'], 'sig' => bin2hex(lock_sign($keys['sk64'], hash('sha256', $snapPre, true))),
        ],
        'entries' => $entriesHex, 'conflicts' => $confGroupsHex,
    ];
}

function lock_bootstrap_anchor(array $cfg, array $keys, array $p, string $aHex, string $bHex, ?array $m, int $now): array {
    $bFile = $p['meta'] . "/buckets/{$bHex}.json";
    $rFile = $p['meta'] . "/rotations/{$aHex}.json";
    $b = lock_read_json($bFile);
    $r = lock_read_json($rFile);
    if ($b !== null && $r !== null) {
        if (lock_auto_expire_pre_freeze($b, $now)) lock_atomic_write($bFile, json_encode($b, JSON_UNESCAPED_SLASHES));
        return [$b, $r];
    }
    if (!is_array($m)) lock_fail(404, 'Anchor bucket not initialized on this server');
    $comms = lock_verify_manifest_chain($m, hex2bin($aHex));
    if ($comms === null) lock_fail(400, 'Invalid current_manifest');
    if (!in_array($keys['pkHex'], $comms[count($comms) - 1]['members'], true)) lock_fail(400, 'Server lock_pub is not a member of active manifest');
    $q = (int)$m['retain_until_quarter'];
    if ($q > $cfg['max_retention_quarter']) lock_fail(422, 'Manifest retain_until_quarter exceeds server limit');
    if ($b === null) {
        if (lock_used_inodes_get($p) >= $cfg['max_inodes']) lock_fail(507, 'Lock inode budget exhausted');
        $b = ['anchor_id' => $aHex, 'retain_until_quarter' => $q, 'creator_mig_pub' => $m['authority']['creator_mig_pub'], 'write_seq' => 0, 'bucket_head' => hash('sha256', 'HUMOCO_BUCKET_INIT_V1' . hex2bin($bHex) . pack('v', $q)), 'freeze_state' => 'active', 'slots' => [], 'conflicts' => [], 'output_claims' => []];
        lock_atomic_write($bFile, json_encode($b, JSON_UNESCAPED_SLASHES));
    }
    if ($r === null) {
        $r = ['active_manifest' => $m, 'last_creator_activity_secs' => min($now, intdiv((int)$m['issued_at_ms'], 1000)), 'voted_proposals_by_rev' => [], 'vetoed_proposal_hashes' => [], 'imported_proposal' => null];
        lock_atomic_write($rFile, json_encode($r, JSON_UNESCAPED_SLASHES));
    }
    if (!file_exists($p['anchors'] . "/{$aHex}.bin")) lock_atomic_write($p['anchors'] . "/{$aHex}.bin", json_encode($m, JSON_UNESCAPED_SLASHES));
    return [$b, $r];
}

function lock_freeze_status(array $keys, array $p, string $aHex, int $now): array {
    $bHex = hash('sha256', 'HUMOCO_SYNC_BUCKET_V1' . hex2bin($aHex) . $keys['pk32']);
    $b = lock_read_json($p['meta'] . "/buckets/{$bHex}.json") ?? lock_fail(404, 'Lock bucket not found on this server');
    lock_auto_expire_pre_freeze($b, $now);
    $r = lock_read_json($p['meta'] . "/rotations/{$aHex}.json");
    $rev = (int)($r['active_manifest']['revision'] ?? 1);
    $fs = $b['freeze_state'];
    $snap = null;
    if (is_array($fs) && isset($fs['pre_proposal']) && $now < (int)$fs['pre_proposal']['expires_at']) {
        $pp = $fs['pre_proposal'];
        $snap = lock_export_snapshot($keys, $p, $b, $bHex, $rev, false, null, (int)$pp['frozen_at'], (int)$pp['expires_at']);
    } elseif (is_array($fs) && isset($fs['permanent_proposal'])) {
        $pm = $fs['permanent_proposal'];
        $snap = lock_export_snapshot($keys, $p, $b, $bHex, (int)$pm['from_rev'], true, hex2bin($pm['proposal_hash']), (int)$pm['frozen_at'], null);
    }
    return ['anchor_id' => $aHex, 'bucket' => $bHex, 'active_manifest' => $r['active_manifest'] ?? null, 'last_creator_activity_secs' => $r['last_creator_activity_secs'] ?? null, 'bucket_freeze_state' => $fs, 'voted_proposal' => $r['voted_proposals_by_rev'][(string)$rev]['proposal'] ?? null, 'snapshot_export' => $snap];
}

function lock_handle_freeze(string $method, array $cfg, array $keys, string $dataDir, int $now): never {
    lock_check_revoked($dataDir);
    $p = lock_paths($dataDir);
    if ($method === 'GET') {
        $aHex = (string)($_GET['anchor_id'] ?? '');
        if (lock_hex_bytes($aHex, 32) === null) lock_fail(400, 'Invalid anchor_id hex');
        lock_ok(200, lock_freeze_status($keys, $p, $aHex, $now));
    }
    $req = json_decode((string)file_get_contents('php://input'), true);
    $act = $req['action'] ?? null;
    if (!is_array($req) || !is_string($act)) lock_fail(400, 'Invalid lock_freeze JSON');
    if ($act === 'fetch_snapshot') {
        $aHex = (string)($req['anchor_id'] ?? '');
        if (lock_hex_bytes($aHex, 32) === null) lock_fail(400, 'Invalid anchor_id hex');
        lock_ok(200, lock_freeze_status($keys, $p, $aHex, $now));
    }
    if ($act === 'pre_freeze') {
        $a32 = lock_hex_bytes($req['anchor_id'] ?? null, 32) ?? lock_fail(400, 'Invalid anchor_id');
        $aHex = $req['anchor_id']; $bHex = hash('sha256', 'HUMOCO_SYNC_BUCKET_V1' . $a32 . $keys['pk32']);
        $res = lock_with_lock($p['meta'] . "/buckets/{$bHex}.lockdir", static function () use ($cfg, $keys, $p, $aHex, $bHex, $req, $now): array {
            [$b, $r] = lock_bootstrap_anchor($cfg, $keys, $p, $aHex, $bHex, $req['current_manifest'] ?? null, $now);
            $rev = (int)$r['active_manifest']['revision']; $fs = $b['freeze_state'];
            if (is_array($fs)) {
                if (isset($fs['epoch_frozen'])) lock_fail(409, 'epoch_frozen');
                if (isset($fs['permanent_proposal'])) lock_fail(409, 'proposal_frozen');
                if (isset($fs['self_frozen'])) lock_fail(409, 'Bucket is self_frozen; submit a signed Propose directly to rotate');
                if (isset($fs['pre_proposal']) && $now < (int)$fs['pre_proposal']['expires_at']) {
                    $pp = $fs['pre_proposal'];
                    return ['status' => 'pre_frozen', 'expires_at' => (int)$pp['expires_at'], 'snapshot_export' => lock_export_snapshot($keys, $p, $b, $bHex, $rev, false, null, (int)$pp['frozen_at'], (int)$pp['expires_at'])];
                }
            }
            $exp = $now + $cfg['pre_freeze_ttl_secs'];
            $b['freeze_state'] = ['pre_proposal' => ['frozen_at' => $now, 'expires_at' => $exp]];
            lock_atomic_write($p['meta'] . "/buckets/{$bHex}.json", json_encode($b, JSON_UNESCAPED_SLASHES));
            return ['status' => 'pre_frozen', 'expires_at' => $exp, 'snapshot_export' => lock_export_snapshot($keys, $p, $b, $bHex, $rev, false, null, $now, $exp)];
        });
        lock_ok(200, $res);
    }
    if ($act === 'heartbeat') {
        $hb = $req['heartbeat'] ?? null;
        $a32 = is_array($hb) ? lock_hex_bytes($hb['anchor_id'] ?? null, 32) : null;
        $ts = $hb['timestamp_secs'] ?? null; $sig = is_array($hb) ? lock_hex_bytes($hb['sig'] ?? null, 64) : null;
        if ($a32 === null || !is_int($ts) || $ts <= 0 || $sig === null) lock_fail(400, 'Invalid CreatorHeartbeat');
        if ($ts > $now + 60) lock_fail(400, 'Heartbeat timestamp is in the future');
        $aHex = $hb['anchor_id']; $bHex = hash('sha256', 'HUMOCO_SYNC_BUCKET_V1' . $a32 . $keys['pk32']);
        $actSecs = lock_with_lock($p['meta'] . "/buckets/{$bHex}.lockdir", static function () use ($cfg, $keys, $p, $a32, $aHex, $bHex, $ts, $sig, $req, $now): int {
            [, $r] = lock_bootstrap_anchor($cfg, $keys, $p, $aHex, $bHex, $req['current_manifest'] ?? null, $now);
            if (!lock_verify_sig(hex2bin($r['active_manifest']['authority']['creator_mig_pub']), $sig, hash('sha256', 'HUMOCO_CREATOR_HB_V1' . $a32 . pack('P', $ts), true))) lock_fail(401, 'Invalid CreatorHeartbeat signature');
            $r['last_creator_activity_secs'] = max((int)$r['last_creator_activity_secs'], $ts);
            lock_atomic_write($p['meta'] . "/rotations/{$aHex}.json", json_encode($r, JSON_UNESCAPED_SLASHES));
            return (int)$r['last_creator_activity_secs'];
        });
        lock_ok(200, ['status' => 'heartbeat_recorded', 'last_creator_activity_secs' => $actSecs]);
    }
    if ($act === 'propose') {
        $prop = $req['proposal'] ?? null;
        $a32 = is_array($prop) ? lock_hex_bytes($prop['anchor_id'] ?? null, 32) : null;
        $pHash32 = is_array($prop) ? lock_proposal_digest($prop) : null;
        if ($a32 === null || $pHash32 === null) lock_fail(400, 'Invalid MigrationProposal');
        $aHex = $prop['anchor_id']; $pHashHex = bin2hex($pHash32); $bHex = hash('sha256', 'HUMOCO_SYNC_BUCKET_V1' . $a32 . $keys['pk32']);
        $res = lock_with_lock($p['meta'] . "/buckets/{$bHex}.lockdir", static function () use ($cfg, $keys, $p, $a32, $aHex, $bHex, $prop, $pHash32, $pHashHex, $req, $now): array {
            [$b, $r] = lock_bootstrap_anchor($cfg, $keys, $p, $aHex, $bHex, $req['current_manifest'] ?? null, $now);
            if (is_array($b['freeze_state']) && isset($b['freeze_state']['epoch_frozen'])) lock_fail(409, 'epoch_frozen');
            if (in_array($pHashHex, $r['vetoed_proposal_hashes'] ?? [], true)) lock_fail(409, 'Proposal was previously vetoed');
            $revKey = (string)$prop['from_rev'];
            if (isset($r['voted_proposals_by_rev'][$revKey])) {
                $vp = $r['voted_proposals_by_rev'][$revKey];
                if ($vp['proposal_hash'] !== $pHashHex) lock_fail(409, 'A conflicting proposal is already locked in voted_proposal[rev]');
                $fAt = $b['freeze_state']['permanent_proposal']['frozen_at'] ?? $vp['accepted_at'];
                return ['status' => 'proposed', 'proposal_hash' => $pHashHex, 'effective_at' => (int)$vp['effective_at'], 'snapshot_export' => lock_export_snapshot($keys, $p, $b, $bHex, (int)$prop['from_rev'], true, $pHash32, (int)$fAt, null)];
            }
            if ((int)$prop['proposed_at'] > $now + 60 || ($now - (int)$prop['proposed_at']) > 3600) lock_fail(400, 'Proposal proposed_at outside fresh 3600s submission window');
            if (!lock_verify_proposal($prop, $a32, $r['active_manifest'])) lock_fail(400, 'Proposal validation failed');
            if ($prop['initiator']['kind'] === 'guarantor' && $now < ((int)$r['last_creator_activity_secs'] + $cfg['creator_inactivity_secs'])) lock_fail(403, 'Creator 30-day inactivity window has not elapsed yet');
            if ($prop['initiator']['kind'] === 'creator') $r['last_creator_activity_secs'] = max((int)$r['last_creator_activity_secs'], $now);
            $effAt = $now + $cfg['proposal_timelock_secs'];
            $r['voted_proposals_by_rev'][$revKey] = ['proposal' => $prop, 'proposal_hash' => $pHashHex, 'accepted_at' => $now, 'effective_at' => $effAt];
            $b['freeze_state'] = ['permanent_proposal' => ['from_rev' => (int)$prop['from_rev'], 'proposal_hash' => $pHashHex, 'frozen_at' => $now, 'effective_at' => $effAt]];
            lock_atomic_write($p['meta'] . "/buckets/{$bHex}.json", json_encode($b, JSON_UNESCAPED_SLASHES));
            lock_atomic_write($p['meta'] . "/rotations/{$aHex}.json", json_encode($r, JSON_UNESCAPED_SLASHES));
            return ['status' => 'proposed', 'proposal_hash' => $pHashHex, 'effective_at' => $effAt, 'snapshot_export' => lock_export_snapshot($keys, $p, $b, $bHex, (int)$prop['from_rev'], true, $pHash32, $now, null)];
        });
        lock_ok(200, $res);
    }
    if ($act === 'veto') {
        $v = $req['veto'] ?? null;
        $a32 = is_array($v) ? lock_hex_bytes($v['anchor_id'] ?? null, 32) : null;
        $ph32 = is_array($v) ? lock_hex_bytes($v['proposal_hash'] ?? null, 32) : null;
        $vp32 = is_array($v) ? lock_hex_bytes($v['vetoer_pub'] ?? null, 32) : null;
        $sig = is_array($v) ? lock_hex_bytes($v['sig'] ?? null, 64) : null;
        if ($a32 === null || $ph32 === null || $vp32 === null || $sig === null || !is_int($v['from_rev'] ?? null) || !is_int($v['vetoed_at'] ?? null) || $v['vetoed_at'] <= 0) lock_fail(400, 'Invalid MigrationVeto');
        if ($v['vetoed_at'] > $now + 60) lock_fail(400, 'Veto timestamp is in the future');
        $aHex = $v['anchor_id']; $bHex = hash('sha256', 'HUMOCO_SYNC_BUCKET_V1' . $a32 . $keys['pk32']);
        lock_with_lock($p['meta'] . "/buckets/{$bHex}.lockdir", static function () use ($p, $v, $a32, $aHex, $bHex, $ph32, $vp32, $sig, $now): void {
            $b = lock_read_json($p['meta'] . "/buckets/{$bHex}.json"); $r = lock_read_json($p['meta'] . "/rotations/{$aHex}.json");
            if ($b === null || $r === null) lock_fail(404, 'Anchor rotation record not found');
            $revKey = (string)$v['from_rev']; $vp = $r['voted_proposals_by_rev'][$revKey] ?? null;
            if ($vp === null) lock_fail(404, 'No pending proposal in this revision');
            if ($vp['proposal_hash'] !== $v['proposal_hash']) lock_fail(409, 'Veto proposal_hash mismatch');
            if ($now >= (int)$vp['effective_at']) lock_fail(409, 'Proposal 72h timelock already expired; veto window closed');
            $auth = $r['active_manifest']['authority'];
            $isC = ($v['vetoer_pub'] === $auth['creator_mig_pub']); $gIdx = array_search($v['vetoer_pub'], $auth['guarantor_mig_pubs'], true);
            if (!$isC && $gIdx === false) lock_fail(401, 'Vetoer is not an authority in manifest');
            $pInit = $vp['proposal']['initiator'];
            if (($pInit['kind'] === 'creator' && $isC) || ($pInit['kind'] === 'guarantor' && $gIdx === $pInit['guarantor_index'])) lock_fail(401, 'Cannot veto own proposal');
            if (!lock_verify_sig($vp32, $sig, hash('sha256', 'HUMOCO_MIGRATION_VETO_V1' . $a32 . pack('P', $v['from_rev']) . $ph32 . $vp32 . pack('P', $v['vetoed_at']), true))) lock_fail(401, 'Invalid veto signature');
            if ($isC) $r['last_creator_activity_secs'] = max((int)$r['last_creator_activity_secs'], $now);
            unset($r['voted_proposals_by_rev'][$revKey]);
            if (!in_array($v['proposal_hash'], $r['vetoed_proposal_hashes'] ?? [], true)) $r['vetoed_proposal_hashes'][] = $v['proposal_hash'];
            if (is_array($b['freeze_state']) && isset($b['freeze_state']['permanent_proposal'])) $b['freeze_state'] = 'active';
            lock_atomic_write($p['meta'] . "/buckets/{$bHex}.json", json_encode($b, JSON_UNESCAPED_SLASHES));
            lock_atomic_write($p['meta'] . "/rotations/{$aHex}.json", json_encode($r, JSON_UNESCAPED_SLASHES));
        });
        lock_ok(200, ['status' => 'vetoed', 'proposal_hash' => $v['proposal_hash']]);
    }
    lock_fail(400, 'Unknown lock_freeze action');
}

function lock_handle_import(array $cfg, array $keys, string $dataDir, int $now): never {
    lock_check_revoked($dataDir);
    $p = lock_paths($dataDir);
    $req = json_decode((string)file_get_contents('php://input'), true);
    $a32 = is_array($req) ? lock_hex_bytes($req['anchor_id'] ?? null, 32) : null;
    $m = $req['active_manifest'] ?? null; $prop = $req['proposal'] ?? null;
    if ($a32 === null || !is_array($m) || !is_array($prop) || !is_array($req['snapshots'] ?? null) || !is_array($req['quorum_certificates'] ?? null)) lock_fail(400, 'Invalid lock_import JSON');
    $histComms = lock_verify_manifest_chain($m, $a32) ?? lock_fail(400, 'Invalid active_manifest chain');
    if (!lock_verify_proposal($prop, $a32, $m)) lock_fail(400, 'Invalid MigrationProposal');
    $newC = lock_validate_committee($prop['new_servers'], (int)$prop['new_threshold']);
    if ($newC === null || !in_array($keys['pkHex'], $newC['members'], true)) lock_fail(400, 'Target server lock_pub is not in proposal.new_servers');
    if ((int)$prop['retain_until_quarter'] > $cfg['max_retention_quarter']) lock_fail(422, 'Proposal retain_until_quarter exceeds server max_retention_quarter');
    if ($now < ((int)$prop['proposed_at'] + $cfg['proposal_timelock_secs'])) lock_fail(409, 'Proposal 72h timelock has not elapsed yet');

    $oldC = $histComms[count($histComms) - 1]; $snaps = $req['snapshots'];
    if (count($snaps) < $oldC['threshold']) lock_fail(400, 'Fewer than Q_old freeze snapshots supplied');
    $pHash32 = lock_proposal_digest($prop); $pHashHex = bin2hex($pHash32);
    $seenSrv = []; $matured = 0; $candBySlot = [];

    foreach ($snaps as $exp) {
        $sn = $exp['snapshot'] ?? null;
        if (!is_array($sn) || ($sn['anchor_id'] ?? '') !== $req['anchor_id'] || ($sn['from_rev'] ?? 0) !== $m['revision']
            || ($sn['retain_until_quarter'] ?? -1) !== $m['retain_until_quarter'] || empty($sn['permanent'])
            || ($sn['proposal_hash'] ?? '') !== $pHashHex || !in_array($sn['lock_pub'] ?? '', $oldC['members'], true) || isset($seenSrv[$sn['lock_pub']])) lock_fail(400, 'Invalid or duplicate FreezeSnapshot');
        $seenSrv[$sn['lock_pub']] = true;
        $slp = hex2bin($sn['lock_pub']); $sbk = lock_hex_bytes($sn['bucket'] ?? null, 32);
        $sbh = lock_hex_bytes($sn['bucket_head'] ?? null, 32); $ssh = lock_hex_bytes($sn['state_hash'] ?? null, 32); $ssig = lock_hex_bytes($sn['sig'] ?? null, 64);
        if ($sbk === null || $sbk !== hash('sha256', 'HUMOCO_SYNC_BUCKET_V1' . $a32 . $slp, true) || $sbh === null || $ssh === null || $ssig === null) lock_fail(400, 'Invalid FreezeSnapshot fields');
        $sPre = 'HUMOCO_FREEZE_SNAP_V1' . $a32 . $sbk . pack('P', $sn['from_rev']) . pack('v', $sn['retain_until_quarter']) . pack('P', $sn['write_seq']) . $sbh . $ssh . "\x01\x01" . $pHash32 . pack('P', $sn['frozen_at']) . pack('P', 0) . $slp;
        if (!lock_verify_sig($slp, $ssig, hash('sha256', $sPre, true))) lock_fail(400, 'Invalid FreezeSnapshot signature');
        if ($now >= ((int)$sn['frozen_at'] + $cfg['proposal_timelock_secs'])) $matured++;

        $parsedE = []; $parsedC = [];
        foreach (($exp['entries'] ?? []) as $h) { $e = lock_parse_entry($h) ?? lock_fail(400, 'Corrupted snapshot entry'); $parsedE[] = $e; $candBySlot[$e['slot']][$e['entryHash']] = $e; }
        foreach (($exp['conflicts'] ?? []) as $grp) {
            $pg = [];
            foreach ($grp as $h) { $e = lock_parse_entry($h) ?? lock_fail(400, 'Corrupted conflict entry'); $pg[] = $e; $candBySlot[$e['slot']][$e['entryHash']] = $e; }
            $parsedC[] = $pg;
        }
        if (lock_freeze_state_hash($a32, (int)$sn['from_rev'], $parsedE, $parsedC) !== $ssh) lock_fail(400, 'FreezeSnapshot state_hash mismatch');
    }
    if ($matured < $oldC['threshold']) lock_fail(409, 'Proposal 72h timelock has not elapsed across Q_old freeze snapshots');

    $ordered = [];
    foreach ($candBySlot as $slot32 => $map) { $list = array_values($map); usort($list, static fn($a, $b) => ($a['depth'] <=> $b['depth']) ?: strcmp($a['entryHash'], $b['entryHash'])); $ordered[] = [$list[0]['depth'], $slot32, $list]; }
    usort($ordered, static fn($a, $b) => ($a[0] <=> $b[0]) ?: strcmp($a[1], $b[1]));
    $cMig32 = hex2bin($m['authority']['creator_mig_pub']); $verified = [];
    foreach ($ordered as [,$slot32, $list]) {
        $vList = [];
        foreach ($list as $e) {
            if ($e['depth'] === 0) { if (lock_verify_entry($e, $a32, $cMig32, $cfg['pow_base_bits'], null) !== null) lock_fail(400, 'Imported root entry fails verification'); }
            else {
                $ok = false; foreach ($verified[$e['parentSlot']] ?? [] as $par) { if (lock_verify_entry($e, $a32, $cMig32, $cfg['pow_base_bits'], $par) === null) { $ok = true; break; } }
                if (!$ok) lock_fail(400, 'Imported entry fails causal verification');
            }
            $vList[] = $e;
        }
        usort($vList, static fn($a, $b) => strcmp($a['entryHash'], $b['entryHash'])); $verified[$slot32] = $vList;
    }

    $qcs = $req['quorum_certificates']; $q = (int)$prop['retain_until_quarter']; $slotsResolved = []; $outClaims = [];
    $recClaim = static function (array $e) use (&$outClaims): void {
        if ($e['depth'] === 0) return;
        $k = bin2hex($e['parentSlot']) . ':' . $e['ob']; $sH = bin2hex($e['slot']);
        if (isset($outClaims[$k]) && $outClaims[$k] !== $sH) lock_fail(400, 'Ambiguous child slot claim');
        $outClaims[$k] = $sH;
    };
    $qcMatchesComm = static function (array $qc, array $e, array $comm, string $a32, int $q): bool {
        $rs = $qc['receipts'] ?? []; if (count($rs) < $comm['threshold']) return false;
        $memSet = array_flip($comm['members']); $seen = []; $ehHex = bin2hex($e['entryHash']);
        foreach ($rs as $r) {
            $lph = $r['lock_pub'] ?? ''; $lp = lock_hex_bytes($lph, 32);
            if ($lp === null || !isset($memSet[$lph]) || isset($seen[$lph]) || ($r['kind'] ?? '') !== 'first_write'
                || ($r['slot'] ?? '') !== $qc['slot'] || ($r['child_lock'] ?? '') !== $qc['child_lock'] || ($r['entry_hash'] ?? '') !== $ehHex
                || ($r['retain_until_quarter'] ?? -1) !== $q || !lock_verify_receipt($r, $lp, hash('sha256', 'HUMOCO_SYNC_BUCKET_V1' . $a32 . $lp, true))) return false;
            $seen[$lph] = true;
        }
        return count($seen) >= $comm['threshold'];
    };

    ksort($verified, SORT_STRING);
    foreach ($verified as $slot32 => $list) {
        if (count($list) === 1) { $recClaim($list[0]); $slotsResolved[$slot32] = ['single', $list[0]]; continue; }
        $winner = null; $slotHex = bin2hex($slot32);
        foreach ($list as $e) {
            $clHex = bin2hex($e['childLock']);
            foreach ($qcs as $qc) {
                if (($qc['slot'] ?? '') !== $slotHex || ($qc['child_lock'] ?? '') !== $clHex) continue;
                foreach ($histComms as $hc) { if ($qcMatchesComm($qc, $e, $hc, $a32, $q)) { $winner = $e; break 3; } }
            }
        }
        if ($winner !== null) { $recClaim($winner); $slotsResolved[$slot32] = ['single', $winner]; }
        else { foreach ($list as $e) $recClaim($e); $slotsResolved[$slot32] = ['conflict', $list]; }
    }

    $impPre = 'HUMOCO_IMPORT_STATE_V1' . $a32 . pack('P', (int)$prop['to_rev']) . pack('P', count($slotsResolved));
    foreach ($slotsResolved as $s32 => $item) {
        $impPre .= $s32;
        if ($item[0] === 'single') $impPre .= "\x01" . $item[1]['entryHash'];
        else { $impPre .= "\x02" . pack('P', count($item[1])); foreach ($item[1] as $e) $impPre .= $e['entryHash']; }
    }
    $impHash32 = hash('sha256', $impPre, true); $impHashHex = bin2hex($impHash32); $aHex = $req['anchor_id'];
    $b32 = hash('sha256', 'HUMOCO_SYNC_BUCKET_V1' . $a32 . $keys['pk32'], true); $bHex = bin2hex($b32); $qStr = lock_format_quarter($q);

    $ackedAt = lock_with_lock($p['meta'] . "/buckets/{$bHex}.lockdir", static function () use ($cfg, $keys, $p, $m, $prop, $a32, $b32, $aHex, $bHex, $pHashHex, $impHashHex, $q, $qStr, $slotsResolved, $outClaims, $now): int {
        $bFile = $p['meta'] . "/buckets/{$bHex}.json"; $rFile = $p['meta'] . "/rotations/{$aHex}.json";
        $r = lock_read_json($rFile) ?? ['active_manifest' => $m, 'last_creator_activity_secs' => min($now, intdiv((int)$m['issued_at_ms'], 1000)), 'voted_proposals_by_rev' => [], 'vetoed_proposal_hashes' => [], 'imported_proposal' => null];
        if (in_array($pHashHex, $r['vetoed_proposal_hashes'] ?? [], true)) lock_fail(409, 'Proposal was vetoed on this server');
        $ei = $r['imported_proposal'] ?? null;
        if (is_array($ei) && $ei['proposal_hash'] === $pHashHex && (int)$ei['to_rev'] === (int)$prop['to_rev'] && $ei['imported_state_hash'] === $impHashHex) return (int)$ei['acked_at'];
        $oldB = lock_read_json($bFile); $oldInodes = $oldB ? (count($oldB['slots'] ?? []) + count($oldB['conflicts'] ?? [])) : 0; $newInodes = count($slotsResolved);
        $used = max(0, lock_used_inodes_get($p) - $oldInodes);
        if ($newInodes > 0 && ($used + $newInodes) > $cfg['max_inodes'] && $oldB === null && $used >= $cfg['max_inodes']) lock_fail(507, 'Lock inode budget exhausted');
        $slotDir = $p['locks'] . "/{$qStr}/{$bHex}";
        if (!is_dir($slotDir) && !mkdir($slotDir, 0755, true) && !is_dir($slotDir)) lock_fail(500, 'Failed to create target slot dir');
        foreach (glob("{$slotDir}/*.lock") ?: [] as $oldF) @unlink($oldF);
        $bh = hash('sha256', 'HUMOCO_BUCKET_INIT_V1' . $b32 . pack('v', $q), true); $ws = 0; $newSlots = []; $newConflicts = [];
        foreach ($slotsResolved as $s32 => $item) {
            $sHex = bin2hex($s32);
            if ($item[0] === 'single') {
                $e = $item[1]; $fHex = hash('sha256', 'HUMOCO_SYNC_FILE_V1' . $s32 . $keys['pk32']);
                if (!lock_atomic_write("{$slotDir}/{$fHex}.lock", $e['wire'])) lock_fail(500, 'Failed to persist imported slot');
                $newSlots[$sHex] = $fHex; $ws++;
                $bh = hash('sha256', 'HUMOCO_BUCKET_STEP_V1' . $bh . pack('P', $ws) . $s32 . $e['entryHash'], true);
            } else $newConflicts[$sHex] = array_map(static fn($e) => $e['hex'], $item[1]);
        }
        $fState = 'active';
        if ($oldB !== null && is_array($oldB['freeze_state'])) {
            $ofs = $oldB['freeze_state'];
            if (isset($ofs['self_frozen']) || isset($ofs['permanent_proposal'])) $fState = $ofs;
            elseif (isset($ofs['pre_proposal']) && $now < (int)$ofs['pre_proposal']['expires_at']) $fState = $ofs;
        }
        lock_atomic_write($bFile, json_encode(['anchor_id' => $aHex, 'retain_until_quarter' => $q, 'creator_mig_pub' => $m['authority']['creator_mig_pub'], 'write_seq' => $ws, 'bucket_head' => bin2hex($bh), 'freeze_state' => $fState, 'slots' => $newSlots, 'conflicts' => $newConflicts, 'output_claims' => $outClaims], JSON_UNESCAPED_SLASHES));
        lock_used_inodes_add($p, $newInodes - $oldInodes);
        $r['imported_proposal'] = ['proposal_hash' => $pHashHex, 'to_rev' => (int)$prop['to_rev'], 'imported_state_hash' => $impHashHex, 'acked_at' => $now];
        lock_atomic_write($rFile, json_encode($r, JSON_UNESCAPED_SLASHES));
        if (!file_exists($p['anchors'] . "/{$aHex}.bin")) lock_atomic_write($p['anchors'] . "/{$aHex}.bin", json_encode($m, JSON_UNESCAPED_SLASHES));
        return $now;
    });

    $ackDig = hash('sha256', 'HUMOCO_IMPORT_ACK_V1' . $a32 . $pHash32 . pack('P', (int)$prop['to_rev']) . $impHash32 . pack('v', $q) . $keys['pk32'] . pack('P', $ackedAt), true);
    lock_ok(200, ['status' => 'imported', 'imported_slots' => count($slotsResolved), 'import_ack' => ['anchor_id' => $aHex, 'proposal_hash' => $pHashHex, 'to_rev' => (int)$prop['to_rev'], 'imported_state_hash' => $impHashHex, 'retain_until_quarter' => $q, 'lock_pub' => $keys['pkHex'], 'acked_at' => $ackedAt, 'sig' => bin2hex(lock_sign($keys['sk64'], $ackDig))]]);
}

function lock_handle_commit(array $cfg, array $keys, string $dataDir, int $now): never {
    lock_check_revoked($dataDir);
    $p = lock_paths($dataDir);
    $req = json_decode((string)file_get_contents('php://input'), true);
    $act = $req['action'] ?? null;
    if (!is_array($req) || !is_string($act)) lock_fail(400, 'Invalid lock_commit JSON');
    $a32 = lock_hex_bytes($req['anchor_id'] ?? null, 32) ?? lock_fail(400, 'Invalid anchor_id');
    $aHex = $req['anchor_id'];

    if ($act === 'sign_commit') {
        $prop = $req['proposal'] ?? null; $ish32 = lock_hex_bytes($req['imported_state_hash'] ?? null, 32); $acks = $req['import_acks'] ?? null;
        if (!is_array($prop) || ($prop['anchor_id'] ?? '') !== $aHex || $ish32 === null || !is_array($acks)) lock_fail(400, 'Invalid sign_commit payload');
        $r = lock_read_json($p['meta'] . "/rotations/{$aHex}.json") ?? lock_fail(404, 'Anchor rotation record not found');
        $am = $r['active_manifest'];
        if ((int)$am['revision'] !== (int)$prop['from_rev']) lock_fail(409, 'Manifest revision mismatch');
        $oldC = lock_validate_committee($am['servers'], (int)$am['threshold']);
        if (!in_array($keys['pkHex'], $oldC['members'], true)) lock_fail(400, 'Server is not in previous committee');
        $vp = $r['voted_proposals_by_rev'][(string)$prop['from_rev']] ?? null;
        $pHash32 = lock_proposal_digest($prop); $pHashHex = $pHash32 !== null ? bin2hex($pHash32) : '';
        if ($vp === null || $vp['proposal_hash'] !== $pHashHex) lock_fail(409, 'Proposal does not match voted_proposal[rev]');
        if ($now < (int)$vp['effective_at']) lock_fail(409, 'Proposal 72h timelock has not elapsed yet');
        $newC = lock_validate_committee($prop['new_servers'], (int)$prop['new_threshold']);
        if ($newC === null || !lock_verify_import_acks($acks, $newC, $a32, $pHash32, (int)$prop['to_rev'], $ish32, (int)$prop['retain_until_quarter'])) lock_fail(401, 'Invalid ImportAck');
        $cDig = hash('sha256', 'HUMOCO_MIGRATION_CERT_V1' . $a32 . $pHash32 . pack('P', $prop['to_rev']) . $ish32, true);
        lock_ok(200, ['status' => 'commit_signed', 'committee_signature' => ['lock_pub' => $keys['pkHex'], 'committed_at' => $now, 'sig' => bin2hex(lock_sign($keys['sk64'], $cDig))]]);
    }
    if ($act === 'finalize') {
        $nm = $req['new_manifest'] ?? null;
        if (!is_array($nm) || ($nm['revision'] ?? 0) <= 1) lock_fail(400, 'Finalize requires migrated manifest revision >= 2');
        $comms = lock_verify_manifest_chain($nm, $a32) ?? lock_fail(400, 'Invalid new_manifest chain');
        $q = (int)$nm['retain_until_quarter'];
        if ($q > $cfg['max_retention_quarter']) lock_fail(422, 'Manifest retain_until_quarter exceeds server limit');
        $latest = $nm['migration_chain'][count($nm['migration_chain']) - 1];
        $lpHashHex = bin2hex(lock_proposal_digest($latest['proposal']));
        $b32 = hash('sha256', 'HUMOCO_SYNC_BUCKET_V1' . $a32 . $keys['pk32'], true); $bHex = bin2hex($b32);
        $inNew = in_array($keys['pkHex'], $comms[count($comms) - 1]['members'], true);

        $newState = lock_with_lock($p['meta'] . "/buckets/{$bHex}.lockdir", static function () use ($p, $keys, $nm, $aHex, $bHex, $b32, $q, $inNew, $lpHashHex, $latest, $now) {
            $bFile = $p['meta'] . "/buckets/{$bHex}.json"; $rFile = $p['meta'] . "/rotations/{$aHex}.json";
            $r = lock_read_json($rFile) ?? ['active_manifest' => $nm, 'last_creator_activity_secs' => min($now, intdiv((int)$nm['issued_at_ms'], 1000)), 'voted_proposals_by_rev' => [], 'vetoed_proposal_hashes' => [], 'imported_proposal' => null];
            if ($inNew) {
                $imp = $r['imported_proposal'] ?? null;
                if (!is_array($imp) || $imp['proposal_hash'] !== $lpHashHex || (int)$imp['to_rev'] !== (int)$nm['revision'] || $imp['imported_state_hash'] !== $latest['imported_state_hash']) lock_fail(409, 'Target server must complete ?lock_import for this revision before Finalize');
            }
            $r['active_manifest'] = $nm; $r['imported_proposal'] = null;
            lock_atomic_write($rFile, json_encode($r, JSON_UNESCAPED_SLASHES));
            lock_atomic_write($p['anchors'] . "/{$aHex}.bin", json_encode($nm, JSON_UNESCAPED_SLASHES));
            $b = lock_read_json($bFile) ?? ['anchor_id' => $aHex, 'retain_until_quarter' => $q, 'creator_mig_pub' => $nm['authority']['creator_mig_pub'], 'write_seq' => 0, 'bucket_head' => hash('sha256', 'HUMOCO_BUCKET_INIT_V1' . $b32 . pack('v', $q)), 'freeze_state' => 'active', 'slots' => [], 'conflicts' => [], 'output_claims' => []];
            $b['freeze_state'] = $inNew ? ((is_array($b['freeze_state']) && isset($b['freeze_state']['self_frozen'])) ? $b['freeze_state'] : 'active') : ['epoch_frozen' => ['committed_rev' => (int)$nm['revision'], 'frozen_at' => $now]];
            lock_atomic_write($bFile, json_encode($b, JSON_UNESCAPED_SLASHES));
            return $b['freeze_state'];
        });
        lock_ok(200, ['status' => 'finalized', 'revision' => (int)$nm['revision'], 'bucket_freeze_state' => $newState]);
    }
    lock_fail(400, 'Unknown lock_commit action');
}
