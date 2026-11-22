#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_BIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin)
      SERVER_BIN="${2:-}"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--bin /path/to/humoco-sync-server]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if ! command -v php >/dev/null 2>&1; then
  echo "Error: 'php' (>= 8.1 + ext-sodium) is required." >&2
  exit 1
fi

PHP_OK="$(php -r 'echo (PHP_VERSION_ID >= 80100 && function_exists("sodium_crypto_sign_detached") && in_array("sha3-256", hash_algos(), true)) ? "ok" : "fail";' 2>/dev/null || echo "fail")"
if [[ "$PHP_OK" != "ok" ]]; then
  echo "Error: PHP >= 8.1 with ext-sodium and sha3-256 is required." >&2
  exit 1
fi

if [[ -z "$SERVER_BIN" ]]; then
  SERVER_BIN="${ROOT_DIR}/rust/target/debug/humoco-sync-server"
  if [[ ! -x "$SERVER_BIN" ]]; then
    cargo build --offline --manifest-path "${ROOT_DIR}/rust/Cargo.toml"
  fi
fi

PASS=0
TMP_DIR="$(mktemp -d)"
PHP_PID=""

cleanup() {
  if [[ -n "$PHP_PID" ]] && kill -0 "$PHP_PID" 2>/dev/null; then
    kill "$PHP_PID" 2>/dev/null || true
    wait "$PHP_PID" 2>/dev/null || true
  fi
  if [[ -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

ok() {
  PASS=$((PASS + 1))
  echo "  [PASS] $1"
}

fail() {
  echo "  [FAIL] $1" >&2
  exit 1
}

assert_eq() {
  if [[ "$1" == "$2" ]]; then
    ok "$3 ($1)"
  else
    fail "$3: expected '$2', got '$1'"
  fi
}

assert_contains() {
  if [[ "$1" == *"$2"* ]]; then
    ok "$3"
  else
    fail "$3: missing '$2' in '$1'"
  fi
}

pick_free_port() {
  for p in $(seq 19100 19199); do
    if ! (echo >/dev/tcp/127.0.0.1/"$p") 2>/dev/null; then
      echo "$p"
      return 0
    fi
  done
  echo "No free loopback port" >&2
  exit 1
}

rand_nonce() {
  od -tx1 -An -N16 /dev/urandom | tr -d ' \n'
}

start_php_server() {
  local docroot="$1"
  local admin_pk="$2"
  local max_inodes="$3"
  local workers="$4"
  local port="$5"
  local log_file="$6"
  local prop_tl="${7:-259200}"

  mkdir -p "$docroot"
  cp "${ROOT_DIR}/php/sync.php" "${ROOT_DIR}/php/lock_handler.php" "${ROOT_DIR}/php/lock_rotation.php" "${ROOT_DIR}/php/index.html" "${ROOT_DIR}/php/robots.txt" "$docroot/"
  cat > "$docroot/config.php" <<EOF
<?php
return [
    'admin_pubkey' => '${admin_pk}',
    'data_dir' => 'humoco_sync_data',
    'max_members' => 300,
    'max_total_storage_mb' => 64,
    'disable_rate_limit' => true,
    'channels' => [
        'card' => ['max_bytes' => 524288, 'ttl_days' => 0],
        'post' => ['max_bytes' => 131072, 'ttl_days' => 30],
    ],
    'lock' => [
        'enabled' => true,
        'max_retention_quarter' => 8159,
        'max_inodes' => ${max_inodes},
        'pow_base_bits' => 8,
        'allow_pow_tickets' => false,
        'ticket_pow_bits' => 16,
        'proposal_timelock_secs' => ${prop_tl},
    ],
];
EOF
  PHP_CLI_SERVER_WORKERS="$workers" php -S "127.0.0.1:${port}" -t "$docroot" "$docroot/sync.php" > "$log_file" 2>&1 &
  PHP_PID=$!
  for _ in $(seq 1 40); do
    if curl -sf "http://127.0.0.1:${port}/sync.php?info" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  cat "$log_file" >&2 || true
  fail "PHP test server failed to start on port $port"
}

stop_php_server() {
  if [[ -n "$PHP_PID" ]] && kill -0 "$PHP_PID" 2>/dev/null; then
    kill "$PHP_PID" 2>/dev/null || true
    wait "$PHP_PID" 2>/dev/null || true
  fi
  PHP_PID=""
}

issue_ticket() {
  local base_url="$1"
  local admin_sk="$2"
  local admin_pk="$3"
  local anchor_id="$4"
  local quarter="$5"
  local out_file="$6"
  local req_file="${out_file}.req"

  printf '{"anchor_id":"%s","retain_until_quarter":%s,"pow_timestamp":null,"pow_nonce":null}' "$anchor_id" "$quarter" > "$req_file"
  local ts nonce sig code
  ts="$(date +%s)"
  nonce="$(rand_nonce)"
  sig="$("$SERVER_BIN" sign-test sign-member --sk "$admin_sk" --method POST --channel lock_ticket --ts "$ts" --nonce "$nonce" --body-file "$req_file")"
  code="$(curl -s -o "$out_file" -w '%{http_code}' -X POST \
    -H "X-Drop-Pubkey: $admin_pk" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    -H 'Content-Type: application/json' \
    --data-binary "@$req_file" \
    "${base_url}/sync.php?lock_ticket")"
  echo "$code"
}

echo "=== PHP Lock Channel Concurrency, Abort, Rollback, Quota & GC Tests ==="
read -r ADMIN_SK ADMIN_PK <<< "$("$SERVER_BIN" sign-test keygen)"
PORT1="$(pick_free_port)"
DOC1="$TMP_DIR/doc1"
start_php_server "$DOC1" "$ADMIN_PK" 50000 8 "$PORT1" "$TMP_DIR/php1.log"
URL1="http://127.0.0.1:${PORT1}"
DATA1="${URL1}/humoco_sync_data"
LOCK_PUB="$(curl -sf "${URL1}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"
[[ ${#LOCK_PUB} -eq 64 ]] || fail "Invalid lock_pub from PHP ?lock_selftest"
QTR=8125

echo "--- Test 1: 16-way parallel writer race on identical slot (link() + mkdir lock) ---"
ANCHOR_RACE="$("$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --anchor-tag "race" --variant anchor_id)"
assert_eq "$(issue_ticket "$URL1" "$ADMIN_SK" "$ADMIN_PK" "$ANCHOR_RACE" "$QTR" "$TMP_DIR/race_ticket.json")" "200" "Issued GenesisTicket for race test"

mkdir -p "$TMP_DIR/race"
for i in $(seq 0 15); do
  "$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --ticket-json "$TMP_DIR/race_ticket.json" --anchor-tag "race" --variant "race:${i}" > "$TMP_DIR/race/req_${i}.json"
done

pids=()
for i in $(seq 0 15); do
  (
    curl -s -o "$TMP_DIR/race/resp_${i}.json" -w '%{http_code}' -X POST \
      -H 'Content-Type: application/json' \
      --data-binary "@$TMP_DIR/race/req_${i}.json" \
      "${URL1}/sync.php?lock" > "$TMP_DIR/race/code_${i}.txt"
  ) &
  pids+=("$!")
done
for pid in "${pids[@]}"; do
  wait "$pid"
done

ok_cnt=0
conf_cnt=0
for i in $(seq 0 15); do
  c="$(cat "$TMP_DIR/race/code_${i}.txt")"
  [[ "$c" == "200" ]] || fail "Race request $i returned HTTP $c: $(cat "$TMP_DIR/race/resp_${i}.json")"
  r="$(cat "$TMP_DIR/race/resp_${i}.json")"
  if [[ "$r" == *'"status":"ok"'* ]]; then
    ok_cnt=$((ok_cnt + 1))
  elif [[ "$r" == *'"status":"conflict"'* ]]; then
    conf_cnt=$((conf_cnt + 1))
  else
    fail "Unexpected race response $i: $r"
  fi
done
assert_eq "$ok_cnt" "1" "Exactly 1 parallel writer wins FirstWrite"
assert_eq "$conf_cnt" "15" "Remaining 15 parallel writers receive ConflictSeen"
RACE_REL="$("$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --anchor-tag "race" --variant read_path)"
assert_eq "$(curl -sf "${DATA1}/${RACE_REL}" | wc -c | tr -d ' ')" "605" "Winning static .lock file is intact (605B)"

echo "--- Test 2: Aborted client retry (ignore_user_abort(true) + idempotency) ---"
ANCHOR_ABT="$("$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --anchor-tag "abort" --variant anchor_id)"
assert_eq "$(issue_ticket "$URL1" "$ADMIN_SK" "$ADMIN_PK" "$ANCHOR_ABT" "$QTR" "$TMP_DIR/abt_ticket.json")" "200" "Issued ticket for abort test"
"$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --ticket-json "$TMP_DIR/abt_ticket.json" --anchor-tag "abort" --variant "seq:0" > "$TMP_DIR/abt_req.json"
curl --max-time 0.002 -s -o /dev/null -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/abt_req.json" "${URL1}/sync.php?lock" || true
sleep 0.25
ABT_RETRY="$(curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/abt_req.json" "${URL1}/sync.php?lock")"
assert_contains "$ABT_RETRY" '"status":"ok"' "Retry after aborted connection succeeds cleanly"
assert_contains "$ABT_RETRY" '"kind":"first_write"' "Retry receives FirstWrite (never treated as conflict)"

echo "--- Test 3: Simulated hoster snapshot rollback triggers Self-Freeze ---"
ANCHOR_RB="$("$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --anchor-tag "rollback" --variant anchor_id)"
assert_eq "$(issue_ticket "$URL1" "$ADMIN_SK" "$ADMIN_PK" "$ANCHOR_RB" "$QTR" "$TMP_DIR/rb_ticket.json")" "200" "Issued ticket for rollback test"
"$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --ticket-json "$TMP_DIR/rb_ticket.json" --anchor-tag "rollback" --variant "seq:0" > "$TMP_DIR/rb_b0.json"
assert_contains "$(curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/rb_b0.json" "${URL1}/sync.php?lock")" '"write_seq":1' "Committed write_seq=1 before backup snapshot"

cp -a "${DOC1}/humoco_sync_data" "${TMP_DIR}/rollback_snapshot"

"$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --ticket-json "$TMP_DIR/rb_ticket.json" --anchor-tag "rollback" --variant "seq:1" > "$TMP_DIR/rb_b1.json"
curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/rb_b1.json" "${URL1}/sync.php?lock" > "$TMP_DIR/rb_head2.json"
assert_contains "$(cat "$TMP_DIR/rb_head2.json")" '"write_seq":2' "Captured server-signed receipt at write_seq=2"

rm -rf "${DOC1}/humoco_sync_data"
cp -a "${TMP_DIR}/rollback_snapshot" "${DOC1}/humoco_sync_data"

"$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --ticket-json "$TMP_DIR/rb_ticket.json" --receipt-json "$TMP_DIR/rb_head2.json" --anchor-tag "rollback" --variant "seq:2" > "$TMP_DIR/rb_detect.json"
RB_CODE="$(curl -s -o "$TMP_DIR/rb_detect_resp.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/rb_detect.json" "${URL1}/sync.php?lock")"
assert_eq "$RB_CODE" "409" "Client presenting write_seq=2 receipt after rollback triggers 409"
assert_contains "$(cat "$TMP_DIR/rb_detect_resp.json")" '"bucket_self_frozen"' "Bucket enters Self-Frozen state"

"$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --ticket-json "$TMP_DIR/rb_ticket.json" --anchor-tag "rollback" --variant "seq:3" > "$TMP_DIR/rb_after.json"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/rb_after.json" "${URL1}/sync.php?lock")" "409" "Self-frozen bucket rejects subsequent writes (409)"

stop_php_server

echo "--- Test 4: Inode budget (80%/100%), DELETE ?account immunity & simulated-clock GC ---"
read -r ADMIN2_SK ADMIN2_PK <<< "$("$SERVER_BIN" sign-test keygen)"
read -r FRIEND2_SK FRIEND2_PK <<< "$("$SERVER_BIN" sign-test keygen)"
PORT2="$(pick_free_port)"
DOC2="$TMP_DIR/doc2"
start_php_server "$DOC2" "$ADMIN2_PK" 5 2 "$PORT2" "$TMP_DIR/php2.log"
URL2="http://127.0.0.1:${PORT2}"
DATA2="${URL2}/humoco_sync_data"
LP2="$(curl -sf "${URL2}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"

# Authorize friend2 in 'lock' and 'card'
printf '{"pubkeys":["%s"]}' "$FRIEND2_PK" > "$TMP_DIR/f2.json"
for ch in lock card; do
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$SERVER_BIN" sign-test sign-admin --sk "$ADMIN2_SK" --action PUT_MEMBERS --channel "$ch" --ts "$ts" --nonce "$nonce" --body-file "$TMP_DIR/f2.json")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $ADMIN2_PK" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$TMP_DIR/f2.json" "${URL2}/sync.php?members&channel=${ch}")" "200" "Authorized friend2 in channel $ch"
done

ANCHOR_Q="$("$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LP2" --admin-pub "$ADMIN2_PK" --quarter "$QTR" --anchor-tag "quota" --variant anchor_id)"
printf '{"anchor_id":"%s","retain_until_quarter":%s,"pow_timestamp":null,"pow_nonce":null}' "$ANCHOR_Q" "$QTR" > "$TMP_DIR/qt_req.json"
ts="$(date +%s)"; nonce="$(rand_nonce)"
sig="$("$SERVER_BIN" sign-test sign-member --sk "$FRIEND2_SK" --method POST --channel lock_ticket --ts "$ts" --nonce "$nonce" --body-file "$TMP_DIR/qt_req.json")"
curl -sf -X POST -H "X-Drop-Pubkey: $FRIEND2_PK" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/qt_req.json" "${URL2}/sync.php?lock_ticket" > "$TMP_DIR/qt_resp.json"

for i in 0 1 2 3; do
  "$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LP2" --admin-pub "$ADMIN2_PK" --quarter "$QTR" --ticket-json "$TMP_DIR/qt_resp.json" --anchor-tag "quota" --variant "seq:${i}" > "$TMP_DIR/q_s${i}.json"
  assert_contains "$(curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/q_s${i}.json" "${URL2}/sync.php?lock")" '"status":"ok"' "Committed quota slot $i (4/5 = 80%)"
done
assert_contains "$(curl -sf "${URL2}/sync.php?info")" '"inode_warning":true' "GET ?info flags inode_warning=true at 80% budget"

"$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LP2" --admin-pub "$ADMIN2_PK" --quarter "$QTR" --ticket-json "$TMP_DIR/qt_resp.json" --anchor-tag "quota" --variant "seq:4" > "$TMP_DIR/q_s4.json"
assert_contains "$(curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/q_s4.json" "${URL2}/sync.php?lock")" '"status":"ok"' "Committed 5th slot (100% budget)"

ANCHOR_Q2="$("$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LP2" --admin-pub "$ADMIN2_PK" --quarter "$QTR" --anchor-tag "quota-full" --variant anchor_id)"
assert_eq "$(issue_ticket "$URL2" "$ADMIN2_SK" "$ADMIN2_PK" "$ANCHOR_Q2" "$QTR" "$TMP_DIR/qt_full.json")" "507" "New POST ?lock_ticket rejected with 507 at 100% inode budget"

# Friend deletes own account -> active locks MUST survive!
ts="$(date +%s)"; nonce="$(rand_nonce)"
sig="$("$SERVER_BIN" sign-test sign-member --sk "$FRIEND2_SK" --method DELETE_ACCOUNT --ts "$ts" --nonce "$nonce")"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "X-Drop-Pubkey: $FRIEND2_PK" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" "${URL2}/sync.php?account")" "200" "DELETE ?account succeeds for friend2"

Q_REL0="$("$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LP2" --admin-pub "$ADMIN2_PK" --quarter "$QTR" --anchor-tag "quota" --variant read_path_seq:0)"
assert_eq "$(curl -sf "${DATA2}/${Q_REL0}" | wc -c | tr -d ' ')" "605" "Active 605B lock survives DELETE ?account & full inode budget"

PURGE_AT="$(php -r "require '${DOC2}/lock_handler.php'; echo lock_purge_after_secs(${QTR});")"
GC_BEFORE="$(php "${DOC2}/lock_handler.php" --gc --config="${DOC2}/config.php" --now="$((PURGE_AT - 1))")"
assert_contains "$GC_BEFORE" "purged_buckets=0 purged_inodes=0" "GC 1s before retention deadline keeps bucket intact"
assert_eq "$(curl -sf "${DATA2}/${Q_REL0}" | wc -c | tr -d ' ')" "605" "Lock remains readable 1s before retention expiry"

GC_AFTER="$(php "${DOC2}/lock_handler.php" --gc --config="${DOC2}/config.php" --now="${PURGE_AT}")"
assert_contains "$GC_AFTER" "purged_buckets=1 purged_inodes=5" "GC at Quartalsende + 30d purges expired bucket & 5 inodes"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${DATA2}/${Q_REL0}")" "404" "Expired lock returns 404 after retention GC"
assert_contains "$(curl -sf "${URL2}/sync.php?info")" '"used_inodes":0' "GET ?info reports used_inodes=0 after GC"

stop_php_server

echo "--- Test 5 (SYNC-S07-01/02): Atomic partial-batch abort, exact nonce expiry & 409 freeze code ---"
read -r ADMIN3_SK ADMIN3_PK <<< "$("$SERVER_BIN" sign-test keygen)"
PORT3="$(pick_free_port)"
DOC3="$TMP_DIR/doc3"
start_php_server "$DOC3" "$ADMIN3_PK" 50000 4 "$PORT3" "$TMP_DIR/php3.log"
URL3="http://127.0.0.1:${PORT3}"
DATA3="${URL3}/humoco_sync_data"
LP3="$(curl -sf "${URL3}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"

ANCHOR_C1="$("$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LP3" --admin-pub "$ADMIN3_PK" --quarter "$QTR" --anchor-tag "s07-c1" --variant anchor_id)"
assert_eq "$(issue_ticket "$URL3" "$ADMIN3_SK" "$ADMIN3_PK" "$ANCHOR_C1" "$QTR" "$TMP_DIR/c1_ticket.json")" "200" "Issued ticket for S07-C1"
"$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LP3" --admin-pub "$ADMIN3_PK" --quarter "$QTR" --ticket-json "$TMP_DIR/c1_ticket.json" --anchor-tag "s07-c1" --variant init > "$TMP_DIR/c1_init.json"

# Craft [entry0, entry1, entry2] where entry2 claims the exact same (entry0.slot, branch 0) -> 409 output_branch_already_claimed
php -r '
  $req = json_decode(file_get_contents($argv[1]), true);
  $a32 = hex2bin($req["anchor_id"]);
  $e0 = hex2bin($req["entries"][0]);
  $slot0 = substr($e0, 5, 32);
  $recv1SkSeed = str_repeat(chr(93), 32);
  $recv1Kp = sodium_crypto_sign_seed_keypair($recv1SkSeed);
  $recv1Sk = sodium_crypto_sign_secretkey($recv1Kp);
  $recv1Pub = sodium_crypto_sign_publickey($recv1Kp);
  $slot2 = hash("sha256", "HUMOCO_SYNC_SLOT_V1" . $a32 . str_repeat(chr(0x33), 32), true);
  $child2 = str_repeat(chr(0x33), 32);
  $recv2Hash = str_repeat(chr(0x78), 32);
  $dig = hash("sha256", "HUMOCO_CAUSAL_OUTPUT_V1" . $a32 . $slot2 . $slot0 . "\x00" . pack("V", 1) . $child2 . $recv1Pub . $recv2Hash . "\x00" . str_repeat("\0", 32), true);
  $csig = sodium_crypto_sign_detached($dig, $recv1Sk);
  $nonce = 0;
  for (;; $nonce++) {
    $h = hash("sha256", "HUMOCO_LOCK_POW_V1" . $slot2 . $child2 . pack("V", 1) . pack("P", $nonce), true);
    if (ord($h[0]) === 0) break;
  }
  $wire2 = "HMLK\x01" . $slot2 . $slot0 . "\x00" . pack("V", 1) . $child2 . $recv1Pub . $recv2Hash . "\x00" . str_repeat("\0", 32) . $csig . "\x00" . str_repeat("\0", 64) . str_repeat("\x67", 265) . pack("P", $nonce);
  $req["entries"][] = bin2hex($wire2);
  file_put_contents($argv[2], json_encode($req, JSON_UNESCAPED_SLASHES));
' "$TMP_DIR/c1_init.json" "$TMP_DIR/c1_abort_claim.json"

ABT_CODE="$(curl -s -o "$TMP_DIR/c1_abort_resp.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/c1_abort_claim.json" "${URL3}/sync.php?lock")"
assert_eq "$ABT_CODE" "409" "SYNC-S07-01: duplicate branch claim in batch returns 409"
assert_contains "$(cat "$TMP_DIR/c1_abort_resp.json")" '"output_branch_already_claimed"' "SYNC-S07-01: 409 error is output_branch_already_claimed"
C1_REL0="$("$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LP3" --admin-pub "$ADMIN3_PK" --quarter "$QTR" --anchor-tag "s07-c1" --variant read_path)"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${DATA3}/${C1_REL0}")" "404" "SYNC-S07-01: aborted prefix entry0 MUST NOT remain readable on disk (404)"
assert_contains "$(curl -sf "${URL3}/sync.php?info")" '"used_inodes":0' "SYNC-S07-01: used_inodes stays 0 after aborted batch"

# Exact-second nonce expiry check (SYNC-S07-02)
NONCE_BOUNDARY="$(php -r '
  require $argv[1];
  $p = lock_paths($argv[2]);
  $ok1 = lock_consume_nonce($p, "req:exact120", 120, 1795000000);
  $okEq = lock_consume_nonce($p, "req:exact120", 120, 1795000120);
  $okAfter = lock_consume_nonce($p, "req:exact120", 120, 1795000121);
  echo ($ok1 ? "1" : "0") . ":" . ($okEq ? "1" : "0") . ":" . ($okAfter ? "1" : "0");
' "${DOC3}/lock_handler.php" "${DOC3}/humoco_sync_data")"
assert_eq "$NONCE_BOUNDARY" "1:0:1" "SYNC-S07-02: lock_consume_nonce rejects replay at exact exp == now"

# Self-frozen bucket ticket returns canonical bucket_self_frozen (SYNC-S07-02)
ANCHOR_SF="$("$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LP3" --admin-pub "$ADMIN3_PK" --quarter "$QTR" --anchor-tag "s07-sf" --variant anchor_id)"
assert_eq "$(issue_ticket "$URL3" "$ADMIN3_SK" "$ADMIN3_PK" "$ANCHOR_SF" "$QTR" "$TMP_DIR/sf_ticket.json")" "200" "Issued ticket for S07-SF"
"$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LP3" --admin-pub "$ADMIN3_PK" --quarter "$QTR" --ticket-json "$TMP_DIR/sf_ticket.json" --anchor-tag "s07-sf" --variant seq:0 > "$TMP_DIR/sf_b0.json"
curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/sf_b0.json" "${URL3}/sync.php?lock" > "$TMP_DIR/sf_rec0.json"
"$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LP3" --admin-pub "$ADMIN3_PK" --quarter "$QTR" --ticket-json "$TMP_DIR/sf_ticket.json" --anchor-tag "s07-sf" --variant seq:1 > "$TMP_DIR/sf_b1.json"
curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/sf_b1.json" "${URL3}/sync.php?lock" > "$TMP_DIR/sf_rec1.json"
# Force bucket tombstone rollback check by deleting bucket metadata & presenting rec1
rm -rf "${DOC3}/humoco_sync_data/.locks_meta/buckets/"*.json
"$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LP3" --admin-pub "$ADMIN3_PK" --quarter "$QTR" --ticket-json "$TMP_DIR/sf_ticket.json" --receipt-json "$TMP_DIR/sf_rec1.json" --anchor-tag "s07-sf" --variant seq:2 > "$TMP_DIR/sf_rb.json"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/sf_rb.json" "${URL3}/sync.php?lock")" "409" "Triggered self_frozen on s07-sf"
assert_eq "$(issue_ticket "$URL3" "$ADMIN3_SK" "$ADMIN3_PK" "$ANCHOR_SF" "$QTR" "$TMP_DIR/sf_ticket_after.json")" "409" "POST ?lock_ticket on self_frozen returns 409"
assert_contains "$(cat "$TMP_DIR/sf_ticket_after.json")" '"error":"bucket_self_frozen"' "SYNC-S07-02: POST ?lock_ticket reports canonical bucket_self_frozen"

stop_php_server

echo "--- Test 6 (SYNC-S07-03/04): Sticky SelfFrozen & Monotonic Rotation Guards ---"
read -r R1_ADMIN_SK R1_ADMIN_PK <<< "$("$SERVER_BIN" sign-test keygen)"
read -r R2_ADMIN_SK R2_ADMIN_PK <<< "$("$SERVER_BIN" sign-test keygen)"
read -r R3_ADMIN_SK R3_ADMIN_PK <<< "$("$SERVER_BIN" sign-test keygen)"
R1_PORT="$(pick_free_port)"
R1_DOC="$TMP_DIR/rot_s1"
start_php_server "$R1_DOC" "$R1_ADMIN_PK" 50000 2 "$R1_PORT" "$TMP_DIR/r1.log"
R1_PID="$PHP_PID"
PHP_PID=""
R1_URL="http://127.0.0.1:${R1_PORT}"
R1_LP="$(curl -sf "${R1_URL}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"

R2_PORT=$((R1_PORT + 1))
while (echo >/dev/tcp/127.0.0.1/"$R2_PORT") 2>/dev/null; do R2_PORT=$((R2_PORT + 1)); done
R2_DOC="$TMP_DIR/rot_s2"
start_php_server "$R2_DOC" "$R2_ADMIN_PK" 50000 2 "$R2_PORT" "$TMP_DIR/r2.log" 0
R2_PID="$PHP_PID"
PHP_PID=""
R2_URL="http://127.0.0.1:${R2_PORT}"
R2_LP="$(curl -sf "${R2_URL}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"

R3_PORT=$((R2_PORT + 1))
while (echo >/dev/tcp/127.0.0.1/"$R3_PORT") 2>/dev/null; do R3_PORT=$((R3_PORT + 1)); done
R3_DOC="$TMP_DIR/rot_s3"
start_php_server "$R3_DOC" "$R3_ADMIN_PK" 50000 2 "$R3_PORT" "$TMP_DIR/r3.log" 0
R3_PID="$PHP_PID"
PHP_PID=""
R3_URL="http://127.0.0.1:${R3_PORT}"
R3_LP="$(curl -sf "${R3_URL}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"

# Clean up extra PHP servers on exit too
cleanup_with_rot() {
  for xp in "${R1_PID:-}" "${R2_PID:-}" "${R3_PID:-}"; do
    if [[ -n "$xp" ]] && kill -0 "$xp" 2>/dev/null; then
      kill "$xp" 2>/dev/null || true
      wait "$xp" 2>/dev/null || true
    fi
  done
  cleanup
}
trap cleanup_with_rot EXIT

# 6a) SelfFrozen must persist across propose -> veto (with guarantor 72h timelock)
"$SERVER_BIN" sign-test rotation make-manifest \
  --s1-lock-pub "$R1_LP" --s1-admin-pub "$R1_ADMIN_PK" --s1-url "$R1_URL" \
  --s2-lock-pub "$R2_LP" --s2-admin-pub "$R2_ADMIN_PK" --s2-url "$R2_URL" \
  --quarter "$QTR" --anchor-tag "sf-veto" > "$TMP_DIR/sfv_m.json"
SFV_ANCHOR="$(sed -n 's/.*"anchor_id":"\([0-9a-f]\{64\}\)".*/\1/p' "$TMP_DIR/sfv_m.json")"
issue_ticket "$R1_URL" "$R1_ADMIN_SK" "$R1_ADMIN_PK" "$SFV_ANCHOR" "$QTR" "$TMP_DIR/sfv_t.json" >/dev/null
"$SERVER_BIN" sign-test make-lock-sample --lock-pub "$R1_LP" --admin-pub "$R1_ADMIN_PK" --quarter "$QTR" --manifest-json "$TMP_DIR/sfv_m.json" --ticket-json "$TMP_DIR/sfv_t.json" --anchor-tag "sf-veto" --variant seq:0 > "$TMP_DIR/sfv_b0.json"
curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/sfv_b0.json" "${R1_URL}/sync.php?lock" > "$TMP_DIR/sfv_r0.json"
"$SERVER_BIN" sign-test make-lock-sample --lock-pub "$R1_LP" --admin-pub "$R1_ADMIN_PK" --quarter "$QTR" --manifest-json "$TMP_DIR/sfv_m.json" --ticket-json "$TMP_DIR/sfv_t.json" --anchor-tag "sf-veto" --variant seq:1 > "$TMP_DIR/sfv_b1.json"
curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/sfv_b1.json" "${R1_URL}/sync.php?lock" > "$TMP_DIR/sfv_r1.json"
# Roll back R1 bucket to write_seq=1 by removing sfv_b1 metadata & presenting sfv_r1
php -r '
  $d = $argv[1]; $a = $argv[2]; $lp = hex2bin($argv[3]);
  $bHex = hash("sha256", "HUMOCO_SYNC_BUCKET_V1" . hex2bin($a) . $lp);
  $bf = "$d/humoco_sync_data/.locks_meta/buckets/$bHex.json";
  $b = json_decode(file_get_contents($bf), true);
  $b["write_seq"] = 0;
  file_put_contents($bf, json_encode($b));
' "$R1_DOC" "$SFV_ANCHOR" "$R1_LP"
"$SERVER_BIN" sign-test make-lock-sample --lock-pub "$R1_LP" --admin-pub "$R1_ADMIN_PK" --quarter "$QTR" --manifest-json "$TMP_DIR/sfv_m.json" --ticket-json "$TMP_DIR/sfv_t.json" --receipt-json "$TMP_DIR/sfv_r1.json" --anchor-tag "sf-veto" --variant seq:2 > "$TMP_DIR/sfv_rb.json"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/sfv_rb.json" "${R1_URL}/sync.php?lock")" "409" "6a: R1 enters self_frozen"

"$SERVER_BIN" sign-test rotation make-propose --manifest-json "$TMP_DIR/sfv_m.json" --ts "$(date +%s)" > "$TMP_DIR/sfv_prop.json"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/sfv_prop.json" "${R1_URL}/sync.php?lock_freeze")" "200" "6a: propose accepted on self_frozen bucket"
"$SERVER_BIN" sign-test rotation make-veto --manifest-json "$TMP_DIR/sfv_m.json" --propose-json "$TMP_DIR/sfv_prop.json" --ts "$(date +%s)" > "$TMP_DIR/sfv_veto.json"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/sfv_veto.json" "${R1_URL}/sync.php?lock_freeze")" "200" "6a: veto accepted"
SFV_AFTER_CODE="$(curl -s -o "$TMP_DIR/sfv_after.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/sfv_b0.json" "${R1_URL}/sync.php?lock")"
assert_eq "$SFV_AFTER_CODE" "409" "SYNC-S07-03: SelfFrozen persists after propose -> veto (409)"
assert_contains "$(cat "$TMP_DIR/sfv_after.json")" '"bucket_self_frozen"' "SYNC-S07-03: freeze error remains bucket_self_frozen after veto"

# 6b) Pure growth (0s timelock, no guarantors) + Sticky SelfFrozen on remaining member R1 across finalize, plus monotonic guards (SYNC-S07-04)
php -r '
  $r1Url = $argv[1]; $r1Ap = $argv[2]; $r1Lp = $argv[3];
  $r2Url = $argv[4]; $r2Ap = $argv[5]; $r2Lp = $argv[6];
  $r3Url = $argv[7]; $r3Ap = $argv[8]; $r3Lp = $argv[9];
  $q = (int)$argv[10]; $outDir = $argv[11];
  $cSeed = hash("sha256", "S07_C2_CREATOR", true);
  $cKp = sodium_crypto_sign_seed_keypair($cSeed);
  $cSk = sodium_crypto_sign_secretkey($cKp);
  $cPk = bin2hex(sodium_crypto_sign_publickey($cKp));
  $encSrv = fn($s) => hex2bin($s["admin_pub"]) . hex2bin($s["lock_pub"]) . "\x00";
  $s1 = ["write_url" => "$r1Url/sync.php", "read_url" => "$r1Url/humoco_sync_data", "admin_pub" => $r1Ap, "lock_pub" => $r1Lp, "nominated_by" => "creator"];
  $s2 = ["write_url" => "$r2Url/sync.php", "read_url" => "$r2Url/humoco_sync_data", "admin_pub" => $r2Ap, "lock_pub" => $r2Lp, "nominated_by" => "creator"];
  $s3 = ["write_url" => "$r3Url/sync.php", "read_url" => "$r3Url/humoco_sync_data", "admin_pub" => $r3Ap, "lock_pub" => $r3Lp, "nominated_by" => "creator"];
  $mkRev1 = function($srvs, $tsMs) use ($cPk, $q, $encSrv) {
    $m = ["revision" => 1, "threshold" => count($srvs) === 1 ? 1 : 2, "servers" => $srvs, "successors" => [], "authority" => ["creator_mig_pub" => $cPk, "guarantor_mig_pubs" => []], "migration_chain" => [], "issued_at_ms" => $tsMs, "retain_until_quarter" => $q];
    $sBin = ""; foreach ($srvs as $s) $sBin .= $encSrv($s);
    $aid = hash("sha256", "HUMOCO_ANCHOR_MANIFEST_V1\0" . pack("P", 1) . chr($m["threshold"]) . chr(count($srvs)) . $sBin . pack("v", 0) . hex2bin($cPk) . chr(0) . pack("P", $tsMs) . pack("v", $q), true);
    return [bin2hex($aid), $m];
  };
  $mkProp = function($aHex, $from, $to, $thr, $srvs, $ts) use ($cSk, $encSrv) {
    $sBin = ""; foreach ($srvs as $s) $sBin .= $encSrv($s);
    $dig = hash("sha256", "HUMOCO_MIGRATION_PROP_V1" . hex2bin($aHex) . pack("P", $from) . pack("P", $to) . chr($thr) . chr(count($srvs)) . $sBin . pack("v", 0) . pack("v", $GLOBALS["q"]) . pack("P", $ts) . "\x00", true);
    return ["anchor_id" => $aHex, "from_rev" => $from, "to_rev" => $to, "new_threshold" => $thr, "new_servers" => $srvs, "new_successors" => [], "retain_until_quarter" => $GLOBALS["q"], "proposed_at" => $ts, "initiator" => ["kind" => "creator"], "proposer_sig" => bin2hex(sodium_crypto_sign_detached($dig, $cSk)), "guarantor_cosigs" => []];
  };
  $GLOBALS["q"] = $q;
  $now = time();
  [$aSfHex, $mSf1] = $mkRev1([$s1], 1794916800000);
  $propSf = $mkProp($aSfHex, 1, 2, 2, [$s1, $s2], $now);
  [$aRotHex, $mRot1] = $mkRev1([$s1], 1794916900000);
  $propRot12 = $mkProp($aRotHex, 1, 2, 2, [$s1, $s2], $now);
  // Make Rev2->Rev3 pure growth ([s1,s2] -> [s1,s2,s3]) so R1 has 0s timelock too, AND also check Rev3->Rev4 replacement on timelock=0 servers R2/R3!
  $propRot23 = $mkProp($aRotHex, 2, 3, 2, [$s1, $s2, $s3], $now);
  $propRot34 = $mkProp($aRotHex, 3, 4, 2, [$s2, $s3], $now);
  [$aUnrelHex, $mUnrel] = $mkRev1([$s3], 1794917000000);
  $propUnrel = $mkProp($aUnrelHex, 1, 2, 2, [$s3, $s2], $now);
  // Write a signed root entry helper data
  $genKp = sodium_crypto_sign_seed_keypair(str_repeat(chr(71), 32));
  $genSk = sodium_crypto_sign_secretkey($genKp); $genPk = sodium_crypto_sign_publickey($genKp);
  $mkRootEntry = function($aHex) use ($cSk, $genSk, $genPk) {
    $a32 = hex2bin($aHex);
    $slot = hash("sha256", "HUMOCO_SYNC_SLOT_V1" . $a32 . str_repeat(chr(0x51), 32), true);
    $cl = str_repeat(chr(0x52), 32); $rh = hash("sha3-256", str_repeat(chr(0x53), 32), true);
    $cd = hash("sha256", "HUMOCO_CAUSAL_OUTPUT_V1" . $a32 . $slot . str_repeat("\0", 32) . "\x00" . pack("V", 0) . $cl . $genPk . $rh . "\x00" . str_repeat("\0", 32), true);
    $csig = sodium_crypto_sign_detached($cd, $genSk);
    $rmd = hash("sha256", "HUMOCO_ROOT_MIG_AUTH_V1" . $a32 . $slot . $genPk, true);
    $rsig = sodium_crypto_sign_detached($rmd, $cSk);
    for ($n = 0;; $n++) { $h = hash("sha256", "HUMOCO_LOCK_POW_V1" . $slot . $cl . pack("V", 0) . pack("P", $n), true); if (ord($h[0]) === 0) break; }
    return bin2hex("HMLK\x01" . $slot . str_repeat("\0", 32) . "\x00" . pack("V", 0) . $cl . $genPk . $rh . "\x00" . str_repeat("\0", 32) . $csig . "\x01" . $rsig . str_repeat("\x44", 265) . pack("P", $n));
  };
  file_put_contents("$outDir/s07_rot_plan.json", json_encode([
    "sf_anchor" => $aSfHex, "sf_m1" => $mSf1, "sf_prop" => $propSf, "sf_entry" => $mkRootEntry($aSfHex),
    "rot_anchor" => $aRotHex, "rot_m1" => $mRot1, "rot_prop12" => $propRot12, "rot_prop23" => $propRot23, "rot_prop34" => $propRot34, "rot_entry" => $mkRootEntry($aRotHex),
    "unrel_anchor" => $aUnrelHex, "unrel_m1" => $mUnrel, "unrel_prop" => $propUnrel,
  ]));
' "$R1_URL" "$R1_ADMIN_PK" "$R1_LP" "$R2_URL" "$R2_ADMIN_PK" "$R2_LP" "$R3_URL" "$R3_ADMIN_PK" "$R3_LP" "$QTR" "$TMP_DIR"

# Run full 6b rotation + rollback + replay sequence via PHP orchestration + curl HTTP assertions
S07_6B_OUT="$(php -r '
  $plan = json_decode(file_get_contents($argv[1]), true);
  $r1 = $argv[2]; $r2 = $argv[3]; $r3 = $argv[4];
  $r1Doc = $argv[5]; $r1Sk = $argv[6]; $r1Pk = $argv[7]; $r1Lp = $argv[8];
  $r2Sk = $argv[9]; $r2Pk = $argv[10]; $r3Sk = $argv[11]; $r3Pk = $argv[12];
  $post = function($url, $body, $hdrs = []) {
    $ch = curl_init($url);
    $h = array_merge(["Content-Type: application/json"], $hdrs);
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_HTTPHEADER => $h, CURLOPT_RETURNTRANSFER => true]);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return [$code, json_decode((string)$resp, true) ?? $resp];
  };
  $issueT = function($url, $skHex, $pkHex, $aHex, $q) use ($post) {
    $body = json_encode(["anchor_id" => $aHex, "retain_until_quarter" => $q, "pow_timestamp" => null, "pow_nonce" => null]);
    $ts = time(); $nonce = bin2hex(random_bytes(16));
    $msg = "HUMOCO-DROP-REQ-V1\nPOST\nlock_ticket\n\n{$ts}\n{$nonce}\n" . hash("sha256", $body);
    $sig = bin2hex(sodium_crypto_sign_detached($msg, hex2bin($skHex) . hex2bin($pkHex)));
    [$c, $j] = $post("$url/sync.php?lock_ticket", $body, ["X-Drop-Pubkey: $pkHex", "X-Drop-Timestamp: $ts", "X-Drop-Nonce: $nonce", "X-Drop-Signature: $sig"]);
    if ($c !== 200) throw new RuntimeException("ticket failed $c");
    return $j["ticket"];
  };
  $doBatch = function($url, $aHex, $lpHex, $entryHex, $m, $t, $kr = null) use ($post) {
    $bHex = hash("sha256", "HUMOCO_SYNC_BUCKET_V1" . hex2bin($aHex) . hex2bin($lpHex));
    return $post("$url/sync.php?lock", json_encode(["anchor_id" => $aHex, "bucket" => $bHex, "recipient_nonce" => bin2hex(random_bytes(32)), "entries" => [$entryHex], "manifest" => $m, "genesis_ticket" => $t, "known_head_receipt" => $kr]));
  };
  // 1) SelfFrozen across pure-growth finalize where R1 remains in new_servers
  $tSf = $issueT($r1, $r1Sk, $r1Pk, $plan["sf_anchor"], $plan["sf_m1"]["retain_until_quarter"]);
  [$c, $bRes] = $doBatch($r1, $plan["sf_anchor"], $r1Lp, $plan["sf_entry"], $plan["sf_m1"], $tSf);
  if ($c !== 200) throw new RuntimeException("sf init batch failed");
  $rec = $bRes["receipts"][0];
  $bHexSf = hash("sha256", "HUMOCO_SYNC_BUCKET_V1" . hex2bin($plan["sf_anchor"]) . hex2bin($r1Lp));
  unlink("$r1Doc/humoco_sync_data/.locks_meta/buckets/$bHexSf.json");
  [$cRb, ] = $doBatch($r1, $plan["sf_anchor"], $r1Lp, $plan["sf_entry"], $plan["sf_m1"], $tSf, $rec);
  if ($cRb !== 409) throw new RuntimeException("sf trigger failed: $cRb");
  [$cPr, $prRes] = $post("$r1/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $plan["sf_prop"], "current_manifest" => $plan["sf_m1"]]));
  if ($cPr !== 200) throw new RuntimeException("sf propose failed: $cPr");
  $impReq = json_encode(["anchor_id" => $plan["sf_anchor"], "active_manifest" => $plan["sf_m1"], "proposal" => $plan["sf_prop"], "snapshots" => [$prRes["snapshot_export"]], "quorum_certificates" => []]);
  [$cI1, $i1] = $post("$r1/sync.php?lock_import", $impReq);
  [$cI2, $i2] = $post("$r2/sync.php?lock_import", $impReq);
  if ($cI1 !== 200 || $cI2 !== 200) throw new RuntimeException("sf import failed $cI1/$cI2");
  $scReq = json_encode(["action" => "sign_commit", "anchor_id" => $plan["sf_anchor"], "proposal" => $plan["sf_prop"], "imported_state_hash" => $i1["import_ack"]["imported_state_hash"], "import_acks" => [$i1["import_ack"], $i2["import_ack"]]]);
  [$cSc, $sc] = $post("$r1/sync.php?lock_commit", $scReq);
  if ($cSc !== 200) throw new RuntimeException("sf sign_commit failed $cSc");
  $sfM2 = ["revision" => 2, "threshold" => 2, "servers" => $plan["sf_prop"]["new_servers"], "successors" => [], "authority" => $plan["sf_m1"]["authority"], "migration_chain" => [["anchor_id" => $plan["sf_anchor"], "genesis_manifest" => $plan["sf_m1"], "proposal" => $plan["sf_prop"], "imported_state_hash" => $i1["import_ack"]["imported_state_hash"], "import_acks" => [$i1["import_ack"], $i2["import_ack"]], "commit_sigs" => [$sc["committee_signature"]]]], "issued_at_ms" => $plan["sf_prop"]["proposed_at"] * 1000, "retain_until_quarter" => $plan["sf_m1"]["retain_until_quarter"]];
  [$cFin, $finRes] = $post("$r1/sync.php?lock_commit", json_encode(["action" => "finalize", "anchor_id" => $plan["sf_anchor"], "new_manifest" => $sfM2]));
  [$cAfterFin, $afterFin] = $doBatch($r1, $plan["sf_anchor"], $r1Lp, $plan["sf_entry"], $sfM2, $tSf);

  // 2) Full Rev1->Rev2->Rev3 rotation on rot_anchor to test SYNC-S07-04 guards
  $tR = $issueT($r1, $r1Sk, $r1Pk, $plan["rot_anchor"], $plan["rot_m1"]["retain_until_quarter"]);
  [$c, ] = $doBatch($r1, $plan["rot_anchor"], $r1Lp, $plan["rot_entry"], $plan["rot_m1"], $tR);
  if ($c !== 200) throw new RuntimeException("rot init failed");
  [, $pr12] = $post("$r1/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $plan["rot_prop12"], "current_manifest" => $plan["rot_m1"]]));
  $imp12Req = json_encode(["anchor_id" => $plan["rot_anchor"], "active_manifest" => $plan["rot_m1"], "proposal" => $plan["rot_prop12"], "snapshots" => [$pr12["snapshot_export"]], "quorum_certificates" => []]);
  [$c12a, $r1Imp12] = $post("$r1/sync.php?lock_import", $imp12Req);
  [$c12b, $r2Imp12] = $post("$r2/sync.php?lock_import", $imp12Req);
  if ($c12a !== 200 || $c12b !== 200) throw new RuntimeException("rot12 import failed");
  [, $sc12] = $post("$r1/sync.php?lock_commit", json_encode(["action" => "sign_commit", "anchor_id" => $plan["rot_anchor"], "proposal" => $plan["rot_prop12"], "imported_state_hash" => $r1Imp12["import_ack"]["imported_state_hash"], "import_acks" => [$r1Imp12["import_ack"], $r2Imp12["import_ack"]]]));
  $rotM2 = ["revision" => 2, "threshold" => 2, "servers" => $plan["rot_prop12"]["new_servers"], "successors" => [], "authority" => $plan["rot_m1"]["authority"], "migration_chain" => [["anchor_id" => $plan["rot_anchor"], "genesis_manifest" => $plan["rot_m1"], "proposal" => $plan["rot_prop12"], "imported_state_hash" => $r1Imp12["import_ack"]["imported_state_hash"], "import_acks" => [$r1Imp12["import_ack"], $r2Imp12["import_ack"]], "commit_sigs" => [$sc12["committee_signature"]]]], "issued_at_ms" => $plan["rot_prop12"]["proposed_at"] * 1000, "retain_until_quarter" => $plan["rot_m1"]["retain_until_quarter"]];
  $fin12Body = json_encode(["action" => "finalize", "anchor_id" => $plan["rot_anchor"], "new_manifest" => $rotM2]);
  $post("$r1/sync.php?lock_commit", $fin12Body);
  $post("$r2/sync.php?lock_commit", $fin12Body);

  // Tests on Rev 2 active servers R1+R2:
  [$cIdemFin, ] = $post("$r2/sync.php?lock_commit", $fin12Body); // idempotent finalize retry
  [$cStaleProp, ] = $post("$r1/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $plan["rot_prop12"]])); // stale rev1 propose on active rev2 R1
  [$cStaleImp, ] = $post("$r2/sync.php?lock_import", $imp12Req); // stale rev1->2 import replay on active rev2 R2
  // Test valid unrelated Rev 2 manifest finalize on R1 (unrel_anchor only includes R3, R2)
  [, $prUnrel] = $post("$r3/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $plan["unrel_prop"], "current_manifest" => $plan["unrel_m1"]]));
  $unrelImpReq = json_encode(["anchor_id" => $plan["unrel_anchor"], "active_manifest" => $plan["unrel_m1"], "proposal" => $plan["unrel_prop"], "snapshots" => [$prUnrel["snapshot_export"]], "quorum_certificates" => []]);
  [$cU1, $uImp3] = $post("$r3/sync.php?lock_import", $unrelImpReq);
  [$cU2, $uImp2] = $post("$r2/sync.php?lock_import", $unrelImpReq);
  if ($cU1 !== 200 || $cU2 !== 200) throw new RuntimeException("unrel import failed $cU1/$cU2");
  [$cUSc, $uSc] = $post("$r3/sync.php?lock_commit", json_encode(["action" => "sign_commit", "anchor_id" => $plan["unrel_anchor"], "proposal" => $plan["unrel_prop"], "imported_state_hash" => $uImp3["import_ack"]["imported_state_hash"], "import_acks" => [$uImp3["import_ack"], $uImp2["import_ack"]]]));
  if ($cUSc !== 200) throw new RuntimeException("unrel sc failed $cUSc");
  $unrelM2 = ["revision" => 2, "threshold" => 2, "servers" => $plan["unrel_prop"]["new_servers"], "successors" => [], "authority" => $plan["unrel_m1"]["authority"], "migration_chain" => [["anchor_id" => $plan["unrel_anchor"], "genesis_manifest" => $plan["unrel_m1"], "proposal" => $plan["unrel_prop"], "imported_state_hash" => $uImp3["import_ack"]["imported_state_hash"], "import_acks" => [$uImp3["import_ack"], $uImp2["import_ack"]], "commit_sigs" => [$uSc["committee_signature"]]]], "issued_at_ms" => $plan["unrel_prop"]["proposed_at"] * 1000, "retain_until_quarter" => $plan["unrel_m1"]["retain_until_quarter"]];
  [$cUnrelFin, ] = $post("$r1/sync.php?lock_commit", json_encode(["action" => "finalize", "anchor_id" => $plan["unrel_anchor"], "new_manifest" => $unrelM2]));

  // Rotate rot_anchor Rev 2 -> Rev 3 ([R1, R2] -> [R1, R2, R3], pure growth -> 0s timelock even on R1!)
  [, $pr123_1] = $post("$r1/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $plan["rot_prop23"]]));
  [, $pr123_2] = $post("$r2/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $plan["rot_prop23"]]));
  $imp23Req = json_encode(["anchor_id" => $plan["rot_anchor"], "active_manifest" => $rotM2, "proposal" => $plan["rot_prop23"], "snapshots" => [$pr123_1["snapshot_export"], $pr123_2["snapshot_export"]], "quorum_certificates" => []]);
  [$c23a, $r1Imp23] = $post("$r1/sync.php?lock_import", $imp23Req);
  [$c23b, $r2Imp23] = $post("$r2/sync.php?lock_import", $imp23Req);
  [$c23c, $r3Imp23] = $post("$r3/sync.php?lock_import", $imp23Req);
  if ($c23a !== 200 || $c23b !== 200 || $c23c !== 200) throw new RuntimeException("rot23 import failed $c23a/$c23b/$c23c");
  [, $sc23_1] = $post("$r1/sync.php?lock_commit", json_encode(["action" => "sign_commit", "anchor_id" => $plan["rot_anchor"], "proposal" => $plan["rot_prop23"], "imported_state_hash" => $r2Imp23["import_ack"]["imported_state_hash"], "import_acks" => [$r1Imp23["import_ack"], $r2Imp23["import_ack"], $r3Imp23["import_ack"]]]));
  [, $sc23_2] = $post("$r2/sync.php?lock_commit", json_encode(["action" => "sign_commit", "anchor_id" => $plan["rot_anchor"], "proposal" => $plan["rot_prop23"], "imported_state_hash" => $r2Imp23["import_ack"]["imported_state_hash"], "import_acks" => [$r1Imp23["import_ack"], $r2Imp23["import_ack"], $r3Imp23["import_ack"]]]));
  $rotM3 = ["revision" => 3, "threshold" => 2, "servers" => $plan["rot_prop23"]["new_servers"], "successors" => [], "authority" => $plan["rot_m1"]["authority"], "migration_chain" => array_merge($rotM2["migration_chain"], [["anchor_id" => $plan["rot_anchor"], "genesis_manifest" => null, "proposal" => $plan["rot_prop23"], "imported_state_hash" => $r2Imp23["import_ack"]["imported_state_hash"], "import_acks" => [$r1Imp23["import_ack"], $r2Imp23["import_ack"], $r3Imp23["import_ack"]], "commit_sigs" => [$sc23_1["committee_signature"], $sc23_2["committee_signature"]]]]), "issued_at_ms" => $plan["rot_prop23"]["proposed_at"] * 1000, "retain_until_quarter" => $plan["rot_m1"]["retain_until_quarter"]];
  $fin23Body = json_encode(["action" => "finalize", "anchor_id" => $plan["rot_anchor"], "new_manifest" => $rotM3]);
  $post("$r1/sync.php?lock_commit", $fin23Body);
  $post("$r2/sync.php?lock_commit", $fin23Body);
  $post("$r3/sync.php?lock_commit", $fin23Body);
  // Test downgrade rev 3 -> rev 2 on R1!
  [$cDowngrade, ] = $post("$r1/sync.php?lock_commit", $fin12Body);
  // Test veto with stale from_rev=1 on rev3 R1!
  $fakeVeto = ["anchor_id" => $plan["rot_anchor"], "from_rev" => 1, "proposal_hash" => str_repeat("aa", 32), "vetoer_pub" => $plan["rot_m1"]["authority"]["creator_mig_pub"], "vetoed_at" => time(), "sig" => str_repeat("00", 64)];
  [$cStaleVeto, ] = $post("$r1/sync.php?lock_freeze", json_encode(["action" => "veto", "veto" => $fakeVeto]));
  echo json_encode([
    "sf_fin_code" => $cFin,
    "sf_after_fin_code" => $cAfterFin,
    "sf_after_fin_err" => $afterFin["error"] ?? "",
    "idem_fin_code" => $cIdemFin,
    "stale_prop_code" => $cStaleProp,
    "stale_imp_code" => $cStaleImp,
    "unrel_fin_code" => $cUnrelFin,
    "downgrade_code" => $cDowngrade,
    "stale_veto_code" => $cStaleVeto,
  ]);
' "$TMP_DIR/s07_rot_plan.json" "$R1_URL" "$R2_URL" "$R3_URL" "$R1_DOC" "$R1_ADMIN_SK" "$R1_ADMIN_PK" "$R1_LP" "$R2_ADMIN_SK" "$R2_ADMIN_PK" "$R3_ADMIN_SK" "$R3_ADMIN_PK")"
assert_contains "$S07_6B_OUT" '"sf_fin_code":200' "SYNC-S07-03: pure-growth finalize on self_frozen R1 succeeds"
assert_contains "$S07_6B_OUT" '"sf_after_fin_code":409' "SYNC-S07-03: R1 stays frozen after propose -> finalize"
assert_contains "$S07_6B_OUT" '"sf_after_fin_err":"bucket_self_frozen"' "SYNC-S07-03: R1 remains bucket_self_frozen after finalize"
assert_contains "$S07_6B_OUT" '"idem_fin_code":200' "SYNC-S07-04: idempotent finalize retry on inNew server returns 200"
assert_contains "$S07_6B_OUT" '"stale_prop_code":409' "SYNC-S07-04: stale rev1 propose on active rev2 server returns 409"
assert_contains "$S07_6B_OUT" '"stale_imp_code":409' "SYNC-S07-04: stale rev1->2 import replay on rev2 server returns 409"
assert_contains "$S07_6B_OUT" '"unrel_fin_code":400' "SYNC-S07-04: unrelated manifest finalize returns 400"
assert_contains "$S07_6B_OUT" '"downgrade_code":409' "SYNC-S07-04: manifest revision downgrade finalize returns 409"
assert_contains "$S07_6B_OUT" '"stale_veto_code":409' "SYNC-S07-04: stale rev1 veto on rev3 server returns 409"

echo "--- Test 7 (SYNC-S07-05): Static If-None-Match, __anchor method/type & CLI router hardening ---"
ROT_ANCHOR_HEX="$(php -r 'echo json_decode(file_get_contents($argv[1]), true)["rot_anchor"];' "$TMP_DIR/s07_rot_plan.json")"
ANCHOR_ETAG="$(curl -sI "${R1_URL}/anchors/${ROT_ANCHOR_HEX}.bin" | tr -d '\r' | sed -n 's/^[Ee][Tt][Aa][Gg]: *//p')"
[[ -n "$ANCHOR_ETAG" ]] || fail "Missing ETag on /anchors/<id>.bin"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -H "If-None-Match: \"0000\", W/${ANCHOR_ETAG}" "${R1_URL}/sync.php?__anchor=${ROT_ANCHOR_HEX}.bin")" "304" "SYNC-S07-05: __anchor honors comma-separated weak W/ ETag list (304)"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -H "If-None-Match: *" "${R1_URL}/anchors/${ROT_ANCHOR_HEX}.bin")" "304" "SYNC-S07-05: static anchor honors If-None-Match: * (304)"
ANCHOR_POST_HDRS="$(curl -si -X POST "${R1_URL}/sync.php?__anchor=${ROT_ANCHOR_HEX}.bin" | tr -d '\r' | tr '[:upper:]' '[:lower:]')"
assert_contains "$ANCHOR_POST_HDRS" "405 method not allowed" "SYNC-S07-05: POST ?__anchor returns 405"
assert_contains "$ANCHOR_POST_HDRS" "allow: get, head" "SYNC-S07-05: POST ?__anchor includes Allow: GET, HEAD"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${R1_URL}/sync.php?__anchor[]=bad")" "404" "SYNC-S07-05: array __anchor[] returns 404"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${R1_URL}/sync.php?lock_selftest&extra=1")" "405" "SYNC-S07-05: extra query param on lock route returns 405"

printf 'secret-tmp' > "${R1_DOC}/humoco_sync_data/leak.tmp.1"
printf 'secret-ld' > "${R1_DOC}/humoco_sync_data/foo.lockdir"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${R1_URL}/humoco_sync_data/leak.tmp.1")" "403" "SYNC-S07-05: CLI router blocks *.tmp* artifact (403)"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${R1_URL}/humoco_sync_data/foo.lockdir")" "403" "SYNC-S07-05: CLI router blocks *.lockdir artifact (403)"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${R1_URL}/humoco_sync_data/%2elock_key.php")" "403" "SYNC-S07-05: CLI router blocks URL-encoded dotfile (403)"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${R1_URL}/humoco_sync_data/.locks_meta/nonces.json")" "403" "SYNC-S07-05: CLI router blocks .locks_meta internals (403)"

echo "--- Test 8 (SYNC-S07-06): Bounded bodies, TypeError-safe JSON parsing & strict schema parity ---"
dd if=/dev/zero bs=1024 count=20 of="$TMP_DIR/s07_big_16k.bin" 2>/dev/null
dd if=/dev/zero bs=1024 count=260 of="$TMP_DIR/s07_big_256k.bin" 2>/dev/null
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/s07_big_16k.bin" "${R1_URL}/sync.php?lock_ticket")" "413" "SYNC-S07-06: POST ?lock_ticket >16KiB returns 413"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/s07_big_256k.bin" "${R1_URL}/sync.php?lock_freeze")" "413" "SYNC-S07-06: POST ?lock_freeze >256KiB returns 413"

# Scalar JSON and nested non-arrays must return 400 (not 500 TypeError)
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '"hello"' "${R1_URL}/sync.php?lock_freeze")" "400" "SYNC-S07-06: scalar JSON string on ?lock_freeze returns 400"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '"hello"' "${R1_URL}/sync.php?lock_commit")" "400" "SYNC-S07-06: scalar JSON string on ?lock_commit returns 400"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"action":"heartbeat","heartbeat":"bad"}' "${R1_URL}/sync.php?lock_freeze")" "400" "SYNC-S07-06: non-array heartbeat on ?lock_freeze returns 400"
printf '{"anchor_id":"%s","active_manifest":{"revision":1,"threshold":1,"servers":["bad"],"successors":[],"authority":{"creator_mig_pub":"%s","guarantor_mig_pubs":[]},"migration_chain":[],"issued_at_ms":1,"retain_until_quarter":8125},"proposal":{},"snapshots":[],"quorum_certificates":[]}' "$ROT_ANCHOR_HEX" "$R1_ADMIN_PK" > "$TMP_DIR/s07_bad_imp.json"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/s07_bad_imp.json" "${R1_URL}/sync.php?lock_import")" "400" "SYNC-S07-06: non-array server element on ?lock_import returns 400"

# Float timestamp rejected with 400
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "X-Drop-Pubkey: $R1_ADMIN_PK" -H "X-Drop-Timestamp: 1795000000.5" -H "X-Drop-Nonce: $(rand_nonce)" -H "X-Drop-Signature: $(printf '0%.0s' {1..128})" -H 'Content-Type: application/json' -d '{}' "${R1_URL}/sync.php?lock_ticket")" "400" "SYNC-S07-06: float X-Drop-Timestamp on ?lock_ticket returns 400"

# Scalar JSON and uppercase hex on PUT ?lock_delegate rejected with 400
printf '"hello"' > "$TMP_DIR/s07_del_scalar.json"
ts="$(date +%s)"; nonce="$(rand_nonce)"
sig="$("$SERVER_BIN" sign-test sign-admin --sk "$R1_ADMIN_SK" --action PUT_LOCK_DELEGATE --ts "$ts" --nonce "$nonce" --body-file "$TMP_DIR/s07_del_scalar.json")"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $R1_ADMIN_PK" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$TMP_DIR/s07_del_scalar.json" "${R1_URL}/sync.php?lock_delegate")" "400" "SYNC-S07-06: scalar JSON on PUT ?lock_delegate returns 400"

"$SERVER_BIN" sign-test sign-lock-delegate --sk "$R1_ADMIN_SK" --lock-pub "$R1_LP" --write-url "${R1_URL}/sync.php" --read-url "${R1_URL}/humoco_sync_data" --issued "$(date +%s)" > "$TMP_DIR/s07_del_upper.json"
php -r '$j = json_decode(file_get_contents($argv[1]), true); $j["admin_pub"] = strtoupper($j["admin_pub"]); file_put_contents($argv[1], json_encode($j));' "$TMP_DIR/s07_del_upper.json"
ts="$(date +%s)"; nonce="$(rand_nonce)"
sig="$("$SERVER_BIN" sign-test sign-admin --sk "$R1_ADMIN_SK" --action PUT_LOCK_DELEGATE --ts "$ts" --nonce "$nonce" --body-file "$TMP_DIR/s07_del_upper.json")"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $R1_ADMIN_PK" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$TMP_DIR/s07_del_upper.json" "${R1_URL}/sync.php?lock_delegate")" "400" "SYNC-S07-06: uppercase admin_pub on PUT ?lock_delegate returns 400"

# Rev-2 manifest with issued_at_ms=0 must be rejected with 400 on finalize
php -r '
  $m = json_decode(file_get_contents($argv[1]), true);
  $m["issued_at_ms"] = 0;
  file_put_contents($argv[2], json_encode(["action" => "finalize", "anchor_id" => $argv[3], "new_manifest" => $m]));
' "${R1_DOC}/humoco_sync_data/anchors/${ROT_ANCHOR_HEX}.bin" "$TMP_DIR/s07_bad_ts_fin.json" "$ROT_ANCHOR_HEX"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_DIR/s07_bad_ts_fin.json" "${R1_URL}/sync.php?lock_commit")" "400" "SYNC-S07-06: Rev-2+ finalize with issued_at_ms=0 returns 400"

stop_php_server

echo "--- Test 9 (SYNC-S07-07): Cold pre_freeze rejection, forged cold heartbeat zero-write & max_buckets=1 cap ---"
read -r B9_ADMIN_SK B9_ADMIN_PK <<< "$("$SERVER_BIN" sign-test keygen)"
B9_PORT="$(pick_free_port)"
B9_DOC="$TMP_DIR/b9_doc"
start_php_server "$B9_DOC" "$B9_ADMIN_PK" 50 1 "$B9_PORT" "$TMP_DIR/b9.log"
php -r '
  $c = file_get_contents($argv[1]);
  $c = str_replace("'\''max_inodes'\'' => 50,", "'\''max_inodes'\'' => 50,\n        '\''max_buckets'\'' => 1,", $c);
  file_put_contents($argv[1], $c);
' "$B9_DOC/config.php"
B9_URL="http://127.0.0.1:${B9_PORT}"
B9_LP="$(curl -sf "${B9_URL}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"

B9_OUT="$(php -r '
  $url = $argv[1]; $doc = $argv[2]; $adminSkHex = $argv[3]; $adminPkHex = $argv[4]; $lpHex = $argv[5]; $qtr = (int)$argv[6];
  $post = static function (string $u, string $body): array {
    $ch = curl_init($u);
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_HTTPHEADER => ["Content-Type: application/json"], CURLOPT_RETURNTRANSFER => true]);
    $resp = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    return [$code, json_decode((string)$resp, true) ?: []];
  };
  $migKp1 = sodium_crypto_sign_keypair();
  $migSk1 = sodium_crypto_sign_secretkey($migKp1); $migPk1 = bin2hex(sodium_crypto_sign_publickey($migKp1));
  $t0 = time() - 10;
  $mkMan = static function (int $issuedMs) use ($url, $adminPkHex, $lpHex, $migPk1, $qtr): array {
    $srv = ["write_url" => "$url/sync.php", "read_url" => "$url/humoco_sync_data", "admin_pub" => $adminPkHex, "lock_pub" => $lpHex, "nominated_by" => "creator"];
    $m = ["revision" => 1, "threshold" => 1, "servers" => [$srv], "successors" => [], "authority" => ["creator_mig_pub" => $migPk1, "guarantor_mig_pubs" => []], "migration_chain" => [], "issued_at_ms" => $issuedMs, "retain_until_quarter" => $qtr];
    $pre = "HUMOCO_ANCHOR_MANIFEST_V1\x00" . pack("P", 1) . "\x01\x01" . hex2bin($adminPkHex) . hex2bin($lpHex) . "\x00" . pack("v", 0) . hex2bin($migPk1) . "\x00" . pack("P", $issuedMs) . pack("v", $qtr);
    return [bin2hex(hash("sha256", $pre, true)), $m];
  };
  [$aid1, $m1] = $mkMan($t0 * 1000);
  [$pfCode, ] = $post("$url/sync.php?lock_freeze", json_encode(["action" => "pre_freeze", "anchor_id" => $aid1, "current_manifest" => $m1]));
  $bucketsAfterPf = count(glob("$doc/humoco_sync_data/.locks_meta/buckets/*.json") ?: []);

  // Forged cold heartbeat -> 401 and still 0 files
  [$fHbCode, ] = $post("$url/sync.php?lock_freeze", json_encode(["action" => "heartbeat", "heartbeat" => ["anchor_id" => $aid1, "timestamp_secs" => $t0, "sig" => str_repeat("00", 64)], "current_manifest" => $m1]));
  $bucketsAfterForgedHb = count(glob("$doc/humoco_sync_data/.locks_meta/buckets/*.json") ?: []);

  // Valid signed cold heartbeat -> 200 (consumes max_buckets=1)
  $hbDig1 = hash("sha256", "HUMOCO_CREATOR_HB_V1" . hex2bin($aid1) . pack("P", $t0), true);
  $hbSig1 = bin2hex(sodium_crypto_sign_detached($hbDig1, $migSk1));
  [$okHbCode, ] = $post("$url/sync.php?lock_freeze", json_encode(["action" => "heartbeat", "heartbeat" => ["anchor_id" => $aid1, "timestamp_secs" => $t0, "sig" => $hbSig1], "current_manifest" => $m1]));

  // Second anchor cold heartbeat -> 507
  [$aid2, $m2] = $mkMan(($t0 + 10) * 1000);
  $hbDig2 = hash("sha256", "HUMOCO_CREATOR_HB_V1" . hex2bin($aid2) . pack("P", $t0 + 10), true);
  $hbSig2 = bin2hex(sodium_crypto_sign_detached($hbDig2, $migSk1));
  [$capHbCode, ] = $post("$url/sync.php?lock_freeze", json_encode(["action" => "heartbeat", "heartbeat" => ["anchor_id" => $aid2, "timestamp_secs" => $t0 + 10, "sig" => $hbSig2], "current_manifest" => $m2]));

  echo json_encode([
    "pf_code" => $pfCode,
    "buckets_after_pf" => $bucketsAfterPf,
    "forged_hb_code" => $fHbCode,
    "buckets_after_forged_hb" => $bucketsAfterForgedHb,
    "ok_hb_code" => $okHbCode,
    "cap_hb_code" => $capHbCode,
  ]);
' "$B9_URL" "$B9_DOC" "$B9_ADMIN_SK" "$B9_ADMIN_PK" "$B9_LP" "$QTR")"
assert_contains "$B9_OUT" '"pf_code":404' "SYNC-S07-07: cold pre_freeze rejected with 404"
assert_contains "$B9_OUT" '"buckets_after_pf":0' "SYNC-S07-07: cold pre_freeze leaves 0 buckets on disk"
assert_contains "$B9_OUT" '"forged_hb_code":401' "SYNC-S07-07: forged cold heartbeat rejected with 401"
assert_contains "$B9_OUT" '"buckets_after_forged_hb":0' "SYNC-S07-07: forged cold heartbeat leaves 0 buckets on disk"
assert_contains "$B9_OUT" '"ok_hb_code":200' "SYNC-S07-07: valid cold heartbeat succeeds within max_buckets=1"
assert_contains "$B9_OUT" '"cap_hb_code":507' "SYNC-S07-07: second cold bucket beyond max_buckets=1 returns 507"

stop_php_server

echo "--- Test 10 (SYNC-S07-08): max_buckets cap across ticket, batch, import & finalize (tombstone exempt) ---"
read -r B10_ADMIN_SK B10_ADMIN_PK <<< "$("$SERVER_BIN" sign-test keygen)"
read -r B10T_ADMIN_SK B10T_ADMIN_PK <<< "$("$SERVER_BIN" sign-test keygen)"
read -r B10U_ADMIN_SK B10U_ADMIN_PK <<< "$("$SERVER_BIN" sign-test keygen)"
B10_PORT="$(pick_free_port)"
B10_DOC="$TMP_DIR/b10_doc"
start_php_server "$B10_DOC" "$B10_ADMIN_PK" 50 1 "$B10_PORT" "$TMP_DIR/b10.log" 0
B10_PID="$PHP_PID"; PHP_PID=""
B10T_PORT=$((B10_PORT + 1))
while (echo >/dev/tcp/127.0.0.1/"$B10T_PORT") 2>/dev/null; do B10T_PORT=$((B10T_PORT + 1)); done
B10T_DOC="$TMP_DIR/b10t_doc"
start_php_server "$B10T_DOC" "$B10T_ADMIN_PK" 50 1 "$B10T_PORT" "$TMP_DIR/b10t.log" 0
B10T_PID="$PHP_PID"; PHP_PID=""
B10U_PORT=$((B10T_PORT + 1))
while (echo >/dev/tcp/127.0.0.1/"$B10U_PORT") 2>/dev/null; do B10U_PORT=$((B10U_PORT + 1)); done
B10U_DOC="$TMP_DIR/b10u_doc"
start_php_server "$B10U_DOC" "$B10U_ADMIN_PK" 50 1 "$B10U_PORT" "$TMP_DIR/b10u.log" 0
B10U_PID="$PHP_PID"; PHP_PID=""
cleanup_b10() {
  for xp in "${B10_PID:-}" "${B10T_PID:-}" "${B10U_PID:-}"; do
    if [[ -n "$xp" ]] && kill -0 "$xp" 2>/dev/null; then
      kill "$xp" 2>/dev/null || true
      wait "$xp" 2>/dev/null || true
    fi
  done
  cleanup_with_rot
}
trap cleanup_b10 EXIT

php -r '
  $c = file_get_contents($argv[1]);
  $c = str_replace("'\''max_inodes'\'' => 50,", "'\''max_inodes'\'' => 50,\n        '\''max_buckets'\'' => 1,", $c);
  file_put_contents($argv[1], $c);
' "$B10_DOC/config.php"

B10_URL="http://127.0.0.1:${B10_PORT}"
B10T_URL="http://127.0.0.1:${B10T_PORT}"
B10U_URL="http://127.0.0.1:${B10U_PORT}"
B10_LP="$(curl -sf "${B10_URL}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"
B10T_LP="$(curl -sf "${B10T_URL}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"
B10U_LP="$(curl -sf "${B10U_URL}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"

B10_OUT="$(php -r '
  $u1 = $argv[1]; $sk1 = $argv[2]; $pk1 = $argv[3]; $lp1 = $argv[4]; $doc1 = $argv[5];
  $u2 = $argv[6]; $pk2 = $argv[7]; $lp2 = $argv[8];
  $u3 = $argv[9]; $pk3 = $argv[10]; $lp3 = $argv[11];
  $q = (int)$argv[12];
  $post = static function (string $u, string $body, array $hdrs = []): array {
    $ch = curl_init($u);
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_HTTPHEADER => array_merge(["Content-Type: application/json"], $hdrs), CURLOPT_RETURNTRANSFER => true]);
    $resp = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    return [$code, json_decode((string)$resp, true) ?: []];
  };
  $issueT = static function (string $u, string $sk, string $pk, string $aHex, int $q) use ($post): array {
    $body = json_encode(["anchor_id" => $aHex, "retain_until_quarter" => $q, "pow_timestamp" => null, "pow_nonce" => null]);
    $ts = time(); $nonce = bin2hex(random_bytes(16));
    $msg = "HUMOCO-DROP-REQ-V1\nPOST\nlock_ticket\n\n{$ts}\n{$nonce}\n" . hash("sha256", $body);
    $sig = bin2hex(sodium_crypto_sign_detached($msg, hex2bin($sk) . hex2bin($pk)));
    return $post("$u/sync.php?lock_ticket", $body, ["X-Drop-Pubkey: $pk", "X-Drop-Timestamp: $ts", "X-Drop-Nonce: $nonce", "X-Drop-Signature: $sig"]);
  };
  $cKp = sodium_crypto_sign_seed_keypair(hash("sha256", "B10_CREATOR", true));
  $cSk = sodium_crypto_sign_secretkey($cKp); $cPk = bin2hex(sodium_crypto_sign_publickey($cKp));
  $mkSrv = static fn(string $u, string $ap, string $lp) => ["write_url" => "$u/sync.php", "read_url" => "$u/humoco_sync_data", "admin_pub" => $ap, "lock_pub" => $lp, "nominated_by" => "creator"];
  $mkMan = static function (array $srvs, int $thr, int $ms) use ($cPk, $q): array {
    $m = ["revision" => 1, "threshold" => $thr, "servers" => $srvs, "successors" => [], "authority" => ["creator_mig_pub" => $cPk, "guarantor_mig_pubs" => []], "migration_chain" => [], "issued_at_ms" => $ms, "retain_until_quarter" => $q];
    $sBin = ""; foreach ($srvs as $s) $sBin .= hex2bin($s["admin_pub"]) . hex2bin($s["lock_pub"]) . "\x00";
    $pre = "HUMOCO_ANCHOR_MANIFEST_V1\x00" . pack("P", 1) . chr($thr) . chr(count($srvs)) . $sBin . pack("v", 0) . hex2bin($cPk) . "\x00" . pack("P", $ms) . pack("v", $q);
    return [bin2hex(hash("sha256", $pre, true)), $m];
  };
  $mkProp = static function (string $aHex, int $from, int $to, int $thr, array $srvs, int $ts) use ($cSk, $q): array {
    $sBin = ""; foreach ($srvs as $s) $sBin .= hex2bin($s["admin_pub"]) . hex2bin($s["lock_pub"]) . "\x00";
    $pDig = hash("sha256", "HUMOCO_MIGRATION_PROP_V1" . hex2bin($aHex) . pack("P", $from) . pack("P", $to) . chr($thr) . chr(count($srvs)) . $sBin . pack("v", 0) . pack("v", $q) . pack("P", $ts) . "\x00", true);
    return ["anchor_id" => $aHex, "from_rev" => $from, "to_rev" => $to, "new_threshold" => $thr, "new_servers" => $srvs, "new_successors" => [], "retain_until_quarter" => $q, "proposed_at" => $ts, "initiator" => ["kind" => "creator"], "proposer_sig" => bin2hex(sodium_crypto_sign_detached($pDig, $cSk)), "guarantor_cosigs" => []];
  };
  $genKp = sodium_crypto_sign_seed_keypair(str_repeat(chr(41), 32));
  $genSk = sodium_crypto_sign_secretkey($genKp); $genPk = sodium_crypto_sign_publickey($genKp);
  $mkRoot = static function (string $aHex) use ($cSk, $genSk, $genPk): string {
    $a32 = hex2bin($aHex);
    $slot = hash("sha256", "HUMOCO_SYNC_SLOT_V1" . $a32 . str_repeat(chr(0x11), 32), true);
    $cl = str_repeat(chr(0x22), 32); $rh = hash("sha3-256", str_repeat(chr(0x33), 32), true);
    $cd = hash("sha256", "HUMOCO_CAUSAL_OUTPUT_V1" . $a32 . $slot . str_repeat("\0", 32) . "\x00" . pack("V", 0) . $cl . $genPk . $rh . "\x00" . str_repeat("\0", 32), true);
    $csig = sodium_crypto_sign_detached($cd, $genSk);
    $rmd = hash("sha256", "HUMOCO_ROOT_MIG_AUTH_V1" . $a32 . $slot . $genPk, true);
    $rsig = sodium_crypto_sign_detached($rmd, $cSk);
    for ($n = 0;; $n++) { $h = hash("sha256", "HUMOCO_LOCK_POW_V1" . $slot . $cl . pack("V", 0) . pack("P", $n), true); if (ord($h[0]) === 0) break; }
    return bin2hex("HMLK\x01" . $slot . str_repeat("\0", 32) . "\x00" . pack("V", 0) . $cl . $genPk . $rh . "\x00" . str_repeat("\0", 32) . $csig . "\x01" . $rsig . str_repeat("\x55", 265) . pack("P", $n));
  };

  $s1 = $mkSrv($u1, $pk1, $lp1); $s2 = $mkSrv($u2, $pk2, $lp2); $s3 = $mkSrv($u3, $pk3, $lp3);
  $t0 = time() - 10;
  [$aid1, $m1] = $mkMan([$s1], 1, $t0 * 1000);
  [$aid2, $m2] = $mkMan([$s1], 1, ($t0 + 1) * 1000);
  [$aid3, $m3] = $mkMan([$s1], 1, ($t0 + 2) * 1000);
  [$aidImp, $mImp] = $mkMan([$s2], 1, ($t0 + 3) * 1000);
  [$aidFin, $mFin] = $mkMan([$s1, $s2, $s3], 2, ($t0 + 4) * 1000);

  // Pre-issue ticket for aid2 and aid3 before max_buckets=1 is reached, and capture a signed receipt for aid3 then wipe aid3 bucket to simulate rollback!
  [, $t2Res] = $issueT($u1, $sk1, $pk1, $aid2, $q);
  [, $t3Res] = $issueT($u1, $sk1, $pk1, $aid3, $q);
  $b3Hex = hash("sha256", "HUMOCO_SYNC_BUCKET_V1" . hex2bin($aid3) . hex2bin($lp1));
  [$c3Init, $b3Res] = $post("$u1/sync.php?lock", json_encode(["anchor_id" => $aid3, "bucket" => $b3Hex, "recipient_nonce" => bin2hex(random_bytes(32)), "entries" => [$mkRoot($aid3)], "manifest" => $m3, "genesis_ticket" => $t3Res["ticket"], "known_head_receipt" => null]));
  if ($c3Init !== 200) throw new RuntimeException("aid3 init failed $c3Init");
  $kr3 = $b3Res["receipts"][0];
  // Wipe aid3 from u1 so max_buckets starts at 0 again
  @unlink("$doc1/humoco_sync_data/.locks_meta/buckets/$b3Hex.json");
  @unlink("$doc1/humoco_sync_data/.locks_meta/rotations/$aid3.json");
  @unlink("$doc1/humoco_sync_data/anchors/$aid3.bin");
  foreach (glob("$doc1/humoco_sync_data/locks/*/$b3Hex/*.lock") ?: [] as $f) @unlink($f);

  // Fill u1 max_buckets=1 with aid1
  [, $t1Res] = $issueT($u1, $sk1, $pk1, $aid1, $q);
  $b1Hex = hash("sha256", "HUMOCO_SYNC_BUCKET_V1" . hex2bin($aid1) . hex2bin($lp1));
  [$c1, ] = $post("$u1/sync.php?lock", json_encode(["anchor_id" => $aid1, "bucket" => $b1Hex, "recipient_nonce" => bin2hex(random_bytes(32)), "entries" => [$mkRoot($aid1)], "manifest" => $m1, "genesis_ticket" => $t1Res["ticket"], "known_head_receipt" => null]));
  if ($c1 !== 200) throw new RuntimeException("fill u1 failed $c1");

  // 1) POST ?lock_ticket unseen aid2 on full u1 -> 507
  [$tCapCode, ] = $issueT($u1, $sk1, $pk1, $aid2, $q);
  // 2) POST ?lock_ticket existing aid1 on full u1 -> 200
  [$tExistCode, ] = $issueT($u1, $sk1, $pk1, $aid1, $q);
  // 3) POST ?lock unseen aid2 with pre-issued ticket on full u1 -> 507
  $b2Hex = hash("sha256", "HUMOCO_SYNC_BUCKET_V1" . hex2bin($aid2) . hex2bin($lp1));
  [$bCapCode, ] = $post("$u1/sync.php?lock", json_encode(["anchor_id" => $aid2, "bucket" => $b2Hex, "recipient_nonce" => bin2hex(random_bytes(32)), "entries" => [$mkRoot($aid2)], "manifest" => $m2, "genesis_ticket" => $t2Res["ticket"], "known_head_receipt" => null]));
  // 4) POST ?lock known_head_receipt tombstone for missing aid3 on full u1 -> 409 bucket_self_frozen
  [$tombCode, $tombBody] = $post("$u1/sync.php?lock", json_encode(["anchor_id" => $aid3, "bucket" => $b3Hex, "recipient_nonce" => bin2hex(random_bytes(32)), "entries" => [$mkRoot($aid3)], "manifest" => null, "genesis_ticket" => null, "known_head_receipt" => $kr3]));
  @unlink("$doc1/humoco_sync_data/.locks_meta/buckets/$b3Hex.json");

  // 5) POST ?lock_import for unseen aidImp ([u2] -> [u2, u1]) on full u1 -> 507
  $propImp = $mkProp($aidImp, 1, 2, 2, [$s2, $s1], $t0);
  [$cPrImp, $prImp] = $post("$u2/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $propImp, "current_manifest" => $mImp]));
  if ($cPrImp !== 200) throw new RuntimeException("propose aidImp failed $cPrImp");
  [$impCapCode, ] = $post("$u1/sync.php?lock_import", json_encode(["anchor_id" => $aidImp, "active_manifest" => $mImp, "proposal" => $propImp, "snapshots" => [$prImp["snapshot_export"]], "quorum_certificates" => []]));

  // 6) POST ?lock_commit finalize for unseen aidFin ([u1, u2, u3] -> [u2, u3], retiring u1) on full u1 -> 507 + 0 files created on u1
  $propFin = $mkProp($aidFin, 1, 2, 2, [$s2, $s3], $t0);
  [, $prFin2] = $post("$u2/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $propFin, "current_manifest" => $mFin]));
  [, $prFin3] = $post("$u3/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $propFin, "current_manifest" => $mFin]));
  $impFinReq = json_encode(["anchor_id" => $aidFin, "active_manifest" => $mFin, "proposal" => $propFin, "snapshots" => [$prFin2["snapshot_export"], $prFin3["snapshot_export"]], "quorum_certificates" => []]);
  [, $iFin2] = $post("$u2/sync.php?lock_import", $impFinReq);
  [, $iFin3] = $post("$u3/sync.php?lock_import", $impFinReq);
  $acksFin = [$iFin2["import_ack"], $iFin3["import_ack"]];
  $ishFin = $iFin2["import_ack"]["imported_state_hash"];
  [, $scFin2] = $post("$u2/sync.php?lock_commit", json_encode(["action" => "sign_commit", "anchor_id" => $aidFin, "proposal" => $propFin, "imported_state_hash" => $ishFin, "import_acks" => $acksFin]));
  [, $scFin3] = $post("$u3/sync.php?lock_commit", json_encode(["action" => "sign_commit", "anchor_id" => $aidFin, "proposal" => $propFin, "imported_state_hash" => $ishFin, "import_acks" => $acksFin]));
  $mFin2 = ["revision" => 2, "threshold" => 2, "servers" => [$s2, $s3], "successors" => [], "authority" => $mFin["authority"], "migration_chain" => [["anchor_id" => $aidFin, "genesis_manifest" => $mFin, "proposal" => $propFin, "imported_state_hash" => $ishFin, "import_acks" => $acksFin, "commit_sigs" => [$scFin2["committee_signature"], $scFin3["committee_signature"]]]], "issued_at_ms" => $t0 * 1000, "retain_until_quarter" => $q];
  [$finCapCode, ] = $post("$u1/sync.php?lock_commit", json_encode(["action" => "finalize", "anchor_id" => $aidFin, "new_manifest" => $mFin2]));
  $finRotLeak = file_exists("$doc1/humoco_sync_data/.locks_meta/rotations/$aidFin.json") ? 1 : 0;
  $finAncLeak = file_exists("$doc1/humoco_sync_data/anchors/$aidFin.bin") ? 1 : 0;

  // 7) Existing bucket aid1 rotation ([u1] -> [u1, u2]) succeeds end-to-end on full u1 -> 200
  $prop12 = $mkProp($aid1, 1, 2, 2, [$s1, $s2], $t0);
  [, $pr12] = $post("$u1/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $prop12]));
  $imp12Req = json_encode(["anchor_id" => $aid1, "active_manifest" => $m1, "proposal" => $prop12, "snapshots" => [$pr12["snapshot_export"]], "quorum_certificates" => []]);
  [$impExistCode, $i1_12] = $post("$u1/sync.php?lock_import", $imp12Req);
  [, $i2_12] = $post("$u2/sync.php?lock_import", $imp12Req);
  $acks12 = [$i1_12["import_ack"], $i2_12["import_ack"]];
  $ish12 = $i1_12["import_ack"]["imported_state_hash"];
  [, $sc1_12] = $post("$u1/sync.php?lock_commit", json_encode(["action" => "sign_commit", "anchor_id" => $aid1, "proposal" => $prop12, "imported_state_hash" => $ish12, "import_acks" => $acks12]));
  $m1_2 = ["revision" => 2, "threshold" => 2, "servers" => [$s1, $s2], "successors" => [], "authority" => $m1["authority"], "migration_chain" => [["anchor_id" => $aid1, "genesis_manifest" => $m1, "proposal" => $prop12, "imported_state_hash" => $ish12, "import_acks" => $acks12, "commit_sigs" => [$sc1_12["committee_signature"]]]], "issued_at_ms" => $t0 * 1000, "retain_until_quarter" => $q];
  [$finExistCode, ] = $post("$u1/sync.php?lock_commit", json_encode(["action" => "finalize", "anchor_id" => $aid1, "new_manifest" => $m1_2]));
  echo json_encode([
    "t_cap" => $tCapCode,
    "t_exist" => $tExistCode,
    "b_cap" => $bCapCode,
    "tomb_code" => $tombCode,
    "tomb_err" => $tombBody["error"] ?? "",
    "imp_cap" => $impCapCode,
    "fin_cap" => $finCapCode,
    "fin_rot_leak" => $finRotLeak,
    "fin_anc_leak" => $finAncLeak,
    "imp_exist" => $impExistCode,
    "fin_exist" => $finExistCode,
  ]);
' "$B10_URL" "$B10_ADMIN_SK" "$B10_ADMIN_PK" "$B10_LP" "$B10_DOC" "$B10T_URL" "$B10T_ADMIN_PK" "$B10T_LP" "$B10U_URL" "$B10U_ADMIN_PK" "$B10U_LP" "$QTR")"

assert_contains "$B10_OUT" '"t_cap":507' "SYNC-S07-08: POST ?lock_ticket rejects unseen bucket past max_buckets=1 (507)"
assert_contains "$B10_OUT" '"t_exist":200' "SYNC-S07-08: POST ?lock_ticket allows existing bucket at max_buckets=1 (200)"
assert_contains "$B10_OUT" '"b_cap":507' "SYNC-S07-08: POST ?lock rejects unseen bucket creation past max_buckets=1 (507)"
assert_contains "$B10_OUT" '"tomb_code":409' "SYNC-S07-08: known_head_receipt rollback tombstone stays exempt from max_buckets=1 (409)"
assert_contains "$B10_OUT" '"tomb_err":"bucket_self_frozen"' "SYNC-S07-08: rollback tombstone returns bucket_self_frozen"
assert_contains "$B10_OUT" '"imp_cap":507' "SYNC-S07-08: POST ?lock_import rejects unseen bucket past max_buckets=1 (507)"
assert_contains "$B10_OUT" '"fin_cap":507' "SYNC-S07-08: POST ?lock_commit finalize rejects unseen bucket past max_buckets=1 (507)"
assert_contains "$B10_OUT" '"fin_rot_leak":0' "SYNC-S07-08: rejected finalize leaves 0 rotation metadata files"
assert_contains "$B10_OUT" '"fin_anc_leak":0' "SYNC-S07-08: rejected finalize leaves 0 static anchor files"
assert_contains "$B10_OUT" '"imp_exist":200' "SYNC-S07-08: POST ?lock_import allows existing bucket rotation at max_buckets=1 (200)"
assert_contains "$B10_OUT" '"fin_exist":200' "SYNC-S07-08: POST ?lock_commit finalize allows existing bucket rotation at max_buckets=1 (200)"

for xp in "${B10_PID:-}" "${B10T_PID:-}" "${B10U_PID:-}"; do
  if [[ -n "$xp" ]] && kill -0 "$xp" 2>/dev/null; then
    kill "$xp" 2>/dev/null || true
    wait "$xp" 2>/dev/null || true
  fi
done
B10_PID=""; B10T_PID=""; B10U_PID=""

echo "--- Test 11 (SYNC-S07-09): lock_import preserves monotonic (write_seq, bucket_head) against pre-rotation receipts ---"
read -r B11_1_SK B11_1_PK <<< "$("$SERVER_BIN" sign-test keygen)"
read -r B11_2_SK B11_2_PK <<< "$("$SERVER_BIN" sign-test keygen)"
read -r B11_3_SK B11_3_PK <<< "$("$SERVER_BIN" sign-test keygen)"
B11_1_PORT="$(pick_free_port)"
B11_1_DOC="$TMP_DIR/b11_1_doc"
start_php_server "$B11_1_DOC" "$B11_1_PK" 50000 1 "$B11_1_PORT" "$TMP_DIR/b11_1.log" 0
B11_1_PID="$PHP_PID"; PHP_PID=""
B11_2_PORT=$((B11_1_PORT + 1))
while (echo >/dev/tcp/127.0.0.1/"$B11_2_PORT") 2>/dev/null; do B11_2_PORT=$((B11_2_PORT + 1)); done
B11_2_DOC="$TMP_DIR/b11_2_doc"
start_php_server "$B11_2_DOC" "$B11_2_PK" 50000 1 "$B11_2_PORT" "$TMP_DIR/b11_2.log" 0
B11_2_PID="$PHP_PID"; PHP_PID=""
B11_3_PORT=$((B11_2_PORT + 1))
while (echo >/dev/tcp/127.0.0.1/"$B11_3_PORT") 2>/dev/null; do B11_3_PORT=$((B11_3_PORT + 1)); done
B11_3_DOC="$TMP_DIR/b11_3_doc"
start_php_server "$B11_3_DOC" "$B11_3_PK" 50000 1 "$B11_3_PORT" "$TMP_DIR/b11_3.log" 0
B11_3_PID="$PHP_PID"; PHP_PID=""
cleanup_b11() {
  for xp in "${B11_1_PID:-}" "${B11_2_PID:-}" "${B11_3_PID:-}"; do
    if [[ -n "$xp" ]] && kill -0 "$xp" 2>/dev/null; then
      kill "$xp" 2>/dev/null || true
      wait "$xp" 2>/dev/null || true
    fi
  done
  cleanup_b10
}
trap cleanup_b11 EXIT

B11_1_URL="http://127.0.0.1:${B11_1_PORT}"
B11_2_URL="http://127.0.0.1:${B11_2_PORT}"
B11_3_URL="http://127.0.0.1:${B11_3_PORT}"
B11_1_LP="$(curl -sf "${B11_1_URL}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"
B11_2_LP="$(curl -sf "${B11_2_URL}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"
B11_3_LP="$(curl -sf "${B11_3_URL}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"

B11_OUT="$(php -r '
  $u1 = $argv[1]; $sk1 = $argv[2]; $pk1 = $argv[3]; $lp1 = $argv[4];
  $u2 = $argv[5]; $sk2 = $argv[6]; $pk2 = $argv[7]; $lp2 = $argv[8];
  $u3 = $argv[9]; $pk3 = $argv[10]; $lp3 = $argv[11];
  $q = (int)$argv[12];
  $post = static function (string $u, string $body, array $hdrs = []): array {
    $ch = curl_init($u);
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_HTTPHEADER => array_merge(["Content-Type: application/json"], $hdrs), CURLOPT_RETURNTRANSFER => true]);
    $resp = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    return [$code, json_decode((string)$resp, true) ?: []];
  };
  $issueT = static function (string $u, string $sk, string $pk, string $aHex, int $q) use ($post): array {
    $body = json_encode(["anchor_id" => $aHex, "retain_until_quarter" => $q, "pow_timestamp" => null, "pow_nonce" => null]);
    $ts = time(); $nonce = bin2hex(random_bytes(16));
    $msg = "HUMOCO-DROP-REQ-V1\nPOST\nlock_ticket\n\n{$ts}\n{$nonce}\n" . hash("sha256", $body);
    $sig = bin2hex(sodium_crypto_sign_detached($msg, hex2bin($sk) . hex2bin($pk)));
    return $post("$u/sync.php?lock_ticket", $body, ["X-Drop-Pubkey: $pk", "X-Drop-Timestamp: $ts", "X-Drop-Nonce: $nonce", "X-Drop-Signature: $sig"]);
  };
  $cKp = sodium_crypto_sign_seed_keypair(hash("sha256", "B11_CREATOR", true));
  $cSk = sodium_crypto_sign_secretkey($cKp); $cPk = bin2hex(sodium_crypto_sign_publickey($cKp));
  $mkSrv = static fn(string $u, string $ap, string $lp) => ["write_url" => "$u/sync.php", "read_url" => "$u/humoco_sync_data", "admin_pub" => $ap, "lock_pub" => $lp, "nominated_by" => "creator"];
  $mkMan = static function (array $srvs, int $thr, int $ms) use ($cPk, $q): array {
    $m = ["revision" => 1, "threshold" => $thr, "servers" => $srvs, "successors" => [], "authority" => ["creator_mig_pub" => $cPk, "guarantor_mig_pubs" => []], "migration_chain" => [], "issued_at_ms" => $ms, "retain_until_quarter" => $q];
    $sBin = ""; foreach ($srvs as $s) $sBin .= hex2bin($s["admin_pub"]) . hex2bin($s["lock_pub"]) . "\x00";
    $pre = "HUMOCO_ANCHOR_MANIFEST_V1\x00" . pack("P", 1) . chr($thr) . chr(count($srvs)) . $sBin . pack("v", 0) . hex2bin($cPk) . "\x00" . pack("P", $ms) . pack("v", $q);
    return [bin2hex(hash("sha256", $pre, true)), $m];
  };
  $mkProp = static function (string $aHex, int $from, int $to, int $thr, array $srvs, int $ts) use ($cSk, $q): array {
    $sBin = ""; foreach ($srvs as $s) $sBin .= hex2bin($s["admin_pub"]) . hex2bin($s["lock_pub"]) . "\x00";
    $pDig = hash("sha256", "HUMOCO_MIGRATION_PROP_V1" . hex2bin($aHex) . pack("P", $from) . pack("P", $to) . chr($thr) . chr(count($srvs)) . $sBin . pack("v", 0) . pack("v", $q) . pack("P", $ts) . "\x00", true);
    return ["anchor_id" => $aHex, "from_rev" => $from, "to_rev" => $to, "new_threshold" => $thr, "new_servers" => $srvs, "new_successors" => [], "retain_until_quarter" => $q, "proposed_at" => $ts, "initiator" => ["kind" => "creator"], "proposer_sig" => bin2hex(sodium_crypto_sign_detached($pDig, $cSk)), "guarantor_cosigs" => []];
  };
  $mkEntry = static function (string $aHex, string $dsTag32, string $pSlot32, int $ob, int $depth, string $senderSk, string $senderPk, string $recvHash, ?string $rootSk) use ($cSk): array {
    $a32 = hex2bin($aHex);
    $slot = hash("sha256", "HUMOCO_SYNC_SLOT_V1" . $a32 . $dsTag32, true);
    $cl = $dsTag32;
    $cd = hash("sha256", "HUMOCO_CAUSAL_OUTPUT_V1" . $a32 . $slot . $pSlot32 . chr($ob) . pack("V", $depth) . $cl . $senderPk . $recvHash . "\x00" . str_repeat("\0", 32), true);
    $csig = sodium_crypto_sign_detached($cd, $senderSk);
    $hasRoot = ($depth === 0) ? "\x01" : "\x00";
    $rsig = ($depth === 0) ? sodium_crypto_sign_detached(hash("sha256", "HUMOCO_ROOT_MIG_AUTH_V1" . $a32 . $slot . $senderPk, true), $rootSk) : str_repeat("\0", 64);
    for ($n = 0;; $n++) { $h = hash("sha256", "HUMOCO_LOCK_POW_V1" . $slot . $cl . pack("V", $depth) . pack("P", $n), true); if (ord($h[0]) === 0) break; }
    $wire = "HMLK\x01" . $slot . $pSlot32 . chr($ob) . pack("V", $depth) . $cl . $senderPk . $recvHash . "\x00" . str_repeat("\0", 32) . $csig . $hasRoot . $rsig . str_repeat("\x33", 265) . pack("P", $n);
    return [$slot, bin2hex($wire)];
  };

  $s1 = $mkSrv($u1, $pk1, $lp1); $s2 = $mkSrv($u2, $pk2, $lp2); $s3 = $mkSrv($u3, $pk3, $lp3);
  $t0 = time() - 10;
  [$aid, $m1] = $mkMan([$s1], 1, $t0 * 1000);
  $b1Hex = hash("sha256", "HUMOCO_SYNC_BUCKET_V1" . hex2bin($aid) . hex2bin($lp1));
  [, $tRes] = $issueT($u1, $sk1, $pk1, $aid, $q);

  // Pick two root entries A and B where slotB < slotA, and write A first then B second!
  $k0 = sodium_crypto_sign_seed_keypair(str_repeat(chr(61), 32));
  $k1 = sodium_crypto_sign_seed_keypair(str_repeat(chr(62), 32));
  $k2 = sodium_crypto_sign_seed_keypair(str_repeat(chr(63), 32));
  $r0Sk = sodium_crypto_sign_secretkey($k0); $r0Pk = sodium_crypto_sign_publickey($k0);
  $r1Sk = sodium_crypto_sign_secretkey($k1); $r1Pk = sodium_crypto_sign_publickey($k1);
  $r2Hash = hash("sha3-256", sodium_crypto_sign_publickey($k2), true);
  $r1Hash = hash("sha3-256", $r1Pk, true);

  [$slotA, $hexA] = $mkEntry($aid, str_repeat("\x11", 32), str_repeat("\0", 32), 0, 0, $r0Sk, $r0Pk, $r1Hash, $cSk);
  [$slotB, $hexB] = $mkEntry($aid, str_repeat("\x22", 32), str_repeat("\0", 32), 0, 0, $r0Sk, $r0Pk, $r1Hash, $cSk);
  if (strcmp($slotB, $slotA) >= 0) {
    // Swap so $slotB < $slotA lexicographically
    [$slotA, $hexA, $slotB, $hexB] = [$slotB, $hexB, $slotA, $hexA];
  }
  [$cA, ] = $post("$u1/sync.php?lock", json_encode(["anchor_id" => $aid, "bucket" => $b1Hex, "recipient_nonce" => bin2hex(random_bytes(32)), "entries" => [$hexA], "manifest" => $m1, "genesis_ticket" => $tRes["ticket"], "known_head_receipt" => null]));
  [$cB, $resB] = $post("$u1/sync.php?lock", json_encode(["anchor_id" => $aid, "bucket" => $b1Hex, "recipient_nonce" => bin2hex(random_bytes(32)), "entries" => [$hexB], "manifest" => null, "genesis_ticket" => null, "known_head_receipt" => null]));
  if ($cA !== 200 || $cB !== 200) throw new RuntimeException("pre-rotation writes failed $cA/$cB");
  $kr2 = $resB["receipts"][0]; // write_seq=2, bucket_head from A->B order

  // Rotate [u1] -> [u1, u2] (0s pure growth)
  $prop12 = $mkProp($aid, 1, 2, 2, [$s1, $s2], $t0);
  [, $pr12] = $post("$u1/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $prop12]));
  $imp12Req = json_encode(["anchor_id" => $aid, "active_manifest" => $m1, "proposal" => $prop12, "snapshots" => [$pr12["snapshot_export"]], "quorum_certificates" => []]);
  [, $i1] = $post("$u1/sync.php?lock_import", $imp12Req);
  [, $i2] = $post("$u2/sync.php?lock_import", $imp12Req);
  $acks = [$i1["import_ack"], $i2["import_ack"]]; $ish = $i1["import_ack"]["imported_state_hash"];
  [, $sc1] = $post("$u1/sync.php?lock_commit", json_encode(["action" => "sign_commit", "anchor_id" => $aid, "proposal" => $prop12, "imported_state_hash" => $ish, "import_acks" => $acks]));
  $m2 = ["revision" => 2, "threshold" => 2, "servers" => [$s1, $s2], "successors" => [], "authority" => $m1["authority"], "migration_chain" => [["anchor_id" => $aid, "genesis_manifest" => $m1, "proposal" => $prop12, "imported_state_hash" => $ish, "import_acks" => $acks, "commit_sigs" => [$sc1["committee_signature"]]]], "issued_at_ms" => $t0 * 1000, "retain_until_quarter" => $q];
  $post("$u1/sync.php?lock_commit", json_encode(["action" => "finalize", "anchor_id" => $aid, "new_manifest" => $m2]));
  $post("$u2/sync.php?lock_commit", json_encode(["action" => "finalize", "anchor_id" => $aid, "new_manifest" => $m2]));

  // Submit spend entryC (child of A) to u1 presenting genuine pre-rotation receipt kr2!
  [, $hexC] = $mkEntry($aid, str_repeat("\x33", 32), $slotA, 0, 1, $r1Sk, $r1Pk, $r2Hash, null);
  [$afterCode, $afterBody] = $post("$u1/sync.php?lock", json_encode(["anchor_id" => $aid, "bucket" => $b1Hex, "recipient_nonce" => bin2hex(random_bytes(32)), "entries" => [$hexC], "manifest" => null, "genesis_ticket" => null, "known_head_receipt" => $kr2]));

  // Also test missing-slot catchup on u2 in [u1, u2] -> [u1, u2, u3] when u2 has A+B (seq=2) and u1 adds C (seq=3): u2 advances 2->3 and keeps kr2 valid!
  // Let us write entryC to u2 without kr2? Wait: u2 got C? Actually u2 was active too! Let us write entryC to u2 (without writing to u1, no we already wrote C to u1; let us write D (child of B) ONLY to u2, then rotate [u1,u2]->[u1,u2,u3], and present kr2 (seq=2) to u1 where u1 imported D and advanced 3->4? Wait: after entryC, u1 is at seq=3, kr3 is receipt from entryC!).
  $kr3 = $afterBody["receipts"][0] ?? null;
  $b2Hex = hash("sha256", "HUMOCO_SYNC_BUCKET_V1" . hex2bin($aid) . hex2bin($lp2));
  [, $hexD] = $mkEntry($aid, str_repeat("\x44", 32), $slotB, 0, 1, $r1Sk, $r1Pk, $r2Hash, null);
  $post("$u2/sync.php?lock", json_encode(["anchor_id" => $aid, "bucket" => $b2Hex, "recipient_nonce" => bin2hex(random_bytes(32)), "entries" => [$hexD], "manifest" => null, "genesis_ticket" => null, "known_head_receipt" => null]));
  $prop23 = $mkProp($aid, 2, 3, 2, [$s1, $s2, $s3], $t0);
  [, $pr23_1] = $post("$u1/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $prop23]));
  [, $pr23_2] = $post("$u2/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $prop23]));
  $imp23Req = json_encode(["anchor_id" => $aid, "active_manifest" => $m2, "proposal" => $prop23, "snapshots" => [$pr23_1["snapshot_export"], $pr23_2["snapshot_export"]], "quorum_certificates" => []]);
  [, $i23_1] = $post("$u1/sync.php?lock_import", $imp23Req);
  [, $i23_2] = $post("$u2/sync.php?lock_import", $imp23Req);
  [, $i23_3] = $post("$u3/sync.php?lock_import", $imp23Req);
  $acks23 = [$i23_1["import_ack"], $i23_2["import_ack"], $i23_3["import_ack"]]; $ish23 = $i23_1["import_ack"]["imported_state_hash"];
  [, $sc23_1] = $post("$u1/sync.php?lock_commit", json_encode(["action" => "sign_commit", "anchor_id" => $aid, "proposal" => $prop23, "imported_state_hash" => $ish23, "import_acks" => $acks23]));
  [, $sc23_2] = $post("$u2/sync.php?lock_commit", json_encode(["action" => "sign_commit", "anchor_id" => $aid, "proposal" => $prop23, "imported_state_hash" => $ish23, "import_acks" => $acks23]));
  $m3 = ["revision" => 3, "threshold" => 2, "servers" => [$s1, $s2, $s3], "successors" => [], "authority" => $m1["authority"], "migration_chain" => array_merge($m2["migration_chain"], [["anchor_id" => $aid, "genesis_manifest" => null, "proposal" => $prop23, "imported_state_hash" => $ish23, "import_acks" => $acks23, "commit_sigs" => [$sc23_1["committee_signature"], $sc23_2["committee_signature"]]]]), "issued_at_ms" => $t0 * 1000, "retain_until_quarter" => $q];
  $post("$u1/sync.php?lock_commit", json_encode(["action" => "finalize", "anchor_id" => $aid, "new_manifest" => $m3]));
  // Present pre-rotation kr3 (write_seq=3) on u1 with retry of hexC (idempotent): u1 imported D so write_seq=4 >= 3 -> MUST return 200!
  [$catchupCode, $catchupBody] = $post("$u1/sync.php?lock", json_encode(["anchor_id" => $aid, "bucket" => $b1Hex, "recipient_nonce" => bin2hex(random_bytes(32)), "entries" => [$hexC], "manifest" => null, "genesis_ticket" => null, "known_head_receipt" => $kr3]));

  echo json_encode([
    "after_code" => $afterCode,
    "after_ws" => $afterBody["receipts"][0]["write_seq"] ?? -1,
    "after_err" => $afterBody["error"] ?? "",
    "catchup_code" => $catchupCode,
    "catchup_ws" => $catchupBody["receipts"][0]["write_seq"] ?? -1,
  ]);
' "$B11_1_URL" "$B11_1_SK" "$B11_1_PK" "$B11_1_LP" "$B11_2_URL" "$B11_2_SK" "$B11_2_PK" "$B11_2_LP" "$B11_3_URL" "$B11_3_PK" "$B11_3_LP" "$QTR")"

assert_contains "$B11_OUT" '"after_code":200' "SYNC-S07-09: pre-rotation known_head_receipt succeeds after out-of-order slot import (200)"
assert_contains "$B11_OUT" '"after_ws":3' "SYNC-S07-09: post-rotation write_seq advances monotonically from 2 to 3"
assert_contains "$B11_OUT" '"catchup_code":200' "SYNC-S07-09: pre-rotation receipt succeeds after union catchup import (200)"
assert_contains "$B11_OUT" '"catchup_ws":4' "SYNC-S07-09: union catchup advances write_seq monotonically from 3 to 4"

echo ""
echo "=== Test 12: SYNC-S07-10 full migration_chain prefix consistency on lock_import & finalize ==="
B12_OUT="$(php -r '
  $u1 = $argv[1]; $sk1 = $argv[2]; $pk1 = $argv[3]; $lp1 = $argv[4];
  $u2 = $argv[5]; $pk2 = $argv[6]; $lp2 = $argv[7];
  $u3 = $argv[8]; $pk3 = $argv[9]; $lp3 = $argv[10];
  $q = (int)$argv[11];
  $post = static function (string $u, string $body, array $hdrs = []): array {
    $ch = curl_init($u);
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_HTTPHEADER => array_merge(["Content-Type: application/json"], $hdrs), CURLOPT_RETURNTRANSFER => true]);
    $resp = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    return [$code, json_decode((string)$resp, true) ?: []];
  };
  $issueT = static function (string $u, string $sk, string $pk, string $aHex, int $q) use ($post): array {
    $body = json_encode(["anchor_id" => $aHex, "retain_until_quarter" => $q, "pow_timestamp" => null, "pow_nonce" => null]);
    $ts = time(); $nonce = bin2hex(random_bytes(16));
    $msg = "HUMOCO-DROP-REQ-V1\nPOST\nlock_ticket\n\n{$ts}\n{$nonce}\n" . hash("sha256", $body);
    $sig = bin2hex(sodium_crypto_sign_detached($msg, hex2bin($sk) . hex2bin($pk)));
    return $post("$u/sync.php?lock_ticket", $body, ["X-Drop-Pubkey: $pk", "X-Drop-Timestamp: $ts", "X-Drop-Nonce: $nonce", "X-Drop-Signature: $sig"]);
  };
  $cKp = sodium_crypto_sign_seed_keypair(hash("sha256", "B12_CREATOR", true));
  $cSk = sodium_crypto_sign_secretkey($cKp); $cPk = bin2hex(sodium_crypto_sign_publickey($cKp));
  $mkSyn = static function (string $label): array {
    $akp = sodium_crypto_sign_seed_keypair(hash("sha256", "B12_ADM_$label", true));
    $lkp = sodium_crypto_sign_seed_keypair(hash("sha256", "B12_LCK_$label", true));
    return [
      "srv" => ["write_url" => "http://127.0.0.1:9/sync.php", "read_url" => "http://127.0.0.1:9/d", "admin_pub" => bin2hex(sodium_crypto_sign_publickey($akp)), "lock_pub" => bin2hex(sodium_crypto_sign_publickey($lkp)), "nominated_by" => "creator"],
      "sk" => sodium_crypto_sign_secretkey($lkp),
      "lp" => bin2hex(sodium_crypto_sign_publickey($lkp)),
    ];
  };
  $syn4 = $mkSyn("S4"); $syn5 = $mkSyn("S5"); $syn6 = $mkSyn("S6");
  $s1 = ["write_url" => "$u1/sync.php", "read_url" => "$u1/humoco_sync_data", "admin_pub" => $pk1, "lock_pub" => $lp1, "nominated_by" => "creator"];
  $s2 = ["write_url" => "$u2/sync.php", "read_url" => "$u2/humoco_sync_data", "admin_pub" => $pk2, "lock_pub" => $lp2, "nominated_by" => "creator"];
  $s3 = ["write_url" => "$u3/sync.php", "read_url" => "$u3/humoco_sync_data", "admin_pub" => $pk3, "lock_pub" => $lp3, "nominated_by" => "creator"];
  $s4 = $syn4["srv"]; $s5 = $syn5["srv"]; $s6 = $syn6["srv"];

  $t0 = time() - 10;
  $m1 = ["revision" => 1, "threshold" => 2, "servers" => [$s1, $s4, $s5], "successors" => [], "authority" => ["creator_mig_pub" => $cPk, "guarantor_mig_pubs" => []], "migration_chain" => [], "issued_at_ms" => $t0 * 1000, "retain_until_quarter" => $q];
  $sBin = ""; foreach ($m1["servers"] as $s) $sBin .= hex2bin($s["admin_pub"]) . hex2bin($s["lock_pub"]) . "\x00";
  $aid = bin2hex(hash("sha256", "HUMOCO_ANCHOR_MANIFEST_V1\x00" . pack("P", 1) . chr(2) . chr(3) . $sBin . pack("v", 0) . hex2bin($cPk) . "\x00" . pack("P", $t0 * 1000) . pack("v", $q), true));
  $a32 = hex2bin($aid);

  $mkProp = static function (int $from, int $to, int $thr, array $srvs, int $ts) use ($aid, $a32, $cSk, $q): array {
    $sb = ""; foreach ($srvs as $s) $sb .= hex2bin($s["admin_pub"]) . hex2bin($s["lock_pub"]) . "\x00";
    $dig = hash("sha256", "HUMOCO_MIGRATION_PROP_V1" . $a32 . pack("P", $from) . pack("P", $to) . chr($thr) . chr(count($srvs)) . $sb . pack("v", 0) . pack("v", $q) . pack("P", $ts) . "\x00", true);
    return ["anchor_id" => $aid, "from_rev" => $from, "to_rev" => $to, "new_threshold" => $thr, "new_servers" => $srvs, "new_successors" => [], "retain_until_quarter" => $q, "proposed_at" => $ts, "initiator" => ["kind" => "creator"], "proposer_sig" => bin2hex(sodium_crypto_sign_detached($dig, $cSk)), "guarantor_cosigs" => []];
  };
  $propDig = static function (array $prop) use ($a32): string {
    $sb = ""; foreach ($prop["new_servers"] as $s) $sb .= hex2bin($s["admin_pub"]) . hex2bin($s["lock_pub"]) . "\x00";
    return hash("sha256", "HUMOCO_MIGRATION_PROP_V1" . $a32 . pack("P", $prop["from_rev"]) . pack("P", $prop["to_rev"]) . chr($prop["new_threshold"]) . chr(count($prop["new_servers"])) . $sb . pack("v", 0) . pack("v", $prop["retain_until_quarter"]) . pack("P", $prop["proposed_at"]) . "\x00", true);
  };
  $mkSnap = static function (array $syn, int $fromRev, string $pDig, int $ts) use ($aid, $a32, $q): array {
    $lp = hex2bin($syn["lp"]);
    $bk = hash("sha256", "HUMOCO_SYNC_BUCKET_V1" . $a32 . $lp, true);
    $bh = hash("sha256", "HUMOCO_BUCKET_INIT_V1" . $bk . pack("v", $q), true);
    $sh = hash("sha256", "HUMOCO_FREEZE_STATE_V1" . $a32 . pack("P", $fromRev) . pack("P", 0) . pack("P", 0), true);
    $pre = "HUMOCO_FREEZE_SNAP_V1" . $a32 . $bk . pack("P", $fromRev) . pack("v", $q) . pack("P", 0) . $bh . $sh . "\x01\x01" . $pDig . pack("P", $ts) . pack("P", 0) . $lp;
    return [
      "snapshot" => ["anchor_id" => $aid, "lock_pub" => $syn["lp"], "bucket" => bin2hex($bk), "from_rev" => $fromRev, "retain_until_quarter" => $q, "write_seq" => 0, "bucket_head" => bin2hex($bh), "state_hash" => bin2hex($sh), "permanent" => true, "proposal_hash" => bin2hex($pDig), "frozen_at" => $ts, "expires_at" => null, "sig" => bin2hex(sodium_crypto_sign_detached(hash("sha256", $pre, true), $syn["sk"]))],
      "entries" => [], "conflicts" => [],
    ];
  };
  $mkAck = static function (array $syn, string $pDig, int $toRev, string $ishHex, int $ts) use ($aid, $a32, $q): array {
    $lp = hex2bin($syn["lp"]);
    $dig = hash("sha256", "HUMOCO_IMPORT_ACK_V1" . $a32 . $pDig . pack("P", $toRev) . hex2bin($ishHex) . pack("v", $q) . $lp . pack("P", $ts), true);
    return ["anchor_id" => $aid, "proposal_hash" => bin2hex($pDig), "to_rev" => $toRev, "imported_state_hash" => $ishHex, "retain_until_quarter" => $q, "lock_pub" => $syn["lp"], "acked_at" => $ts, "sig" => bin2hex(sodium_crypto_sign_detached($dig, $syn["sk"]))];
  };
  $mkCommitSig = static function (array $syn, string $pDig, int $toRev, string $ishHex, int $ts) use ($a32): array {
    $dig = hash("sha256", "HUMOCO_MIGRATION_CERT_V1" . $a32 . $pDig . pack("P", $toRev) . hex2bin($ishHex), true);
    return ["lock_pub" => $syn["lp"], "committed_at" => $ts, "sig" => bin2hex(sodium_crypto_sign_detached($dig, $syn["sk"]))];
  };

  // 1. Bootstrap m1 on u1 & u2, and pre-collect u1/u2 import_acks for forked branch B (m1 -> m2B with proposed_at = t0+1) before finalizing m2A.
  [, $tRes] = $issueT($u1, $sk1, $pk1, $aid, $q);
  $rkp = sodium_crypto_sign_seed_keypair(str_repeat(chr(71), 32));
  $slot = hash("sha256", "HUMOCO_SYNC_SLOT_V1" . $a32 . str_repeat("\x12", 32), true);
  $cl = str_repeat("\x12", 32);
  $rHash = hash("sha3-256", sodium_crypto_sign_publickey($rkp), true);
  $cd = hash("sha256", "HUMOCO_CAUSAL_OUTPUT_V1" . $a32 . $slot . str_repeat("\0", 32) . "\x00" . pack("V", 0) . $cl . sodium_crypto_sign_publickey($rkp) . $rHash . "\x00" . str_repeat("\0", 32), true);
  $rsig = sodium_crypto_sign_detached(hash("sha256", "HUMOCO_ROOT_MIG_AUTH_V1" . $a32 . $slot . sodium_crypto_sign_publickey($rkp), true), $cSk);
  for ($n = 0;; $n++) { $h = hash("sha256", "HUMOCO_LOCK_POW_V1" . $slot . $cl . pack("V", 0) . pack("P", $n), true); if (ord($h[0]) === 0) break; }
  $hexE = bin2hex("HMLK\x01" . $slot . str_repeat("\0", 32) . "\x00" . pack("V", 0) . $cl . sodium_crypto_sign_publickey($rkp) . $rHash . "\x00" . str_repeat("\0", 32) . sodium_crypto_sign_detached($cd, sodium_crypto_sign_secretkey($rkp)) . "\x01" . $rsig . str_repeat("\x33", 265) . pack("P", $n));
  $b1Hex = hash("sha256", "HUMOCO_SYNC_BUCKET_V1" . $a32 . hex2bin($lp1));
  $post("$u1/sync.php?lock", json_encode(["anchor_id" => $aid, "bucket" => $b1Hex, "recipient_nonce" => bin2hex(random_bytes(32)), "entries" => [$hexE], "manifest" => $m1, "genesis_ticket" => $tRes["ticket"], "known_head_receipt" => null]));

  $prop12A = $mkProp(1, 2, 3, [$s1, $s2, $s4, $s5], $t0);
  $prop12B = $mkProp(1, 2, 3, [$s1, $s2, $s4, $s5], $t0 + 1); // same committee/thr, distinct proposed_at
  $pd12A = $propDig($prop12A); $pd12B = $propDig($prop12B);
  [, $pr12A] = $post("$u1/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $prop12A]));

  // Collect u1/u2 import_acks for m2B using synthetic snapshots from s4+s5 (quorum=2) while u1/u2 are still rev 1.
  $imp12BReq = json_encode(["anchor_id" => $aid, "active_manifest" => $m1, "proposal" => $prop12B, "snapshots" => [$mkSnap($syn4, 1, $pd12B, $t0), $mkSnap($syn5, 1, $pd12B, $t0)], "quorum_certificates" => []]);
  [, $i1B] = $post("$u1/sync.php?lock_import", $imp12BReq);
  [, $i2B] = $post("$u2/sync.php?lock_import", $imp12BReq);
  $ish12B = $i1B["import_ack"]["imported_state_hash"];
  $acks12B = [$i1B["import_ack"], $i2B["import_ack"], $mkAck($syn4, $pd12B, 2, $ish12B, $t0), $mkAck($syn5, $pd12B, 2, $ish12B, $t0)];
  $m2B = ["revision" => 2, "threshold" => 3, "servers" => [$s1, $s2, $s4, $s5], "successors" => [], "authority" => $m1["authority"], "migration_chain" => [["anchor_id" => $aid, "genesis_manifest" => $m1, "proposal" => $prop12B, "imported_state_hash" => $ish12B, "import_acks" => $acks12B, "commit_sigs" => [$mkCommitSig($syn4, $pd12B, 2, $ish12B, $t0), $mkCommitSig($syn5, $pd12B, 2, $ish12B, $t0)]]], "issued_at_ms" => ($t0 + 1) * 1000, "retain_until_quarter" => $q];

  // Construct standalone forked branch B2 (m1 -> m2B_alt=[s4,s5] -> m3B_alt=[s4,s5,s6] -> m4B_alt=[s4,s5]) completely in PHP!
  $prop12BAlt = $mkProp(1, 2, 2, [$s4, $s5], $t0 + 2); $pd12BA = $propDig($prop12BAlt);
  $ish12BA = bin2hex(hash("sha256", "HUMOCO_IMPORT_STATE_V1" . $a32 . pack("P", 2) . pack("P", 0), true));
  $m2BAlt = ["revision" => 2, "threshold" => 2, "servers" => [$s4, $s5], "successors" => [], "authority" => $m1["authority"], "migration_chain" => [["anchor_id" => $aid, "genesis_manifest" => $m1, "proposal" => $prop12BAlt, "imported_state_hash" => $ish12BA, "import_acks" => [$mkAck($syn4, $pd12BA, 2, $ish12BA, $t0), $mkAck($syn5, $pd12BA, 2, $ish12BA, $t0)], "commit_sigs" => [$mkCommitSig($syn4, $pd12BA, 2, $ish12BA, $t0), $mkCommitSig($syn5, $pd12BA, 2, $ish12BA, $t0)]]], "issued_at_ms" => ($t0 + 2) * 1000, "retain_until_quarter" => $q];
  $prop23BAlt = $mkProp(2, 3, 2, [$s4, $s5, $s6], $t0 + 2); $pd23BA = $propDig($prop23BAlt);
  $ish23BA = bin2hex(hash("sha256", "HUMOCO_IMPORT_STATE_V1" . $a32 . pack("P", 3) . pack("P", 0), true));
  $m3BAlt = ["revision" => 3, "threshold" => 2, "servers" => [$s4, $s5, $s6], "successors" => [], "authority" => $m1["authority"], "migration_chain" => array_merge($m2BAlt["migration_chain"], [["anchor_id" => $aid, "genesis_manifest" => null, "proposal" => $prop23BAlt, "imported_state_hash" => $ish23BA, "import_acks" => [$mkAck($syn4, $pd23BA, 3, $ish23BA, $t0), $mkAck($syn5, $pd23BA, 3, $ish23BA, $t0), $mkAck($syn6, $pd23BA, 3, $ish23BA, $t0)], "commit_sigs" => [$mkCommitSig($syn4, $pd23BA, 3, $ish23BA, $t0), $mkCommitSig($syn5, $pd23BA, 3, $ish23BA, $t0)]]]), "issued_at_ms" => ($t0 + 2) * 1000, "retain_until_quarter" => $q];
  $prop34BFin = $mkProp(3, 4, 2, [$s4, $s5], $t0 + 3); $pd34BF = $propDig($prop34BFin);
  $ish34BF = bin2hex(hash("sha256", "HUMOCO_IMPORT_STATE_V1" . $a32 . pack("P", 4) . pack("P", 0), true));
  $m4BAlt = ["revision" => 4, "threshold" => 2, "servers" => [$s4, $s5], "successors" => [], "authority" => $m1["authority"], "migration_chain" => array_merge($m3BAlt["migration_chain"], [["anchor_id" => $aid, "genesis_manifest" => null, "proposal" => $prop34BFin, "imported_state_hash" => $ish34BF, "import_acks" => [$mkAck($syn4, $pd34BF, 4, $ish34BF, $t0), $mkAck($syn5, $pd34BF, 4, $ish34BF, $t0)], "commit_sigs" => [$mkCommitSig($syn4, $pd34BF, 4, $ish34BF, $t0), $mkCommitSig($syn5, $pd34BF, 4, $ish34BF, $t0)]]]), "issued_at_ms" => ($t0 + 3) * 1000, "retain_until_quarter" => $q];
  $prop34BImp = $mkProp(3, 4, 3, [$s1, $s4, $s5, $s6], $t0 + 4); // pure growth adding s1 from m3BAlt (N=4 requires thr>=3)

  // 2. Finalize canonical m2A on u1 & u2
  $imp12AReq = json_encode(["anchor_id" => $aid, "active_manifest" => $m1, "proposal" => $prop12A, "snapshots" => [$pr12A["snapshot_export"], $mkSnap($syn4, 1, $pd12A, $t0)], "quorum_certificates" => []]);
  [, $i1A] = $post("$u1/sync.php?lock_import", $imp12AReq);
  [, $i2A] = $post("$u2/sync.php?lock_import", $imp12AReq);
  $ish12A = $i1A["import_ack"]["imported_state_hash"];
  $acks12A = [$i1A["import_ack"], $i2A["import_ack"], $mkAck($syn4, $pd12A, 2, $ish12A, $t0), $mkAck($syn5, $pd12A, 2, $ish12A, $t0)];
  [, $sc1A] = $post("$u1/sync.php?lock_commit", json_encode(["action" => "sign_commit", "anchor_id" => $aid, "proposal" => $prop12A, "imported_state_hash" => $ish12A, "import_acks" => $acks12A]));
  $m2A = ["revision" => 2, "threshold" => 3, "servers" => [$s1, $s2, $s4, $s5], "successors" => [], "authority" => $m1["authority"], "migration_chain" => [["anchor_id" => $aid, "genesis_manifest" => $m1, "proposal" => $prop12A, "imported_state_hash" => $ish12A, "import_acks" => $acks12A, "commit_sigs" => [$sc1A["committee_signature"], $mkCommitSig($syn4, $pd12A, 2, $ish12A, $t0)]]], "issued_at_ms" => $t0 * 1000, "retain_until_quarter" => $q];
  $post("$u1/sync.php?lock_commit", json_encode(["action" => "finalize", "anchor_id" => $aid, "new_manifest" => $m2A]));
  $post("$u2/sync.php?lock_commit", json_encode(["action" => "finalize", "anchor_id" => $aid, "new_manifest" => $m2A]));

  // Test Case 1 (positive control): linear continuation m2A -> m3A MUST return 200
  $prop23A = $mkProp(2, 3, 3, [$s1, $s2, $s3, $s4, $s5], $t0); $pd23A = $propDig($prop23A);
  [, $pr23A1] = $post("$u1/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $prop23A]));
  [, $pr23A2] = $post("$u2/sync.php?lock_freeze", json_encode(["action" => "propose", "proposal" => $prop23A]));
  $imp23AReq = json_encode(["anchor_id" => $aid, "active_manifest" => $m2A, "proposal" => $prop23A, "snapshots" => [$pr23A1["snapshot_export"], $pr23A2["snapshot_export"], $mkSnap($syn4, 2, $pd23A, $t0)], "quorum_certificates" => []]);
  [, $i23A1] = $post("$u1/sync.php?lock_import", $imp23AReq);
  [, $i23A2] = $post("$u2/sync.php?lock_import", $imp23AReq);
  [, $i23A3] = $post("$u3/sync.php?lock_import", $imp23AReq);
  $ish23A = $i23A1["import_ack"]["imported_state_hash"];
  $acks23A = [$i23A1["import_ack"], $i23A2["import_ack"], $i23A3["import_ack"], $mkAck($syn4, $pd23A, 3, $ish23A, $t0), $mkAck($syn5, $pd23A, 3, $ish23A, $t0)];
  [, $sc23A1] = $post("$u1/sync.php?lock_commit", json_encode(["action" => "sign_commit", "anchor_id" => $aid, "proposal" => $prop23A, "imported_state_hash" => $ish23A, "import_acks" => $acks23A]));
  [, $sc23A2] = $post("$u2/sync.php?lock_commit", json_encode(["action" => "sign_commit", "anchor_id" => $aid, "proposal" => $prop23A, "imported_state_hash" => $ish23A, "import_acks" => $acks23A]));
  $cert1A = ["anchor_id" => $aid, "genesis_manifest" => null, "proposal" => $prop23A, "imported_state_hash" => $ish23A, "import_acks" => $acks23A, "commit_sigs" => [$sc23A1["committee_signature"], $sc23A2["committee_signature"], $mkCommitSig($syn4, $pd23A, 3, $ish23A, $t0)]];
  $m3A = ["revision" => 3, "threshold" => 3, "servers" => [$s1, $s2, $s3, $s4, $s5], "successors" => [], "authority" => $m1["authority"], "migration_chain" => [$m2A["migration_chain"][0], $cert1A], "issued_at_ms" => $t0 * 1000, "retain_until_quarter" => $q];
  [$linCode, ] = $post("$u1/sync.php?lock_commit", json_encode(["action" => "finalize", "anchor_id" => $aid, "new_manifest" => $m3A]));

  // Test Case 2: finalize at rev 3 === exRev(3) where latest cert[1] matches cert1A but prefix cert[0] is cert0_B MUST return 409!
  $m3SameTailFork = ["revision" => 3, "threshold" => 3, "servers" => [$s1, $s2, $s3, $s4, $s5], "successors" => [], "authority" => $m1["authority"], "migration_chain" => [$m2B["migration_chain"][0], $cert1A], "issued_at_ms" => $t0 * 1000, "retain_until_quarter" => $q];
  [$finEqTailForkCode, ] = $post("$u1/sync.php?lock_commit", json_encode(["action" => "finalize", "anchor_id" => $aid, "new_manifest" => $m3SameTailFork]));

  // Test Case 3: lock_import at rev 3 -> to_rev 4 with conflicting cert[0] MUST return 409
  $pd34BI = $propDig($prop34BImp);
  [$impForkCode, ] = $post("$u1/sync.php?lock_import", json_encode(["anchor_id" => $aid, "active_manifest" => $m3BAlt, "proposal" => $prop34BImp, "snapshots" => [$mkSnap($syn4, 3, $pd34BI, $t0), $mkSnap($syn5, 3, $pd34BI, $t0)], "quorum_certificates" => []]));

  // Test Case 4: finalize at rev 4 > exRev(3) with conflicting cert[0] MUST return 409
  [$finHigherForkCode, ] = $post("$u1/sync.php?lock_commit", json_encode(["action" => "finalize", "anchor_id" => $aid, "new_manifest" => $m4BAlt]));

  echo json_encode([
    "imp_fork" => $impForkCode,
    "fin_higher_fork" => $finHigherForkCode,
    "lin_ok" => $linCode,
    "fin_eq_tail_fork" => $finEqTailForkCode,
  ]);
' "$B11_1_URL" "$B11_1_SK" "$B11_1_PK" "$B11_1_LP" "$B11_2_URL" "$B11_2_PK" "$B11_2_LP" "$B11_3_URL" "$B11_3_PK" "$B11_3_LP" "$QTR")"

assert_contains "$B12_OUT" '"imp_fork":409' "SYNC-S07-10: lock_import rejects forked migration_chain prefix (409)"
assert_contains "$B12_OUT" '"fin_higher_fork":409' "SYNC-S07-10: finalize rev > exRev rejects forked migration_chain prefix (409)"
assert_contains "$B12_OUT" '"lin_ok":200' "SYNC-S07-10: valid linear continuation m2A -> m3A succeeds (200)"
assert_contains "$B12_OUT" '"fin_eq_tail_fork":409' "SYNC-S07-10: finalize rev === exRev rejects forked prefix cert[0] even with matching latest cert[1] (409)"

echo ""
echo "=== Test 13: SYNC-S07-11 IPv4-mapped IPv6 & IPv6 /64 rate-limit normalization ==="
B13_OUT="$(php -r '
  require $argv[1];
  $base = $argv[2];
  $syncSec = static function (): void {
    $f = microtime(true) - floor(microtime(true));
    if ($f > 0.6) usleep((int)((1.02 - $f) * 1000000));
  };
  $mkPaths = static function (string $sub) use ($base): array {
    $d = "$base/$sub";
    $p = lock_paths($d);
    @mkdir($p["meta"], 0755, true);
    return $p;
  };

  // (a) IPv6 /64 prefix grouping: 60 calls across ::1..::3c exhausts 2001:db8:abcd:0001::/64; ::ffff::99 is blocked, distinct /64 is allowed
  $syncSec();
  $pA = $mkPaths("rl_a");
  for ($i = 1; $i <= 60; $i++) {
    $_SERVER["REMOTE_ADDR"] = sprintf("2001:db8:abcd:0001::%x", $i);
    if (!lock_ip_ratelimit_allow($pA, false)) throw new RuntimeException("unexpected throttle at $i");
  }
  $_SERVER["REMOTE_ADDR"] = "2001:db8:abcd:0001:ffff::99";
  $same64Allow = lock_ip_ratelimit_allow($pA, false);
  $_SERVER["REMOTE_ADDR"] = "2001:db8:abcd:0002::1";
  $other64Allow = lock_ip_ratelimit_allow($pA, false);

  // (b) IPv4-mapped IPv6 normalization: ::ffff:198.51.100.7 shares bucket with 198.51.100.7 (and uppercase ::FFFF:C633:6407 if inet_pton supports it)
  $syncSec();
  $pB = $mkPaths("rl_b");
  for ($i = 1; $i <= 60; $i++) {
    $_SERVER["REMOTE_ADDR"] = ($i % 2 === 0) ? "::ffff:198.51.100.7" : "::FFFF:c633:6407";
    if (!lock_ip_ratelimit_allow($pB, false)) throw new RuntimeException("unexpected mapped throttle at $i");
  }
  $_SERVER["REMOTE_ADDR"] = "198.51.100.7";
  $mappedV4Allow = lock_ip_ratelimit_allow($pB, false);

  // (c) ::1 loopback isolation from ::2
  $syncSec();
  $pC = $mkPaths("rl_c");
  for ($i = 1; $i <= 60; $i++) {
    $_SERVER["REMOTE_ADDR"] = "::1";
    if (!lock_ip_ratelimit_allow($pC, false)) throw new RuntimeException("unexpected ::1 throttle at $i");
  }
  $_SERVER["REMOTE_ADDR"] = "0:0:0:0:0:0:0:1";
  $loopAliasAllow = lock_ip_ratelimit_allow($pC, false);
  $_SERVER["REMOTE_ADDR"] = "::2";
  $nonLoopAllow = lock_ip_ratelimit_allow($pC, false);

  echo json_encode([
    "same64_allow" => $same64Allow,
    "other64_allow" => $other64Allow,
    "mapped_v4_allow" => $mappedV4Allow,
    "loop_alias_allow" => $loopAliasAllow,
    "non_loop_allow" => $nonLoopAllow,
  ]);
' "${ROOT_DIR}/php/lock_handler.php" "$TMP_DIR")"

assert_contains "$B13_OUT" '"same64_allow":false' "SYNC-S07-11: IPv6 addresses in same /64 share lock rate-limit bucket"
assert_contains "$B13_OUT" '"other64_allow":true' "SYNC-S07-11: IPv6 address in distinct /64 stays unthrottled"
assert_contains "$B13_OUT" '"mapped_v4_allow":false' "SYNC-S07-11: ::ffff:a.b.c.d shares lock rate-limit bucket with IPv4"
assert_contains "$B13_OUT" '"loop_alias_allow":false' "SYNC-S07-11: canonicalized ::1 shares bucket with 0:0:0:0:0:0:0:1"
assert_contains "$B13_OUT" '"non_loop_allow":true' "SYNC-S07-11: ::1 loopback stays isolated from ::2"

echo ""
echo "All PHP lock concurrency, rollback, quota & GC tests passed! (${PASS} assertions)"
