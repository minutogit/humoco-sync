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

echo ""
echo "All PHP lock concurrency, rollback, quota & GC tests passed! (${PASS} assertions)"
