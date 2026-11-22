#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE=""
SYNC_URL=""
ADMIN_SK=""
MEMBER_SK=""
NFS_DIR=""
CONCURRENCY=12
SAMPLES=25
OUT_FILE=""
SERVER_BIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)
      MODE="remote"
      SYNC_URL="${2:-}"
      shift 2
      ;;
    --admin-sk)
      ADMIN_SK="${2:-}"
      shift 2
      ;;
    --member-sk)
      MEMBER_SK="${2:-}"
      shift 2
      ;;
    --local-php)
      MODE="local-php"
      shift
      ;;
    --local-rust)
      MODE="local-rust"
      shift
      ;;
    --nfs-dir)
      NFS_DIR="${2:-}"
      shift 2
      ;;
    --concurrency)
      CONCURRENCY="${2:-12}"
      shift 2
      ;;
    --samples)
      SAMPLES="${2:-25}"
      shift 2
      ;;
    --out)
      OUT_FILE="${2:-}"
      shift 2
      ;;
    --bin)
      SERVER_BIN="${2:-}"
      shift 2
      ;;
    -h|--help)
      cat <<'USAGE'
Usage:
  measure_hoster.sh --url https://hoster.example/sync.php --admin-sk <64-hex> [--member-sk <64-hex>] [--concurrency 12] [--samples 25] [--out report.md]
  measure_hoster.sh --local-php [--nfs-dir /path/on/nfs] [--concurrency 12] [--samples 25] [--out report.md]
  measure_hoster.sh --local-rust [--concurrency 12] [--samples 25] [--out report.md]
USAGE
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$MODE" ]]; then
  echo "Error: Specify --url <...>, --local-php, or --local-rust." >&2
  exit 1
fi
if [[ "$MODE" == "remote" && ( -z "$SYNC_URL" || ( -z "$ADMIN_SK" && -z "$MEMBER_SK" ) ) ]]; then
  echo "Error: --url mode requires --admin-sk (or --member-sk)." >&2
  exit 1
fi
if [[ "$SAMPLES" -lt 3 ]]; then SAMPLES=3; fi
if [[ "$CONCURRENCY" -lt 2 ]]; then CONCURRENCY=2; fi

if [[ -z "$SERVER_BIN" ]]; then
  SERVER_BIN="${ROOT_DIR}/rust/target/debug/humoco-sync-server"
  if [[ ! -x "$SERVER_BIN" ]]; then
    echo "Building local vector/crypto helper (humoco-sync-server)..." >&2
    cargo build --offline --manifest-path "${ROOT_DIR}/rust/Cargo.toml" >&2
  fi
fi

TMP_ROOT=""
if [[ -n "$NFS_DIR" ]]; then
  mkdir -p "$NFS_DIR"
  TMP_ROOT="$(mktemp -d "${NFS_DIR%/}/humoco-bench.XXXXXX")"
else
  TMP_ROOT="$(mktemp -d)"
fi
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "$TMP_ROOT" && -d "$TMP_ROOT" ]]; then
    rm -rf "$TMP_ROOT"
  fi
}
trap cleanup EXIT

pick_free_port() {
  for p in $(seq 19200 19299); do
    if ! (echo >/dev/tcp/127.0.0.1/"$p") 2>/dev/null; then
      echo "$p"
      return 0
    fi
  done
  echo "Could not find free port" >&2
  exit 1
}

rand_nonce() {
  od -tx1 -An -N16 /dev/urandom | tr -d ' \n'
}

json_str() {
  printf '%s' "$1" | tr -d '\n' | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"
}

json_num() {
  printf '%s' "$1" | tr -d '\n' | sed -n "s/.*\"$2\":\([0-9][0-9]*\).*/\1/p"
}

json_bool() {
  printf '%s' "$1" | tr -d '\n' | sed -n "s/.*\"$2\":\(true\|false\).*/\1/p"
}

compute_stats_ms() {
  local file="$1"
  LC_ALL=C sort -n "$file" | awk '
    { a[++n] = $1 * 1000.0 }
    END {
      if (n == 0) { printf "0.0\t0.0\t0.0\t0.0"; exit }
      idx50 = int((n - 1) * 0.50) + 1
      idx95 = int((n - 1) * 0.95) + 1
      idx99 = int((n - 1) * 0.99) + 1
      printf "%.1f\t%.1f\t%.1f\t%.1f", a[1], a[idx50], a[idx95], a[idx99]
    }
  '
}

if [[ "$MODE" == "local-php" ]]; then
  if ! command -v php >/dev/null 2>&1; then
    echo "Error: 'php' (>= 8.1 + ext-sodium) is not installed." >&2
    exit 1
  fi
  PORT="$(pick_free_port)"
  read -r ADMIN_SK ADMIN_PK <<< "$("$SERVER_BIN" sign-test keygen)"
  DOCROOT="$TMP_ROOT/php_docroot"
  mkdir -p "$DOCROOT"
  cp "${ROOT_DIR}/php/sync.php" "${ROOT_DIR}/php/lock_handler.php" "${ROOT_DIR}/php/lock_rotation.php" "${ROOT_DIR}/php/index.html" "${ROOT_DIR}/php/robots.txt" "$DOCROOT/"
  cat > "$DOCROOT/config.php" <<EOF
<?php
return [
    'admin_pubkey' => '${ADMIN_PK}',
    'data_dir' => 'humoco_sync_data',
    'max_members' => 300,
    'max_total_storage_mb' => 64,
    'disable_rate_limit' => true,
    'channels' => ['card' => ['max_bytes' => 524288, 'ttl_days' => 30]],
    'lock' => [
        'enabled' => true,
        'max_retention_quarter' => 8159,
        'max_inodes' => 50000,
        'pow_base_bits' => 8,
        'allow_pow_tickets' => false,
        'ticket_pow_bits' => 16,
    ],
];
EOF
  PHP_CLI_SERVER_WORKERS="$CONCURRENCY" php -S "127.0.0.1:${PORT}" -t "$DOCROOT" "$DOCROOT/sync.php" > "$TMP_ROOT/server.log" 2>&1 &
  SERVER_PID=$!
  SYNC_URL="http://127.0.0.1:${PORT}/sync.php"
elif [[ "$MODE" == "local-rust" ]]; then
  PORT="$(pick_free_port)"
  read -r ADMIN_SK ADMIN_PK <<< "$("$SERVER_BIN" sign-test keygen)"
  cat > "$TMP_ROOT/config.toml" <<EOF
[server]
bind = "127.0.0.1:${PORT}"
public_base_url = "http://127.0.0.1:${PORT}"
data_dir = "humoco_sync_data"
db_path = "${TMP_ROOT}/rust-bench.redb"
admin_pubkey = "${ADMIN_PK}"
trusted_proxy_hops = 0
[security]
ip_requests_per_minute = 100000
pubkey_requests_per_minute = 100000
[lock]
enabled = true
EOF
  "$SERVER_BIN" serve --config "$TMP_ROOT/config.toml" > "$TMP_ROOT/server.log" 2>&1 &
  SERVER_PID=$!
  SYNC_URL="http://127.0.0.1:${PORT}/sync.php"
fi

if [[ "$MODE" != "remote" ]]; then
  READY=false
  for _ in $(seq 1 40); do
    if curl -sf "${SYNC_URL}?info" >/dev/null 2>&1; then
      READY=true
      break
    fi
    sleep 0.1
  done
  [[ "$READY" == "true" ]] || { cat "$TMP_ROOT/server.log" >&2 || true; echo "Local server failed to start" >&2; exit 1; }
fi

CALLER_SK="${MEMBER_SK:-$ADMIN_SK}"
CALLER_PK="$("$SERVER_BIN" sign-test pubkey --sk "$CALLER_SK")"
ADMIN_PK=""
if [[ -n "$ADMIN_SK" ]]; then
  ADMIN_PK="$("$SERVER_BIN" sign-test pubkey --sk "$ADMIN_SK")"
fi

RUN_TAG="bench-$(date +%s)-$(od -tx1 -An -N4 /dev/urandom | tr -d ' \n')"

echo "=== Measuring HuMoCo Lock Server: ${SYNC_URL} ==="
COLD_LINE="$(curl -s -o "$TMP_ROOT/info.json" -w '%{http_code}\t%{time_total}' "${SYNC_URL}?info")"
COLD_CODE="${COLD_LINE%%$'\t'*}"
COLD_MS="$(awk -v t="${COLD_LINE#*$'\t'}" 'BEGIN { printf "%.1f", t * 1000.0 }')"
[[ "$COLD_CODE" == "200" ]] || { echo "GET ?info failed with HTTP $COLD_CODE" >&2; exit 1; }

INFO_JSON="$(cat "$TMP_ROOT/info.json")"
READ_URL="$(json_str "$INFO_JSON" "read_url")"
POW_BITS="$(json_num "$INFO_JSON" "pow_base_bits")"; POW_BITS="${POW_BITS:-8}"
MAX_INODES="$(json_num "$INFO_JSON" "max_inodes")"; MAX_INODES="${MAX_INODES:-0}"
USED_INODES_BEFORE="$(json_num "$INFO_JSON" "used_inodes")"; USED_INODES_BEFORE="${USED_INODES_BEFORE:-0}"
DROP_PUB="$(json_str "$INFO_JSON" "drop_pub")"

SELFTEST_JSON="$(curl -sf "${SYNC_URL}?lock_selftest")"
RUNTIME="$(json_str "$SELFTEST_JSON" "runtime")"; RUNTIME="${RUNTIME:-unknown}"
PHP_VER="$(json_str "$SELFTEST_JSON" "php_version")"; PHP_VER="${PHP_VER:-n/a}"
LOCK_PUB="$(json_str "$SELFTEST_JSON" "lock_pub")"
ALL_PASSED="$(json_bool "$SELFTEST_JSON" "all_passed")"
CHECK_LINK="$(json_str "$SELFTEST_JSON" "atomic_link_eexist")"
CHECK_FSYNC="$(json_str "$SELFTEST_JSON" "fsync")"
CHECK_ABORT="$(json_str "$SELFTEST_JSON" "ignore_user_abort")"
CHECK_FCGI="$(json_str "$SELFTEST_JSON" "fastcgi_finish_request")"
FREE_INODES="$(json_num "$SELFTEST_JSON" "free_inodes")"; FREE_INODES="${FREE_INODES:-0}"

[[ ${#LOCK_PUB} -eq 64 ]] || { echo "Missing lock_pub in ?lock_selftest: $SELFTEST_JSON" >&2; exit 1; }
[[ -n "$ADMIN_PK" ]] || ADMIN_PK="$DROP_PUB"

KEY_LEAK_CODE="$(curl -s -o /dev/null -w '%{http_code}' "${READ_URL%/}/.lock_key.php")"
KEY_LEAK_SAFE="FAIL (${KEY_LEAK_CODE})"
if [[ "$KEY_LEAK_CODE" == "403" || "$KEY_LEAK_CODE" == "404" ]]; then
  KEY_LEAK_SAFE="PASS (${KEY_LEAK_CODE})"
fi

# Check custom X-Drop-* headers via HEAD (WAF check 1)
HEAD_CODE="$(curl -s -o /dev/null -w '%{http_code}' -I -H "X-Drop-Pubkey: ${CALLER_PK}" -H "X-Channel: card" "$SYNC_URL")"

# Check PUT ?lock_delegate if admin_sk given
DELEGATE_RESULT="skipped"
if [[ -n "$ADMIN_SK" ]]; then
  issued="$(date +%s)"
  del_read_url="${READ_URL:-${SYNC_URL%/*}/data}"
  "$SERVER_BIN" sign-test sign-lock-delegate --sk "$ADMIN_SK" --lock-pub "$LOCK_PUB" --write-url "$SYNC_URL" --read-url "$del_read_url" --issued "$issued" > "$TMP_ROOT/del.json"
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$SERVER_BIN" sign-test sign-admin --sk "$ADMIN_SK" --action PUT_LOCK_DELEGATE --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/del.json")"
  DEL_CODE="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $ADMIN_PK" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$TMP_ROOT/del.json" "${SYNC_URL}?lock_delegate")"
  if [[ "$DEL_CODE" == "200" ]]; then DELEGATE_RESULT="PASS (200)"; else DELEGATE_RESULT="FAIL (${DEL_CODE})"; fi
fi

# Warm probe latencies
: > "$TMP_ROOT/lat_probe.txt"
PROBE_PASS=0
for i in $(seq 1 "$SAMPLES"); do
  pn="$(rand_nonce)$(rand_nonce)"
  line="$(curl -s -o "$TMP_ROOT/probe_resp.json" -w '%{http_code}\t%{time_total}' -X POST -H 'Content-Type: application/json' -d "{\"probe\":true,\"client_nonce\":\"${pn}\"}" "${SYNC_URL}?lock")"
  code="${line%%$'\t'*}"; tm="${line#*$'\t'}"
  if [[ "$code" == "200" ]] && [[ "$(cat "$TMP_ROOT/probe_resp.json")" == *'"probe_ok":true'* ]]; then
    PROBE_PASS=$((PROBE_PASS + 1))
    echo "$tm" >> "$TMP_ROOT/lat_probe.txt"
  fi
done
PROBE_STATS="$(compute_stats_ms "$TMP_ROOT/lat_probe.txt")"

# Issue GenesisTicket for latency anchor
QTR=8125
ANCHOR_LAT="$("$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --anchor-tag "${RUN_TAG}-lat" --pow-bits "$POW_BITS" --variant anchor_id)"
printf '{"anchor_id":"%s","retain_until_quarter":%s,"pow_timestamp":null,"pow_nonce":null}' "$ANCHOR_LAT" "$QTR" > "$TMP_ROOT/lat_treq.json"
ts="$(date +%s)"; nonce="$(rand_nonce)"
sig="$("$SERVER_BIN" sign-test sign-member --sk "$CALLER_SK" --method POST --channel lock_ticket --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/lat_treq.json")"
TICKET_CODE="$(curl -s -o "$TMP_ROOT/lat_tresp.json" -w '%{http_code}' -X POST -H "X-Drop-Pubkey: $CALLER_PK" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/lat_treq.json" "${SYNC_URL}?lock_ticket")"
[[ "$TICKET_CODE" == "200" ]] || { echo "POST ?lock_ticket failed with HTTP $TICKET_CODE: $(cat "$TMP_ROOT/lat_tresp.json")" >&2; exit 1; }

# Pre-generate all seq payloads & retry payloads before timing
mkdir -p "$TMP_ROOT/seq_reqs"
for i in $(seq 0 "$((SAMPLES - 1))"); do
  "$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --ticket-json "$TMP_ROOT/lat_tresp.json" --anchor-tag "${RUN_TAG}-lat" --pow-bits "$POW_BITS" --variant "seq:${i}" > "$TMP_ROOT/seq_reqs/${i}.json"
done

# Measure FirstWrite POST ?lock latency
: > "$TMP_ROOT/lat_write.txt"
WRITE_OK=0
for i in $(seq 0 "$((SAMPLES - 1))"); do
  line="$(curl -s -o "$TMP_ROOT/w_resp.json" -w '%{http_code}\t%{time_total}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/seq_reqs/${i}.json" "${SYNC_URL}?lock")"
  code="${line%%$'\t'*}"; tm="${line#*$'\t'}"
  if [[ "$code" == "200" ]] && [[ "$(cat "$TMP_ROOT/w_resp.json")" == *'"status":"ok"'* ]]; then
    WRITE_OK=$((WRITE_OK + 1))
    echo "$tm" >> "$TMP_ROOT/lat_write.txt"
  fi
done
WRITE_STATS="$(compute_stats_ms "$TMP_ROOT/lat_write.txt")"

# Measure Idempotent Retry POST ?lock latency
: > "$TMP_ROOT/lat_retry.txt"
RETRY_OK=0
for i in $(seq 0 "$((SAMPLES - 1))"); do
  line="$(curl -s -o "$TMP_ROOT/r_resp.json" -w '%{http_code}\t%{time_total}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/seq_reqs/${i}.json" "${SYNC_URL}?lock")"
  code="${line%%$'\t'*}"; tm="${line#*$'\t'}"
  if [[ "$code" == "200" ]] && [[ "$(cat "$TMP_ROOT/r_resp.json")" == *'"status":"ok"'* ]]; then
    RETRY_OK=$((RETRY_OK + 1))
    echo "$tm" >> "$TMP_ROOT/lat_retry.txt"
  fi
done
RETRY_STATS="$(compute_stats_ms "$TMP_ROOT/lat_retry.txt")"

# Measure static .lock GET latency
: > "$TMP_ROOT/lat_get.txt"
GET_OK=0
for i in $(seq 0 "$((SAMPLES - 1))"); do
  rel="$("$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --anchor-tag "${RUN_TAG}-lat" --pow-bits "$POW_BITS" --variant "read_path_seq:${i}")"
  line="$(curl -s -o "$TMP_ROOT/get_slot.bin" -w '%{http_code}\t%{time_total}' "${READ_URL%/}/${rel}")"
  code="${line%%$'\t'*}"; tm="${line#*$'\t'}"
  sz="$(wc -c < "$TMP_ROOT/get_slot.bin" | tr -d ' ')"
  if [[ "$code" == "200" && "$sz" == "605" ]]; then
    GET_OK=$((GET_OK + 1))
    echo "$tm" >> "$TMP_ROOT/lat_get.txt"
  fi
done
GET_STATS="$(compute_stats_ms "$TMP_ROOT/lat_get.txt")"

# Measure P-way parallel contention atomicity on fresh race anchor
ANCHOR_RACE="$("$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --anchor-tag "${RUN_TAG}-race" --pow-bits "$POW_BITS" --variant anchor_id)"
printf '{"anchor_id":"%s","retain_until_quarter":%s,"pow_timestamp":null,"pow_nonce":null}' "$ANCHOR_RACE" "$QTR" > "$TMP_ROOT/race_treq.json"
ts="$(date +%s)"; nonce="$(rand_nonce)"
sig="$("$SERVER_BIN" sign-test sign-member --sk "$CALLER_SK" --method POST --channel lock_ticket --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/race_treq.json")"
RACE_TCODE="$(curl -s -o "$TMP_ROOT/race_tresp.json" -w '%{http_code}' -X POST -H "X-Drop-Pubkey: $CALLER_PK" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/race_treq.json" "${SYNC_URL}?lock_ticket")"
[[ "$RACE_TCODE" == "200" ]] || { echo "Race POST ?lock_ticket failed with HTTP $RACE_TCODE" >&2; exit 1; }

mkdir -p "$TMP_ROOT/race_reqs"
for i in $(seq 0 "$((CONCURRENCY - 1))"); do
  "$SERVER_BIN" sign-test make-lock-sample --lock-pub "$LOCK_PUB" --admin-pub "$ADMIN_PK" --quarter "$QTR" --ticket-json "$TMP_ROOT/race_tresp.json" --anchor-tag "${RUN_TAG}-race" --pow-bits "$POW_BITS" --variant "race:${i}" > "$TMP_ROOT/race_reqs/${i}.json"
done

pids=()
for i in $(seq 0 "$((CONCURRENCY - 1))"); do
  (
    curl -s -o "$TMP_ROOT/race_reqs/resp_${i}.json" -w '%{http_code}\t%{time_total}\n' -X POST \
      -H 'Content-Type: application/json' \
      --data-binary "@$TMP_ROOT/race_reqs/${i}.json" \
      "${SYNC_URL}?lock" > "$TMP_ROOT/race_reqs/meta_${i}.txt"
  ) &
  pids+=("$!")
done
for pid in "${pids[@]}"; do wait "$pid"; done

RACE_OK=0; RACE_CONF=0; RACE_ERR=0
: > "$TMP_ROOT/lat_race.txt"
for i in $(seq 0 "$((CONCURRENCY - 1))"); do
  line="$(cat "$TMP_ROOT/race_reqs/meta_${i}.txt")"
  code="${line%%$'\t'*}"; tm="${line#*$'\t'}"
  body="$(cat "$TMP_ROOT/race_reqs/resp_${i}.json")"
  if [[ "$code" == "200" ]] && [[ "$body" == *'"status":"ok"'* ]]; then
    RACE_OK=$((RACE_OK + 1)); echo "$tm" >> "$TMP_ROOT/lat_race.txt"
  elif [[ "$code" == "200" ]] && [[ "$body" == *'"status":"conflict"'* ]]; then
    RACE_CONF=$((RACE_CONF + 1)); echo "$tm" >> "$TMP_ROOT/lat_race.txt"
  else
    RACE_ERR=$((RACE_ERR + 1))
  fi
done
RACE_STATS="$(compute_stats_ms "$TMP_ROOT/lat_race.txt")"
INFO_AFTER="$(curl -sf "${SYNC_URL}?info")"
USED_INODES_AFTER="$(json_num "$INFO_AFTER" "used_inodes")"; USED_INODES_AFTER="${USED_INODES_AFTER:-0}"
INODE_DELTA=$((USED_INODES_AFTER - USED_INODES_BEFORE))

fmt_row() {
  local stats="$1"
  IFS=$'\t' read -r vmin vp50 vp95 vp99 <<< "$stats"
  echo "| ${vmin} ms | ${vp50} ms | ${vp95} ms | ${vp99} ms |"
}

IFS=$'\t' read -r _ W_P50 _ W_P99 <<< "$WRITE_STATS"
IFS=$'\t' read -r _ G_P50 _ G_P99 <<< "$GET_STATS"
IFS=$'\t' read -r _ C_P50 _ C_P99 <<< "$RACE_STATS"

OVERALL="PASS"
if [[ "$ALL_PASSED" != "true" || "$KEY_LEAK_SAFE" != PASS* || "$HEAD_CODE" != "200" || "$DELEGATE_RESULT" == FAIL* || "$PROBE_PASS" -ne "$SAMPLES" || "$RACE_OK" -ne 1 || "$RACE_ERR" -ne 0 || "$WRITE_OK" -ne "$SAMPLES" || "$RETRY_OK" -ne "$SAMPLES" || "$GET_OK" -ne "$SAMPLES" ]]; then
  OVERALL="FAIL"
fi

REPORT=$(cat <<EOF
# HuMoCo Lock Server Measurement Report

- **Target:** \`${SYNC_URL}\` (Mode: \`${MODE}\`, Runtime: \`${RUNTIME}\`, PHP: \`${PHP_VER}\`${NFS_DIR:+, NFS: \`$NFS_DIR\`})
- **Date (UTC):** $(date -u +%Y-%m-%dT%H:%M:%SZ)
- **Overall Verdict:** **${OVERALL}**
- **Lock Pubkey:** \`${LOCK_PUB}\`

## 1. Selftest & Security Checks

| Check | Result |
|---|---|
| \`GET ?lock_selftest\` \`all_passed\` | \`${ALL_PASSED}\` |
| \`atomic_link_eexist\` / \`fsync\` / \`ignore_user_abort\` / \`fastcgi_finish_request\` | \`${CHECK_LINK}\` / \`${CHECK_FSYNC}\` / \`${CHECK_ABORT}\` / \`${CHECK_FCGI}\` |
| Static \`.lock_key.php\` leak guard | **${KEY_LEAK_SAFE}** |
| Custom headers \`HEAD\` (\`X-Drop-Pubkey\`, \`X-Channel\`) | HTTP \`${HEAD_CODE}\` |
| \`PUT ?lock_delegate\` | \`${DELEGATE_RESULT}\` |
| \`POST ?lock_ticket\` | HTTP \`${TICKET_CODE}\` |
| WAF zero-write \`POST ?lock\` probe (${PROBE_PASS}/${SAMPLES}) | $([ "$PROBE_PASS" -eq "$SAMPLES" ] && echo "PASS" || echo "FAIL") |
| Inode usage delta (expected $((SAMPLES + 1))) | \`${USED_INODES_BEFORE} -> ${USED_INODES_AFTER}\` (\`+${INODE_DELTA}\`, free: \`${FREE_INODES}/${MAX_INODES}\`) |

## 2. Latency Distribution (Cold = ${COLD_MS} ms, N = ${SAMPLES}, Concurrency P = ${CONCURRENCY})

| Operation | Success | min | p50 | p95 | p99 |
|---|---|---|---|---|---|
| \`POST ?lock\` WAF Probe | ${PROBE_PASS}/${SAMPLES} | $(fmt_row "$PROBE_STATS" | sed 's/^| //;s/ |$//') |
| \`POST ?lock\` FirstWrite (605B) | ${WRITE_OK}/${SAMPLES} | $(fmt_row "$WRITE_STATS" | sed 's/^| //;s/ |$//') |
| \`POST ?lock\` Idempotent Retry | ${RETRY_OK}/${SAMPLES} | $(fmt_row "$RETRY_STATS" | sed 's/^| //;s/ |$//') |
| Static \`GET *.lock\` (605B) | ${GET_OK}/${SAMPLES} | $(fmt_row "$GET_STATS" | sed 's/^| //;s/ |$//') |
| Parallel Race (${CONCURRENCY}x on 1 slot) | ${RACE_OK} ok / ${RACE_CONF} conflict / ${RACE_ERR} err | $(fmt_row "$RACE_STATS" | sed 's/^| //;s/ |$//') |

## 3. Ready-to-Paste Row for \`docs/concepts/sync_double_spend_schutz_plan.md\` §6.8

\`| <Hoster / Tarif> | PHP ${PHP_VER} (${RUNTIME}) | ${W_P50} ms | ${W_P99} ms | ${G_P50} ms (${G_P99} ms) | ${RACE_OK} FirstWrite / ${RACE_CONF} Conflict / ${RACE_ERR} Err (${C_P99} ms p99) | link=${CHECK_LINK}, fsync=${CHECK_FSYNC}, abort=${CHECK_ABORT}, fcgi=${CHECK_FCGI} | free=${FREE_INODES}/${MAX_INODES} | WAF=$([ "$PROBE_PASS" -eq "$SAMPLES" ] && echo ok || echo fail), KeyGuard=${KEY_LEAK_CODE} |\`
EOF
)

printf '%s\n' "$REPORT"
if [[ -n "$OUT_FILE" ]]; then
  printf '%s\n' "$REPORT" > "$OUT_FILE"
  echo ""
  echo "Saved measurement report to ${OUT_FILE}"
fi

if [[ "$OVERALL" != "PASS" ]]; then
  exit 1
fi
