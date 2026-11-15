#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="both"
ALLOW_MISSING_PHP=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="${2:-}"
      shift 2
      ;;
    --allow-missing-php)
      ALLOW_MISSING_PHP=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--target rust|php|both] [--allow-missing-php]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

case "$TARGET" in
  rust|php|both) ;;
  *)
    echo "Invalid --target '$TARGET' (expected rust, php, or both)" >&2
    exit 1
    ;;
esac

PASS_COUNT=0
FAIL_COUNT=0
SERVER_PID=""
TMP_ROOT=""

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

ok() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "  [PASS] $1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "  [FAIL] $1" >&2
  exit 1
}

assert_eq() {
  local actual="$1"
  local expected="$2"
  local msg="$3"
  if [[ "$actual" == "$expected" ]]; then
    ok "$msg ($actual)"
  else
    fail "$msg: expected '$expected', got '$actual'"
  fi
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    ok "$msg"
  else
    fail "$msg: missing '$needle' in output: $haystack"
  fi
}

pick_free_port() {
  for p in $(seq 18910 18999); do
    if ! (echo >/dev/tcp/127.0.0.1/"$p") 2>/dev/null; then
      echo "$p"
      return 0
    fi
  done
  echo "Could not find free loopback port" >&2
  exit 1
}

rand_nonce() {
  od -tx1 -An -N16 /dev/urandom | tr -d ' \n'
}

sha256_file_hex() {
  sha256sum "$1" | awk '{print $1}'
}

run_blackbox_protocol_suite() {
  local label="$1"
  local base_url="$2"
  local sync_path="$3"
  local helper_bin="$4"
  local admin_sk="$5"
  local admin_pk="$6"
  local friend_sk="$7"
  local friend_pk="$8"
  local intruder_sk="$9"
  local intruder_pk="${10}"
  local test_hybrid="${11}"

  local endpoint="${base_url}${sync_path}"
  local data_url="${base_url}/humoco_sync_data"

  echo "=== Group 1 ($label): Server Discovery (?info) & Landing ==="
  local info_json
  info_json="$(curl -sf "${endpoint}?info")"
  assert_contains "$info_json" "\"drop_pub\":\"$admin_pk\"" "?info returns admin drop_pub"
  assert_contains "$info_json" "\"read_url\":\"$data_url\"" "?info returns read_url"
  if [[ "$label" == "rust" ]]; then
    local info_clean
    info_clean="$(curl -sf "${base_url}/sync?info")"
    assert_eq "$info_clean" "$info_json" "/sync?info matches /sync.php?info byte-for-byte"
  fi

  local method_code
  method_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$endpoint")"
  assert_eq "$method_code" "405" "Unsupported POST returns 405 Method Not Allowed"

  echo "=== Group 2 ($label): PUT ?members & HEAD Capabilities ==="
  local ts nonce sig
  local unauth_headers
  unauth_headers="$(curl -sI -H "X-Drop-Pubkey: $friend_pk" -H "X-Channel: card" "$endpoint" | tr -d '\r')"
  assert_contains "$unauth_headers" "x-drop-authorized: false" "HEAD returns unauthorized before PUT ?members"

  printf '{"pubkeys":["%s"]}' "$friend_pk" > "$TMP_ROOT/members.json"
  ts="$(date +%s)"
  nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-admin --sk "$admin_sk" --action PUT_MEMBERS --channel card --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/members.json")"
  local pm_code
  pm_code="$(curl -s -o "$TMP_ROOT/pm_out.json" -w '%{http_code}' -X PUT \
    -H "X-Drop-Pubkey: $admin_pk" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    --data-binary "@$TMP_ROOT/members.json" \
    "${endpoint}?members&channel=card")"
  assert_eq "$pm_code" "200" "PUT ?members succeeds"

  local auth_headers
  auth_headers="$(curl -sI -H "X-Drop-Pubkey: $friend_pk" -H "X-Channel: card" "$endpoint" | tr -d '\r')"
  assert_contains "$auth_headers" "x-drop-authorized: true" "HEAD returns authorized=true after PUT ?members"

  echo "=== Group 3 ($label): Slot PUT, index.json, ETag, 304, 412 ==="
  printf 'ciphertext-v1' > "$TMP_ROOT/card1.bin"
  ts="$(date +%s)"
  nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$friend_sk" --method PUT --channel card --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/card1.bin")"
  local put1_code
  put1_code="$(curl -s -o "$TMP_ROOT/put1.json" -w '%{http_code}' -X PUT \
    -H "X-Drop-Pubkey: $friend_pk" \
    -H "X-Channel: card" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    -H "If-None-Match: *" \
    --data-binary "@$TMP_ROOT/card1.bin" \
    "$endpoint")"
  assert_eq "$put1_code" "200" "PUT slot with If-None-Match: * creates slot"
  local etag1
  etag1="$(sha256_file_hex "$TMP_ROOT/card1.bin")"

  # Duplicate If-None-Match: * must fail with 412
  ts="$(date +%s)"
  nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$friend_sk" --method PUT --channel card --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/card1.bin")"
  local inm_fail
  inm_fail="$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "X-Drop-Pubkey: $friend_pk" \
    -H "X-Channel: card" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    -H "If-None-Match: *" \
    --data-binary "@$TMP_ROOT/card1.bin" \
    "$endpoint")"
  assert_eq "$inm_fail" "412" "If-None-Match: * returns 412 when slot exists"

  # Conditional GET + If-None-Match -> 304
  local get_code
  get_code="$(curl -s -o "$TMP_ROOT/fetched_card.bin" -w '%{http_code}' "${data_url}/${friend_pk}.card.bin")"
  assert_eq "$get_code" "200" "Static GET returns encrypted slot"
  local get_304
  get_304="$(curl -s -o /dev/null -w '%{http_code}' -H "If-None-Match: \"${etag1}\"" "${data_url}/${friend_pk}.card.bin")"
  assert_eq "$get_304" "304" "Static GET with matching ETag returns 304"

  # index.json contains friend card
  local idx_json
  idx_json="$(curl -sf "${data_url}/index.json")"
  assert_contains "$idx_json" "\"id\":\"$friend_pk\"" "index.json lists authorized friend slot"

  echo "=== Group 4 ($label): Admin GET ?status ==="
  ts="$(date +%s)"
  nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-admin --sk "$admin_sk" --action STATUS --ts "$ts" --nonce "$nonce")"
  local st_json
  st_json="$(curl -sf \
    -H "X-Drop-Pubkey: $admin_pk" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    "${endpoint}?status")"
  assert_contains "$st_json" "\"admin_pubkey\":\"$admin_pk\"" "GET ?status returns server telemetry"

  echo "=== Group 5 ($label): Security (Replay 409, Timestamp Drift 401, Bad Sig 401) ==="
  local replay_code
  replay_code="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "X-Drop-Pubkey: $admin_pk" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    "${endpoint}?status")"
  assert_eq "$replay_code" "409" "Replayed nonce returns 409 Conflict"

  local bad_sig_code
  nonce="$(rand_nonce)"
  bad_sig_code="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "X-Drop-Pubkey: $admin_pk" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" \
    "${endpoint}?status")"
  assert_eq "$bad_sig_code" "401" "Invalid signature returns 401 Unauthorized"

  local old_ts=$((ts - 300))
  nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-admin --sk "$admin_sk" --action STATUS --ts "$old_ts" --nonce "$nonce")"
  local drift_code
  drift_code="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "X-Drop-Pubkey: $admin_pk" \
    -H "X-Drop-Timestamp: $old_ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    "${endpoint}?status")"
  assert_eq "$drift_code" "401" "Stale timestamp returns 401 Unauthorized"

  echo "=== Group 6 ($label): X-Drop-Prefix & Path Traversal ==="
  printf 'home-device-slot' > "$TMP_ROOT/home.bin"
  ts="$(date +%s)"
  nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$friend_sk" --method PUT --channel card --prefix home --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/home.bin")"
  local pfx_code
  pfx_code="$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "X-Drop-Pubkey: $friend_pk" \
    -H "X-Channel: card" \
    -H "X-Drop-Prefix: home" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    --data-binary "@$TMP_ROOT/home.bin" \
    "$endpoint")"
  assert_eq "$pfx_code" "200" "PUT with valid X-Drop-Prefix succeeds"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${data_url}/${friend_pk}_home.card.bin")" "200" "Prefixed slot readable"

  local bad_pfx_code
  bad_pfx_code="$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "X-Drop-Pubkey: $friend_pk" \
    -H "X-Channel: card" \
    -H "X-Drop-Prefix: bad--prefix" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $(rand_nonce)" \
    -H "X-Drop-Signature: $sig" \
    --data-binary "@$TMP_ROOT/home.bin" \
    "$endpoint")"
  assert_eq "$bad_pfx_code" "400" "Double-dash prefix rejected with 400"

  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "${data_url}/../config.toml")" "404" "Path traversal blocked (404)"

  echo "=== Group 7 ($label): Media Channel (X-Media-Id, Ownership, index.json Exclusion) ==="
  printf 'media-webp-blob' > "$TMP_ROOT/m1.bin"
  local media_id
  media_id="$(sha256_file_hex "$TMP_ROOT/m1.bin")"
  ts="$(date +%s)"
  nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$friend_sk" --method PUT --channel media --media-id "$media_id" --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/m1.bin")"
  local m_put
  m_put="$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "X-Drop-Pubkey: $friend_pk" \
    -H "X-Channel: media" \
    -H "X-Media-Id: $media_id" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    --data-binary "@$TMP_ROOT/m1.bin" \
    "$endpoint")"
  assert_eq "$m_put" "200" "PUT media blob succeeds"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${data_url}/${media_id}.media.bin")" "200" "Media blob readable statically"

  local idx_media
  idx_media="$(curl -sf "${data_url}/index.json")"
  if [[ "$idx_media" == *"$media_id"* ]]; then
    fail "index.json must NEVER include media blobs"
  else
    ok "Media blob excluded from index.json"
  fi

  # Single media delete
  ts="$(date +%s)"
  nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$friend_sk" --method DELETE --channel media --media-id "$media_id" --ts "$ts" --nonce "$nonce")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE \
    -H "X-Drop-Pubkey: $friend_pk" \
    -H "X-Channel: media" \
    -H "X-Media-Id: $media_id" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    "$endpoint")" "200" "DELETE single media blob succeeds"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${data_url}/${media_id}.media.bin")" "404" "Deleted media returns 404"

  echo "=== Group 8 ($label): Revocation (?revoke -> 410 Gone -> Clear) ==="
  ts="$(date +%s)"
  "$helper_bin" sign-test sign-revoke-notice --sk "$admin_sk" --issued "$ts" --effective "$((ts + 60))" --reason "Server moving" > "$TMP_ROOT/revoke.json"
  nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-admin --sk "$admin_sk" --action PUT_REVOKE --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/revoke.json")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "X-Drop-Pubkey: $admin_pk" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    --data-binary "@$TMP_ROOT/revoke.json" \
    "${endpoint}?revoke")" "200" "PUT ?revoke publishes revocation"

  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -I -H "X-Drop-Pubkey: $friend_pk" "$endpoint")" "410" "Revoked server returns 410 Gone on HEAD"
  assert_contains "$(curl -sf "${data_url}/revocation.json")" "Server moving" "revocation.json published"

  printf '{"issued_at":%s,"effective_at":null}' "$ts" > "$TMP_ROOT/clear_revoke.json"
  nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-admin --sk "$admin_sk" --action PUT_REVOKE --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/clear_revoke.json")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "X-Drop-Pubkey: $admin_pk" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    --data-binary "@$TMP_ROOT/clear_revoke.json" \
    "${endpoint}?revoke")" "200" "PUT ?revoke clear restores server"

  if [[ "$test_hybrid" == "true" ]]; then
    echo "=== Group 9 ($label): Hybrid Isolation & DELETE ?account ==="
    # Register intruder_pk via public /register/open gate
    assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST \
      -d "pubkey=${intruder_pk}" \
      "${base_url}/register/open")" "303" "Public registration /register/open activates user"

    # Registered user uploads slot
    printf 'public-registered-card' > "$TMP_ROOT/pub_card.bin"
    ts="$(date +%s)"
    nonce="$(rand_nonce)"
    sig="$("$helper_bin" sign-test sign-member --sk "$intruder_sk" --method PUT --channel card --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/pub_card.bin")"
    assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
      -H "X-Drop-Pubkey: $intruder_pk" \
      -H "X-Channel: card" \
      -H "X-Drop-Timestamp: $ts" \
      -H "X-Drop-Nonce: $nonce" \
      -H "X-Drop-Signature: $sig" \
      --data-binary "@$TMP_ROOT/pub_card.bin" \
      "${base_url}/sync")" "200" "Registered user uploads via /sync alias"

    local hybrid_idx
    hybrid_idx="$(curl -sf "${data_url}/index.json")"
    if [[ "$hybrid_idx" == *"$intruder_pk"* ]]; then
      fail "index.json leaked public registered user pubkey!"
    else
      ok "Public registered user omitted from index.json"
    fi

    # Admin empties friend list -> public registered user MUST survive!
    printf '{"pubkeys":[]}' > "$TMP_ROOT/empty_members.json"
    ts="$(date +%s)"
    nonce="$(rand_nonce)"
    sig="$("$helper_bin" sign-test sign-admin --sk "$admin_sk" --action PUT_MEMBERS --channel card --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/empty_members.json")"
    assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
      -H "X-Drop-Pubkey: $admin_pk" \
      -H "X-Drop-Timestamp: $ts" \
      -H "X-Drop-Nonce: $nonce" \
      -H "X-Drop-Signature: $sig" \
      --data-binary "@$TMP_ROOT/empty_members.json" \
      "${endpoint}?members&channel=card")" "200" "Admin clears admin_app friends list"

    assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${data_url}/${friend_pk}.card.bin")" "404" "Removed friend slot pruned"
    assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${data_url}/${intruder_pk}.card.bin")" "200" "Registered user slot survives admin member reset"

    # Registered user deletes own account via DELETE /sync.php?account
    ts="$(date +%s)"
    nonce="$(rand_nonce)"
    sig="$("$helper_bin" sign-test sign-member --sk "$intruder_sk" --method DELETE_ACCOUNT --ts "$ts" --nonce "$nonce")"
    assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE \
      -H "X-Drop-Pubkey: $intruder_pk" \
      -H "X-Drop-Timestamp: $ts" \
      -H "X-Drop-Nonce: $nonce" \
      -H "X-Drop-Signature: $sig" \
      "${endpoint}?account")" "200" "DELETE ?account wipes registered user and blobs"
    assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${data_url}/${intruder_pk}.card.bin")" "404" "Wiped registered user slot returns 404"
  fi
}

echo "Building humoco-sync-server binary (offline)..."
cargo build --offline --manifest-path "${ROOT_DIR}/rust/Cargo.toml"
SERVER_BIN="${ROOT_DIR}/rust/target/debug/humoco-sync-server"
if [[ ! -x "$SERVER_BIN" ]]; then
  echo "Missing built binary at $SERVER_BIN" >&2
  exit 1
fi

TMP_ROOT="$(mktemp -d)"

if [[ "$TARGET" == "rust" || "$TARGET" == "both" ]]; then
  echo ""
  echo ">>> Running Blackbox Test Suite against RUST daemon <<<"
  PORT="$(pick_free_port)"
  read -r ADMIN_SK ADMIN_PK <<< "$("$SERVER_BIN" sign-test keygen)"
  read -r FRIEND_SK FRIEND_PK <<< "$("$SERVER_BIN" sign-test keygen)"
  read -r INTRUDER_SK INTRUDER_PK <<< "$("$SERVER_BIN" sign-test keygen)"

  cat > "$TMP_ROOT/config.toml" <<EOF
[server]
bind = "127.0.0.1:${PORT}"
public_base_url = "http://127.0.0.1:${PORT}"
data_dir = "humoco_sync_data"
db_path = "${TMP_ROOT}/rust-test.redb"
admin_pubkey = "${ADMIN_PK}"
soft_warning_percent = 80
trusted_proxy_hops = 0

[mode]
enable_admin_app = true
admin_app_profile = "friends"
max_admin_members = 300
enable_public_registration = true
default_public_profile = "free"
registration_gates = ["open", "code"]
enable_builtin_ui = true
service_name = "HuMoCo Blackbox Test"

[storage]
max_total_storage_mb = 64
max_free_pool_mb = 32
downgrade_grace_days = 7

[security]
ip_requests_per_minute = 5000
pubkey_requests_per_minute = 5000
max_registrations_per_ipv4_24_per_day = 100
max_registrations_per_ipv6_48_per_day = 100
EOF

  "$SERVER_BIN" serve --config "$TMP_ROOT/config.toml" > "$TMP_ROOT/rust-server.log" 2>&1 &
  SERVER_PID=$!

  READY=false
  for _ in $(seq 1 40); do
    if curl -sf "http://127.0.0.1:${PORT}/sync.php?info" >/dev/null 2>&1; then
      READY=true
      break
    fi
    sleep 0.1
  done
  if [[ "$READY" != "true" ]]; then
    cat "$TMP_ROOT/rust-server.log" >&2 || true
    fail "Rust server failed to become ready"
  fi

  run_blackbox_protocol_suite \
    "rust" \
    "http://127.0.0.1:${PORT}" \
    "/sync.php" \
    "$SERVER_BIN" \
    "$ADMIN_SK" "$ADMIN_PK" \
    "$FRIEND_SK" "$FRIEND_PK" \
    "$INTRUDER_SK" "$INTRUDER_PK" \
    "true"

  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
fi

if [[ "$TARGET" == "php" || "$TARGET" == "both" ]]; then
  if ! command -v php >/dev/null 2>&1; then
    if [[ "$ALLOW_MISSING_PHP" == "true" ]]; then
      echo ""
      echo "[SKIP] PHP binary not installed (--allow-missing-php specified)."
    else
      echo "Error: 'php' binary not found. Pass --target rust or --allow-missing-php." >&2
      exit 1
    fi
  else
    echo ""
    echo ">>> Running Blackbox Test Suite against PHP built-in server <<<"
    PHP_PORT="$(pick_free_port)"
    read -r ADMIN_SK ADMIN_PK <<< "$("$SERVER_BIN" sign-test keygen)"
    read -r FRIEND_SK FRIEND_PK <<< "$("$SERVER_BIN" sign-test keygen)"
    read -r INTRUDER_SK INTRUDER_PK <<< "$("$SERVER_BIN" sign-test keygen)"

    PHP_DOCROOT="$TMP_ROOT/php_docroot"
    mkdir -p "$PHP_DOCROOT"
    cp "${ROOT_DIR}/php/sync.php" "$PHP_DOCROOT/"
    cat > "$PHP_DOCROOT/config.php" <<EOF
<?php
return [
    'admin_pubkey' => '${ADMIN_PK}',
    'data_dir' => 'humoco_sync_data',
    'max_members' => 300,
    'max_total_storage_mb' => 64,
    'soft_warning_percent' => 80,
    'channels' => [
        'card'   => ['max_bytes' => 524288,  'ttl_days' => 0],
        'wot'    => ['max_bytes' => 131072,  'ttl_days' => 0],
        'backup' => ['max_bytes' => 4194304, 'ttl_days' => 0],
        'post'   => ['max_bytes' => 131072,  'ttl_days' => 30],
        'media'  => ['max_bytes' => 524288, 'max_user_count' => 12, 'max_user_bytes' => 3145728, 'max_channel_mb' => 32, 'ttl_days' => 90],
    ],
];
EOF
    php -S "127.0.0.1:${PHP_PORT}" -t "$PHP_DOCROOT" > "$TMP_ROOT/php-server.log" 2>&1 &
    SERVER_PID=$!

    READY=false
    for _ in $(seq 1 40); do
      if curl -sf "http://127.0.0.1:${PHP_PORT}/sync.php?info" >/dev/null 2>&1; then
        READY=true
        break
      fi
      sleep 0.1
    done
    if [[ "$READY" != "true" ]]; then
      cat "$TMP_ROOT/php-server.log" >&2 || true
      fail "PHP server failed to become ready"
    fi

    run_blackbox_protocol_suite \
      "php" \
      "http://127.0.0.1:${PHP_PORT}" \
      "/sync.php" \
      "$SERVER_BIN" \
      "$ADMIN_SK" "$ADMIN_PK" \
      "$FRIEND_SK" "$FRIEND_PK" \
      "$INTRUDER_SK" "$INTRUDER_PK" \
      "false"

    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
fi

echo ""
echo "All blackbox checks passed! (${PASS_COUNT} assertions passed, 0 failed)"
