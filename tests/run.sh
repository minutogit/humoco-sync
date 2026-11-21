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
  local start="${1:-18910}"
  for p in $(seq "$start" 18999); do
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
  unauth_headers="$(curl -sI -H "X-Drop-Pubkey: $friend_pk" -H "X-Channel: card" "$endpoint" | tr -d '\r' | tr '[:upper:]' '[:lower:]')"
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
  auth_headers="$(curl -sI -H "X-Drop-Pubkey: $friend_pk" -H "X-Channel: card" "$endpoint" | tr -d '\r' | tr '[:upper:]' '[:lower:]')"
  assert_contains "$auth_headers" "x-drop-authorized: true" "HEAD returns authorized=true after PUT ?members"
  local expected_card_max="524288"
  if [[ "$label" == "rust" ]]; then
    expected_card_max="1048576"
  fi
  assert_contains "$auth_headers" "x-channel-max-bytes: ${expected_card_max}" "HEAD returns X-Channel-Max-Bytes for authorized card channel"
  assert_contains "$auth_headers" "x-slot-occupied: false" "HEAD returns X-Slot-Occupied: false before upload"

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
  local put1_json
  put1_json="$(cat "$TMP_ROOT/put1.json")"
  assert_contains "$put1_json" '"slot_ack"' "PUT slot response includes signed slot_ack"
  assert_contains "$put1_json" '"lock_pub":"' "slot_ack includes server lock_pub"
  if ! grep -Eq '"sig":"[0-9a-f]{128}"' "$TMP_ROOT/put1.json"; then
    fail "slot_ack signature must be 128 lowercase hex chars: $put1_json"
  fi
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
  assert_contains "$st_json" "\"max_members\":" "GET ?status includes max_members"
  assert_contains "$st_json" "\"max_user_bytes\":" "GET ?status includes max_user_bytes"

  local cfg_ts cfg_nonce cfg_sig
  printf '{"max_total_storage_mb":512,"max_members":10,"max_user_storage_mb":5}' > "$TMP_ROOT/admin_cfg_bad.json"
  cfg_ts="$(date +%s)"
  cfg_nonce="$(rand_nonce)"
  cfg_sig="$("$helper_bin" sign-test sign-admin --sk "$admin_sk" --action PUT_ADMIN_CONFIG --ts "$cfg_ts" --nonce "$cfg_nonce" --body-file "$TMP_ROOT/admin_cfg_bad.json")"
  local bad_cfg_code
  bad_cfg_code="$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "X-Drop-Pubkey: $admin_pk" \
    -H "X-Drop-Timestamp: $cfg_ts" \
    -H "X-Drop-Nonce: $cfg_nonce" \
    -H "X-Drop-Signature: $cfg_sig" \
    -H "Content-Type: application/json" \
    --data-binary "@$TMP_ROOT/admin_cfg_bad.json" \
    "${endpoint}?admin_config")"
  assert_eq "$bad_cfg_code" "400" "PUT ?admin_config rejects max_user_storage_mb < 10 with 400"

  printf '{"max_total_storage_mb":1024,"max_members":250,"max_user_storage_mb":20}' > "$TMP_ROOT/admin_cfg_ok.json"
  cfg_ts="$(date +%s)"
  cfg_nonce="$(rand_nonce)"
  cfg_sig="$("$helper_bin" sign-test sign-admin --sk "$admin_sk" --action PUT_ADMIN_CONFIG --ts "$cfg_ts" --nonce "$cfg_nonce" --body-file "$TMP_ROOT/admin_cfg_ok.json")"
  local ok_cfg_json
  ok_cfg_json="$(curl -sf -X PUT \
    -H "X-Drop-Pubkey: $admin_pk" \
    -H "X-Drop-Timestamp: $cfg_ts" \
    -H "X-Drop-Nonce: $cfg_nonce" \
    -H "X-Drop-Signature: $cfg_sig" \
    -H "Content-Type: application/json" \
    --data-binary "@$TMP_ROOT/admin_cfg_ok.json" \
    "${endpoint}?admin_config")"
  assert_contains "$ok_cfg_json" "\"max_members\":250" "PUT ?admin_config updates max_members live"
  assert_contains "$ok_cfg_json" "\"max_user_bytes\":20971520" "PUT ?admin_config updates max_user_bytes live"

  # Restore 300 members / 2048 MB / 25 MB
  printf '{"max_total_storage_mb":2048,"max_members":300,"max_user_storage_mb":25}' > "$TMP_ROOT/admin_cfg_restore.json"
  cfg_ts="$(date +%s)"
  cfg_nonce="$(rand_nonce)"
  cfg_sig="$("$helper_bin" sign-test sign-admin --sk "$admin_sk" --action PUT_ADMIN_CONFIG --ts "$cfg_ts" --nonce "$cfg_nonce" --body-file "$TMP_ROOT/admin_cfg_restore.json")"
  curl -sf -X PUT \
    -H "X-Drop-Pubkey: $admin_pk" \
    -H "X-Drop-Timestamp: $cfg_ts" \
    -H "X-Drop-Nonce: $cfg_nonce" \
    -H "X-Drop-Signature: $cfg_sig" \
    -H "Content-Type: application/json" \
    --data-binary "@$TMP_ROOT/admin_cfg_restore.json" \
    "${endpoint}?admin_config" > /dev/null

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

  echo "=== Group 10 ($label): Lock Channel Blackbox (SYNC-006b) ==="
  local info_lock_json
  info_lock_json="$(curl -sf "${endpoint}?info")"
  assert_contains "$info_lock_json" '"lock"' "GET ?info includes lock metadata"
  assert_contains "$info_lock_json" '"selftest"' "GET ?info includes cached selftest report"

  local selftest_json lock_pub_bb
  selftest_json="$(curl -sf "${endpoint}?lock_selftest")"
  assert_contains "$selftest_json" '"all_passed":true' "GET ?lock_selftest reports all_passed=true"
  lock_pub_bb="$(printf '%s' "$selftest_json" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"
  if [[ ${#lock_pub_bb} -ne 64 ]]; then
    fail "Failed to parse lock_pub from ?lock_selftest: $selftest_json"
  else
    ok "Extracted 64-hex lock_pub from ?lock_selftest"
  fi

  if [[ "$label" == "php" ]]; then
    local kl_code
    kl_code="$(curl -s -o /dev/null -w '%{http_code}' "${data_url}/.lock_key.php")"
    if [[ "$kl_code" == "403" || "$kl_code" == "404" ]]; then
      ok "PHP .lock_key.php protected against static HTTP leak ($kl_code)"
    else
      fail "PHP .lock_key.php leaked with HTTP $kl_code"
    fi
  fi

  # PUT ?lock_delegate (admin-signed + inner HUMOCO-LOCK-DELEGATE-V1)
  local issued_bb
  issued_bb="$(date +%s)"
  "$helper_bin" sign-test sign-lock-delegate --sk "$admin_sk" --lock-pub "$lock_pub_bb" --write-url "$endpoint" --read-url "$data_url" --issued "$issued_bb" > "$TMP_ROOT/lock_delegate.json"
  ts="$(date +%s)"
  nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-admin --sk "$admin_sk" --action PUT_LOCK_DELEGATE --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/lock_delegate.json")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "X-Drop-Pubkey: $admin_pk" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    --data-binary "@$TMP_ROOT/lock_delegate.json" \
    "${endpoint}?lock_delegate")" "200" "PUT ?lock_delegate persists signed admin delegation"

  # Zero-write WAF probe
  local probe_nonce probe_resp
  probe_nonce="$(rand_nonce)$(rand_nonce)"
  probe_resp="$(curl -sf -X POST -H 'Content-Type: application/json' \
    -d "{\"probe\":true,\"client_nonce\":\"${probe_nonce}\"}" \
    "${endpoint}?lock")"
  assert_contains "$probe_resp" '"probe_ok":true' "POST ?lock WAF probe returns signed probe_ok"

  # Grant friend_pk 'lock' channel membership & request GenesisTicket
  printf '{"pubkeys":["%s"]}' "$friend_pk" > "$TMP_ROOT/lock_members.json"
  ts="$(date +%s)"
  nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-admin --sk "$admin_sk" --action PUT_MEMBERS --channel lock --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/lock_members.json")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "X-Drop-Pubkey: $admin_pk" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    --data-binary "@$TMP_ROOT/lock_members.json" \
    "${endpoint}?members&channel=lock")" "200" "PUT ?members&channel=lock authorizes lock member"

  local lock_head_headers
  lock_head_headers="$(curl -sI -H "X-Drop-Pubkey: $friend_pk" -H "X-Channel: lock" "$endpoint" | tr -d '\r' | tr '[:upper:]' '[:lower:]')"
  assert_contains "$lock_head_headers" "x-drop-authorized: true" "HEAD with X-Channel: lock returns authorized=true"
  assert_contains "$lock_head_headers" "x-drop-channels: " "HEAD includes X-Drop-Channels"
  assert_contains "$lock_head_headers" "lock" "HEAD X-Drop-Channels includes lock channel"

  local bb_quarter=8125 anchor_bb
  anchor_bb="$("$helper_bin" sign-test make-lock-sample --lock-pub "$lock_pub_bb" --admin-pub "$admin_pk" --quarter "$bb_quarter" --variant anchor_id)"
  printf '{"anchor_id":"%s","retain_until_quarter":%s,"pow_timestamp":null,"pow_nonce":null}' "$anchor_bb" "$bb_quarter" > "$TMP_ROOT/ticket_req.json"
  ts="$(date +%s)"
  nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$friend_sk" --method POST --channel lock_ticket --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/ticket_req.json")"
  assert_eq "$(curl -s -o "$TMP_ROOT/ticket_resp.json" -w '%{http_code}' -X POST \
    -H "X-Drop-Pubkey: $friend_pk" \
    -H "X-Drop-Timestamp: $ts" \
    -H "X-Drop-Nonce: $nonce" \
    -H "X-Drop-Signature: $sig" \
    -H 'Content-Type: application/json' \
    --data-binary "@$TMP_ROOT/ticket_req.json" \
    "${endpoint}?lock_ticket")" "200" "POST ?lock_ticket issues signed GenesisTicket"

  # Submit unauthenticated PoS batch (depth=0 + depth=1), verify idempotency, conflict, and 605B static read
  "$helper_bin" sign-test make-lock-sample --lock-pub "$lock_pub_bb" --admin-pub "$admin_pk" --quarter "$bb_quarter" --ticket-json "$TMP_ROOT/ticket_resp.json" --variant init > "$TMP_ROOT/lock_batch.json"
  local lock_batch_resp
  lock_batch_resp="$(curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/lock_batch.json" "${endpoint}?lock")"
  assert_contains "$lock_batch_resp" '"status":"ok"' "POST ?lock commits batch with FirstWrite receipts"

  local lock_retry_resp
  lock_retry_resp="$(curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/lock_batch.json" "${endpoint}?lock")"
  assert_contains "$lock_retry_resp" '"write_seq":2' "POST ?lock retry is idempotent at write_seq=2"

  "$helper_bin" sign-test make-lock-sample --lock-pub "$lock_pub_bb" --admin-pub "$admin_pk" --quarter "$bb_quarter" --ticket-json "$TMP_ROOT/ticket_resp.json" --variant conflict > "$TMP_ROOT/lock_conflict.json"
  local lock_conflict_resp
  lock_conflict_resp="$(curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/lock_conflict.json" "${endpoint}?lock")"
  assert_contains "$lock_conflict_resp" '"status":"conflict"' "POST ?lock double-spend returns ConflictSeen"

  local lock_read_rel static_len
  lock_read_rel="$("$helper_bin" sign-test make-lock-sample --lock-pub "$lock_pub_bb" --admin-pub "$admin_pk" --quarter "$bb_quarter" --variant read_path)"
  static_len="$(curl -sf "${data_url}/${lock_read_rel}" | wc -c | tr -d ' ')"
  assert_eq "$static_len" "605" "Static lock read returns exact 605-byte wire entry"

  echo "=== Group 11 ($label): Rotation Pre-Freeze, Veto & Timelock Parity ==="
  local s2_dum_sk s2_dum_pk anchor_g11
  read -r s2_dum_sk s2_dum_pk <<< "$("$helper_bin" sign-test keygen)"
  "$helper_bin" sign-test rotation make-manifest \
    --s1-lock-pub "$lock_pub_bb" --s1-admin-pub "$admin_pk" --s1-url "$base_url" \
    --s2-lock-pub "$s2_dum_pk" --s2-admin-pub "$s2_dum_pk" --s2-url "http://127.0.0.1:1" \
    --quarter "$bb_quarter" --anchor-tag "${label}-g11" > "$TMP_ROOT/g11_manifest_${label}.json"
  anchor_g11="$("$helper_bin" sign-test make-lock-sample --lock-pub "$lock_pub_bb" --admin-pub "$admin_pk" --quarter "$bb_quarter" --manifest-json "$TMP_ROOT/g11_manifest_${label}.json" --variant anchor_id)"
  printf '{"anchor_id":"%s","retain_until_quarter":%s,"pow_timestamp":null,"pow_nonce":null}' "$anchor_g11" "$bb_quarter" > "$TMP_ROOT/g11_treq.json"
  ts="$(date +%s)"
  nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$friend_sk" --method POST --channel lock_ticket --ts "$ts" --nonce "$nonce" --body-file "$TMP_ROOT/g11_treq.json")"
  curl -sf -X POST -H "X-Drop-Pubkey: $friend_pk" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/g11_treq.json" "${endpoint}?lock_ticket" > "$TMP_ROOT/g11_tresp.json"
  "$helper_bin" sign-test make-lock-sample --lock-pub "$lock_pub_bb" --admin-pub "$admin_pk" --quarter "$bb_quarter" --ticket-json "$TMP_ROOT/g11_tresp.json" --manifest-json "$TMP_ROOT/g11_manifest_${label}.json" --anchor-tag "${label}-g11" --variant seq:0 > "$TMP_ROOT/g11_b0.json"
  assert_contains "$(curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/g11_b0.json" "${endpoint}?lock")" '"status":"ok"' "G11 commits initial root lock prior to rotation"

  "$helper_bin" sign-test rotation make-pre-freeze --manifest-json "$TMP_ROOT/g11_manifest_${label}.json" > "$TMP_ROOT/g11_pf_req.json"
  assert_eq "$(curl -s -o "$TMP_ROOT/g11_pf_resp.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/g11_pf_req.json" "${endpoint}?lock_freeze")" "200" "POST ?lock_freeze pre_freeze returns 200"
  assert_eq "$("$helper_bin" sign-test rotation verify-freeze --freeze-json "$TMP_ROOT/g11_pf_resp.json" --expected-lock-pub "$lock_pub_bb" --min-entries 1)" "verified_snapshot" "Pre-freeze SnapshotExport signature & state_hash verified"

  "$helper_bin" sign-test make-lock-sample --lock-pub "$lock_pub_bb" --admin-pub "$admin_pk" --quarter "$bb_quarter" --ticket-json "$TMP_ROOT/g11_tresp.json" --manifest-json "$TMP_ROOT/g11_manifest_${label}.json" --anchor-tag "${label}-g11" --variant seq:1 > "$TMP_ROOT/g11_b1.json"
  assert_eq "$(curl -s -o "$TMP_ROOT/g11_pf_block.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/g11_b1.json" "${endpoint}?lock")" "409" "POST ?lock returns 409 during pre_freeze"
  assert_contains "$(cat "$TMP_ROOT/g11_pf_block.json")" '"pre_proposal_frozen"' "409 reports pre_proposal_frozen"

  "$helper_bin" sign-test rotation make-propose --manifest-json "$TMP_ROOT/g11_manifest_${label}.json" --ts "$(date +%s)" > "$TMP_ROOT/g11_prop_req.json"
  assert_eq "$(curl -s -o "$TMP_ROOT/g11_prop_resp.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/g11_prop_req.json" "${endpoint}?lock_freeze")" "200" "POST ?lock_freeze propose returns 200"
  assert_eq "$("$helper_bin" sign-test rotation verify-freeze --freeze-json "$TMP_ROOT/g11_prop_resp.json" --expected-lock-pub "$lock_pub_bb" --min-entries 1)" "verified_snapshot" "Permanent FreezeSnapshot signature & state_hash verified"
  assert_eq "$(curl -s -o "$TMP_ROOT/g11_pr_block.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/g11_b1.json" "${endpoint}?lock")" "409" "POST ?lock returns 409 during proposal_frozen"
  assert_contains "$(cat "$TMP_ROOT/g11_pr_block.json")" '"proposal_frozen"' "409 reports proposal_frozen"

  "$helper_bin" sign-test rotation make-veto --manifest-json "$TMP_ROOT/g11_manifest_${label}.json" --propose-json "$TMP_ROOT/g11_prop_req.json" --ts "$(date +%s)" > "$TMP_ROOT/g11_veto_req.json"
  assert_eq "$(curl -s -o "$TMP_ROOT/g11_veto_resp.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/g11_veto_req.json" "${endpoint}?lock_freeze")" "200" "Guarantor veto succeeds during 72h timelock"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/g11_b1.json" "${endpoint}?lock")" "200" "POST ?lock unfreezes and succeeds after Guarantor veto"

  "$helper_bin" sign-test rotation make-propose --manifest-json "$TMP_ROOT/g11_manifest_${label}.json" --ts "$(($(date +%s) + 1))" > "$TMP_ROOT/g11_prop2_req.json"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/g11_prop2_req.json" "${endpoint}?lock_freeze")" "200" "Fresh proposal after veto locks bucket again"
  "$helper_bin" sign-test rotation make-sign-commit --manifest-json "$TMP_ROOT/g11_manifest_${label}.json" --propose-json "$TMP_ROOT/g11_prop2_req.json" > "$TMP_ROOT/g11_early_commit.json"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$TMP_ROOT/g11_early_commit.json" "${endpoint}?lock_commit")" "409" "72h proposal timelock blocks premature ?lock_commit (409)"
}

run_two_server_rotation_parity() {
  local label="$1"
  local helper_bin="$2"
  local r1_port r2_port
  r1_port="$(pick_free_port 18910)"
  r2_port="$(pick_free_port $((r1_port + 1)))"

  local r_sk1 r_pk1 r_sk2 r_pk2
  read -r r_sk1 r_pk1 <<< "$("$helper_bin" sign-test keygen)"
  read -r r_sk2 r_pk2 <<< "$("$helper_bin" sign-test keygen)"
  local r_dir="$TMP_ROOT/rot2_${label}"
  mkdir -p "$r_dir/s1" "$r_dir/s2"
  local p1="" p2=""

  if [[ "$label" == "rust" ]]; then
    for idx in 1 2; do
      local prt ap pk
      if [[ "$idx" == "1" ]]; then prt="$r1_port"; ap="$r_pk1"; else prt="$r2_port"; ap="$r_pk2"; fi
      cat > "$r_dir/s${idx}/config.toml" <<EOF
[server]
bind = "127.0.0.1:${prt}"
public_base_url = "http://127.0.0.1:${prt}"
data_dir = "humoco_sync_data"
db_path = "${r_dir}/s${idx}/db.redb"
admin_pubkey = "${ap}"
trusted_proxy_hops = 0
[security]
ip_requests_per_minute = 5000
pubkey_requests_per_minute = 5000
[lock]
enabled = true
proposal_timelock_secs = 0
EOF
    done
    "$helper_bin" serve --config "$r_dir/s1/config.toml" > "$r_dir/s1.log" 2>&1 &
    p1=$!
    "$helper_bin" serve --config "$r_dir/s2/config.toml" > "$r_dir/s2.log" 2>&1 &
    p2=$!
  else
    for idx in 1 2; do
      local ap
      if [[ "$idx" == "1" ]]; then ap="$r_pk1"; else ap="$r_pk2"; fi
      cp "${ROOT_DIR}/php/sync.php" "${ROOT_DIR}/php/lock_handler.php" "${ROOT_DIR}/php/lock_rotation.php" "$r_dir/s${idx}/"
      cat > "$r_dir/s${idx}/config.php" <<EOF
<?php
return [
    'admin_pubkey' => '${ap}',
    'data_dir' => 'humoco_sync_data',
    'max_members' => 300,
    'max_total_storage_mb' => 64,
    'disable_rate_limit' => true,
    'channels' => ['card' => ['max_bytes' => 524288, 'ttl_days' => 0]],
    'lock' => ['enabled' => true, 'max_retention_quarter' => 8159, 'max_inodes' => 50000, 'pow_base_bits' => 8, 'allow_pow_tickets' => false, 'ticket_pow_bits' => 16, 'proposal_timelock_secs' => 0],
];
EOF
    done
    PHP_CLI_SERVER_WORKERS=2 php -S "127.0.0.1:${r1_port}" -t "$r_dir/s1" "$r_dir/s1/sync.php" > "$r_dir/s1.log" 2>&1 &
    p1=$!
    PHP_CLI_SERVER_WORKERS=2 php -S "127.0.0.1:${r2_port}" -t "$r_dir/s2" "$r_dir/s2/sync.php" > "$r_dir/s2.log" 2>&1 &
    p2=$!
  fi

  local ok_up=0
  for _ in $(seq 1 40); do
    if curl -sf "http://127.0.0.1:${r1_port}/sync.php?info" >/dev/null 2>&1 && curl -sf "http://127.0.0.1:${r2_port}/sync.php?info" >/dev/null 2>&1; then
      ok_up=1
      break
    fi
    sleep 0.1
  done
  if [[ "$ok_up" -ne 1 ]]; then
    kill "$p1" "$p2" 2>/dev/null || true
    fail "Rotation pair ($label) failed to become ready"
  fi

  echo "=== Group 12 ($label): Full 2-Server 3-Phase Rotation & Anchor Discovery Parity ==="
  local u1="http://127.0.0.1:${r1_port}" u2="http://127.0.0.1:${r2_port}"
  local lp1 lp2 qtr=8125 ts nonce sig anchor_e2e
  lp1="$(curl -sf "${u1}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"
  lp2="$(curl -sf "${u2}/sync.php?lock_selftest" | sed -n 's/.*"lock_pub":"\([0-9a-f]\{64\}\)".*/\1/p')"
  "$helper_bin" sign-test rotation make-manifest \
    --s1-lock-pub "$lp1" --s1-admin-pub "$r_pk1" --s1-url "$u1" \
    --s2-lock-pub "$lp2" --s2-admin-pub "$r_pk2" --s2-url "$u2" \
    --quarter "$qtr" --anchor-tag "${label}-e2e" > "$r_dir/manifest.json"
  anchor_e2e="$("$helper_bin" sign-test make-lock-sample --lock-pub "$lp1" --admin-pub "$r_pk1" --quarter "$qtr" --manifest-json "$r_dir/manifest.json" --anchor-tag "${label}-e2e" --variant anchor_id)"

  printf '{"anchor_id":"%s","retain_until_quarter":%s,"pow_timestamp":null,"pow_nonce":null}' "$anchor_e2e" "$qtr" > "$r_dir/treq.json"
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$r_sk1" --method POST --channel lock_ticket --ts "$ts" --nonce "$nonce" --body-file "$r_dir/treq.json")"
  curl -sf -X POST -H "X-Drop-Pubkey: $r_pk1" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" -H 'Content-Type: application/json' --data-binary "@$r_dir/treq.json" "${u1}/sync.php?lock_ticket" > "$r_dir/tresp.json"
  "$helper_bin" sign-test make-lock-sample --lock-pub "$lp1" --admin-pub "$r_pk1" --quarter "$qtr" --ticket-json "$r_dir/tresp.json" --manifest-json "$r_dir/manifest.json" --anchor-tag "${label}-e2e" --variant seq:0 > "$r_dir/b0.json"
  assert_contains "$(curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$r_dir/b0.json" "${u1}/sync.php?lock")" '"status":"ok"' "S1 commits seq:0 before rotation"

  ts="$(date +%s)"
  "$helper_bin" sign-test rotation make-propose --manifest-json "$r_dir/manifest.json" --ts "$ts" > "$r_dir/prop.json"
  assert_eq "$(curl -s -o "$r_dir/s1_freeze.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$r_dir/prop.json" "${u1}/sync.php?lock_freeze")" "200" "Phase 1 (?lock_freeze propose) succeeds on S1"
  assert_eq "$(curl -s -o "$r_dir/s1_get_freeze.json" -w '%{http_code}' "${u1}/sync.php?lock_freeze&anchor_id=${anchor_e2e}")" "200" "GET ?lock_freeze returns snapshot status"
  assert_eq "$("$helper_bin" sign-test rotation verify-freeze --freeze-json "$r_dir/s1_get_freeze.json" --expected-lock-pub "$lp1" --min-entries 1)" "verified_snapshot" "GET ?lock_freeze snapshot verified"

  "$helper_bin" sign-test rotation make-import --manifest-json "$r_dir/manifest.json" --propose-json "$r_dir/prop.json" --freeze-json "$r_dir/s1_freeze.json" > "$r_dir/import_req.json"
  assert_eq "$(curl -s -o "$r_dir/s2_import.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$r_dir/import_req.json" "${u2}/sync.php?lock_import")" "200" "Phase 2 (?lock_import) succeeds on S2"
  "$helper_bin" sign-test rotation verify-import-ack --import-resp-json "$r_dir/s2_import.json" --expected-lock-pub "$lp2" >/dev/null
  ok "ImportAck cryptographic signature verified against S2 lock_pub"

  "$helper_bin" sign-test rotation make-sign-commit --manifest-json "$r_dir/manifest.json" --propose-json "$r_dir/prop.json" --import-resp-json "$r_dir/s2_import.json" > "$r_dir/sc_req.json"
  assert_eq "$(curl -s -o "$r_dir/s1_sc.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$r_dir/sc_req.json" "${u1}/sync.php?lock_commit")" "200" "Phase 3 (?lock_commit sign_commit) succeeds on S1"

  "$helper_bin" sign-test rotation make-finalize --manifest-json "$r_dir/manifest.json" --propose-json "$r_dir/prop.json" --import-resp-json "$r_dir/s2_import.json" --sign-commit-resp-json "$r_dir/s1_sc.json" > "$r_dir/fin_req.json"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$r_dir/fin_req.json" "${u1}/sync.php?lock_commit")" "200" "Phase 3 (?lock_commit finalize) succeeds on S1"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$r_dir/fin_req.json" "${u2}/sync.php?lock_commit")" "200" "Phase 3 (?lock_commit finalize) succeeds on S2"

  curl -sf "${u2}/anchors/${anchor_e2e}.bin" > "$r_dir/anchor_root.bin"
  assert_eq "$("$helper_bin" sign-test rotation verify-manifest --manifest-json "$r_dir/anchor_root.bin" --expected-anchor-id "$anchor_e2e" --expected-rev 2)" "verified_rev_2" "GET /anchors/<anchor_id>.bin serves valid rev-2 manifest"
  curl -sf "${u2}/humoco_sync_data/anchors/${anchor_e2e}.bin" > "$r_dir/anchor_data.bin"
  assert_eq "$("$helper_bin" sign-test rotation verify-manifest --manifest-json "$r_dir/anchor_data.bin" --expected-anchor-id "$anchor_e2e" --expected-rev 2)" "verified_rev_2" "GET /<data_dir>/anchors/<anchor_id>.bin serves valid rev-2 manifest"

  assert_eq "$(curl -s -o "$r_dir/s1_after.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$r_dir/b0.json" "${u1}/sync.php?lock")" "409" "Old server S1 returns 409 epoch_frozen after finalize"
  assert_contains "$(cat "$r_dir/s1_after.json")" '"epoch_frozen"' "409 carries epoch_frozen error"
  assert_eq "$("$helper_bin" sign-test rotation verify-manifest --manifest-json "$r_dir/s1_after.json" --expected-anchor-id "$anchor_e2e" --expected-rev 2 --wrapped-field latest_manifest)" "verified_rev_2" "409 epoch_frozen embeds verified rev-2 latest_manifest"

  local r2_rel
  r2_rel="$("$helper_bin" sign-test make-lock-sample --lock-pub "$lp2" --admin-pub "$r_pk1" --quarter "$qtr" --manifest-json "$r_dir/manifest.json" --anchor-tag "${label}-e2e" --variant read_path_seq:0)"
  assert_eq "$(curl -sf "${u2}/humoco_sync_data/${r2_rel}" | wc -c | tr -d ' ')" "605" "Imported slot migrated onto S2 static read URL (605B)"

  "$helper_bin" sign-test make-lock-sample --lock-pub "$lp2" --admin-pub "$r_pk2" --quarter "$qtr" --ticket-json "$r_dir/tresp.json" --manifest-json "$r_dir/manifest.json" --anchor-tag "${label}-e2e" --variant seq:1 > "$r_dir/b1_s2.json"
  assert_contains "$(curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$r_dir/b1_s2.json" "${u2}/sync.php?lock")" '"status":"ok"' "Post-rotation spend seq:1 succeeds on new committee S2"

  kill "$p1" "$p2" 2>/dev/null || true
  wait "$p1" "$p2" 2>/dev/null || true
}

run_php_s06_security_regression_tests() {
  local helper_bin="$1"
  echo "=== Group 13 (php): S06 Security & Parity Regression Suite ==="

  local s06_dir="$TMP_ROOT/s06_reg"
  mkdir -p "$s06_dir"
  local s_admin_sk s_admin_pk s_mem_sk s_mem_pk
  read -r s_admin_sk s_admin_pk <<< "$("$helper_bin" sign-test keygen)"
  read -r s_mem_sk s_mem_pk <<< "$("$helper_bin" sign-test keygen)"

  # --- Cluster 1: Rate-limiter pepper persistence, 900s lockout expiry & CGNAT exemption ---
  local rl_dir="$s06_dir/rl"
  mkdir -p "$rl_dir"
  cp "${ROOT_DIR}/php/sync.php" "${ROOT_DIR}/php/lock_handler.php" "${ROOT_DIR}/php/lock_rotation.php" "${ROOT_DIR}/php/index.html" "${ROOT_DIR}/php/robots.txt" "$rl_dir/"
  cat > "$rl_dir/config.php" <<EOF
<?php
return [
    'admin_pubkey' => '${s_admin_pk}',
    'data_dir' => 'humoco_sync_data',
    'max_members' => 300,
    'max_total_storage_mb' => 64,
    'disable_rate_limit' => false,
    'channels' => [
        'card'   => ['max_bytes' => 524288, 'ttl_days' => 30],
        'media'  => ['max_bytes' => 524288, 'max_user_count' => 12, 'max_user_bytes' => 3145728, 'max_channel_mb' => 32, 'ttl_days' => 90],
    ],
    'lock' => ['enabled' => true],
];
EOF
  local rl_port
  rl_port="$(pick_free_port 18930)"
  PHP_CLI_SERVER_WORKERS=2 php -S "127.0.0.1:${rl_port}" -t "$rl_dir" "$rl_dir/sync.php" > "$s06_dir/rl.log" 2>&1 &
  local rl_pid=$!
  for _ in $(seq 1 40); do
    if curl -sf "http://127.0.0.1:${rl_port}/sync.php?info" >/dev/null 2>&1; then break; fi
    sleep 0.1
  done

  local got_info_429=false
  for _ in $(seq 1 35); do
    local ic
    ic="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${rl_port}/sync.php?info")"
    if [[ "$ic" == "429" ]]; then
      got_info_429=true
      break
    fi
  done
  assert_eq "$got_info_429" "true" "SYNC-S06-01: GET ?info persists pepper and enforces 429 burst limit on fresh server"

  # Authorize s_mem_pk on card before lockout tests
  printf '{"pubkeys":["%s"]}' "$s_mem_pk" > "$s06_dir/mem.json"
  local ts nonce sig
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-admin --sk "$s_admin_sk" --action PUT_MEMBERS --channel card --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/mem.json")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_admin_pk" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$s06_dir/mem.json" "http://127.0.0.1:${rl_port}/sync.php?members&channel=card")" "200" "SYNC-S06-01: authorized member for CGNAT exemption test"

  # Trigger 10 failed HEAD requests -> 11th HEAD must return 429
  for _ in $(seq 1 10); do
    curl -s -o /dev/null -I -H "X-Drop-Pubkey: invalid" "http://127.0.0.1:${rl_port}/sync.php"
  done
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -I -H "X-Drop-Pubkey: $s_mem_pk" "http://127.0.0.1:${rl_port}/sync.php")" "429" "SYNC-S06-01: 10 failed HEADs trigger IP lockout (429)"

  # Unauthenticated/invalid PUT while IP is locked must return 429 (not 401)
  printf 'cgnat-test' > "$s06_dir/cgnat.bin"
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: card" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $(printf '0%.0s' {1..128})" --data-binary "@$s06_dir/cgnat.bin" "http://127.0.0.1:${rl_port}/sync.php")" "429" "SYNC-S06-01: invalid signature PUT while IP-locked returns 429"

  # Valid Ed25519-signed PUT from the SAME locked IP must still succeed (Proxy-Safe Member Exemption)
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$s_mem_sk" --method PUT --channel card --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/cgnat.bin")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: card" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$s06_dir/cgnat.bin" "http://127.0.0.1:${rl_port}/sync.php")" "200" "SYNC-S06-01: valid Ed25519 PUT bypasses IP lockout (CGNAT exemption)"

  # Age all bucket lastTs in ratelimit.bin.php by 901 seconds -> lockout must expire!
  php -r '
    $f = $argv[1];
    $fp = fopen($f, "r+b");
    for ($i = 0; $i < 4096; $i++) {
      fseek($fp, 28 + $i * 16);
      $raw = fread($fp, 16);
      $b = unpack("VipTag/VlastTs/ftokens/VfailCount", $raw);
      if ($b["ipTag"] !== 0 && $b["lastTs"] > 1000) {
        $b["lastTs"] -= 901;
        fseek($fp, 28 + $i * 16);
        fwrite($fp, pack("VVfV", $b["ipTag"], $b["lastTs"], (float)$b["tokens"], (int)$b["failCount"]));
      }
    }
    fflush($fp); fclose($fp);
  ' "$rl_dir/ratelimit.bin.php"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -I -H "X-Drop-Pubkey: $s_mem_pk" "http://127.0.0.1:${rl_port}/sync.php")" "200" "SYNC-S06-01: IP lockout expires cleanly after 900s"

  kill "$rl_pid" 2>/dev/null || true
  wait "$rl_pid" 2>/dev/null || true

  # --- Cluster 2: Nonce durability on errors, non-destructive 507 & pre-commit lock_key guard ---
  local c2_dir="$s06_dir/c2"
  mkdir -p "$c2_dir"
  cp "${ROOT_DIR}/php/sync.php" "${ROOT_DIR}/php/lock_handler.php" "${ROOT_DIR}/php/lock_rotation.php" "${ROOT_DIR}/php/index.html" "${ROOT_DIR}/php/robots.txt" "$c2_dir/"
  cat > "$c2_dir/config.php" <<EOF
<?php
return [
    'admin_pubkey' => '${s_admin_pk}',
    'data_dir' => 'humoco_sync_data',
    'max_members' => 300,
    'max_total_storage_mb' => 1,
    'max_user_storage_mb' => 1,
    'disable_rate_limit' => true,
    'channels' => [
        'card'   => ['max_bytes' => 524288,  'ttl_days' => 30],
        'backup' => ['max_bytes' => 5242880, 'ttl_days' => 180],
        'media'  => ['max_bytes' => 524288, 'max_user_count' => 12, 'max_user_bytes' => 1048576, 'max_channel_mb' => 32, 'ttl_days' => 90],
    ],
    'lock' => ['enabled' => true],
];
EOF
  local s_mem2_sk s_mem2_pk
  read -r s_mem2_sk s_mem2_pk <<< "$("$helper_bin" sign-test keygen)"
  local c2_port
  c2_port="$(pick_free_port 18940)"
  PHP_CLI_SERVER_WORKERS=2 php -S "127.0.0.1:${c2_port}" -t "$c2_dir" "$c2_dir/sync.php" > "$s06_dir/c2.log" 2>&1 &
  local c2_pid=$!
  for _ in $(seq 1 40); do
    if curl -sf "http://127.0.0.1:${c2_port}/sync.php?info" >/dev/null 2>&1; then break; fi
    sleep 0.1
  done
  local c2_ep="http://127.0.0.1:${c2_port}/sync.php"
  local c2_data="http://127.0.0.1:${c2_port}/humoco_sync_data"

  printf '{"pubkeys":["%s","%s"]}' "$s_mem_pk" "$s_mem2_pk" > "$s06_dir/c2_members.json"
  for ch in card backup media; do
    ts="$(date +%s)"; nonce="$(rand_nonce)"
    sig="$("$helper_bin" sign-test sign-admin --sk "$s_admin_sk" --action PUT_MEMBERS --channel "$ch" --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/c2_members.json")"
    assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_admin_pk" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$s06_dir/c2_members.json" "${c2_ep}?members&channel=${ch}")" "200" "SYNC-S06-03: setup members on $ch"
  done

  # 1) Nonce consumption persisted on PUT ?admin_config 400 error
  printf '{"max_total_storage_mb":10,"max_members":10,"max_user_storage_mb":5}' > "$s06_dir/c2_bad_cfg.json"
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-admin --sk "$s_admin_sk" --action PUT_ADMIN_CONFIG --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/c2_bad_cfg.json")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_admin_pk" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$s06_dir/c2_bad_cfg.json" "${c2_ep}?admin_config")" "400" "SYNC-S06-03: bad admin_config returns 400"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_admin_pk" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$s06_dir/c2_bad_cfg.json" "${c2_ep}?admin_config")" "409" "SYNC-S06-03: replayed nonce after 400 admin_config returns 409"

  # 2) Nonce consumption persisted on PUT 412 If-Match error
  printf 'hello-412' > "$s06_dir/c2_412.bin"
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$s_mem_sk" --method PUT --channel card --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/c2_412.bin")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: card" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" -H 'If-Match: "0000000000000000000000000000000000000000000000000000000000000000"' --data-binary "@$s06_dir/c2_412.bin" "${c2_ep}")" "412" "SYNC-S06-03: PUT If-Match mismatch returns 412"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: card" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" -H 'If-Match: "0000000000000000000000000000000000000000000000000000000000000000"' --data-binary "@$s06_dir/c2_412.bin" "${c2_ep}")" "409" "SYNC-S06-03: replayed nonce after 412 PUT returns 409"

  # 3) Nonce consumption persisted on empty DELETE slot 200
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$s_mem_sk" --method DELETE --channel card --ts "$ts" --nonce "$nonce")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: card" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" "${c2_ep}")" "200" "SYNC-S06-03: empty DELETE slot returns 200"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: card" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" "${c2_ep}")" "409" "SYNC-S06-03: replayed nonce after empty DELETE returns 409"

  # 4) Non-destructive 507: unachievable global quota must NOT evict existing media
  dd if=/dev/zero bs=1024 count=400 of="$s06_dir/c2_m.bin" 2>/dev/null
  local c2_mid
  c2_mid="$(sha256_file_hex "$s06_dir/c2_m.bin")"
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$s_mem_sk" --method PUT --channel media --media-id "$c2_mid" --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/c2_m.bin")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: media" -H "X-Media-Id: $c2_mid" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$s06_dir/c2_m.bin" "${c2_ep}")" "200" "SYNC-S06-03: mem1 uploads 400KB media"

  dd if=/dev/zero bs=1024 count=450 of="$s06_dir/c2_b1.bin" 2>/dev/null
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$s_mem2_sk" --method PUT --channel backup --prefix p1 --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/c2_b1.bin")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_mem2_pk" -H "X-Channel: backup" -H "X-Drop-Prefix: p1" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$s06_dir/c2_b1.bin" "${c2_ep}")" "200" "SYNC-S06-03: mem2 uploads 450KB backup"

  dd if=/dev/zero bs=1024 count=600 of="$s06_dir/c2_b2.bin" 2>/dev/null
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$s_mem2_sk" --method PUT --channel backup --prefix p2 --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/c2_b2.bin")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_mem2_pk" -H "X-Channel: backup" -H "X-Drop-Prefix: p2" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$s06_dir/c2_b2.bin" "${c2_ep}")" "507" "SYNC-S06-03: impossible 600KB upload returns 507"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${c2_data}/${c2_mid}.media.bin")" "200" "SYNC-S06-03: 507 failure preserves mem1 media blob atomically"

  # 5) Anti-amnesia lock_key failure before slot commit
  mkdir -p "$c2_dir/humoco_sync_data/locks/2031-Q2/0000"
  rm -f "$c2_dir/humoco_sync_data/.lock_key.php"
  printf 'should-not-commit' > "$s06_dir/c2_amnesia.bin"
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$s_mem_sk" --method PUT --channel card --prefix amnesia --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/c2_amnesia.bin")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: card" -H "X-Drop-Prefix: amnesia" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$s06_dir/c2_amnesia.bin" "${c2_ep}")" "500" "SYNC-S06-03: anti-amnesia lock_key error aborts PUT with 500"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${c2_data}/${s_mem_pk}_amnesia.card.bin")" "404" "SYNC-S06-03: aborted slot is NOT written to disk without slot_ack"

  kill "$c2_pid" 2>/dev/null || true
  wait "$c2_pid" 2>/dev/null || true

  # --- Cluster 3 & 4: Preconditions on media, HEAD media TTL, PUT ?members isolation, DELETE oracle, ?revoke S01-06 parity, routing, admin_pubkey reload, data_dir & .htaccess ---
  local c3_dir="$s06_dir/c3"
  mkdir -p "$c3_dir"
  cp "${ROOT_DIR}/php/sync.php" "${ROOT_DIR}/php/lock_handler.php" "${ROOT_DIR}/php/lock_rotation.php" "${ROOT_DIR}/php/index.html" "${ROOT_DIR}/php/robots.txt" "${ROOT_DIR}/php/.htaccess" "$c3_dir/"
  cat > "$c3_dir/config.php" <<EOF
<?php
return [
    'admin_pubkey' => '${s_admin_pk}',
    'data_dir' => 'humoco_sync_data',
    'max_members' => 300,
    'max_total_storage_mb' => 64,
    'max_user_storage_mb' => 25,
    'disable_rate_limit' => true,
    'channels' => [
        'card'   => ['max_bytes' => 524288, 'ttl_days' => 30],
        'media'  => ['max_bytes' => 524288, 'max_user_count' => 12, 'max_user_bytes' => 3145728, 'max_channel_mb' => 32, 'ttl_days' => 1],
    ],
    'lock' => ['enabled' => true],
];
EOF
  local c3_port
  c3_port="$(pick_free_port 18950)"
  PHP_CLI_SERVER_WORKERS=2 php -S "127.0.0.1:${c3_port}" -t "$c3_dir" "$c3_dir/sync.php" > "$s06_dir/c3.log" 2>&1 &
  local c3_pid=$!
  for _ in $(seq 1 40); do
    if curl -sf "http://127.0.0.1:${c3_port}/sync.php?info" >/dev/null 2>&1; then break; fi
    sleep 0.1
  done
  local c3_ep="http://127.0.0.1:${c3_port}/sync.php"
  local c3_data="http://127.0.0.1:${c3_port}/humoco_sync_data"

  printf '{"pubkeys":["%s"]}' "$s_mem_pk" > "$s06_dir/c3_mem.json"
  for ch in card media; do
    ts="$(date +%s)"; nonce="$(rand_nonce)"
    sig="$("$helper_bin" sign-test sign-admin --sk "$s_admin_sk" --action PUT_MEMBERS --channel "$ch" --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/c3_mem.json")"
    assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_admin_pk" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$s06_dir/c3_mem.json" "${c3_ep}?members&channel=${ch}")" "200" "SYNC-S06-04: authorize $ch"
  done

  # 1) PUT media If-None-Match: * and If-Match preconditions
  printf 'media-precond-v1' > "$s06_dir/c3_m1.bin"
  local c3_mid1
  c3_mid1="$(sha256_file_hex "$s06_dir/c3_m1.bin")"
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$s_mem_sk" --method PUT --channel media --media-id "$c3_mid1" --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/c3_m1.bin")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: media" -H "X-Media-Id: $c3_mid1" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" -H 'If-None-Match: *' --data-binary "@$s06_dir/c3_m1.bin" "${c3_ep}")" "200" "SYNC-S06-04: initial PUT media If-None-Match: * succeeds"

  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$s_mem_sk" --method PUT --channel media --media-id "$c3_mid1" --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/c3_m1.bin")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: media" -H "X-Media-Id: $c3_mid1" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" -H 'If-None-Match: *' --data-binary "@$s06_dir/c3_m1.bin" "${c3_ep}")" "412" "SYNC-S06-04: duplicate PUT media If-None-Match: * returns 412"

  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-member --sk "$s_mem_sk" --method PUT --channel media --media-id "$c3_mid1" --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/c3_m1.bin")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: media" -H "X-Media-Id: $c3_mid1" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" -H 'If-Match: "0000000000000000000000000000000000000000000000000000000000000000"' --data-binary "@$s06_dir/c3_m1.bin" "${c3_ep}")" "412" "SYNC-S06-04: PUT media If-Match mismatch returns 412"

  # 2) PUT ?members&channel=card [] must NOT wipe members.media.php authorized media
  printf '{"pubkeys":[]}' > "$s06_dir/c3_empty.json"
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-admin --sk "$s_admin_sk" --action PUT_MEMBERS --channel card --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/c3_empty.json")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_admin_pk" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$s06_dir/c3_empty.json" "${c3_ep}?members&channel=card")" "200" "SYNC-S06-04: clear card membership"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "${c3_data}/${c3_mid1}.media.bin")" "200" "SYNC-S06-04: explicit media member keeps media when card list cleared"

  # 3) PUT ?members rejects trailing newline inside pubkeys (\z anchor)
  printf '{"pubkeys":["%s\\n"]}' "$s_mem_pk" > "$s06_dir/c3_nl_pk.json"
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-admin --sk "$s_admin_sk" --action PUT_MEMBERS --channel card --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/c3_nl_pk.json")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_admin_pk" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$s06_dir/c3_nl_pk.json" "${c3_ep}?members&channel=card")" "400" "SYNC-S06-04: PUT ?members rejects pubkey with trailing newline"

  # 4) HEAD media TTL expiry parity
  touch -d "3 days ago" "$c3_dir/humoco_sync_data/${c3_mid1}.media.bin"
  local head_exp_media
  head_exp_media="$(curl -sI -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: media" -H "X-Media-Id: $c3_mid1" "${c3_ep}" | tr -d '\r' | tr '[:upper:]' '[:lower:]')"
  assert_contains "$head_exp_media" "x-slot-occupied: false" "SYNC-S06-04: HEAD reports X-Slot-Occupied: false for TTL-expired media"
  assert_contains "$head_exp_media" "x-media-count: 0" "SYNC-S06-04: HEAD excludes TTL-expired media from X-Media-Count"

  # 5) DELETE standard slot must return 401 (never 404 oracle) on bad signature for non-member
  local rand_sk rand_pk
  read -r rand_sk rand_pk <<< "$("$helper_bin" sign-test keygen)"
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "X-Drop-Pubkey: $rand_pk" -H "X-Channel: card" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $(printf '0%.0s' {1..128})" "${c3_ep}")" "401" "SYNC-S06-04: DELETE on non-member returns 401 before membership/slot oracle"

  # 6) PUT ?revoke SYNC-S01-06 validation parity
  php -r '
    $adminSkHex = $argv[1]; $adminPkHex = $argv[2]; $outDir = $argv[3];
    $sk = hex2bin($adminSkHex) . hex2bin($adminPkHex);
    $ts = time();
    $mk = function($drop, $issued, $eff, $rw, $rr, $rp, $reason) use ($sk) {
      $msg = "HUMOCO-DROP-REVOKE-V1\n" . strtolower($drop) . "\n{$issued}\n{$eff}\n{$rw}\n{$rr}\n" . strtolower($rp) . "\n" . ($reason ?? "");
      $sig = bin2hex(sodium_crypto_sign_detached($msg, $sk));
      return json_encode(["drop_pub" => $drop, "issued_at" => $issued, "effective_at" => $eff, "reason" => $reason, "replacement" => ["write_url" => $rw, "read_url" => $rr, "drop_pub" => $rp], "signature" => $sig], JSON_UNESCAPED_SLASHES);
    };
    file_put_contents("$outDir/rev_bad_host.json", $mk($adminPkHex, $ts, $ts+60, "http://localhost.evil.com/sync.php", "https://new.example/data", $adminPkHex, "ok"));
    file_put_contents("$outDir/rev_bad_ctrl.json", $mk($adminPkHex, $ts, $ts+60, "https://new.example/sync.php", "https://new.example/data", $adminPkHex, "ok\x07bell"));
  ' "$s_admin_sk" "$s_admin_pk" "$s06_dir"
  for bad_rev in "$s06_dir/rev_bad_host.json" "$s06_dir/rev_bad_ctrl.json"; do
    ts="$(date +%s)"; nonce="$(rand_nonce)"
    sig="$("$helper_bin" sign-test sign-admin --sk "$s_admin_sk" --action PUT_REVOKE --ts "$ts" --nonce "$nonce" --body-file "$bad_rev")"
    assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_admin_pk" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$bad_rev" "${c3_ep}?revoke")" "400" "SYNC-S06-05: PUT ?revoke rejects $(basename "$bad_rev") with 400"
  done

  # 7) Strict query routing (405), bounded admin_config body (413), non-int timestamp (400), admin_pubkey sync
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -I -H "X-Drop-Pubkey: $s_mem_pk" "${c3_ep}?extra=1")" "405" "SYNC-S06-05: HEAD with extra query returns 405"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: card" "${c3_ep}?admin_config&extra=1")" "405" "SYNC-S06-05: PUT with extra query returns 405"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: card" "${c3_ep}?extra=1")" "405" "SYNC-S06-05: DELETE with extra query returns 405"

  dd if=/dev/zero bs=1024 count=20 of="$s06_dir/c3_big_cfg.bin" 2>/dev/null
  ts="$(date +%s)"; nonce="$(rand_nonce)"
  sig="$("$helper_bin" sign-test sign-admin --sk "$s_admin_sk" --action PUT_ADMIN_CONFIG --ts "$ts" --nonce "$nonce" --body-file "$s06_dir/c3_big_cfg.bin")"
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_admin_pk" -H "X-Drop-Timestamp: $ts" -H "X-Drop-Nonce: $nonce" -H "X-Drop-Signature: $sig" --data-binary "@$s06_dir/c3_big_cfg.bin" "${c3_ep}?admin_config")" "413" "SYNC-S06-05: PUT ?admin_config >16KiB returns 413"

  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "X-Drop-Pubkey: $s_mem_pk" -H "X-Channel: card" -H "X-Drop-Timestamp: 1795000000.5" -H "X-Drop-Nonce: $(rand_nonce)" -H "X-Drop-Signature: $(printf '0%.0s' {1..128})" --data-binary "@$s06_dir/c3_m1.bin" "${c3_ep}")" "400" "SYNC-S06-05: PUT rejects float timestamp with 400"

  # Update admin_pubkey in config.php after .state.php exists -> GET ?info must reflect new drop_pub
  php -r '
    $f = $argv[1]; $old = $argv[2]; $new = $argv[3];
    file_put_contents($f, str_replace($old, $new, file_get_contents($f)));
  ' "$c3_dir/config.php" "$s_admin_pk" "$rand_pk"
  assert_contains "$(curl -sf "${c3_ep}?info")" "\"drop_pub\":\"${rand_pk}\"" "SYNC-S06-05: GET ?info reflects updated config.php admin_pubkey"

  kill "$c3_pid" 2>/dev/null || true
  wait "$c3_pid" 2>/dev/null || true

  # 8) Cluster 4: data_dir traversal/docroot-collapse & .htaccess dotfile protection
  local ht_match
  ht_match="$(php -r '
    $ht = file_get_contents($argv[1]);
    if (preg_match("/<FilesMatch\\s+\"([^\"]+)\"/", $ht, $m)) {
      $re = "#" . $m[1] . "#";
      echo (preg_match($re, ".lock_key.php") && preg_match($re, ".htaccess")) ? "ok" : "fail";
    } else { echo "fail"; }
  ' "${ROOT_DIR}/php/.htaccess")"
  assert_eq "$ht_match" "ok" "SYNC-S06-06: php/.htaccess denies arbitrary dotfiles including .lock_key.php"

  local dd_port
  dd_port="$(pick_free_port 18960)"
  mkdir -p "$s06_dir/dd_srv"
  cp "${ROOT_DIR}/php/sync.php" "${ROOT_DIR}/php/lock_handler.php" "$s06_dir/dd_srv/"
  cat > "$s06_dir/dd_srv/config.php" <<EOF
<?php
return ['admin_pubkey' => '${s_admin_pk}', 'data_dir' => '.'];
EOF
  php -S "127.0.0.1:${dd_port}" -t "$s06_dir/dd_srv" "$s06_dir/dd_srv/sync.php" > "$s06_dir/dd.log" 2>&1 &
  local dd_pid=$!
  sleep 0.25
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${dd_port}/sync.php?info")" "500" "SYNC-S06-06: data_dir='.' rejected with 500"
  kill "$dd_pid" 2>/dev/null || true
  wait "$dd_pid" 2>/dev/null || true
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

  run_two_server_rotation_parity "rust" "$SERVER_BIN"
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
    cp "${ROOT_DIR}/php/sync.php" "${ROOT_DIR}/php/lock_handler.php" "${ROOT_DIR}/php/lock_rotation.php" "${ROOT_DIR}/php/index.html" "${ROOT_DIR}/php/robots.txt" "$PHP_DOCROOT/"
    cat > "$PHP_DOCROOT/config.php" <<EOF
<?php
return [
    'admin_pubkey' => '${ADMIN_PK}',
    'data_dir' => 'humoco_sync_data',
    'max_members' => 300,
    'max_total_storage_mb' => 64,
    'soft_warning_percent' => 80,
    'disable_rate_limit' => true,
    'channels' => [
        'card'   => ['max_bytes' => 524288,  'ttl_days' => 0],
        'wot'    => ['max_bytes' => 131072,  'ttl_days' => 0],
        'backup' => ['max_bytes' => 4194304, 'ttl_days' => 0],
        'post'   => ['max_bytes' => 131072,  'ttl_days' => 30],
        'media'  => ['max_bytes' => 524288, 'max_user_count' => 12, 'max_user_bytes' => 3145728, 'max_channel_mb' => 32, 'ttl_days' => 90],
    ],
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
    PHP_CLI_SERVER_WORKERS=4 php -S "127.0.0.1:${PHP_PORT}" -t "$PHP_DOCROOT" "$PHP_DOCROOT/sync.php" > "$TMP_ROOT/php-server.log" 2>&1 &
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

    run_two_server_rotation_parity "php" "$SERVER_BIN"

    run_php_s06_security_regression_tests "$SERVER_BIN"

    echo ""
    echo ">>> Running PHP Lock Concurrency, Rollback, Quota & GC Tests <<<"
    bash "${ROOT_DIR}/tests/test_php_locks.sh" --bin "$SERVER_BIN"
  fi
fi

echo ""
echo "All blackbox checks passed! (${PASS_COUNT} assertions passed, 0 failed)"
