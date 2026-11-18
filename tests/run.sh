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
  "$helper_bin" sign-test sign-lock-delegate --sk "$admin_sk" --lock-pub "$lock_pub_bb" --issued "$issued_bb" > "$TMP_ROOT/lock_delegate.json"
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

    echo ""
    echo ">>> Running PHP Lock Concurrency, Rollback, Quota & GC Tests <<<"
    bash "${ROOT_DIR}/tests/test_php_locks.sh" --bin "$SERVER_BIN"
  fi
fi

echo ""
echo "All blackbox checks passed! (${PASS_COUNT} assertions passed, 0 failed)"
