use std::collections::BTreeMap;
use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Json, Router};
use serde::Deserialize;

use crate::config::Config;
use crate::crypto::{
    check_timestamp_window, format_admin_post_lock_selftest_message,
    format_admin_put_config_message, format_admin_put_lock_delegate_message,
    format_admin_put_members_message, format_admin_put_revoke_message, format_admin_status_message,
    format_delete_account_message, normalize_pubkey_hex, parse_member_message, sha256_hex,
    unix_now, validate_admin_member_channel, validate_channel, validate_drop_prefix,
    validate_nonce_hex, verify_ed25519_hex, verify_revocation_notice, RevocationNotice,
};
use crate::db::{normalize_etag, AdminConfigOverrides, ConditionalPrecondition};
use crate::lock_rotation::{LockCommitRequest, LockFreezeRequest, LockImportRequest};
use crate::locks::{LockBatchRequest, LockDelegation, LockTicketRequest, TicketCallerAuth};
use crate::ratelimit::extract_client_ip;
use crate::state::{db_err_to_response, json_error, AppState};

pub fn sync_router(cfg: &Config) -> Router<AppState> {
    let data_route = format!("/{}/:filename", cfg.server.data_dir);
    let anchor_data_route = format!("/{}/anchors/:filename", cfg.server.data_dir);
    let lock_read_route = format!("/{}/locks/:quarter/:bucket/:filename", cfg.server.data_dir);
    Router::new()
        .route("/sync.php", any(handle_sync_endpoint))
        .route("/sync", any(handle_sync_endpoint))
        .route(&lock_read_route, any(handle_static_lock))
        .route(&anchor_data_route, any(handle_static_anchor))
        .route("/anchors/:filename", any(handle_static_anchor))
        .route(&data_route, any(handle_static_data))
}

#[derive(Deserialize)]
struct PutMembersPayload {
    pubkeys: Vec<String>,
}

#[derive(Deserialize)]
struct PutAdminConfigPayload {
    max_total_storage_mb: u64,
    max_members: usize,
    max_user_storage_mb: u64,
}

async fn handle_sync_endpoint(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    req: Request<Body>,
) -> Response {
    let (parts, body) = req.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let headers = parts.headers;

    let peer_addr = peer.map(|ConnectInfo(s)| s);
    let client_ip = extract_client_ip(peer_addr, &headers, state.config.server.trusted_proxy_hops);
    if !state.rate_limiter.allow_ip(client_ip) {
        return json_error(StatusCode::TOO_MANY_REQUESTS, "IP rate limit exceeded");
    }

    let query_params = parse_query_map(&uri);

    match method {
        Method::GET => {
            if query_params.contains_key("info") && query_params.len() == 1 {
                handle_get_info(&state).await
            } else if query_params.contains_key("status") && query_params.len() == 1 {
                handle_get_status(&state, &headers).await
            } else if query_params.contains_key("lock_selftest") && query_params.len() == 1 {
                handle_get_lock_selftest(&state).await
            } else if query_params.contains_key("lock_freeze")
                && query_params.contains_key("anchor_id")
                && query_params.len() == 2
            {
                let anchor_hex = query_params
                    .get("anchor_id")
                    .map(|s| s.as_str())
                    .unwrap_or("");
                handle_get_lock_freeze(&state, anchor_hex).await
            } else {
                method_not_allowed()
            }
        }
        Method::HEAD => {
            if !query_params.is_empty() {
                return method_not_allowed();
            }
            handle_head(&state, &headers).await
        }
        Method::PUT => {
            if query_params.contains_key("members") {
                let channel = query_params
                    .get("channel")
                    .map(|s| s.as_str())
                    .unwrap_or("");
                handle_put_members(&state, &headers, channel, body).await
            } else if query_params.contains_key("admin_config") && query_params.len() == 1 {
                handle_put_admin_config(&state, &headers, body).await
            } else if query_params.contains_key("revoke") && query_params.len() == 1 {
                handle_put_revoke(&state, &headers, body).await
            } else if query_params.contains_key("lock_delegate") && query_params.len() == 1 {
                handle_put_lock_delegate(&state, &headers, body).await
            } else if query_params.is_empty() {
                handle_put_slot(&state, &headers, body).await
            } else {
                method_not_allowed()
            }
        }
        Method::POST => {
            if query_params.contains_key("lock_ticket") && query_params.len() == 1 {
                handle_post_lock_ticket(&state, &headers, body).await
            } else if query_params.contains_key("lock_selftest") && query_params.len() == 1 {
                handle_post_lock_selftest(&state, &headers, body).await
            } else if query_params.contains_key("lock_freeze") && query_params.len() == 1 {
                handle_post_lock_freeze(&state, body).await
            } else if query_params.contains_key("lock_import") && query_params.len() == 1 {
                handle_post_lock_import(&state, body).await
            } else if query_params.contains_key("lock_commit") && query_params.len() == 1 {
                handle_post_lock_commit(&state, body).await
            } else if query_params.contains_key("lock") && query_params.len() == 1 {
                handle_post_lock(&state, body).await
            } else {
                method_not_allowed()
            }
        }
        Method::DELETE => {
            if query_params.contains_key("account") && query_params.len() == 1 {
                handle_delete_account(&state, &headers, body).await
            } else if query_params.is_empty() {
                handle_delete_slot(&state, &headers, body).await
            } else {
                method_not_allowed()
            }
        }
        _ => method_not_allowed(),
    }
}

fn method_not_allowed() -> Response {
    let mut resp = json_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "Method or query not allowed",
    );
    resp.headers_mut().insert(
        header::ALLOW,
        HeaderValue::from_static("GET, HEAD, PUT, DELETE, POST"),
    );
    resp
}

async fn handle_get_info(state: &AppState) -> Response {
    let revocation = match state.db.get_revocation() {
        Ok(r) => r,
        Err(e) => return db_err_to_response(e),
    };
    let lock_info = match state.db.get_lock_info_json(&state.config, unix_now()) {
        Ok(v) => v,
        Err(e) => return db_err_to_response(e),
    };
    let payload = serde_json::json!({
        "drop_pub": state.db.effective_drop_pub(&state.config),
        "read_url": state.config.read_url(),
        "register_url": state.config.register_url(),
        "channels": state.config.supported_channels(),
        "revocation": revocation,
        "lock": lock_info,
    });
    let mut resp = (StatusCode::OK, Json(payload)).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

async fn handle_get_status(state: &AppState, headers: &HeaderMap) -> Response {
    let Ok((pubkey, ts, nonce, sig)) = extract_drop_auth_headers(headers) else {
        return json_error(StatusCode::BAD_REQUEST, "Missing or invalid auth headers");
    };
    if state.config.server.admin_pubkey.is_empty() || pubkey != state.config.server.admin_pubkey {
        return json_error(StatusCode::FORBIDDEN, "Admin pubkey required");
    }
    let now = unix_now();
    if !check_timestamp_window(ts, now) {
        return json_error(StatusCode::UNAUTHORIZED, "Timestamp outside allowed window");
    }
    let msg = format_admin_status_message(ts, &nonce);
    if !verify_ed25519_hex(&pubkey, &sig, msg.as_bytes()) {
        return json_error(StatusCode::UNAUTHORIZED, "Invalid admin signature");
    }
    match state.db.check_and_consume_nonce(&nonce, now) {
        Ok(true) => {}
        Ok(false) => return json_error(StatusCode::CONFLICT, "Nonce already used"),
        Err(e) => return db_err_to_response(e),
    }
    match state.db.admin_status(&state.config, now) {
        Ok(status) => {
            let mut resp = (StatusCode::OK, Json(status)).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_head(state: &AppState, headers: &HeaderMap) -> Response {
    let Some(pubkey) = headers
        .get("x-drop-pubkey")
        .and_then(|v| v.to_str().ok())
        .and_then(normalize_pubkey_hex)
    else {
        return json_error(StatusCode::BAD_REQUEST, "Missing or invalid X-Drop-Pubkey");
    };
    if !state.rate_limiter.allow_pubkey(&pubkey) {
        return json_error(StatusCode::TOO_MANY_REQUESTS, "Pubkey rate limit exceeded");
    }

    match state.db.get_revocation() {
        Ok(Some(_)) => return gone_revoked_response(state),
        Ok(None) => {}
        Err(e) => return db_err_to_response(e),
    }

    let channel = match headers.get("x-channel").and_then(|v| v.to_str().ok()) {
        Some(raw) => match validate_channel(raw) {
            Some(ch) => Some(ch),
            None => return json_error(StatusCode::BAD_REQUEST, "Invalid X-Channel"),
        },
        None => None,
    };

    let prefix = match headers.get("x-drop-prefix").and_then(|v| v.to_str().ok()) {
        Some(raw) if !raw.trim().is_empty() => {
            if channel.as_deref() == Some("media") {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "X-Drop-Prefix is disallowed on media channel",
                );
            }
            match validate_drop_prefix(raw) {
                Some(p) => Some(p),
                None => return json_error(StatusCode::BAD_REQUEST, "Invalid X-Drop-Prefix"),
            }
        }
        _ => None,
    };

    let media_id = match headers.get("x-media-id").and_then(|v| v.to_str().ok()) {
        Some(raw) if !raw.trim().is_empty() => match normalize_pubkey_hex(raw) {
            Some(m) => Some(m),
            None => return json_error(StatusCode::BAD_REQUEST, "Invalid X-Media-Id"),
        },
        _ => None,
    };

    let now = unix_now();
    let cap = match state.db.head_capability(
        &state.config,
        &pubkey,
        channel.as_deref(),
        prefix.as_deref(),
        media_id.as_deref(),
        now,
    ) {
        Ok(c) => c,
        Err(e) => return db_err_to_response(e),
    };

    let mut resp = StatusCode::OK.into_response();
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    insert_header_str(
        h,
        "X-Drop-Authorized",
        if cap.authorized { "true" } else { "false" },
    );
    if !cap.allowed_channels.is_empty() {
        insert_header_str(h, "X-Drop-Channels", &cap.allowed_channels.join(","));
    }
    if let Some(max_b) = cap.channel_max_bytes {
        insert_header_str(h, "X-Channel-Max-Bytes", &max_b.to_string());
    }
    if let Some(ttl) = cap.channel_ttl_days {
        insert_header_str(h, "X-Channel-Ttl-Days", &ttl.to_string());
    }
    if let Some(occ) = cap.slot_occupied {
        insert_header_str(h, "X-Slot-Occupied", if occ { "true" } else { "false" });
    }
    if let Some(ref etag) = cap.slot_etag {
        insert_header_str(h, "ETag", &format!("\"{}\"", etag));
    }
    if let Some(mc) = cap.media_max_count {
        insert_header_str(h, "X-Media-Max-Count", &mc.to_string());
    }
    if let Some(mb) = cap.media_max_user_bytes {
        insert_header_str(h, "X-Media-Max-Bytes", &mb.to_string());
    }
    insert_header_str(h, "X-Media-Count", &cap.media_used_count.to_string());
    insert_header_str(h, "X-Media-Bytes", &cap.media_used_bytes.to_string());
    resp
}

async fn handle_put_members(
    state: &AppState,
    headers: &HeaderMap,
    raw_channel: &str,
    body: Body,
) -> Response {
    let Some(channel) = validate_admin_member_channel(raw_channel) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "Missing or invalid channel query parameter",
        );
    };
    let Ok((pubkey, ts, nonce, sig)) = extract_drop_auth_headers(headers) else {
        return json_error(StatusCode::BAD_REQUEST, "Missing or invalid auth headers");
    };
    if state.config.server.admin_pubkey.is_empty() || pubkey != state.config.server.admin_pubkey {
        return json_error(StatusCode::FORBIDDEN, "Admin pubkey required");
    }
    let now = unix_now();
    if !check_timestamp_window(ts, now) {
        return json_error(StatusCode::UNAUTHORIZED, "Timestamp outside allowed window");
    }

    let bytes = match axum::body::to_bytes(body, 512 * 1024).await {
        Ok(b) => b,
        Err(_) => return json_error(StatusCode::PAYLOAD_TOO_LARGE, "Members payload too large"),
    };
    let body_hash = sha256_hex(&bytes);
    let msg = format_admin_put_members_message(&channel, ts, &nonce, &body_hash);
    if !verify_ed25519_hex(&pubkey, &sig, msg.as_bytes()) {
        return json_error(StatusCode::UNAUTHORIZED, "Invalid admin signature");
    }

    match state.db.check_and_consume_nonce(&nonce, now) {
        Ok(true) => {}
        Ok(false) => return json_error(StatusCode::CONFLICT, "Nonce already used"),
        Err(e) => return db_err_to_response(e),
    }

    let payload: PutMembersPayload = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid members JSON"),
    };

    let mut clean_pks = Vec::with_capacity(payload.pubkeys.len());
    for raw_pk in &payload.pubkeys {
        let Some(norm) = normalize_pubkey_hex(raw_pk) else {
            return json_error(StatusCode::BAD_REQUEST, "Invalid member pubkey hex");
        };
        clean_pks.push(norm);
    }

    match state
        .db
        .put_admin_members(&state.config, &channel, &clean_pks, now)
    {
        Ok(count) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ok",
                "channel": channel,
                "members": count,
            })),
        )
            .into_response(),
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_put_admin_config(state: &AppState, headers: &HeaderMap, body: Body) -> Response {
    if !state.config.mode.enable_admin_app {
        return json_error(StatusCode::FORBIDDEN, "Admin app management disabled");
    }
    let (bytes, now) = match verify_admin_request_with_body(
        state,
        headers,
        body,
        16 * 1024,
        format_admin_put_config_message,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let payload: PutAdminConfigPayload = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid admin_config JSON"),
    };

    if payload.max_members == 0 || payload.max_members > 100_000 {
        return json_error(
            StatusCode::BAD_REQUEST,
            "max_members must be between 1 and 100000",
        );
    }
    if payload.max_user_storage_mb < 10 {
        return json_error(
            StatusCode::BAD_REQUEST,
            "max_user_storage_mb must be at least 10 MB",
        );
    }
    if payload.max_total_storage_mb < payload.max_user_storage_mb
        || payload.max_total_storage_mb > 10_485_760
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "max_total_storage_mb must be between max_user_storage_mb and 10485760 MB",
        );
    }

    let ov = AdminConfigOverrides {
        max_total_storage_mb: payload.max_total_storage_mb,
        max_members: payload.max_members,
        max_user_storage_mb: payload.max_user_storage_mb,
    };
    if let Err(e) = state.db.set_admin_config_overrides(&ov) {
        return db_err_to_response(e);
    }

    match state.db.admin_status(&state.config, now) {
        Ok(status) => {
            let mut resp = (StatusCode::OK, Json(status)).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_put_revoke(state: &AppState, headers: &HeaderMap, body: Body) -> Response {
    let Ok((pubkey, ts, nonce, sig)) = extract_drop_auth_headers(headers) else {
        return json_error(StatusCode::BAD_REQUEST, "Missing or invalid auth headers");
    };
    if state.config.server.admin_pubkey.is_empty() || pubkey != state.config.server.admin_pubkey {
        return json_error(StatusCode::FORBIDDEN, "Admin pubkey required");
    }
    let now = unix_now();
    if !check_timestamp_window(ts, now) {
        return json_error(StatusCode::UNAUTHORIZED, "Timestamp outside allowed window");
    }

    let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Revocation payload too large",
            )
        }
    };
    let body_hash = sha256_hex(&bytes);
    let msg = format_admin_put_revoke_message(ts, &nonce, &body_hash);
    if !verify_ed25519_hex(&pubkey, &sig, msg.as_bytes()) {
        return json_error(StatusCode::UNAUTHORIZED, "Invalid admin signature");
    }

    match state.db.check_and_consume_nonce(&nonce, now) {
        Ok(true) => {}
        Ok(false) => return json_error(StatusCode::CONFLICT, "Nonce already used"),
        Err(e) => return db_err_to_response(e),
    }

    let val: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid revocation JSON"),
    };

    let should_clear = val.is_null()
        || val.get("clear").and_then(|v| v.as_bool()) == Some(true)
        || val.get("revoked").and_then(|v| v.as_bool()) == Some(false)
        || val.get("effective_at").is_some_and(|v| v.is_null());

    if should_clear {
        return match state.db.set_revocation(None) {
            Ok(()) => (
                StatusCode::OK,
                Json(serde_json::json!({ "status": "ok", "revoked": false })),
            )
                .into_response(),
            Err(e) => db_err_to_response(e),
        };
    }

    let notice_val = val.get("notice").unwrap_or(&val);
    let notice: RevocationNotice = match serde_json::from_value(notice_val.clone()) {
        Ok(n) => n,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid revocation notice fields"),
    };

    if let Err(err) = verify_revocation_notice(&notice, &state.config.server.admin_pubkey) {
        return json_error(StatusCode::BAD_REQUEST, &err);
    }

    match state.db.set_revocation(Some(&notice)) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ok",
                "revoked": true,
                "revocation": notice,
            })),
        )
            .into_response(),
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_put_slot(state: &AppState, headers: &HeaderMap, body: Body) -> Response {
    match state.db.get_revocation() {
        Ok(Some(_)) => return gone_revoked_response(state),
        Ok(None) => {}
        Err(e) => return db_err_to_response(e),
    }

    let Ok((pubkey, ts, nonce, sig)) = extract_drop_auth_headers(headers) else {
        return json_error(StatusCode::BAD_REQUEST, "Missing or invalid auth headers");
    };
    if !state.rate_limiter.allow_pubkey(&pubkey) {
        return json_error(StatusCode::TOO_MANY_REQUESTS, "Pubkey rate limit exceeded");
    }

    let Some(channel) = headers
        .get("x-channel")
        .and_then(|v| v.to_str().ok())
        .and_then(validate_channel)
    else {
        return json_error(StatusCode::BAD_REQUEST, "Missing or invalid X-Channel");
    };

    let now = unix_now();
    if !check_timestamp_window(ts, now) {
        return json_error(StatusCode::UNAUTHORIZED, "Timestamp outside allowed window");
    }

    let (target, prefix_opt, media_id_opt) = if channel == "media" {
        if headers
            .get("x-drop-prefix")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| !s.trim().is_empty())
        {
            return json_error(
                StatusCode::BAD_REQUEST,
                "X-Drop-Prefix is disallowed on media channel",
            );
        }
        let Some(mid) = headers
            .get("x-media-id")
            .and_then(|v| v.to_str().ok())
            .and_then(normalize_pubkey_hex)
        else {
            return json_error(StatusCode::BAD_REQUEST, "Missing or invalid X-Media-Id");
        };
        (format!("media:{}", mid), None, Some(mid))
    } else {
        if headers
            .get("x-media-id")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| !s.trim().is_empty())
        {
            return json_error(
                StatusCode::BAD_REQUEST,
                "X-Media-Id is only valid on media channel",
            );
        }
        let prefix = match headers.get("x-drop-prefix").and_then(|v| v.to_str().ok()) {
            Some(raw) if !raw.trim().is_empty() => match validate_drop_prefix(raw) {
                Some(p) => Some(p),
                None => return json_error(StatusCode::BAD_REQUEST, "Invalid X-Drop-Prefix"),
            },
            _ => None,
        };
        (channel.clone(), prefix, None)
    };

    let max_body = state.config.max_upload_body_bytes();
    let bytes = match axum::body::to_bytes(body, max_body).await {
        Ok(b) => b,
        Err(_) => return json_error(StatusCode::PAYLOAD_TOO_LARGE, "Payload too large"),
    };
    let body_hash = sha256_hex(&bytes);
    let canonical = parse_member_message(
        "PUT",
        &target,
        prefix_opt.as_deref().unwrap_or(""),
        ts,
        &nonce,
        &body_hash,
    );
    if !verify_ed25519_hex(&pubkey, &sig, canonical.as_bytes()) {
        return json_error(StatusCode::UNAUTHORIZED, "Invalid signature");
    }

    match state.db.check_and_consume_nonce(&nonce, now) {
        Ok(true) => {}
        Ok(false) => return json_error(StatusCode::CONFLICT, "Nonce already used"),
        Err(e) => return db_err_to_response(e),
    }

    let if_match = headers.get(header::IF_MATCH).and_then(|v| v.to_str().ok());
    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    let precondition = ConditionalPrecondition::from_headers(if_match, if_none_match);

    let outcome = if let Some(ref mid) = media_id_opt {
        state
            .db
            .put_media(&state.config, &pubkey, mid, &bytes, &precondition, now)
    } else {
        state.db.put_slot(
            &state.config,
            &pubkey,
            &channel,
            prefix_opt.as_deref(),
            &bytes,
            &precondition,
            now,
        )
    };

    match outcome {
        Ok(out) => {
            let etag = out.etag.clone();
            let mut body_json = serde_json::json!({
                "status": "ok",
                "channel": out.channel,
                "bytes": out.bytes,
                "etag": out.etag,
                "evicted_media": out.evicted_media,
            });
            if media_id_opt.is_none() {
                match state
                    .db
                    .sign_slot_ack(&pubkey, prefix_opt.as_deref(), &channel, &etag, now)
                {
                    Ok(ack) => {
                        body_json["slot_ack"] = ack;
                    }
                    Err(e) => return db_err_to_response(e),
                }
            }
            let mut resp = (StatusCode::OK, Json(body_json)).into_response();
            insert_header_str(resp.headers_mut(), "ETag", &format!("\"{}\"", etag));
            resp
        }
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_delete_slot(state: &AppState, headers: &HeaderMap, body: Body) -> Response {
    match state.db.get_revocation() {
        Ok(Some(_)) => return gone_revoked_response(state),
        Ok(None) => {}
        Err(e) => return db_err_to_response(e),
    }

    let Ok((pubkey, ts, nonce, sig)) = extract_drop_auth_headers(headers) else {
        return json_error(StatusCode::BAD_REQUEST, "Missing or invalid auth headers");
    };
    if !state.rate_limiter.allow_pubkey(&pubkey) {
        return json_error(StatusCode::TOO_MANY_REQUESTS, "Pubkey rate limit exceeded");
    }

    let Some(channel) = headers
        .get("x-channel")
        .and_then(|v| v.to_str().ok())
        .and_then(validate_channel)
    else {
        return json_error(StatusCode::BAD_REQUEST, "Missing or invalid X-Channel");
    };

    let now = unix_now();
    if !check_timestamp_window(ts, now) {
        return json_error(StatusCode::UNAUTHORIZED, "Timestamp outside allowed window");
    }

    let (target, prefix_opt, media_id_opt) = if channel == "media" {
        if headers
            .get("x-drop-prefix")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| !s.trim().is_empty())
        {
            return json_error(
                StatusCode::BAD_REQUEST,
                "X-Drop-Prefix is disallowed on media channel",
            );
        }
        let media_id = match headers.get("x-media-id").and_then(|v| v.to_str().ok()) {
            Some(raw) if !raw.trim().is_empty() => match normalize_pubkey_hex(raw) {
                Some(m) => Some(m),
                None => return json_error(StatusCode::BAD_REQUEST, "Invalid X-Media-Id"),
            },
            _ => None,
        };
        let target = match &media_id {
            Some(mid) => format!("media:{}", mid),
            None => "media".to_string(),
        };
        (target, None, media_id)
    } else {
        let prefix = match headers.get("x-drop-prefix").and_then(|v| v.to_str().ok()) {
            Some(raw) if !raw.trim().is_empty() => match validate_drop_prefix(raw) {
                Some(p) => Some(p),
                None => return json_error(StatusCode::BAD_REQUEST, "Invalid X-Drop-Prefix"),
            },
            _ => None,
        };
        (channel.clone(), prefix, None)
    };

    let bytes = match axum::body::to_bytes(body, 4096).await {
        Ok(b) => b,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid DELETE body"),
    };
    let body_hash = sha256_hex(&bytes);
    let canonical = parse_member_message(
        "DELETE",
        &target,
        prefix_opt.as_deref().unwrap_or(""),
        ts,
        &nonce,
        &body_hash,
    );
    if !verify_ed25519_hex(&pubkey, &sig, canonical.as_bytes()) {
        return json_error(StatusCode::UNAUTHORIZED, "Invalid signature");
    }

    match state.db.check_and_consume_nonce(&nonce, now) {
        Ok(true) => {}
        Ok(false) => return json_error(StatusCode::CONFLICT, "Nonce already used"),
        Err(e) => return db_err_to_response(e),
    }

    if channel == "media" {
        match state
            .db
            .delete_media(&state.config, &pubkey, media_id_opt.as_deref(), now)
        {
            Ok(deleted) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "ok",
                    "channel": "media",
                    "deleted": deleted,
                })),
            )
                .into_response(),
            Err(e) => db_err_to_response(e),
        }
    } else {
        match state
            .db
            .delete_slot(&state.config, &pubkey, &channel, prefix_opt.as_deref(), now)
        {
            Ok(()) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "ok",
                    "channel": channel,
                })),
            )
                .into_response(),
            Err(e) => db_err_to_response(e),
        }
    }
}

async fn handle_delete_account(state: &AppState, headers: &HeaderMap, body: Body) -> Response {
    let Ok((pubkey, ts, nonce, sig)) = extract_drop_auth_headers(headers) else {
        return json_error(StatusCode::BAD_REQUEST, "Missing or invalid auth headers");
    };
    if !state.rate_limiter.allow_pubkey(&pubkey) {
        return json_error(StatusCode::TOO_MANY_REQUESTS, "Pubkey rate limit exceeded");
    }
    let now = unix_now();
    if !check_timestamp_window(ts, now) {
        return json_error(StatusCode::UNAUTHORIZED, "Timestamp outside allowed window");
    }
    let bytes = match axum::body::to_bytes(body, 1024).await {
        Ok(b) => b,
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "DELETE ?account body must be empty",
            )
        }
    };
    if !bytes.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "DELETE ?account body must be empty",
        );
    }

    let msg = format_delete_account_message(ts, &nonce);
    if !verify_ed25519_hex(&pubkey, &sig, msg.as_bytes()) {
        return json_error(StatusCode::UNAUTHORIZED, "Invalid signature");
    }

    match state.db.check_and_consume_nonce(&nonce, now) {
        Ok(true) => {}
        Ok(false) => return json_error(StatusCode::CONFLICT, "Nonce already used"),
        Err(e) => return db_err_to_response(e),
    }

    match state.db.delete_account_and_data(&pubkey, false) {
        Ok((deleted_slots, deleted_media, deleted_account)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ok",
                "deleted_account": deleted_account,
                "deleted_slots": deleted_slots,
                "deleted_media": deleted_media,
            })),
        )
            .into_response(),
        Err(e) => db_err_to_response(e),
    }
}

async fn verify_admin_request_with_body<F>(
    state: &AppState,
    headers: &HeaderMap,
    body: Body,
    max_body_bytes: usize,
    format_msg: F,
) -> Result<(Vec<u8>, u64), Response>
where
    F: FnOnce(i64, &str, &str) -> String,
{
    let Ok((pubkey, ts, nonce, sig)) = extract_drop_auth_headers(headers) else {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "Missing or invalid auth headers",
        ));
    };
    if state.config.server.admin_pubkey.is_empty() || pubkey != state.config.server.admin_pubkey {
        return Err(json_error(StatusCode::FORBIDDEN, "Admin pubkey required"));
    }
    let now = unix_now();
    if !check_timestamp_window(ts, now) {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "Timestamp outside allowed window",
        ));
    }
    let bytes = match axum::body::to_bytes(body, max_body_bytes).await {
        Ok(b) => b.to_vec(),
        Err(_) => {
            return Err(json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Request body too large",
            ));
        }
    };
    let body_hash = sha256_hex(&bytes);
    let msg = format_msg(ts, &nonce, &body_hash);
    if !verify_ed25519_hex(&pubkey, &sig, msg.as_bytes()) {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "Invalid admin signature",
        ));
    }
    match state.db.check_and_consume_nonce(&nonce, now) {
        Ok(true) => Ok((bytes, now)),
        Ok(false) => Err(json_error(StatusCode::CONFLICT, "Nonce already used")),
        Err(e) => Err(db_err_to_response(e)),
    }
}

async fn handle_get_lock_selftest(state: &AppState) -> Response {
    match state.db.get_or_run_lock_selftest(&state.config, unix_now()) {
        Ok(report) => {
            let mut resp = (StatusCode::OK, Json(report)).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_post_lock_selftest(state: &AppState, headers: &HeaderMap, body: Body) -> Response {
    let (_bytes, now) = match verify_admin_request_with_body(
        state,
        headers,
        body,
        4096,
        format_admin_post_lock_selftest_message,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    match state.db.run_lock_selftest(&state.config, now) {
        Ok(report) => {
            let mut resp = (StatusCode::OK, Json(report)).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_put_lock_delegate(state: &AppState, headers: &HeaderMap, body: Body) -> Response {
    let (bytes, _now) = match verify_admin_request_with_body(
        state,
        headers,
        body,
        16 * 1024,
        format_admin_put_lock_delegate_message,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let del: LockDelegation = match serde_json::from_slice(&bytes) {
        Ok(d) => d,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid lock delegation JSON"),
    };

    match state.db.set_lock_delegation(&state.config, del) {
        Ok(saved) => (StatusCode::OK, Json(saved)).into_response(),
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_post_lock_ticket(state: &AppState, headers: &HeaderMap, body: Body) -> Response {
    match state.db.get_revocation() {
        Ok(Some(_)) => return gone_revoked_response(state),
        Ok(None) => {}
        Err(e) => return db_err_to_response(e),
    }

    let has_any_auth_header = headers.contains_key("x-drop-pubkey")
        || headers.contains_key("x-drop-timestamp")
        || headers.contains_key("x-drop-nonce")
        || headers.contains_key("x-drop-signature");

    let parsed_auth = if has_any_auth_header {
        let Ok((pubkey, ts, nonce, sig)) = extract_drop_auth_headers(headers) else {
            return json_error(StatusCode::BAD_REQUEST, "Missing or invalid auth headers");
        };
        if !state.rate_limiter.allow_pubkey(&pubkey) {
            return json_error(StatusCode::TOO_MANY_REQUESTS, "Pubkey rate limit exceeded");
        }
        Some((pubkey, ts, nonce, sig))
    } else {
        None
    };

    let bytes = match axum::body::to_bytes(body, 16 * 1024).await {
        Ok(b) => b,
        Err(_) => return json_error(StatusCode::PAYLOAD_TOO_LARGE, "Ticket request too large"),
    };

    let req: LockTicketRequest = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid lock_ticket JSON"),
    };

    let caller = match &parsed_auth {
        Some((pubkey, ts, nonce, sig)) => TicketCallerAuth::SignedMember {
            pubkey_hex: pubkey,
            timestamp: *ts,
            nonce,
            sig,
            raw_body: &bytes,
        },
        None => TicketCallerAuth::UnauthenticatedPow,
    };

    match state
        .db
        .issue_genesis_ticket(&state.config, caller, req, unix_now())
    {
        Ok(ticket) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ticket": ticket })),
        )
            .into_response(),
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_post_lock(state: &AppState, body: Body) -> Response {
    match state.db.get_revocation() {
        Ok(Some(_)) => return gone_revoked_response(state),
        Ok(None) => {}
        Err(e) => return db_err_to_response(e),
    }

    let bytes = match axum::body::to_bytes(body, 256 * 1024).await {
        Ok(b) => b,
        Err(_) => return json_error(StatusCode::PAYLOAD_TOO_LARGE, "Lock payload too large"),
    };

    let val: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid lock JSON"),
    };

    if val.get("probe").and_then(|v| v.as_bool()) == Some(true) {
        let Some(client_nonce) = val.get("client_nonce").and_then(|v| v.as_str()) else {
            return json_error(StatusCode::BAD_REQUEST, "Missing probe client_nonce");
        };
        return match state
            .db
            .sign_lock_probe(&state.config, client_nonce, unix_now())
        {
            Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
            Err(e) => db_err_to_response(e),
        };
    }

    let req: LockBatchRequest = match serde_json::from_value(val) {
        Ok(r) => r,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid lock batch request JSON"),
    };

    match state.db.process_lock_batch(&state.config, req, unix_now()) {
        Ok((code, body)) => {
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, Json(body)).into_response()
        }
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_get_lock_freeze(state: &AppState, anchor_hex: &str) -> Response {
    match state.db.get_revocation() {
        Ok(Some(_)) => return gone_revoked_response(state),
        Ok(None) => {}
        Err(e) => return db_err_to_response(e),
    }
    let Ok(anchor_id) = humoco_proto::decode_hex_fixed::<32>(anchor_hex) else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid anchor_id hex");
    };
    match state
        .db
        .get_lock_freeze_status(&state.config, anchor_id, unix_now())
    {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_post_lock_freeze(state: &AppState, body: Body) -> Response {
    match state.db.get_revocation() {
        Ok(Some(_)) => return gone_revoked_response(state),
        Ok(None) => {}
        Err(e) => return db_err_to_response(e),
    }
    let bytes = match axum::body::to_bytes(body, 256 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Lock freeze payload too large",
            )
        }
    };
    let req: LockFreezeRequest = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid lock_freeze JSON"),
    };
    match state.db.process_lock_freeze(&state.config, req, unix_now()) {
        Ok((code, val)) => {
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, Json(val)).into_response()
        }
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_post_lock_import(state: &AppState, body: Body) -> Response {
    match state.db.get_revocation() {
        Ok(Some(_)) => return gone_revoked_response(state),
        Ok(None) => {}
        Err(e) => return db_err_to_response(e),
    }
    let bytes = match axum::body::to_bytes(body, 8 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Lock import payload too large",
            )
        }
    };
    let req: LockImportRequest = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid lock_import JSON"),
    };
    match state.db.process_lock_import(&state.config, req, unix_now()) {
        Ok((code, val)) => {
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, Json(val)).into_response()
        }
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_post_lock_commit(state: &AppState, body: Body) -> Response {
    match state.db.get_revocation() {
        Ok(Some(_)) => return gone_revoked_response(state),
        Ok(None) => {}
        Err(e) => return db_err_to_response(e),
    }
    let bytes = match axum::body::to_bytes(body, 2 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Lock commit payload too large",
            )
        }
    };
    let req: LockCommitRequest = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid lock_commit JSON"),
    };
    match state.db.process_lock_commit(&state.config, req, unix_now()) {
        Ok((code, val)) => {
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, Json(val)).into_response()
        }
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_static_anchor(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    method: Method,
    Path(filename): Path<String>,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed();
    }
    let peer_addr = peer.map(|ConnectInfo(s)| s);
    let client_ip = extract_client_ip(peer_addr, &headers, state.config.server.trusted_proxy_hops);
    if !state.rate_limiter.allow_ip(client_ip) {
        return json_error(StatusCode::TOO_MANY_REQUESTS, "IP rate limit exceeded");
    }
    if !state.config.lock.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(anchor_hex) = filename.strip_suffix(".bin") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if humoco_proto::decode_hex_fixed::<32>(anchor_hex).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(normalize_etag);

    match state.db.get_static_anchor_manifest(anchor_hex) {
        Ok(Some(bytes)) => {
            let etag = sha256_hex(&bytes);
            if if_none_match.as_deref() == Some(etag.as_str()) {
                return not_modified_with_etag(&etag, "no-cache");
            }
            binary_or_json_response(method, "application/json", &etag, "no-cache", bytes)
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_static_lock(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    method: Method,
    Path((quarter, bucket, filename)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed();
    }
    let peer_addr = peer.map(|ConnectInfo(s)| s);
    let client_ip = extract_client_ip(peer_addr, &headers, state.config.server.trusted_proxy_hops);
    if !state.rate_limiter.allow_ip(client_ip) {
        return json_error(StatusCode::TOO_MANY_REQUESTS, "IP rate limit exceeded");
    }
    if !state.config.lock.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(file_hex) = filename.strip_suffix(".lock") else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match state.db.get_static_lock_entry(&quarter, &bucket, file_hex) {
        Ok(Some(bytes)) => {
            let etag = sha256_hex(&bytes);
            binary_or_json_response(
                method,
                "application/octet-stream",
                &etag,
                "public, max-age=31536000, immutable",
                bytes,
            )
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => db_err_to_response(e),
    }
}

async fn handle_static_data(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    method: Method,
    Path(filename): Path<String>,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed();
    }
    let peer_addr = peer.map(|ConnectInfo(s)| s);
    let client_ip = extract_client_ip(peer_addr, &headers, state.config.server.trusted_proxy_hops);
    if !state.rate_limiter.allow_ip(client_ip) {
        return json_error(StatusCode::TOO_MANY_REQUESTS, "IP rate limit exceeded");
    }

    if filename.is_empty()
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains("..")
    {
        return StatusCode::NOT_FOUND.into_response();
    }

    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(normalize_etag);

    if filename == "index.json" {
        return match state.db.build_admin_index(&state.config) {
            Ok((entries, etag)) => {
                if if_none_match.as_deref() == Some(etag.as_str()) {
                    return not_modified_with_etag(&etag, "no-cache");
                }
                let mut resp = (StatusCode::OK, Json(entries)).into_response();
                insert_header_str(resp.headers_mut(), "ETag", &format!("\"{}\"", etag));
                insert_header_str(resp.headers_mut(), "Cache-Control", "no-cache");
                if method == Method::HEAD {
                    *resp.body_mut() = Body::empty();
                }
                resp
            }
            Err(e) => db_err_to_response(e),
        };
    }

    if filename == "revocation.json" {
        return match state.db.get_revocation() {
            Ok(Some(notice)) => {
                let bytes = match serde_json::to_vec(&notice) {
                    Ok(b) => b,
                    Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                };
                let etag = sha256_hex(&bytes);
                if if_none_match.as_deref() == Some(etag.as_str()) {
                    return not_modified_with_etag(&etag, "no-cache");
                }
                binary_or_json_response(method, "application/json", &etag, "no-cache", bytes)
            }
            Ok(None) => StatusCode::NOT_FOUND.into_response(),
            Err(e) => db_err_to_response(e),
        };
    }

    let Some(stem) = filename.strip_suffix(".bin") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some((slot_or_media, channel)) = stem.rsplit_once('.') else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let now = unix_now();
    if channel == "media" {
        let Some(media_id) = normalize_pubkey_hex(slot_or_media) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if slot_or_media != media_id {
            return StatusCode::NOT_FOUND.into_response();
        }
        return match state.db.get_media_blob(&state.config, &media_id, now) {
            Ok(Some((meta, data))) => {
                if if_none_match.as_deref() == Some(meta.etag.as_str()) {
                    return not_modified_with_etag(&meta.etag, "public, max-age=60");
                }
                let _ = state.db.touch_media_access(&media_id, now);
                binary_or_json_response(
                    method,
                    "application/octet-stream",
                    &meta.etag,
                    "public, max-age=60",
                    data,
                )
            }
            Ok(None) => StatusCode::NOT_FOUND.into_response(),
            Err(e) => db_err_to_response(e),
        };
    }

    if !matches!(channel, "card" | "wot" | "backup" | "post") {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !is_valid_slot_id_exact(slot_or_media) {
        return StatusCode::NOT_FOUND.into_response();
    }

    match state
        .db
        .get_slot_blob(&state.config, channel, slot_or_media, now)
    {
        Ok(Some((meta, data))) => {
            if if_none_match.as_deref() == Some(meta.etag.as_str()) {
                return not_modified_with_etag(&meta.etag, "no-cache");
            }
            binary_or_json_response(
                method,
                "application/octet-stream",
                &meta.etag,
                "no-cache",
                data,
            )
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => db_err_to_response(e),
    }
}

fn is_valid_slot_id_exact(s: &str) -> bool {
    if let Some((pk, prefix)) = s.split_once('_') {
        normalize_pubkey_hex(pk).as_deref() == Some(pk)
            && validate_drop_prefix(prefix).as_deref() == Some(prefix)
    } else {
        normalize_pubkey_hex(s).as_deref() == Some(s)
    }
}

fn binary_or_json_response(
    method: Method,
    content_type: &'static str,
    etag: &str,
    cache_control: &'static str,
    bytes: Vec<u8>,
) -> Response {
    let mut resp = if method == Method::HEAD {
        Response::new(Body::empty())
    } else {
        Response::new(Body::from(bytes))
    };
    *resp.status_mut() = StatusCode::OK;
    insert_header_str(resp.headers_mut(), "Content-Type", content_type);
    insert_header_str(resp.headers_mut(), "ETag", &format!("\"{}\"", etag));
    insert_header_str(resp.headers_mut(), "Cache-Control", cache_control);
    resp
}

fn not_modified_with_etag(etag: &str, cache_control: &'static str) -> Response {
    let mut resp = StatusCode::NOT_MODIFIED.into_response();
    insert_header_str(resp.headers_mut(), "ETag", &format!("\"{}\"", etag));
    insert_header_str(resp.headers_mut(), "Cache-Control", cache_control);
    resp
}

fn gone_revoked_response(state: &AppState) -> Response {
    let notice = state.db.get_revocation().ok().flatten();
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": "This sync service has been revoked",
            "revocation": notice,
        })),
    )
        .into_response()
}

fn extract_drop_auth_headers(headers: &HeaderMap) -> Result<(String, i64, String, String), ()> {
    let pubkey = headers
        .get("x-drop-pubkey")
        .and_then(|v| v.to_str().ok())
        .and_then(normalize_pubkey_hex)
        .ok_or(())?;
    let ts: i64 = headers
        .get("x-drop-timestamp")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<i64>().ok())
        .ok_or(())?;
    let nonce = headers
        .get("x-drop-nonce")
        .and_then(|v| v.to_str().ok())
        .and_then(validate_nonce_hex)
        .ok_or(())?;
    let sig = headers
        .get("x-drop-signature")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| {
            s.len() == 128
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or(())?;
    Ok((pubkey, ts, nonce, sig))
}

fn parse_query_map(uri: &Uri) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Some(q) = uri.query() {
        for (k, v) in form_urlencoded::parse(q.as_bytes()) {
            map.insert(k.into_owned(), v.into_owned());
        }
    }
    map
}

fn insert_header_str(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let (Ok(hn), Ok(hv)) = (
        header::HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.insert(hn, hv);
    }
}
