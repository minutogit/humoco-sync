use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::crypto::{normalize_pubkey_hex, unix_now};
use crate::db::AccountStatus;
use crate::state::{db_err_to_response, json_error, AppState};

pub fn admin_api_router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/stats", get(api_stats))
        .route("/api/v1/admin/users", get(api_list_users))
        .route(
            "/api/v1/admin/users/:pubkey",
            get(api_get_user).delete(api_delete_user),
        )
        .route(
            "/api/v1/admin/users/:pubkey/profile",
            post(api_set_user_profile),
        )
        .route(
            "/api/v1/admin/users/:pubkey/status",
            post(api_set_user_status),
        )
        .route(
            "/api/v1/admin/codes",
            get(api_list_codes).post(api_create_codes),
        )
}

fn check_bearer_auth(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let configured_hash = if !state
        .config
        .security
        .api_bearer_token_hash
        .trim()
        .is_empty()
    {
        &state.config.security.api_bearer_token_hash
    } else {
        &state.config.security.admin_token_hash
    };
    if configured_hash.trim().is_empty() {
        return Some(json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Admin API token not configured",
        ));
    }
    let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return Some(json_error(
            StatusCode::UNAUTHORIZED,
            "Missing Authorization header",
        ));
    };
    let Some(token) = auth.strip_prefix("Bearer ").map(str::trim) else {
        return Some(json_error(
            StatusCode::UNAUTHORIZED,
            "Expected Bearer token",
        ));
    };
    if !state.token_verifier.verify_token(configured_hash, token) {
        return Some(json_error(StatusCode::FORBIDDEN, "Invalid Bearer token"));
    }
    None
}

async fn api_stats(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(resp) = check_bearer_auth(&state, &headers) {
        return resp;
    }
    let now = unix_now();
    match state.db.admin_status(&state.config, now) {
        Ok(stats) => (StatusCode::OK, Json(stats)).into_response(),
        Err(e) => db_err_to_response(e),
    }
}

async fn api_list_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(resp) = check_bearer_auth(&state, &headers) {
        return resp;
    }
    let now = unix_now();
    match state.db.list_admin_users(&state.config, now) {
        Ok(users) => (StatusCode::OK, Json(serde_json::json!({ "users": users }))).into_response(),
        Err(e) => db_err_to_response(e),
    }
}

async fn api_get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_pk): Path<String>,
) -> Response {
    if let Some(resp) = check_bearer_auth(&state, &headers) {
        return resp;
    }
    let Some(pk) = normalize_pubkey_hex(&raw_pk) else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid pubkey hex");
    };
    let now = unix_now();
    match state.db.get_admin_user_summary(&state.config, &pk, now) {
        Ok(Some(u)) => (StatusCode::OK, Json(u)).into_response(),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "User not found"),
        Err(e) => db_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct SetProfilePayload {
    profile: String,
    #[serde(default)]
    duration_days: Option<u32>,
    #[serde(default)]
    contact_email: Option<String>,
}

async fn api_set_user_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_pk): Path<String>,
    Json(payload): Json<SetProfilePayload>,
) -> Response {
    if let Some(resp) = check_bearer_auth(&state, &headers) {
        return resp;
    }
    let Some(pk) = normalize_pubkey_hex(&raw_pk) else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid pubkey hex");
    };
    let now = unix_now();
    if let Err(e) = state.db.register_or_upgrade_user(
        &state.config,
        &pk,
        payload.profile.trim(),
        payload.contact_email.as_deref(),
        payload.duration_days,
        "admin",
        now,
    ) {
        return db_err_to_response(e);
    }
    match state.db.get_admin_user_summary(&state.config, &pk, now) {
        Ok(Some(summary)) => (StatusCode::OK, Json(summary)).into_response(),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "User not found"),
        Err(e) => db_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct SetStatusPayload {
    status: AccountStatus,
}

async fn api_set_user_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_pk): Path<String>,
    Json(payload): Json<SetStatusPayload>,
) -> Response {
    if let Some(resp) = check_bearer_auth(&state, &headers) {
        return resp;
    }
    let Some(pk) = normalize_pubkey_hex(&raw_pk) else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid pubkey hex");
    };
    let now = unix_now();
    if let Err(e) = state.db.set_user_status(&pk, payload.status, now) {
        return db_err_to_response(e);
    }
    match state.db.get_admin_user_summary(&state.config, &pk, now) {
        Ok(Some(summary)) => (StatusCode::OK, Json(summary)).into_response(),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "User not found"),
        Err(e) => db_err_to_response(e),
    }
}

async fn api_delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_pk): Path<String>,
) -> Response {
    if let Some(resp) = check_bearer_auth(&state, &headers) {
        return resp;
    }
    let Some(pk) = normalize_pubkey_hex(&raw_pk) else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid pubkey hex");
    };
    match state.db.delete_account_and_data(&pk, false) {
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

async fn api_list_codes(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(resp) = check_bearer_auth(&state, &headers) {
        return resp;
    }
    match state.db.list_redeem_codes() {
        Ok(codes) => (StatusCode::OK, Json(serde_json::json!({ "codes": codes }))).into_response(),
        Err(e) => db_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct CreateCodesPayload {
    #[serde(default = "default_code_count")]
    count: usize,
    profile: String,
    #[serde(default)]
    duration_days: Option<u32>,
    #[serde(default = "default_max_uses")]
    max_uses: u32,
    #[serde(default)]
    expires_in_days: Option<u32>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    prefix: Option<String>,
}

fn default_code_count() -> usize {
    1
}
fn default_max_uses() -> u32 {
    1
}

async fn api_create_codes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateCodesPayload>,
) -> Response {
    if let Some(resp) = check_bearer_auth(&state, &headers) {
        return resp;
    }
    let count = payload.count.clamp(1, 500);
    let now = unix_now();
    match state.db.create_redeem_codes(
        &state.config,
        count,
        payload.profile.trim(),
        payload.duration_days,
        payload.max_uses,
        payload.expires_in_days,
        payload.note,
        payload.prefix.as_deref(),
        now,
    ) {
        Ok(codes) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "codes": codes })),
        )
            .into_response(),
        Err(e) => db_err_to_response(e),
    }
}
