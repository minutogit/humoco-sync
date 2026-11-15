use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::config::Config;
use crate::crypto::TokenVerifierCache;
use crate::db::{DbError, SyncDb};
use crate::mailer::Mailer;
use crate::ratelimit::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Arc<SyncDb>,
    pub rate_limiter: Arc<RateLimiter>,
    pub token_verifier: Arc<TokenVerifierCache>,
    pub mailer: Arc<Mailer>,
}

impl AppState {
    pub fn from_config(cfg: Config) -> Result<Self, DbError> {
        let db = Arc::new(SyncDb::open(&cfg.server.db_path, &cfg.server.server_pepper_hex)?);
        let rate_limiter = Arc::new(RateLimiter::new(
            cfg.security.ip_requests_per_minute,
            cfg.security.pubkey_requests_per_minute,
            cfg.security.max_registrations_per_ipv4_24_per_day,
            cfg.security.max_registrations_per_ipv6_48_per_day,
        ));
        let mailer = Arc::new(Mailer::new(cfg.email.clone()));
        Ok(Self {
            config: Arc::new(cfg),
            db,
            rate_limiter,
            token_verifier: Arc::new(TokenVerifierCache::default()),
            mailer,
        })
    }
}

#[derive(Serialize)]
pub struct ErrorBody<'a> {
    pub error: &'a str,
}

pub fn json_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(ErrorBody { error: msg })).into_response()
}

pub fn db_err_to_response(err: DbError) -> Response {
    match err {
        DbError::Http { status, message } => {
            if status == 412 {
                if let Some(current_etag) = message.strip_prefix("ETAG_MISMATCH:") {
                    let mut resp = (
                        StatusCode::PRECONDITION_FAILED,
                        Json(serde_json::json!({
                            "error": "Precondition failed (ETag mismatch)",
                            "current_etag": if current_etag.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(current_etag.to_string()) },
                        })),
                    )
                        .into_response();
                    if !current_etag.is_empty() {
                        if let Ok(hv) = format!("\"{}\"", current_etag).parse() {
                            resp.headers_mut().insert(axum::http::header::ETAG, hv);
                        }
                    }
                    return resp;
                }
            }
            let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            json_error(code, &message)
        }
        other => {
            tracing::error!(error = %other, "Database internal error");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal storage error")
        }
    }
}
