#![forbid(unsafe_code)]

pub mod admin_api;
pub mod config;
pub mod crypto;
pub mod db;
pub mod lock_rotation;
pub mod locks;
pub mod mailer;
pub mod ratelimit;
pub mod state;
pub mod sync_routes;
pub mod web_routes;

use axum::extract::DefaultBodyLimit;
use axum::Router;

use crate::state::AppState;

const WEB_FORM_MAX_BODY_BYTES: usize = 64 * 1024;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .merge(sync_routes::sync_router(&state.config))
        .merge(web_routes::web_router(&state.config))
        .merge(admin_api::admin_api_router())
        // Caps Axum FromRequest extractors (web_routes::Form) without restricting
        // sync_routes / admin_api streaming Body::to_bytes per-endpoint limits.
        .layer(DefaultBodyLimit::max(WEB_FORM_MAX_BODY_BYTES))
        .with_state(state)
}
