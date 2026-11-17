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

pub fn build_router(state: AppState) -> Router {
    let max_body = state.config.max_upload_body_bytes().saturating_add(65_536);
    Router::new()
        .merge(sync_routes::sync_router(&state.config))
        .merge(web_routes::web_router(&state.config))
        .merge(admin_api::admin_api_router())
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state)
}
