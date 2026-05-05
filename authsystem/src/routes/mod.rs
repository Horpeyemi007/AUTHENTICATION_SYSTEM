use axum::Router;
use sqlx::PgPool;
use tower_sessions::{MemoryStore, SessionManagerLayer};

use dashmap::DashMap;
use std::sync::Arc;

use crate::auth::OAuthSession;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub auth_codes: Arc<DashMap<String, OAuthSession>>,
}

pub fn create_route(db_pool: PgPool) -> Router {
    // configure session store
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_name("auth_session")
        .with_secure(false);

    let state = AppState {
        db: db_pool,
        auth_codes: Arc::new(DashMap::new()),
    };

    let auth_route = crate::auth::routes().route_layer(session_layer);
    Router::new()
        .route("/health", axum::routing::get(|| async { "OK" }))
        .nest("/auth", auth_route)
        .nest("/users", crate::users::routes())
        .with_state(state)
}
