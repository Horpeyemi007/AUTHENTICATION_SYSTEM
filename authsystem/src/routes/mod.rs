use axum::Router;
use sqlx::PgPool;
use tower_sessions::{MemoryStore, SessionManagerLayer};
use tower_sessions_redis_store::fred::clients::RedisClient;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub redis: RedisClient,
}

pub fn create_route(db_pool: PgPool, redis_client: RedisClient) -> Router {
    // configure session store
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_name("auth_session")
        .with_secure(false);
    let state = AppState {
        db: db_pool,
        redis: redis_client,
    };

    let auth_route = crate::auth::routes().route_layer(session_layer);
    Router::new()
        .route("/health", axum::routing::get(|| async { "OK" }))
        .nest("/auth", auth_route)
        .with_state(state)
}
