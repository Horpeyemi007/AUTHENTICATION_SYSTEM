mod auth;
mod infrastructure;
mod routes;
mod users;

use std::net::SocketAddr;

use infrastructure::{config::Config, create_redis_client, db};

#[tokio::main]
async fn main() {
    let config = Config::load_env();
    let db_pool = db::create_pool(config.database_url)
        .await
        .expect("Failed tp connect to database");

    let redis_client = create_redis_client(config.redis_url).await;

    // start the server
    let addr = SocketAddr::from(([127, 0, 0, 1], config.server_port));
    println!(
        "Authentication server starting on {} and running on port: {}",
        config.environment,
        addr.port()
    );

    // setup router
    let app = routes::create_route(db_pool, redis_client);

    // listen and serve
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
