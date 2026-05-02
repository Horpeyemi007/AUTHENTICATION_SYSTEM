use tower_sessions_redis_store::fred::clients::RedisClient;
use tower_sessions_redis_store::fred::prelude::*;

pub async fn create_redis_client(redis_url: String) -> RedisClient {
    let config = RedisConfig::from_url(&redis_url).expect("Invalid Redis Url");
    let client = RedisClient::new(config, None, None, None);
    let _ = client.connect();
    client
        .wait_for_connect()
        .await
        .expect("Failed to connect to redis server");

    client
}
