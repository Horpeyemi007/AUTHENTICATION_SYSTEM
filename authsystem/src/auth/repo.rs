use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
}

pub async fn find_oauth_client(
    conn: &PgPool,
    client_id: &str,
) -> Result<Option<OAuthClient>, sqlx::Error> {
    let rec = sqlx::query_as(
        "SELECT client_id, client_secret_hash, redirect_uris, grant_types, scopes FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .fetch_optional(conn)
        .await?;

    Ok(rec)
}
