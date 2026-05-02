use askama::Template;
use axum::Json;
use axum::extract::Query;
use axum::extract::{Form, State};
use axum::{
    self,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tower_sessions::Session;
use tower_sessions_redis_store::fred::interfaces::KeysInterface;
use tower_sessions_redis_store::fred::types::Expiration;

use super::repo::find_oauth_client;
use super::{create_jwt, generate_auth_code, verify_user_password};
use crate::auth::repo::OAuthClient;
use crate::routes::AppState;
use crate::users::find_by_email;

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {}

#[derive(Deserialize, Serialize)]
pub struct AuthRequestParams {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    state: String,
    code_challenge: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginDto {
    email: String,
    password: String,
}

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct OAuthSession {
    pub user_id: uuid::Uuid,
    pub client_id: String,
}

// GET "/auth/login"
pub async fn show_login() -> impl IntoResponse {
    let template = LoginTemplate {};
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to render template",
        )
            .into_response(),
    }
}

// POST "/auth/login"
pub async fn handle_login(
    session: Session,
    State(state): State<AppState>,
    Form(payload): Form<LoginDto>,
) -> impl IntoResponse {
    let user = match find_by_email(&state.db, &payload.email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Redirect::to("/auth/login?error=Invalid+email+or+password").into_response();
        }
        Err(_) => {
            return Redirect::to("/auth/login?error=Invalid+email+or+password").into_response();
        }
    };

    // verify_password in spawn_blocking due to argon to small delay
    let password_hash = user.password_hash.clone();
    let password = payload.password.clone();
    let is_valid_password =
        tokio::task::spawn_blocking(move || verify_user_password(&password, &password_hash))
            .await
            .unwrap_or(false);
    if !is_valid_password {
        return Redirect::to("/auth/login?error=Invalid+email+or+password").into_response();
    }

    // store the user session
    let _ = session.insert("user_id", user.id).await;
    // check if auth session exists
    let auth_session: Option<AuthRequestParams> = session.get("pending_auth").await.unwrap_or(None);
    if let Some(params) = auth_session {
        // delete the key so its not used twice
        let _ = session.remove::<AuthRequestParams>("pending_auth").await;
        let redirect_url = format!(
            "/auth/authorize?client_id={}&redirect_uri={}&response_type={}&state={}",
            params.client_id, params.redirect_uri, params.response_type, params.state
        );
        Redirect::to(&redirect_url).into_response()
    } else {
        (StatusCode::BAD_REQUEST, "No active Pending OAuth session").into_response()
    }
}

// GET "/auth/authorize" 1st handshake
pub async fn handle_authorize(
    session: Session,
    State(state): State<AppState>,
    Query(params): Query<AuthRequestParams>,
) -> impl IntoResponse {
    // 1. check if the user is logged in
    let user_id: Option<uuid::Uuid> = session.get("user_id").await.unwrap_or(None);

    if user_id.is_none() {
        // not logged in
        let _ = session.insert("pending_auth", &params).await;
        return Redirect::to("/auth/login").into_response();
    }

    // 2. verify that client exist
    let client = find_oauth_client(&state.db, &params.client_id).await;
    match client {
        Ok(Some(client)) => {
            // validate client redirect url
            if !client.redirect_uris.contains(&params.redirect_uri) {
                return (StatusCode::BAD_REQUEST, "Invalid redirect url").into_response();
            }
            // generate the authentication code and also save in redis temporarily (5 mins)
            let auth_code = generate_auth_code();
            let session_data = OAuthSession {
                user_id: user_id.unwrap(),
                client_id: params.client_id,
            };
            let redis_key = format!("auth_code:{}", auth_code);
            let auth_code_session_data = match serde_json::to_string(&session_data) {
                Ok(j) => j,
                Err(_) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Serialization error")
                        .into_response();
                }
            };

            if let Err(e) = state
                .redis
                .set::<(), _, _>(
                    redis_key,
                    auth_code_session_data,
                    Some(Expiration::EX(300)),
                    None,
                    false,
                )
                .await
            {
                eprint!("Redis Error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to save auth code",
                )
                    .into_response();
            }

            let redirect_url = format!(
                "{}?code={}&state={}",
                params.redirect_uri, auth_code, params.state
            );
            Redirect::to(&redirect_url).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Error: Client not found").into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error: Failed to fetch client",
        )
            .into_response(),
    }
}

// POST "/auth/token" 2nd handshake
pub async fn handle_generate_token(
    State(state): State<AppState>,
    Form(payload): Form<TokenRequest>,
) -> impl IntoResponse {
    match payload.grant_type.as_str() {
        "authorization_code" => handle_auth_code_grant(state, payload).await,
        _ => (StatusCode::UNPROCESSABLE_ENTITY, "Unsupported grant type").into_response(),
    }
}

async fn handle_auth_code_grant(
    state: AppState,
    payload: TokenRequest,
) -> axum::response::Response {
    // validate the client
    let client = match validate_client(
        &state.db,
        &payload.client_id,
        payload.client_secret.as_deref().unwrap_or(""),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return e,
    };

    let code = match payload.code.as_deref() {
        Some(c) => c.to_string(),
        None => return (StatusCode::BAD_REQUEST, "Missing code").into_response(),
    };

    let redirect_uri = match payload.redirect_uri.as_deref() {
        Some(r) => r.to_string(),
        None => return (StatusCode::BAD_REQUEST, "Missing redirect_uri").into_response(),
    };

    // validate redirect url
    if !client.redirect_uris.contains(&redirect_uri) {
        return (StatusCode::UNAUTHORIZED, "Invalid redirect URI").into_response();
    }

    // verify and delete the auth code from redis
    let redis_key = format!("auth_code:{}", code);
    let auth_code_session_data: Option<String> = match state.redis.getdel(&redis_key).await {
        Ok(data) => data,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Redis error").into_response(),
    };

    let redis_data: OAuthSession = match auth_code_session_data {
        Some(json) => serde_json::from_str(&json).unwrap(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid or expired token",
            )
                .into_response();
        }
    };
    // create access token
    let user_permission = vec!["read:patients".to_string(), "write:patients".to_string()];
    let access_token = create_jwt(&redis_data.user_id, &payload.client_id, user_permission);

    // return tokens
    let response = TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: None,
        scope: client.scopes,
    };

    Json(response).into_response()
}

async fn validate_client(
    db: &PgPool,
    client_id: &str,
    client_secret: &str,
) -> Result<OAuthClient, axum::response::Response> {
    let client = match find_oauth_client(db, client_id).await {
        Ok(Some(client)) => client,
        _ => return Err((StatusCode::UNAUTHORIZED, "Invalid Client").into_response()),
    };

    let db_secret = client.client_secret_hash.as_deref().unwrap_or("");
    if db_secret != client_secret {
        return Err((StatusCode::UNAUTHORIZED, "Invalid Secret").into_response());
    }

    Ok(client)
}
