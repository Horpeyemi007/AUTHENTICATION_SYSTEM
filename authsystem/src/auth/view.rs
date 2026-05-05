use askama::Template;
use axum::Json;
use axum::extract::Query;
use axum::extract::{Form, State};
use axum::{
    self,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tower_sessions::Session;
use uuid::Uuid;

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
    pub expires_at: Option<i64>,
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
        Err(e) => {
            eprintln!("Error occurred: {}", e);
            return Redirect::to("/auth/login?error=Invalid+email+or+password").into_response();
        }
    };

    // verify_password in spawn_blocking due to argon2 small delay
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
            // generate the authentication code and also save in session temporarily (5 mins)
            let auth_code = generate_auth_code();
            let session_data = OAuthSession {
                user_id: user_id.unwrap(),
                client_id: params.client_id,
                expires_at: None,
            };

            state.auth_codes.insert(auth_code.clone(), session_data);

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
    session: Session,
    State(state): State<AppState>,
    Form(payload): Form<TokenRequest>,
) -> impl IntoResponse {
    match payload.grant_type.as_str() {
        "authorization_code" => handle_auth_code_grant(state, session, payload).await,
        "refresh_token" => handle_refresh_token_grant(state, session, payload).await,
        _ => (StatusCode::UNPROCESSABLE_ENTITY, "Unsupported grant type").into_response(),
    }
}

async fn handle_auth_code_grant(
    state: AppState,
    session: Session,
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

    // get and remove the auth code (one time)
    let session_data: OAuthSession = match state.auth_codes.remove(&code) {
        Some((_, data)) => data,
        None => {
            return (StatusCode::BAD_REQUEST, "Invalid or expired auth code").into_response();
        }
    };
    // create access token
    let user_permission = vec!["read:patients".to_string(), "write:patients".to_string()];
    let access_token = create_jwt(&session_data.user_id, &payload.client_id, user_permission);

    // generate the refresh token also
    let refresh_token =
        generate_refresh_token(session, session_data.user_id, payload.client_id).await;

    // return tokens
    let response = TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some(refresh_token),
        scope: client.scopes,
    };

    Json(response).into_response()
}

async fn handle_refresh_token_grant(
    state: AppState,
    session: Session,
    payload: TokenRequest,
) -> axum::response::Response {
    // get refresh token from payload
    let refresh_token = match payload.refresh_token.as_deref() {
        Some(t) => t.to_string(),
        None => return (StatusCode::BAD_REQUEST, "Missing refresh token").into_response(),
    };

    // validate client and secret
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

    // fetch, validate and delete the token from session
    let token_key = format!("refresh_token:{}", refresh_token);
    let token_session: Option<OAuthSession> = session.get(&token_key).await.unwrap_or(None);

    let token_data = match token_session {
        Some(token) => {
            if Utc::now().timestamp() > token.expires_at.unwrap() {
                let _ = session.remove::<OAuthSession>(&token_key).await;
                return (StatusCode::UNAUTHORIZED, "Refresh token expired").into_response();
            }
            let _ = session.remove::<OAuthSession>(&token_key).await;
            token
        }
        None => return (StatusCode::UNAUTHORIZED, "Invalid refresh token").into_response(),
    };
    // verify refresh token belongs to this client
    if token_data.client_id != payload.client_id {
        return (StatusCode::UNAUTHORIZED, "Client mismatch").into_response();
    }
    // issue new access token
    let user_permissions = vec!["read:patients".to_string(), "write:patients".to_string()];
    let new_access_token = create_jwt(&token_data.user_id, &token_data.client_id, user_permissions);
    // generate new refresh token (rotation)
    let refresh_token =
        generate_refresh_token(session, token_data.user_id, token_data.client_id).await;

    // return tokens
    let response = TokenResponse {
        access_token: new_access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some(refresh_token),
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

// @INFO: needs to verify if this is in a different session (Will test it when i implemented the client system)
async fn generate_refresh_token(session: Session, user_id: Uuid, client_id: String) -> String {
    let refresh_token = generate_auth_code();
    let token_key = format!("refresh_token:{}", refresh_token);

    let session_data = OAuthSession {
        user_id,
        client_id,
        expires_at: Some(Utc::now().timestamp() + (60 * 3)), // 3 minutes
    };

    let _ = session.insert(&token_key, session_data).await;

    return refresh_token;
}
