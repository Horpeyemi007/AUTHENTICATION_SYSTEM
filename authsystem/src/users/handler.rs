use crate::auth::hash_password;
use crate::routes::AppState;
use crate::users::{RegisterUserDto, repo};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

pub async fn create_user(
    State(state): State<AppState>,
    Json(mut payload): Json<RegisterUserDto>,
) -> impl IntoResponse {
    // hash the user password
    let password = payload.password.clone();
    payload.password = match tokio::task::spawn_blocking(move || hash_password(&password)).await {
        Ok(Ok(hash)) => hash,
        Ok(Err(e)) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password").into_response();
        }
    };

    // create the user in the db
    match repo::create_user(&state.db, &payload).await {
        Ok(user_id) => (StatusCode::CREATED, user_id.to_string()).into_response(),
        Err(e) => {
            eprintln!("Failed to create user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create user, Please try again",
            )
                .into_response()
        }
    }
}
