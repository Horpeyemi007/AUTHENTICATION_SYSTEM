use crate::auth::hash_password;
use crate::routes::AppState;
use crate::users::{RegisterUserDto, repo};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

pub async fn create_user(
    State(state): State<AppState>,
    Json(mut payload): Json<RegisterUserDto>,
) -> impl IntoResponse {
}
