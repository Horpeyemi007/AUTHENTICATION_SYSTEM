mod handler;
mod model;
mod repo;

pub use model::*;
pub use repo::*;

use crate::{routes::AppState, users::handler::create_user};
use axum::{Router, routing::post};

pub fn routes() -> Router<AppState> {
    Router::new().route("/register", post(create_user))
}
