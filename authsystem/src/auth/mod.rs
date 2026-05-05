mod authutil;
mod repo;
mod view;

pub use authutil::*;
pub use view::*;

use crate::routes::AppState;
use axum::{Router, routing::get, routing::post};

use crate::auth::view::{handle_authorize, handle_generate_token, handle_login, show_login};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(show_login))
        .route("/authorize", get(handle_authorize))
        .route("/login", post(handle_login))
        .route("/token", post(handle_generate_token))
}
