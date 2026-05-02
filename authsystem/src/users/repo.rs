use super::{RegisterUserDto, User};
use sqlx::PgPool;
use uuid::Uuid;

pub async fn create_user(conn: &PgPool, dto: &RegisterUserDto) -> Result<Uuid, sqlx::Error> {
    let rec = sqlx::query_scalar(
        "INSERT INTO users (email, password_hash, first_name, last_name)
            VALUES ($1, $2, $3, $4)
            RETURNING id",
    )
    .bind(dto.email.to_lowercase())
    .bind(&dto.password)
    .bind(&dto.first_name)
    .bind(&dto.last_name)
    .fetch_one(conn)
    .await?;

    Ok(rec)
}

pub async fn find_by_email(conn: &PgPool, email: &str) -> Result<Option<User>, sqlx::Error> {
    let rec = sqlx::query_as("SELECT * FROM users WHERE email = $1")
        .bind(email.to_lowercase())
        .fetch_optional(conn)
        .await?;

    Ok(rec)
}
