use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use chrono::{Duration, Utc};
use rand::{RngCore, thread_rng};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;

use jsonwebtoken::{EncodingKey, Header, encode};

#[derive(Serialize, Deserialize, Debug)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub client_id: String,
    pub permissions: Vec<String>,
}

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    // hash the password
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| {
            eprint!("Failed to hash password: {}", e);
            format!("Something went wrong")
        })?
        .to_string();

    Ok(password_hash)
}

pub fn verify_user_password(password: &str, hash: &str) -> bool {
    // parse the hash string back to the PasswordHash struct
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(hash) => hash,
        Err(e) => {
            eprint!("Failed to parse password hash: {}", e);
            return false;
        }
    };
    // verify the password against the hash
    let is_valid = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();

    is_valid
}

pub fn generate_auth_code() -> String {
    let mut buf = [0u8; 32]; // 32 bytes = 256 bits
    thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn create_jwt(user_id: &Uuid, client_id: &str, permissions: Vec<String>) -> String {
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(1))
        .expect("Valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        iat: Utc::now().timestamp() as usize,
        exp: expiration,
        client_id: client_id.to_owned(),
        permissions,
    };

    let secret = env::var("JWT_SECRET").expect("JWT Secret key not set");

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .unwrap()
}
