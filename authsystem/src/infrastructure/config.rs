use dotenvy::dotenv;
use std::env;

pub struct Config {
    pub database_url: String,
    pub server_port: u16,
    pub environment: String,
    pub redis_url: String,
}

impl Config {
    pub fn load_env() -> Self {
        dotenv().ok();
        Self {
            database_url: env::var("DATABASE_URL")
                .expect("*******DATABASE_URL is required********"),
            server_port: env::var("PORT")
                .expect("*******PORT is required******")
                .parse()
                .unwrap(),
            environment: env::var("ENVIRONMENT").expect("********ENVIRONMENT is required*******"),
            redis_url: env::var("REDIS_URL").expect("********REDIS_URL is required*********"),
        }
    }
}
