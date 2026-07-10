use std::env;

pub struct Config {
    pub grpc_endpoint: String,
    pub http_port: u16,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            grpc_endpoint: env::var("BEEMON_GRPC_ENDPOINT")
                .unwrap_or_else(|_| "127.0.0.1:50051".into()),
            http_port: env::var("BEEMON_HTTP_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8080),
        }
    }
}
