//! Configuration loaded from environment variables (docker-compose passes
//! `BEEMON_LOG_LEVEL` and `BEEMON_EVENT_LIMIT`). The daemon listens on
//! `BEEMON_GRPC_PORT` (default 50051, matching the BFF's default dial target).

use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub grpc_addr: String,
    pub grpc_port: u16,
    pub log_directive: String,
    pub event_limit: usize,
    pub rates_poll_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            grpc_addr: "0.0.0.0".to_string(),
            grpc_port: 50051,
            log_directive: "warn".to_string(),
            event_limit: 150,
            rates_poll_secs: 5,
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        let mut c = Self::default();
        if let Ok(p) = env::var("BEEMON_GRPC_PORT") {
            if let Ok(n) = p.parse() {
                c.grpc_port = n;
            }
        }
        if let Ok(addr) = env::var("BEEMON_GRPC_ADDR") {
            c.grpc_addr = addr;
        }
        if let Ok(l) = env::var("BEEMON_LOG_LEVEL") {
            if !l.is_empty() {
                c.log_directive = l;
            }
        }
        if let Ok(el) = env::var("BEEMON_EVENT_LIMIT") {
            if let Ok(n) = el.parse() {
                c.event_limit = n;
            }
        }
        if let Ok(s) = env::var("BEEMON_RATES_POLL_SECS") {
            if let Ok(n) = s.parse::<u64>() {
                c.rates_poll_secs = n.max(1);
            }
        }
        c
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.grpc_addr, self.grpc_port)
    }
}