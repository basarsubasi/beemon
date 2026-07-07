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
    pub rates_poll_millis: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            grpc_addr: "0.0.0.0".to_string(),
            grpc_port: 50051,
            log_directive: "warn".to_string(),
            event_limit: 150,
            rates_poll_millis: 1000,
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
        if let Ok(s) = env::var("BEEMON_RATES_POLL_MILLIS") {
            if let Ok(n) = s.parse::<u64>() {
                c.rates_poll_millis = n.max(10);
            }
        }
        c
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.grpc_addr, self.grpc_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = Config::default();
        assert_eq!(cfg.grpc_addr, "0.0.0.0");
        assert_eq!(cfg.grpc_port, 50051);
        assert_eq!(cfg.rates_poll_millis, 1000);
        assert_eq!(cfg.event_limit, 150);
        assert_eq!(cfg.log_directive, "warn");
    }

    #[test]
    fn test_bind_addr() {
        let cfg = Config::default();
        assert_eq!(cfg.bind_addr(), "0.0.0.0:50051");
    }

    #[test]
    fn test_from_env_all_vars() {
        std::env::set_var("BEEMON_GRPC_ADDR", "127.0.0.1");
        std::env::set_var("BEEMON_GRPC_PORT", "9000");
        std::env::set_var("BEEMON_RATES_POLL_MILLIS", "10");
        std::env::set_var("BEEMON_EVENT_LIMIT", "200");
        std::env::set_var("BEEMON_LOG_LEVEL", "debug");

        let cfg = Config::from_env();
        assert_eq!(cfg.grpc_addr, "127.0.0.1");
        assert_eq!(cfg.grpc_port, 9000);
        assert_eq!(cfg.rates_poll_millis, 10);
        assert_eq!(cfg.event_limit, 200);
        assert_eq!(cfg.log_directive, "debug");

        // Cleanup
        std::env::remove_var("BEEMON_GRPC_ADDR");
        std::env::remove_var("BEEMON_GRPC_PORT");
        std::env::remove_var("BEEMON_RATES_POLL_MILLIS");
        std::env::remove_var("BEEMON_EVENT_LIMIT");
        std::env::remove_var("BEEMON_LOG_LEVEL");
    }

    #[test]
    fn test_from_env_partial() {
        // Clear all vars first
        std::env::remove_var("BEEMON_GRPC_ADDR");
        std::env::remove_var("BEEMON_GRPC_PORT");
        std::env::remove_var("BEEMON_RATES_POLL_MILLIS");
        std::env::remove_var("BEEMON_EVENT_LIMIT");
        std::env::remove_var("BEEMON_LOG_LEVEL");

        // Set only some
        std::env::set_var("BEEMON_GRPC_PORT", "8080");
        std::env::set_var("BEEMON_LOG_LEVEL", "warn");

        let cfg = Config::from_env();
        assert_eq!(cfg.grpc_addr, "0.0.0.0"); // default
        assert_eq!(cfg.grpc_port, 8080); // from env
        assert_eq!(cfg.rates_poll_millis, 1000); // default
        assert_eq!(cfg.event_limit, 150); // default
        assert_eq!(cfg.log_directive, "warn"); // from env

        // Cleanup
        std::env::remove_var("BEEMON_GRPC_PORT");
        std::env::remove_var("BEEMON_LOG_LEVEL");
    }

    #[test]
    fn test_from_env_invalid_values() {
        std::env::set_var("BEEMON_GRPC_PORT", "not_a_number");
        std::env::set_var("BEEMON_RATES_POLL_MILLIS", "invalid");

        let cfg = Config::from_env();
        // Should fall back to defaults for invalid values
        assert_eq!(cfg.grpc_port, 50051);
        assert_eq!(cfg.rates_poll_millis, 1000);

        // Cleanup
        std::env::remove_var("BEEMON_GRPC_PORT");
        std::env::remove_var("BEEMON_RATES_POLL_SECS");
    }
}