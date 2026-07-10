use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub http_port: u16,
    pub log_directive: String,
    pub event_limit: usize,
    pub rates_poll_millis: u64,
    pub scanner_period_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http_port: 5055,
            log_directive: "info".to_string(),
            event_limit: 5000,
            rates_poll_millis: 2000,
            scanner_period_secs: 1,
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        let mut c = Self::default();
        if let Ok(p) = env::var("BEEMON_WEBUI_PORT") {
            if let Ok(n) = p.parse() {
                c.http_port = n;
            }
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
        if let Ok(s) = env::var("BEEMON_SCANNER_PERIOD_SECS") {
            if let Ok(n) = s.parse::<u64>() {
                c.scanner_period_secs = n.max(1);
            }
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = Config::default();
        assert_eq!(cfg.http_port, 5055);
        assert_eq!(cfg.rates_poll_millis, 2000);
        assert_eq!(cfg.event_limit, 5000);
        assert_eq!(cfg.log_directive, "info");
        assert_eq!(cfg.scanner_period_secs, 1);
    }

    #[test]
    fn test_config_from_env() {
        std::env::set_var("BEEMON_WEBUI_PORT", "9000");
        std::env::set_var("BEEMON_LOG_LEVEL", "debug");
        std::env::set_var("BEEMON_EVENT_LIMIT", "200");
        std::env::set_var("BEEMON_RATES_POLL_MILLIS", "500");
        std::env::set_var("BEEMON_SCANNER_PERIOD_SECS", "5");

        let cfg = Config::from_env();
        assert_eq!(cfg.http_port, 9000);
        assert_eq!(cfg.log_directive, "debug");
        assert_eq!(cfg.event_limit, 200);
        assert_eq!(cfg.rates_poll_millis, 500);
        assert_eq!(cfg.scanner_period_secs, 5);

        std::env::remove_var("BEEMON_WEBUI_PORT");
        std::env::remove_var("BEEMON_LOG_LEVEL");
        std::env::remove_var("BEEMON_EVENT_LIMIT");
        std::env::remove_var("BEEMON_RATES_POLL_MILLIS");
        std::env::remove_var("BEEMON_SCANNER_PERIOD_SECS");
    }
}
