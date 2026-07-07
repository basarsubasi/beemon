//! Cgroup v2 limit readers (header-only, public crate-level helpers used
//! by `cgroup_tree_cache`). All functions return 0 on any failure — the proto
//! documents "0 means no limit", so callers don't need to special-case errors.

use std::fs;
use std::path::PathBuf;

/// `memory.max` / `pids.max` contain either a positive integer or the
/// literal `max`. `max` → 0 (proto: "no limit"). Any IO/parse failure → 0.
pub fn read_u64_max(path: &PathBuf) -> u64 {
    let s = match fs::read_to_string(path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return 0,
    };
    if s == "max" {
        return 0;
    }
    s.parse().unwrap_or(0)
}

/// `cpu.max` contains `<quota> <period>`. Quota is `max` (no limit) or an
/// integer; period is always an integer (microseconds).
pub fn read_cpu_max(path: &PathBuf) -> (u64, u64) {
    let s = match fs::read_to_string(path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return (0, 0),
    };
    let mut it = s.split_whitespace();
    let quota_s = it.next().unwrap_or("max");
    let period_s = it.next().unwrap_or("0");
    let quota = if quota_s == "max" { 0 } else { quota_s.parse().unwrap_or(0) };
    let period = period_s.parse().unwrap_or(0);
    (quota, period)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_u64_max_with_number() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "1048576").unwrap();
        let path = tmp.path().to_path_buf();
        assert_eq!(read_u64_max(&path), 1048576);
    }

    #[test]
    fn test_read_u64_max_with_max_literal() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "max").unwrap();
        let path = tmp.path().to_path_buf();
        assert_eq!(read_u64_max(&path), 0);
    }

    #[test]
    fn test_read_u64_max_with_whitespace() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "  2048  ").unwrap();
        let path = tmp.path().to_path_buf();
        assert_eq!(read_u64_max(&path), 2048);
    }

    #[test]
    fn test_read_u64_max_nonexistent_file() {
        let path = PathBuf::from("/nonexistent/path/to/file");
        assert_eq!(read_u64_max(&path), 0);
    }

    #[test]
    fn test_read_u64_max_invalid_content() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "not_a_number").unwrap();
        let path = tmp.path().to_path_buf();
        assert_eq!(read_u64_max(&path), 0);
    }

    #[test]
    fn test_read_u64_max_zero() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "0").unwrap();
        let path = tmp.path().to_path_buf();
        assert_eq!(read_u64_max(&path), 0);
    }

    #[test]
    fn test_read_cpu_max_with_values() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "100000 100000").unwrap();
        let path = tmp.path().to_path_buf();
        let (quota, period) = read_cpu_max(&path);
        assert_eq!(quota, 100000);
        assert_eq!(period, 100000);
    }

    #[test]
    fn test_read_cpu_max_with_max_quota() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "max 100000").unwrap();
        let path = tmp.path().to_path_buf();
        let (quota, period) = read_cpu_max(&path);
        assert_eq!(quota, 0);
        assert_eq!(period, 100000);
    }

    #[test]
    fn test_read_cpu_max_nonexistent_file() {
        let path = PathBuf::from("/nonexistent/path/to/file");
        let (quota, period) = read_cpu_max(&path);
        assert_eq!(quota, 0);
        assert_eq!(period, 0);
    }

    #[test]
    fn test_read_cpu_max_invalid_quota() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "invalid 100000").unwrap();
        let path = tmp.path().to_path_buf();
        let (quota, period) = read_cpu_max(&path);
        assert_eq!(quota, 0);
        assert_eq!(period, 100000);
    }

    #[test]
    fn test_read_cpu_max_invalid_period() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "100000 invalid").unwrap();
        let path = tmp.path().to_path_buf();
        let (quota, period) = read_cpu_max(&path);
        assert_eq!(quota, 100000);
        assert_eq!(period, 0);
    }

    #[test]
    fn test_read_cpu_max_missing_period() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "50000").unwrap();
        let path = tmp.path().to_path_buf();
        let (quota, period) = read_cpu_max(&path);
        assert_eq!(quota, 50000);
        assert_eq!(period, 0);
    }

    #[test]
    fn test_read_cpu_max_empty_file() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let (quota, period) = read_cpu_max(&path);
        assert_eq!(quota, 0);
        assert_eq!(period, 0);
    }

    #[test]
    fn test_read_cpu_max_with_whitespace() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "  200000   100000  ").unwrap();
        let path = tmp.path().to_path_buf();
        let (quota, period) = read_cpu_max(&path);
        assert_eq!(quota, 200000);
        assert_eq!(period, 100000);
    }
}