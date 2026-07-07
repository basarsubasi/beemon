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