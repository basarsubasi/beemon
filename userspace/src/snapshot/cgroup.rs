//! Cgroup v2 limit reads. Walks `/proc/<pid>/cgroup` to find the cgroup-v2
//! path (format `0::<path>`), then reads the relevant `.max` files under
//! `/sys/fs/cgroup/<path>/`.
//!
//! On any failure (not in a cgroup, cgroup v1 host, file missing) we leave
//! the corresponding limit field at 0 — the proto documents "0 means no
//! limit", so the UI treats that gracefully.

use std::fs;
use std::path::PathBuf;

/// (memory_limit_bytes, cpu_quota_us, cpu_period_us, pids_limit).
/// All four default to 0 (no limit) when cgroup info is unavailable.
pub fn read_limits(pid: u32) -> (u64, u64, u64, u64) {
    let cgroup_path = match resolve_cgroup_v2_path(pid) {
        Some(p) => p,
        None => return (0, 0, 0, 0),
    };
    let base = PathBuf::from("/sys/fs/cgroup").join(&cgroup_path);

    let mem = read_u64_max(&base.join("memory.max"));
    let (quota, period) = read_cpu_max(&base.join("cpu.max"));
    let pids = read_u64_max(&base.join("pids.max"));
    (mem, quota, period, pids)
}

/// Parse `/proc/<pid>/cgroup` lines, return the v2 path (the line whose
/// hierarchy id is `0`). Returns None on any error or if no v2 line is found.
fn resolve_cgroup_v2_path(pid: u32) -> Option<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    for line in raw.lines() {
        // Format: `<hierarchy_id>:<controllers>:<path>`
        // cgroup v2 (unified) uses hierarchy id 0 and empty controllers.
        let mut parts = line.splitn(3, ':');
        let h = parts.next()?;
        let _c = parts.next();
        let path = parts.next()?;
        if h == "0" && !path.is_empty() {
            // Some v2 setups use `/<path>`; some put the whole controller
            // name. The path is usable as-is under /sys/fs/cgroup.
            return Some(path.trim_start_matches('/').to_string());
        }
    }
    None
}

/// `memory.max` / `pids.max` contain either a single positive integer or
/// the literal `max`. `max` → 0 (proto: "no limit").
fn read_u64_max(path: &PathBuf) -> u64 {
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
fn read_cpu_max(path: &PathBuf) -> (u64, u64) {
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