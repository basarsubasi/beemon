//! Host-wide fields populated by the scanner: total memory, per-core CPU%,
//! and the host's namespace inode set (read once at startup).
//!
//! Per-core CPU% is computed from successive reads of `/proc/stat` lines
//! `cpu<N> user nice system idle iowait irq softirq steal guest guest_nice`.

use std::fs;
use std::time::Instant;

/// Per-core counters tracked between scanner runs.
#[derive(Clone, Copy, Default)]
pub struct CpuSample {
    pub busy: u64, // user+nice+system+irq+softirq+steal
    pub total: u64, // busy + idle + iowait
}

/// Compute per-core CPU% from two successive `/proc/stat` samples.
/// Returns one `f32` per cpu (capped to [0, 100]).
pub fn per_core_percent(prev: &[CpuSample], curr: &[CpuSample]) -> Vec<f32> {
    let n = prev.len().min(curr.len());
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let d_busy = curr[i].busy.saturating_sub(prev[i].busy);
        let d_total = curr[i].total.saturating_sub(prev[i].total);
        let pct = if d_total == 0 {
            0.0
        } else {
            (d_busy as f32 / d_total as f32) * 100.0
        };
        out.push(pct.clamp(0.0, 100.0));
    }
    out
}

/// Read per-core counters from `/proc/stat`. Returns entry per `cpu<N>` line.
pub fn read_cpu_samples() -> Vec<CpuSample> {
    let raw = fs::read_to_string("/proc/stat").unwrap_or_default();
    let mut out = Vec::new();
    for line in raw.lines() {
        if !line.starts_with("cpu") || line.starts_with("cpu ") {
            continue;
        }
        // line: `cpu0  user nice system idle iowait irq softirq steal guest guest_nice`
        let mut it = line.split_whitespace();
        let _name = it.next();
        let fields: Vec<u64> = it.filter_map(|s| s.parse().ok()).collect();
        if fields.len() < 4 {
            continue;
        }
        let user = fields[0];
        let nice = fields[1];
        let system = fields[2];
        let idle = fields[3];
        let iowait = *fields.get(4).unwrap_or(&0);
        let irq = *fields.get(5).unwrap_or(&0);
        let softirq = *fields.get(6).unwrap_or(&0);
        let steal = *fields.get(7).unwrap_or(&0);
        let busy = user + nice + system + irq + softirq + steal;
        let total = busy + idle + iowait;
        out.push(CpuSample { busy, total });
    }
    out
}

/// Total system memory in bytes from `/proc/meminfo` `MemTotal:` (kB → B).
pub fn read_memtotal_bytes() -> u64 {
    let raw = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            return kb * 1024;
        }
    }
    0
}

/// Host's own namespace inodes, formatted as `<type>:[<inode>]` strings.
/// Read from `/proc/self/ns/` once at startup (they don't change per host).
pub fn read_host_namespaces() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc/self/ns") {
        for e in entries.flatten() {
            if let Ok(target) = fs::read_link(e.path()) {
                if let Some(s) = target.to_str() {
                    out.push(s.to_string());
                }
            }
        }
    }
    out.sort();
    out
}

/// Used by the scanner to seed its previous-sample clock. Currently only
/// consumed when we ever need a wall-clock reference for diagnostics.
#[allow(dead_code)]
pub fn now() -> Instant {
    Instant::now()
}