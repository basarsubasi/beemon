//! Cache of cgroup v2 limits keyed by cgroup path. Many processes share the
//! same cgroup (e.g. all tasks in a container share one path); the scanner
//! reads `memory.max` / `cpu.max` / `pids.max` ONCE per cgroup path (with a
//! 10s TTL) instead of once per pid per scan.
//!
//! Held as `Arc<Mutex<CgroupTreeCache>>`. The scanner holds the lock briefly
//! per pid iteration; gRPC handlers do not touch this cache (they read the
//! data indirectly via [`crate::snapshot::SnapshotCache`]).
//!
//! Invalidation: 10s TTL covers the natural refresh. Forced invalidation is
//! triggered by a `LimitChangedEvent` synthesized in the rates poller (TODO:
//! wired up once we read cgroup events from BPF — for now, TTL is enough
//! because the UI re-opens the details view frequently).

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::cgroup::{read_cpu_max, read_u64_max};

/// Limits for one cgroup. Memory/CPU/PID values; `0` conventionally means
/// "no limit" (proto convention).
#[derive(Clone, Copy, Debug, Default)]
pub struct CgroupLimits {
    pub memory_limit_bytes: u64,
    pub cpu_quota_us: u64,
    pub cpu_period_us: u64,
    pub pids_limit: u64,
}

pub struct CgroupTreeCache {
    entries: HashMap<String, CgroupLimits>,
    loaded_at: HashMap<String, Instant>,
    ttl: Duration,
    /// Number of distinct cgroups we've cached since startup; useful as a
    /// diagnostic of cache effectiveness.
    pub total_paths_seen: u64,
}

impl CgroupTreeCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            loaded_at: HashMap::new(),
            ttl,
            total_paths_seen: 0,
        }
    }

    /// Returns limits for the given cgroup path, loading it from sysfs if
    /// missing or stale. Returns `None` for a `None` path (process not in
    /// any v2 cgroup — proto: "0 means no limit").
    pub fn get_or_load(&mut self, cgroup_path: &Option<String>) -> Option<CgroupLimits> {
        let path = cgroup_path.as_ref()?;
        let stale = self
            .loaded_at
            .get(path)
            .map(|t| t.elapsed() > self.ttl)
            .unwrap_or(true);
        if stale {
            let limits = read_cgroup_limits(path);
            let was_new = !self.entries.contains_key(path);
            self.entries.insert(path.clone(), limits);
            self.loaded_at.insert(path.clone(), Instant::now());
            if was_new {
                self.total_paths_seen += 1;
            }
        }
        self.entries.get(path).copied()
    }

    /// Force-invalidate a single cgroup path (called when the BPF side emits
    /// a cgroup write event for a path; currently unused since none of the
    /// existing alerts include the path, but reserved for future use).
    pub fn invalidate(&mut self, path: &str) {
        self.entries.remove(path);
        self.loaded_at.remove(path);
    }

    /// Number of distinct cgroup paths currently cached.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

fn read_cgroup_limits(cgroup_path: &str) -> CgroupLimits {
    let base = PathBuf::from("/sys/fs/cgroup").join(cgroup_path);
    let memory_limit_bytes = read_u64_max(&base.join("memory.max"));
    let (cpu_quota_us, cpu_period_us) = read_cpu_max(&base.join("cpu.max"));
    let pids_limit = read_u64_max(&base.join("pids.max"));
    CgroupLimits {
        memory_limit_bytes,
        cpu_quota_us,
        cpu_period_us,
        pids_limit,
    }
}

/// Convenience: read the limits for a *host-level* process (no cgroup `path`).
/// Returns zero-values appropriate for "no limit". Used when a pid has no
/// resolvable cgroup.
pub fn no_limits() -> CgroupLimits {
    CgroupLimits::default()
}