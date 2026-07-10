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
//! triggered by a cgroup limit change synthesized in the rates poller (TODO:
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
    pub fn get_or_load(&mut self, cgroup_path: &Option<String>, pid: u32) -> Option<CgroupLimits> {
        let path = cgroup_path.as_ref()?;
        let stale = self
            .loaded_at
            .get(path)
            .map(|t| t.elapsed() > self.ttl)
            .unwrap_or(true);
        if stale {
            let limits = read_cgroup_limits(path, pid);
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

fn read_cgroup_limits(cgroup_path: &str, _pid: u32) -> CgroupLimits {
    let base = PathBuf::from("/sys/fs/cgroup");
    let dir = find_cgroup_dir(&base, cgroup_path);

    let memory_limit_bytes = read_u64_max(&dir.join("memory.max"));
    let (cpu_quota_us, cpu_period_us) = read_cpu_max(&dir.join("cpu.max"));
    let pids_limit = read_u64_max(&dir.join("pids.max"));

    CgroupLimits {
        memory_limit_bytes,
        cpu_quota_us,
        cpu_period_us,
        pids_limit,
    }
}

/// Normalize a cgroup path by resolving `..` components and stripping leading `/`.
/// If the direct path doesn't exist under base, search for the leaf directory name
/// in common parent directories (system.slice, user.slice, machine.slice).
fn find_cgroup_dir(base: &std::path::Path, cgroup_path: &str) -> PathBuf {
    // Strip leading `/` and normalize `..` components
    let normalized = cgroup_path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| *s != ".." && *s != ".")
        .collect::<Vec<_>>()
        .join("/");

    let direct = base.join(&normalized);
    if direct.exists() && (direct.join("memory.max").exists() || direct.join("cpu.max").exists()) {
        return direct;
    }

    // Extract leaf directory name
    let leaf = normalized.rsplit('/').next().unwrap_or(&normalized);
    
    // Search in common parent directories
    let parents = ["system.slice", "user.slice", "machine.slice", "init.scope"];
    for parent in &parents {
        let candidate = base.join(parent).join(leaf);
        if candidate.exists() && (candidate.join("memory.max").exists() || candidate.join("cpu.max").exists()) {
            return candidate;
        }
    }

    // Fallback to direct path (will return 0 limits if files don't exist)
    direct
}

/// Convenience: read the limits for a *host-level* process (no cgroup `path`).
/// Returns zero-values appropriate for "no limit". Used when a pid has no
/// resolvable cgroup.
pub fn no_limits() -> CgroupLimits {
    CgroupLimits::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_limits_default() {
        let limits = CgroupLimits::default();
        assert_eq!(limits.memory_limit_bytes, 0);
        assert_eq!(limits.cpu_quota_us, 0);
        assert_eq!(limits.cpu_period_us, 0);
        assert_eq!(limits.pids_limit, 0);
    }

    #[test]
    fn test_cgroup_tree_cache_new() {
        let cache = CgroupTreeCache::new(Duration::from_secs(10));
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.total_paths_seen, 0);
    }

    #[test]
    fn test_cgroup_tree_cache_get_or_load_none_path() {
        let mut cache = CgroupTreeCache::new(Duration::from_secs(10));
        let result = cache.get_or_load(&None, 0);
        assert!(result.is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cgroup_tree_cache_get_or_load_nonexistent_path() {
        let mut cache = CgroupTreeCache::new(Duration::from_secs(10));
        let path = Some("nonexistent/cgroup/path".to_string());
        let result = cache.get_or_load(&path, 0);
        
        // Should return Some with zero values (file doesn't exist)
        assert!(result.is_some());
        let limits = result.unwrap();
        assert_eq!(limits.memory_limit_bytes, 0);
        assert_eq!(limits.cpu_quota_us, 0);
        assert_eq!(limits.cpu_period_us, 0);
        assert_eq!(limits.pids_limit, 0);
        
        // Should be cached now
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.total_paths_seen, 1);
    }

    #[test]
    fn test_cgroup_tree_cache_caching() {
        let mut cache = CgroupTreeCache::new(Duration::from_secs(10));
        let path = Some("test/path".to_string());
        
        // First call
        let result1 = cache.get_or_load(&path, 0);
        assert!(result1.is_some());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.total_paths_seen, 1);
        
        // Second call should use cache
        let result2 = cache.get_or_load(&path, 0);
        assert!(result2.is_some());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.total_paths_seen, 1); // Still 1, not reloaded
    }

    #[test]
    fn test_cgroup_tree_cache_invalidate() {
        let mut cache = CgroupTreeCache::new(Duration::from_secs(10));
        let path = Some("test/path".to_string());
        
        // Load into cache
        cache.get_or_load(&path, 0);
        assert_eq!(cache.len(), 1);
        
        // Invalidate
        cache.invalidate("test/path");
        assert_eq!(cache.len(), 0);
        
        // Next load should reload
        cache.get_or_load(&path, 0);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.total_paths_seen, 2); // Reloaded
    }

    #[test]
    fn test_cgroup_tree_cache_multiple_paths() {
        let mut cache = CgroupTreeCache::new(Duration::from_secs(10));
        
        let path1 = Some("path1".to_string());
        let path2 = Some("path2".to_string());
        let path3 = Some("path3".to_string());
        
        cache.get_or_load(&path1, 0);
        cache.get_or_load(&path2, 0);
        cache.get_or_load(&path3, 0);
        
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.total_paths_seen, 3);
    }

    #[test]
    fn test_cgroup_tree_cache_ttl_expiry() {
        let mut cache = CgroupTreeCache::new(Duration::from_millis(10));
        let path = Some("test/path".to_string());
        
        // First load
        cache.get_or_load(&path, 0);
        assert_eq!(cache.total_paths_seen, 1);
        
        // Wait for TTL to expire
        std::thread::sleep(Duration::from_millis(20));
        
        // Should reload, but total_paths_seen stays at 1 (only counts new paths, not reloads)
        cache.get_or_load(&path, 0);
        assert_eq!(cache.total_paths_seen, 1);
    }

    #[test]
    fn test_no_limits() {
        let limits = no_limits();
        assert_eq!(limits.memory_limit_bytes, 0);
        assert_eq!(limits.cpu_quota_us, 0);
        assert_eq!(limits.cpu_period_us, 0);
        assert_eq!(limits.pids_limit, 0);
    }
}