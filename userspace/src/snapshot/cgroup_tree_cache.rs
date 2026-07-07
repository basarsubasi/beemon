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
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::cgroup::{read_cpu_max, read_u64_max, read_u64_max_v1};

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

/// Check if a relative path looks like a cgroup v2 leaf under base.
fn has_v2_limits(base: &Path, rel: &str) -> bool {
    let dir = base.join(rel);
    dir.join("memory.max").exists() || dir.join("cpu.max").exists() || dir.join("pids.max").exists()
}

/// Check if a relative path looks like a cgroup v1 leaf under base.
fn has_v1_limits(base: &Path, rel: &str) -> bool {
    base.join("memory").join(rel).join("memory.limit_in_bytes").exists()
        || base.join("cpu").join(rel).join("cpu.cfs_quota_us").exists()
        || base.join("pids").join(rel).join("pids.max").exists()
}

/// Translate between cgroup path representations commonly used by container
/// runtimes under systemd. Docker uses `docker/<id>`, systemd models it as
/// `system.slice/docker-<id>.scope`. Containerd uses
/// `system.slice/containerd-<id>.scope` or `kubepods-*`. This helper
/// generates alternative path forms to try when the raw path doesn't resolve.
fn runtime_cgroup_alternatives(cgroup_path: &str) -> Vec<String> {
    let mut alts = Vec::new();
    // docker/<id> <-> system.slice/docker-<id>.scope
    if let Some(id) = cgroup_path.strip_prefix("docker/") {
        alts.push(format!("system.slice/docker-{}.scope", id));
    }
    if let Some(rest) = cgroup_path.strip_prefix("system.slice/docker-") {
        if let Some(id) = rest.strip_suffix(".scope") {
            alts.push(format!("docker/{}", id));
        }
    }
    // containerd: system.slice/containerd-<id>.scope
    // Nothing to reverse-map; the direct path is already the systemd form.
    // k8s: kubepods/... — already a direct path, no remapping needed.
    alts
}

fn find_cgroup_rel_path(base: &Path, cgroup_path: &str, pid: u32) -> String {
    // Collect candidate paths to try, in priority order.
    let mut candidates: Vec<String> = Vec::new();

    // 1. Direct path from /proc/<pid>/cgroup
    candidates.push(cgroup_path.to_string());

    // 2. Runtime-specific alternative paths (Docker systemd remapping, etc.)
    for alt in runtime_cgroup_alternatives(cgroup_path) {
        candidates.push(alt);
    }

    // 3. If the path contains a leading segment like "system.slice/" or
    //    "user.slice/", try stripping it (some systems report the full
    //    systemd path but the cgroup is mounted at a different mountpoint).
    {
        let stripped: String = cgroup_path.split('/').skip(1).collect::<Vec<_>>().join("/");
        if !stripped.is_empty() && stripped != cgroup_path {
            candidates.push(stripped);
        }
    }

    // 4. /sys/fs/cgroup/<pid> (used by some cgroup v1 layouts)
    candidates.push(pid.to_string());

    // Try each candidate: prefer directories that have actual resource files.
    for rel in &candidates {
        if has_v2_limits(base, rel) || has_v1_limits(base, rel) {
            return rel.clone();
        }
    }

    // Fallback: return the first candidate even if it doesn't exist, so
    // read_u64_max/read_cpu_max handle the missing-file case gracefully.
    candidates.into_iter().next().unwrap_or_else(|| cgroup_path.to_string())
}

fn read_cgroup_limits(cgroup_path: &str, pid: u32) -> CgroupLimits {
    let base = PathBuf::from("/sys/fs/cgroup");
    let rel_path = find_cgroup_rel_path(&base, cgroup_path, pid);
    let v2_dir = base.join(&rel_path);

    // Try cgroup v2 files first, then fall back to cgroup v1 files.
    let memory_limit_bytes = {
        let v2 = read_u64_max(&v2_dir.join("memory.max"));
        if v2 != 0 || !base.join("memory").join(&rel_path).join("memory.limit_in_bytes").exists() {
            v2
        } else {
            read_u64_max_v1(&base.join("memory").join(&rel_path).join("memory.limit_in_bytes"))
        }
    };

    let (cpu_quota_us, cpu_period_us) = {
        let (v2_quota, v2_period) = read_cpu_max(&v2_dir.join("cpu.max"));
        if v2_quota != 0 || v2_period != 0 || !base.join("cpu").join(&rel_path).join("cpu.cfs_quota_us").exists() {
            (v2_quota, v2_period)
        } else {
            let quota = read_u64_max_v1(&base.join("cpu").join(&rel_path).join("cpu.cfs_quota_us"));
            let period = read_u64_max_v1(&base.join("cpu").join(&rel_path).join("cpu.cfs_period_us"));
            (quota, period)
        }
    };

    let pids_limit = {
        let v2 = read_u64_max(&v2_dir.join("pids.max"));
        if v2 != 0 || !base.join("pids").join(&rel_path).join("pids.max").exists() {
            v2
        } else {
            // Note: cgroup v1 pids limit is typically pids.max too
            read_u64_max_v1(&base.join("pids").join(&rel_path).join("pids.max"))
        }
    };

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

    #[test]
    fn test_find_cgroup_rel_path() {
        use std::fs;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let base_path = dir.path().join("sys/fs/cgroup");
        fs::create_dir_all(&base_path).unwrap();

        // 1. Direct path with v2 resource files
        let p1 = base_path.join("some/direct/path");
        fs::create_dir_all(&p1).unwrap();
        fs::File::create(p1.join("memory.max")).unwrap();
        assert_eq!(find_cgroup_rel_path(&base_path, "some/direct/path", 123), "some/direct/path");

        // 2. docker/<id> -> system.slice/docker-<id>.scope (with resource files)
        let p2 = base_path.join("system.slice/docker-abcdef.scope");
        fs::create_dir_all(&p2).unwrap();
        fs::File::create(p2.join("memory.max")).unwrap();
        assert_eq!(find_cgroup_rel_path(&base_path, "docker/abcdef", 123), "system.slice/docker-abcdef.scope");

        // 3. system.slice/docker-<id>.scope -> docker/<id> (with resource files)
        let p3 = base_path.join("docker/12345");
        fs::create_dir_all(&p3).unwrap();
        fs::File::create(p3.join("cpu.max")).unwrap();
        assert_eq!(find_cgroup_rel_path(&base_path, "system.slice/docker-12345.scope", 123), "docker/12345");

        // 4. Fallback to /sys/fs/cgroup/<pid> (with resource files)
        let p4 = base_path.join("999");
        fs::create_dir_all(&p4).unwrap();
        fs::File::create(p4.join("memory.max")).unwrap();
        assert_eq!(find_cgroup_rel_path(&base_path, "missing/path", 999), "999");

        // 5. Ultimate fallback: no candidate has resource files -> first candidate
        assert_eq!(find_cgroup_rel_path(&base_path, "not/found", 404), "not/found");

        // 6. cgroup v1 fallback: directory with memory.limit_in_bytes under memory controller
        let p6_mem = base_path.join("memory/v1/path");
        fs::create_dir_all(&p6_mem).unwrap();
        fs::File::create(p6_mem.join("memory.limit_in_bytes")).unwrap();
        assert_eq!(find_cgroup_rel_path(&base_path, "v1/path", 777), "v1/path");
    }
}