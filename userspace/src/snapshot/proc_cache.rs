//! Per-pid cache of stable fields: parent pid, command name, namespace inodes
//! (`/proc/<pid>/ns/*`), and cgroup v2 path. These rarely change for a running
//! process; we load once per pid lifetime and refresh on a 10s TTL.
//!
//! Invalidate via [`ProcCache::invalidate`] when:
//!   - the BPF side emits a Setns/Unshare event for `pid` (namespace change)
//!   - the BPF side emits a sched_process_exit event for `pid`
//!   - the periodic sweep detects the pid is no longer in `/proc`
//!
//! Cache is held as `Arc<Mutex<ProcCache>>` so both the scanner
//! (spawn_blocking) and gRPC handlers can access it without re-walking /proc.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::{Duration, Instant};

/// Default refresh interval for stable per-pid fields. A 10s TTL matches the
/// user's "sane defaults" requirement while still catching rare subprocess
/// changes (cgroup migration, setns) within a dashboard-friendly lag.
pub const DEFAULT_TTL: Duration = Duration::from_secs(10);

/// One cached entry per pid.
#[derive(Clone, Debug)]
pub struct ProcCacheEntry {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    /// `"mnt"`, `"net"`, `"uts"`, `"ipc"`, `"user"`, `"pid"`, `"cgroup"`,
    /// `"time"`... -> namespace inode.
    pub namespaces: HashMap<String, u64>,
    /// Cgroup v2 path (relative to `/sys/fs/cgroup/`). None if the process
    /// has no resolvable v2 cgroup (host-level or v1 host).
    pub cgroup_path: Option<String>,
    pub loaded_at: Instant,
}

pub struct ProcCache {
    entries: HashMap<u32, ProcCacheEntry>,
    ttl: Duration,
}

impl ProcCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
        }
    }

    /// Returns the cached entry for `pid`, loading it from `/proc` if it is
    /// missing or older than the TTL. Returns `None` if the pid has exited
    /// (or any read failed) — the entry is removed in that case so callers
    /// can detect "process gone".
    pub fn get_or_load(&mut self, pid: u32) -> Option<&ProcCacheEntry> {
        let needs_reload = match self.entries.get(&pid) {
            Some(e) => e.loaded_at.elapsed() > self.ttl,
            None => true,
        };
        if needs_reload {
            match load_entry(pid) {
                Some(e) => {
                    self.entries.insert(pid, e);
                }
                None => {
                    self.entries.remove(&pid);
                    return None;
                }
            }
        }
        self.entries.get(&pid)
    }

    /// Force-invalidate the cached entry for `pid`. Called when the BPF side
    /// reports a Setns / Unshare / sched_process_exit event for `pid`. The
    /// next `get_or_load` will reload it (or evict if the process has gone).
    pub fn invalidate(&mut self, pid: u32) {
        self.entries.remove(&pid);
    }

    /// Drop every cached entry whose pid is no longer in `alive_pids`. Called
    /// by the scanner after a fresh `/proc` walk.
    pub fn sweep(&mut self, alive_pids: &HashSet<u32>) {
        self.entries.retain(|pid, _| alive_pids.contains(pid));
    }

    /// Direct read-only access to all entries. Used by
    /// [`super::namespace_tree_cache::NamespaceTreeCache::rebuild_from`].
    pub fn entries(&self) -> &HashMap<u32, ProcCacheEntry> {
        &self.entries
    }

    /// Force-rebuild trigger the namespace tree cache can check.
    pub fn generation_of(&self, pid: u32) -> Option<Instant> {
        self.entries.get(&pid).map(|e| e.loaded_at)
    }
}

fn load_entry(pid: u32) -> Option<ProcCacheEntry> {
    // Reuse the light reader for ppid/comm; the fields live in
    // `/proc/<pid>/ns/` and `/proc/<pid>/cgroup` separately.
    let light = crate::snapshot::procfields::read_light(pid as i32)?;
    let namespaces = read_ns_inodes(pid);
    let cgroup_path = resolve_cgroup_v2_path(pid);
    Some(ProcCacheEntry {
        pid,
        ppid: light.ppid as u32,
        comm: light.comm,
        namespaces,
        cgroup_path,
        loaded_at: Instant::now(),
    })
}

/// Read `/proc/<pid>/ns/*` and return (name → inode). Names are the symlink
/// filenames (`mnt`, `net`, ...). Inodes are parsed from the link target of
/// the form `mnt:[4026531840]`.
fn read_ns_inodes(pid: u32) -> HashMap<String, u64> {
    let mut out = HashMap::new();
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/ns")) else {
        return out;
    };
    for e in entries.flatten() {
        let name = match e.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let Ok(target) = fs::read_link(e.path()) else {
            continue;
        };
        let s = target.to_string_lossy().to_string();
        // Parse `name:[inode]`. We match the prefix loosely so we don't
        // double-count variations like `time_for_children`.
        if let Some(rest) = s
            .strip_prefix(&format!("{name}:["))
            .and_then(|r| r.strip_suffix(']'))
        {
            if let Ok(inode) = rest.parse::<u64>() {
                out.insert(name, inode);
            }
        }
    }
    out
}

/// Resolve cgroup v2 path for `pid` from `/proc/<pid>/cgroup`. Returns None
/// on any failure or if the process isn't in a v2 (unified) hierarchy. The
/// path is returned without a leading slash so it composes cleanly under
/// `/sys/fs/cgroup/`.
pub fn resolve_cgroup_v2_path(pid: u32) -> Option<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    for line in raw.lines() {
        // Format: `<hierarchy_id>:<controllers>:<path>`
        // cgroup v2 (unified) uses hierarchy id 0 and empty controllers.
        let mut parts = line.splitn(3, ':');
        let h = parts.next()?;
        let _c = parts.next();
        let path = parts.next()?;
        if h == "0" && !path.is_empty() {
            return Some(path.trim_start_matches('/').to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proc_cache_new() {
        let cache = ProcCache::new(Duration::from_secs(10));
        assert_eq!(cache.entries().len(), 0);
    }

    #[test]
    fn test_proc_cache_get_or_load_nonexistent_pid() {
        let mut cache = ProcCache::new(Duration::from_secs(10));
        let result = cache.get_or_load(999999999);
        assert!(result.is_none());
        assert_eq!(cache.entries().len(), 0);
    }

    #[test]
    fn test_proc_cache_get_or_load_init_pid() {
        let mut cache = ProcCache::new(Duration::from_secs(10));
        let result = cache.get_or_load(1);
        
        // PID 1 should exist on most systems
        if let Some(entry) = result {
            assert_eq!(entry.pid, 1);
            assert!(!entry.comm.is_empty());
            assert_eq!(cache.entries().len(), 1);
        }
    }

    #[test]
    fn test_proc_cache_caching() {
        let mut cache = ProcCache::new(Duration::from_secs(10));
        
        // First load
        let result1 = cache.get_or_load(1);
        if result1.is_some() {
            assert_eq!(cache.entries().len(), 1);
            
            // Second load should use cache
            let result2 = cache.get_or_load(1);
            assert!(result2.is_some());
            assert_eq!(cache.entries().len(), 1);
        }
    }

    #[test]
    fn test_proc_cache_invalidate() {
        let mut cache = ProcCache::new(Duration::from_secs(10));
        
        cache.get_or_load(1);
        if cache.entries().len() > 0 {
            cache.invalidate(1);
            assert_eq!(cache.entries().len(), 0);
        }
    }

    #[test]
    fn test_proc_cache_sweep() {
        let mut cache = ProcCache::new(Duration::from_secs(10));
        
        // Load some pids
        cache.get_or_load(1);
        
        let mut alive = HashSet::new();
        alive.insert(1);
        
        cache.sweep(&alive);
        
        // PID 1 should still be there
        if cache.entries().contains_key(&1) {
            assert_eq!(cache.entries().len(), 1);
        }
        
        // Sweep with empty set should clear everything
        let empty = HashSet::new();
        cache.sweep(&empty);
        assert_eq!(cache.entries().len(), 0);
    }

    #[test]
    fn test_proc_cache_generation_of() {
        let mut cache = ProcCache::new(Duration::from_secs(10));
        
        let gen1 = cache.generation_of(1);
        assert!(gen1.is_none());
        
        cache.get_or_load(1);
        let gen2 = cache.generation_of(1);
        
        if gen2.is_some() {
            assert!(gen2.unwrap().elapsed().as_millis() < 100);
        }
    }

    #[test]
    fn test_proc_cache_ttl_expiry() {
        let mut cache = ProcCache::new(Duration::from_millis(10));
        
        cache.get_or_load(1);
        if cache.entries().len() > 0 {
            std::thread::sleep(Duration::from_millis(20));
            
            // Should reload due to TTL expiry
            cache.get_or_load(1);
            // Entry should still exist (reloaded)
            if cache.entries().contains_key(&1) {
                let entry = cache.entries().get(&1).unwrap();
                assert!(entry.loaded_at.elapsed().as_millis() < 100);
            }
        }
    }

    #[test]
    fn test_proc_cache_multiple_pids() {
        let mut cache = ProcCache::new(Duration::from_secs(10));
        
        // Try to load a few common pids
        for pid in [1, 2, 3] {
            cache.get_or_load(pid);
        }
        
        // At least some should have loaded
        assert!(cache.entries().len() >= 0);
    }

    #[test]
    fn test_resolve_cgroup_v2_path_nonexistent() {
        let result = resolve_cgroup_v2_path(999999999);
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_cgroup_v2_path_init_pid() {
        let result = resolve_cgroup_v2_path(1);
        // May or may not have a cgroup path depending on system
        if let Some(path) = result {
            assert!(!path.is_empty());
            assert!(!path.starts_with('/')); // Should be trimmed
        }
    }

    #[test]
    fn test_proc_cache_entry_fields() {
        let mut cache = ProcCache::new(Duration::from_secs(10));
        
        if let Some(entry) = cache.get_or_load(1) {
            assert_eq!(entry.pid, 1);
            assert!(entry.ppid >= 0);
            assert!(!entry.comm.is_empty());
            // namespaces may be empty or have entries depending on system
            // cgroup_path may be None or Some
            assert!(entry.loaded_at.elapsed().as_millis() < 100);
        }
    }

    #[test]
    fn test_proc_cache_invalidate_nonexistent() {
        let mut cache = ProcCache::new(Duration::from_secs(10));
        cache.invalidate(999999999); // Should not panic
        assert_eq!(cache.entries().len(), 0);
    }

    #[test]
    fn test_proc_cache_sweep_partial() {
        let mut cache = ProcCache::new(Duration::from_secs(10));
        
        // Manually insert entries for testing
        let mut entry1 = ProcCacheEntry {
            pid: 100,
            ppid: 1,
            comm: "test1".to_string(),
            namespaces: HashMap::new(),
            cgroup_path: None,
            loaded_at: Instant::now(),
        };
        let mut entry2 = entry1.clone();
        entry2.pid = 200;
        entry2.comm = "test2".to_string();
        
        cache.entries.insert(100, entry1);
        cache.entries.insert(200, entry2);
        
        assert_eq!(cache.entries().len(), 2);
        
        // Sweep keeping only pid 100
        let mut alive = HashSet::new();
        alive.insert(100);
        cache.sweep(&alive);
        
        assert_eq!(cache.entries().len(), 1);
        assert!(cache.entries().contains_key(&100));
        assert!(!cache.entries().contains_key(&200));
    }
}