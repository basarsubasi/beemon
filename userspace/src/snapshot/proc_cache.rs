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