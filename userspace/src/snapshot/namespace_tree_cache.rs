//! Reverse index `(ns_type, inode) -> {pids}` built from the
//! [`super::proc_cache::ProcCache`]. Used by `GetNamespaceDetails` to find a
//! reference pid when the caller provides `reference_pid = 0`, and by future
//! "show me everyone in this namespace" UI surfaces.
//!
//! The tree is rebuilt from proc_cache every 10s (TTL) by the scanner. The
//! build is `O(n*p)` where `n` is #pids and `p` is #ns-types per pid (~8 on
//! modern kernels), so it's a few thousand inserts per rebuild.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use super::proc_cache::ProcCacheEntry;

pub const DEFAULT_TTL: Duration = Duration::from_secs(10);

pub struct NamespaceTreeCache {
    /// `(ns_type, inode) -> set of pids` sharing that namespace.
    tree: HashMap<(String, u64), HashSet<u32>>,
    built_at: Option<Instant>,
    ttl: Duration,
}

impl NamespaceTreeCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            tree: HashMap::new(),
            built_at: None,
            ttl,
        }
    }

    /// Rebuild the tree from the current proc_cache contents. Called by the
    /// scanner when [`is_stale`] returns true (i.e. roughly every TTL).
    pub fn rebuild_from(&mut self, proc_cache: &HashMap<u32, ProcCacheEntry>) {
        let mut tree: HashMap<(String, u64), HashSet<u32>> = HashMap::new();
        for (pid, entry) in proc_cache {
            for (ns_type, inode) in &entry.namespaces {
                tree.entry((ns_type.clone(), *inode))
                    .or_insert_with(HashSet::new)
                    .insert(*pid);
            }
        }
        self.tree = tree;
        self.built_at = Some(Instant::now());
    }

    /// Force the next [`rebuild_from`] call to actually rebuild, regardless
    /// of when the last one happened. Called when a Setns/Unshare/exit BPF
    /// event invalidates the cached namespace membership.
    pub fn invalidate(&mut self) {
        self.built_at = None;
    }

    /// True if the tree needs a rebuild (older than TTL or never built).
    pub fn is_stale(&self) -> bool {
        match self.built_at {
            None => true,
            Some(t) => t.elapsed() > self.ttl,
        }
    }

    /// Returns any single pid sharing the given `(ns_type, inode)`. Used by
    /// `GetNamespaceDetails` when `reference_pid = 0`.
    pub fn find_any_pid(&self, ns_type: &str, inode: u64) -> Option<u32> {
        self.tree
            .get(&(ns_type.to_string(), inode))
            .and_then(|pids| pids.iter().next().copied())
    }

    /// Returns every pid sharing the given `(ns_type, inode)`. Sorted for
    /// deterministic gRPC output.
    pub fn pids_in(&self, ns_type: &str, inode: u64) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .tree
            .get(&(ns_type.to_string(), inode))
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        v.sort_unstable();
        v
    }

    /// For diagnostics.
    pub fn num_entries(&self) -> usize {
        self.tree.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::proc_cache::ProcCacheEntry;
    use std::time::Instant;

    fn make_entry(pid: u32, namespaces: HashMap<String, u64>) -> ProcCacheEntry {
        ProcCacheEntry {
            pid,
            ppid: 1,
            comm: format!("test_{}", pid),
            namespaces,
            cgroup_path: None,
            managed_by: None,
            loaded_at: Instant::now(),
        }
    }

    #[test]
    fn test_namespace_tree_cache_new() {
        let cache = NamespaceTreeCache::new(Duration::from_secs(10));
        assert!(cache.is_stale());
        assert_eq!(cache.num_entries(), 0);
    }

    #[test]
    fn test_namespace_tree_cache_rebuild_empty() {
        let mut cache = NamespaceTreeCache::new(Duration::from_secs(10));
        let proc_cache = HashMap::new();
        
        cache.rebuild_from(&proc_cache);
        
        assert!(!cache.is_stale());
        assert_eq!(cache.num_entries(), 0);
    }

    #[test]
    fn test_namespace_tree_cache_rebuild_with_data() {
        let mut cache = NamespaceTreeCache::new(Duration::from_secs(10));
        let mut proc_cache = HashMap::new();
        
        let mut ns1 = HashMap::new();
        ns1.insert("mnt".to_string(), 4026531840);
        ns1.insert("net".to_string(), 4026531992);
        
        let mut ns2 = HashMap::new();
        ns2.insert("mnt".to_string(), 4026531840); // Same mnt as pid 1
        ns2.insert("net".to_string(), 4026531993); // Different net
        
        proc_cache.insert(1, make_entry(1, ns1));
        proc_cache.insert(2, make_entry(2, ns2));
        
        cache.rebuild_from(&proc_cache);
        
        assert!(!cache.is_stale());
        assert_eq!(cache.num_entries(), 3); // 2 mnt entries + 1 net entry (but 2 different inodes)
    }

    #[test]
    fn test_namespace_tree_cache_find_any_pid() {
        let mut cache = NamespaceTreeCache::new(Duration::from_secs(10));
        let mut proc_cache = HashMap::new();
        
        let mut ns = HashMap::new();
        ns.insert("mnt".to_string(), 4026531840);
        
        proc_cache.insert(100, make_entry(100, ns.clone()));
        proc_cache.insert(200, make_entry(200, ns));
        
        cache.rebuild_from(&proc_cache);
        
        let pid = cache.find_any_pid("mnt", 4026531840);
        assert!(pid.is_some());
        assert!(pid == Some(100) || pid == Some(200));
    }

    #[test]
    fn test_namespace_tree_cache_find_any_pid_not_found() {
        let mut cache = NamespaceTreeCache::new(Duration::from_secs(10));
        let proc_cache = HashMap::new();
        
        cache.rebuild_from(&proc_cache);
        
        let pid = cache.find_any_pid("mnt", 9999999);
        assert!(pid.is_none());
    }

    #[test]
    fn test_namespace_tree_cache_pids_in() {
        let mut cache = NamespaceTreeCache::new(Duration::from_secs(10));
        let mut proc_cache = HashMap::new();
        
        let mut ns = HashMap::new();
        ns.insert("mnt".to_string(), 4026531840);
        
        proc_cache.insert(300, make_entry(300, ns.clone()));
        proc_cache.insert(100, make_entry(100, ns.clone()));
        proc_cache.insert(200, make_entry(200, ns));
        
        cache.rebuild_from(&proc_cache);
        
        let pids = cache.pids_in("mnt", 4026531840);
        assert_eq!(pids, vec![100, 200, 300]); // Sorted
    }

    #[test]
    fn test_namespace_tree_cache_pids_in_empty() {
        let mut cache = NamespaceTreeCache::new(Duration::from_secs(10));
        let proc_cache = HashMap::new();
        
        cache.rebuild_from(&proc_cache);
        
        let pids = cache.pids_in("mnt", 9999999);
        assert!(pids.is_empty());
    }

    #[test]
    fn test_namespace_tree_cache_invalidate() {
        let mut cache = NamespaceTreeCache::new(Duration::from_secs(10));
        let proc_cache = HashMap::new();
        
        cache.rebuild_from(&proc_cache);
        assert!(!cache.is_stale());
        
        cache.invalidate();
        assert!(cache.is_stale());
    }

    #[test]
    fn test_namespace_tree_cache_ttl_expiry() {
        let mut cache = NamespaceTreeCache::new(Duration::from_millis(10));
        let proc_cache = HashMap::new();
        
        cache.rebuild_from(&proc_cache);
        assert!(!cache.is_stale());
        
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.is_stale());
    }

    #[test]
    fn test_namespace_tree_cache_multiple_namespaces_per_pid() {
        let mut cache = NamespaceTreeCache::new(Duration::from_secs(10));
        let mut proc_cache = HashMap::new();
        
        let mut ns = HashMap::new();
        ns.insert("mnt".to_string(), 4026531840);
        ns.insert("net".to_string(), 4026531992);
        ns.insert("uts".to_string(), 4026531838);
        ns.insert("ipc".to_string(), 4026531839);
        
        proc_cache.insert(1, make_entry(1, ns));
        
        cache.rebuild_from(&proc_cache);
        
        assert_eq!(cache.num_entries(), 4);
        assert_eq!(cache.pids_in("mnt", 4026531840), vec![1]);
        assert_eq!(cache.pids_in("net", 4026531992), vec![1]);
        assert_eq!(cache.pids_in("uts", 4026531838), vec![1]);
        assert_eq!(cache.pids_in("ipc", 4026531839), vec![1]);
    }
}