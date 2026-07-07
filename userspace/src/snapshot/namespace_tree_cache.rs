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