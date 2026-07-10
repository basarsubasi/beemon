pub mod cache;
pub mod cgroup;
pub mod cgroup_tree_cache;
pub mod details;
pub mod host;
pub mod manager;
pub mod namespace_tree_cache;
pub mod proc_cache;
pub mod procfields;
pub mod scanner;

pub use cache::SnapshotCache;
pub use cgroup_tree_cache::{CgroupLimits, CgroupTreeCache};
pub use namespace_tree_cache::NamespaceTreeCache;
pub use proc_cache::{ProcCache, ProcCacheEntry};

use std::sync::{Arc, Mutex};

use crate::pb::event::Event as Oneof;

/// A small bundle of the caches the BPF event stream is allowed to
/// invalidate. Held by the ringbuf task and called for every converted
/// `Event` so that stale proc_cache entries and namespace-tree structure
/// get evicted promptly on setns / unshare / process exit.
#[derive(Clone)]
pub struct CacheInvalidators {
    pub proc_cache: Arc<Mutex<ProcCache>>,
    pub namespace_tree: Arc<Mutex<NamespaceTreeCache>>,
}

impl CacheInvalidators {
    /// Inspect an event and invalidate any affected cache entries.
    pub fn on_event(&self, ev: &crate::pb::Event) {
        let Some(oneof) = &ev.event else { return };
        let (invalidate_proc, invalidate_tree) = match oneof {
            // sched_process_exit: process gone — drop its cached stable fields
            // so the next scanner sweep won't reuse them.
            Oneof::Process(p) if p.is_exit => (true, false),
            // Setns changes which namespaces the process belongs to →
            // invalidate proc_cache (ns inodes) AND the namespace tree.
            Oneof::Setns(_) => (true, true),
            // Unshare is similar to Setns (it allocates a new namespace).
            Oneof::Unshare(_) => (true, true),
            // Other events don't affect cached stable fields.
            _ => (false, false),
        };

        if invalidate_proc {
            if let Ok(mut pc) = self.proc_cache.lock() {
                pc.invalidate(ev.pid);
            }
        }
        if invalidate_tree {
            if let Ok(mut nt) = self.namespace_tree.lock() {
                nt.invalidate();
            }
        }
    }
}
