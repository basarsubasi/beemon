//! Snapshot cache shared between the background scanner task and the gRPC
//! service. Read via `Arc<RwLock<SnapshotCache>>`; written only by the scanner.

use std::time::Instant;

use crate::pb::pb::Process;

/// Per-process snapshot maintained by the 2-second background scanner.
/// `ListProcesses` clones this out wholesale; `GetProcessMetadata` reads the
/// entry for the requested `pid` and then enriches it with on-demand
/// `open_files` / `active_connections` walks.
#[derive(Clone, Debug, Default)]
pub struct SnapshotCache {
    pub processes: Vec<Process>,
    pub host_cpu_per_core_percent: Vec<f32>,
    pub host_namespaces: Vec<String>,
    pub host_memory_total_bytes: u64,
    pub updated_at: Option<Instant>,
}