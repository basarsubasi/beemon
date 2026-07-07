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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_cache_default() {
        let cache = SnapshotCache::default();
        assert!(cache.processes.is_empty());
        assert!(cache.host_cpu_per_core_percent.is_empty());
        assert!(cache.host_namespaces.is_empty());
        assert_eq!(cache.host_memory_total_bytes, 0);
        assert!(cache.updated_at.is_none());
    }

    #[test]
    fn test_snapshot_cache_clone() {
        let cache = SnapshotCache::default();
        let cloned = cache.clone();
        assert_eq!(cache.processes.len(), cloned.processes.len());
        assert_eq!(cache.host_memory_total_bytes, cloned.host_memory_total_bytes);
        assert_eq!(cache.updated_at, cloned.updated_at);
    }

    #[test]
    fn test_snapshot_cache_with_data() {
        let mut cache = SnapshotCache::default();
        let now = Instant::now();
        
        cache.processes.push(Process {
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            state: "S".to_string(),
            memory_usage_bytes: 1024 * 1024,
            cpu_usage_percent: 0.5,
            memory_limit_bytes: 0,
            cpu_quota_us: 0,
            cpu_period_us: 0,
            pids_limit: 0,
            namespaces: vec!["mnt:[4026531840]".to_string()],
            open_files: vec![],
            active_connections: vec![],
            io_read_bytes: 1000,
            io_write_bytes: 500,
            net_rx_bytes: 2000,
            net_tx_bytes: 1000,
        });

        cache.host_cpu_per_core_percent = vec![25.0, 30.0, 20.0, 35.0];
        cache.host_namespaces = vec!["mnt:[4026531840]".to_string(), "net:[4026531992]".to_string()];
        cache.host_memory_total_bytes = 8 * 1024 * 1024 * 1024; // 8 GB
        cache.updated_at = Some(now);

        assert_eq!(cache.processes.len(), 1);
        assert_eq!(cache.processes[0].pid, 1);
        assert_eq!(cache.processes[0].name, "systemd");
        assert_eq!(cache.host_cpu_per_core_percent.len(), 4);
        assert_eq!(cache.host_namespaces.len(), 2);
        assert_eq!(cache.host_memory_total_bytes, 8 * 1024 * 1024 * 1024);
        assert_eq!(cache.updated_at, Some(now));
    }

    #[test]
    fn test_snapshot_cache_multiple_processes() {
        let mut cache = SnapshotCache::default();
        
        for i in 1..=5 {
            cache.processes.push(Process {
                pid: i,
                ppid: i - 1,
                name: format!("process_{}", i),
                state: "R".to_string(),
                memory_usage_bytes: i as u64 * 1024,
                cpu_usage_percent: i as f32 * 10.0,
                memory_limit_bytes: 0,
                cpu_quota_us: 0,
                cpu_period_us: 0,
                pids_limit: 0,
                namespaces: vec![],
                open_files: vec![],
                active_connections: vec![],
                io_read_bytes: i as u64 * 100,
                io_write_bytes: i as u64 * 50,
                net_rx_bytes: 0,
                net_tx_bytes: 0,
            });
        }

        assert_eq!(cache.processes.len(), 5);
        assert_eq!(cache.processes[0].pid, 1);
        assert_eq!(cache.processes[4].pid, 5);
        assert_eq!(cache.processes[2].name, "process_3");
    }
}