//! Background 2-second scanner task. For each running pid it reads the
//! light `/proc/<pid>` fields, computes CPU% from successive utime+stime
//! deltas, and pulls stable per-pid metadata (ns inodes, cgroup path,
//! cgroup limits) from the three shared caches so that those syscalls are
//! O(unique paths) across the host, not O(num_pids) per scan.
//!
//! Output: writes [`SnapshotCache`] into an `Arc<RwLock<SnapshotCache>>`
//! consumed by `ListProcesses` and `GetProcessMetadata`.
//!
//! Results get io_*/net_* byte counters from the cached [`RateSnapshot`]
//! (BPF map cumulative, populated by the 5s rates poller).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use procfs::process::all_processes;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::warn;

use crate::pb::pb::Process;
use crate::rates::RateSnapshot;
use crate::snapshot::cache::SnapshotCache;
use crate::snapshot::cgroup_tree_cache::CgroupTreeCache;
use crate::snapshot::host;
use crate::snapshot::namespace_tree_cache::NamespaceTreeCache;
use crate::snapshot::proc_cache::ProcCache;
use crate::snapshot::procfields::{self, state_label};

const CLKTCK: f32 = 100.0; // sysconf(_SC_CLK_TCK) on Linux is always 100.

/// Per-pid CPU sample retained between scanner iterations for delta calc.
#[derive(Clone, Copy)]
struct CpuPrev {
    pid: i32,
    utime_stime: u64,
    sampled_at: Instant,
}

/// Spawn the scanner. It owns three caches (proc_cache, cgroup_tree_cache,
/// namespace_tree_cache) which it mutates inside `spawn_blocking` closures
/// so the rest of the daemon can read them via the same `Arc<Mutex<>>`.
pub fn spawn(
    cache: Arc<RwLock<SnapshotCache>>,
    rates: Arc<RwLock<RateSnapshot>>,
    proc_cache: Arc<Mutex<ProcCache>>,
    cgroup_tree: Arc<Mutex<CgroupTreeCache>>,
    namespace_tree: Arc<Mutex<NamespaceTreeCache>>,
    period_secs: u64,
) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(period_secs.max(1)));
        let mut prev_cpu: HashMap<i32, CpuPrev> = HashMap::new();
        let host_namespaces = host::read_host_namespaces();
        let mut prev_host_cpu: Vec<host::CpuSample> = Vec::new();
        let host_mem_total = host::read_memtotal_bytes();
        loop {
            ticker.tick().await;

            let rates_snap = rates.read().await.clone();

            let snap = scan_once(
                &mut prev_cpu,
                &mut prev_host_cpu,
                &host_namespaces,
                host_mem_total,
                &rates_snap,
                &proc_cache,
                &cgroup_tree,
                &namespace_tree,
            );

            *cache.write().await = snap;
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn scan_once(
    prev_cpu: &mut HashMap<i32, CpuPrev>,
    prev_host_cpu: &mut Vec<host::CpuSample>,
    host_namespaces: &[String],
    host_mem_total: u64,
    rates: &RateSnapshot,
    proc_cache: &Mutex<ProcCache>,
    cgroup_tree: &Mutex<CgroupTreeCache>,
    namespace_tree: &Mutex<NamespaceTreeCache>,
) -> SnapshotCache {
    let now = Instant::now();

    // Per-core CPU% from /proc/stat.
    let curr_host_cpu = host::read_cpu_samples();
    let host_cpu_per_core_percent = host::per_core_percent(prev_host_cpu, &curr_host_cpu);
    *prev_host_cpu = curr_host_cpu;

    let mut processes: Vec<Process> = Vec::new();
    let mut alive_pids: HashSet<u32> = HashSet::new();
    let mut next_prev_cpu: HashMap<i32, CpuPrev> = HashMap::new();

    let iter = match all_processes() {
        Ok(i) => i,
        Err(e) => {
            warn!(error = %e, "all_processes() failed; cache not refreshed");
            return SnapshotCache {
                processes: Vec::new(),
                host_cpu_per_core_percent,
                host_namespaces: host_namespaces.to_vec(),
                host_memory_total_bytes: host_mem_total,
                updated_at: Some(now),
            };
        }
    };

    // We take the cache locks once for the whole scan; contention is light
    // (gRPC handlers only briefly touch proc_cache, cgroup_tree, or
    // namespace_tree).
    let mut pc_lock = proc_cache.lock().expect("proc_cache lock poisoned");
    let mut cg_lock = cgroup_tree.lock().expect("cgroup_tree lock poisoned");

    for proc_result in iter {
        let p = match proc_result {
            Ok(p) => p,
            Err(_) => continue,
        };
        let pid = p.pid;
        let light = match procfields::read_light(pid) {
            Some(lp) => lp,
            None => continue,
        };
        alive_pids.insert(pid as u32);
        let cpu_pct = compute_cpu_pct(prev_cpu, &light, now, &mut next_prev_cpu);

        // Stable fields via proc_cache: ns inodes + cgroup path. Avoids the
        // ~8 readlinks + 1 cgroup read per pid per scan; the cache
        // refreshes at most once every 10s.
        let (cgroup_path, namespace_strings) = match pc_lock.get_or_load(pid as u32) {
            Some(entry) => {
                let ns_strings: Vec<String> = entry
                    .namespaces
                    .iter()
                    .map(|(t, inode)| format!("{t}:[{inode}]"))
                    .collect();
                (entry.cgroup_path.clone(), ns_strings)
            }
            None => (None, Vec::new()),
        };

        // Cgroup limits shared across all pids in the same path. With the
        // cache this is a sysfs read every 10s per unique cgroup, not per pid.
        let (mem_limit, cpu_quota, cpu_period, pids_limit) =
            cg_lock.get_or_load(&cgroup_path, pid as u32).map_or((0, 0, 0, 0), |l| {
                (l.memory_limit_bytes, l.cpu_quota_us, l.cpu_period_us, l.pids_limit)
            });

        // Per-pid io/net byte counters: cumulative, from the cached BPF map
        // snapshot. Cold pids (not in target_pids) yield zero entries — which
        // the proto documents as "0 means the BPF map is cold".
        let io = rates.cumulative_io.get(&(pid as u32));

        let pb_proc = Process {
            pid: pid as u32,
            ppid: light.ppid as u32,
            name: light.comm.clone(),
            state: state_label(light.state_char).to_string(),
            memory_usage_bytes: light.rss_bytes,
            cpu_usage_percent: cpu_pct,
            memory_limit_bytes: mem_limit,
            cpu_quota_us: cpu_quota,
            cpu_period_us: cpu_period,
            pids_limit,
            namespaces: namespace_strings,
            open_files: Vec::new(),
            active_connections: Vec::new(),
            io_read_bytes: io.map(|s| s.file_read_bytes).unwrap_or(0),
            io_write_bytes: io.map(|s| s.file_write_bytes).unwrap_or(0),
            net_rx_bytes: io.map(|s| s.net_rx_bytes).unwrap_or(0),
            net_tx_bytes: io.map(|s| s.net_tx_bytes).unwrap_or(0),
        };

        if pb_proc.pid == 0 {
            continue;
        }
        processes.push(pb_proc);
    }

    // Sweep stale proc_cache entries (pids that have exited).
    pc_lock.sweep(&alive_pids);
    let pc_snapshot: HashMap<u32, _> = pc_lock.entries().clone();
    drop(pc_lock);
    drop(cg_lock);

    // Rebuild namespace_tree if it's stale. Done OUTSIDE the cache lock to
    // keep critical sections short — we clone proc_cache entries briefly.
    {
        let mut ns_lock = namespace_tree.lock().expect("namespace_tree lock poisoned");
        if ns_lock.is_stale() {
            ns_lock.rebuild_from(&pc_snapshot);
        }
    }

    *prev_cpu = next_prev_cpu;

    SnapshotCache {
        processes,
        host_cpu_per_core_percent,
        host_namespaces: host_namespaces.to_vec(),
        host_memory_total_bytes: host_mem_total,
        updated_at: Some(now),
    }
}

/// CPU% from successive utime+stime samples: 100 * (delta_ticks /
/// delta_seconds) / CLKTCK. Capped to [0, 100]. Writes the new prev entry.
fn compute_cpu_pct(
    prev_cpu: &HashMap<i32, CpuPrev>,
    light: &procfields::LightProc,
    now: Instant,
    next_prev_cpu: &mut HashMap<i32, CpuPrev>,
) -> f32 {
    let cur = light.utime + light.stime;
    let new_prev = CpuPrev {
        pid: light.pid,
        utime_stime: cur,
        sampled_at: now,
    };
    next_prev_cpu.insert(light.pid, new_prev);

    let Some(prev) = prev_cpu.get(&light.pid) else {
        return 0.0; // first sample for this pid; no delta yet
    };
    let d_ticks = cur.saturating_sub(prev.utime_stime);
    let d_secs = now
        .duration_since(prev.sampled_at)
        .as_secs_f32()
        .max(0.0001);
    let pct = (d_ticks as f32 / d_secs / CLKTCK) * 100.0;
    pct.clamp(0.0, 100.0)
}
