//! Background 2-second scanner task. For each running pid it reads the
//! light `/proc/<pid>` fields, computes CPU% from successive utime+stime
//! deltas, looks up cgroup v2 limits + namespaces, and pulls io_*/net_*
//! byte counters from the cached `RateSnapshot` (BPF map cumulative).
//!
//! Results are written via `Arc<RwLock<SnapshotCache>>` for consumption by
//! `ListProcesses` and `GetProcessMetadata`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use procfs::process::all_processes;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::warn;

use crate::pb::pb::Process;
use crate::rates::RateSnapshot;
use crate::snapshot::cache::SnapshotCache;
use crate::snapshot::cgroup;
use crate::snapshot::host;
use crate::snapshot::procfields::{self, LightProc, state_label};

const CLKTCK: f32 = 100.0; // sysconf(_SC_CLK_TCK) on Linux is always 100.

/// Per-pid CPU sample retained between scanner iterations.
#[derive(Clone, Copy, Default)]
struct CpuPrev {
    pid: i32,
    utime_stime: u64,
    sampled_at: Instant,
}

/// Spawn the 2-second background scanner. Holds previous CPU samples
/// internally so it can compute deltas; writes into the shared cache.
pub fn spawn(
    cache: Arc<RwLock<SnapshotCache>>,
    rates: Arc<RwLock<RateSnapshot>>,
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

            // The whole scan is synchronous (blocking IO + BPF map reads);
            // run it on a blocking thread so the tokio runtime isn't stalled.
            let rates_snap = rates.read().await.clone();
            let cache_clone = tokio::task::spawn_blocking(move || {
                scan_once(&mut prev_cpu, &mut prev_host_cpu, &host_namespaces, host_mem_total, &rates_snap)
            })
            .await;

            match cache_clone {
                Ok(snap) => {
                    *cache.write().await = snap;
                }
                Err(e) => warn!(error = %e, "scan_once join failed"),
            }
        }
    });
}

/// One full scan pass. Returns the new `SnapshotCache`. Updates `prev_cpu`
/// and `prev_host_cpu` so the next iteration can compute deltas.
fn scan_once(
    prev_cpu: &mut HashMap<i32, CpuPrev>,
    prev_host_cpu: &mut Vec<host::CpuSample>,
    host_namespaces: &[String],
    host_mem_total: u64,
    rates: &RateSnapshot,
) -> SnapshotCache {
    let now = Instant::now();

    // Per-core CPU% from /proc/stat.
    let curr_host_cpu = host::read_cpu_samples();
    let host_cpu_per_core_percent = host::per_core_percent(prev_host_cpu, &curr_host_cpu);
    *prev_host_cpu = curr_host_cpu;

    let mut processes = Vec::new();
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
        let cpu_pct = compute_cpu_pct(prev_cpu, &light, now, &mut next_prev_cpu);

        // cgroup + namespaces are cheap per-pid; reads from sysfs symlinks.
        let (mem_limit, cpu_quota, cpu_period, pids_limit) = cgroup::read_limits(pid as u32);
        let namespaces = procfields::read_namespaces(pid);

        // Per-pid io/net byte counters: cumulative, from the cached BPF map
        // snapshot. Cold pids (not in target_pids) yield zero entries — which
        // the proto documents as "0 means the BPF map is cold".
        let io = rates.cumulative_io.get(&(pid as u32));

        let mut pb_proc = Process {
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
            namespaces,
            open_files: Vec::new(),
            active_connections: Vec::new(),
            io_read_bytes: io.map(|s| s.file_read_bytes).unwrap_or(0),
            io_write_bytes: io.map(|s| s.file_write_bytes).unwrap_or(0),
            net_rx_bytes: io.map(|s| s.net_rx_bytes).unwrap_or(0),
            net_tx_bytes: io.map(|s| s.net_tx_bytes).unwrap_or(0),
        };

        // The proto validates `pid > 0`. /proc never has pid 0, but assert.
        if pb_proc.pid == 0 {
            continue;
        }

        processes.push(pb_proc);
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
    light: &LightProc,
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