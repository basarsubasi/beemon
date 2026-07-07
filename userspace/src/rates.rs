//! 5-second rates poller. Reads the BPF `process_io_stats` LRU_PERCPU_HASH
//! and `process_net_flow_stats` HASH maps, then publishes:
//!   - per-pid cumulative `IoStat` (for filling `Process.io_*_bytes` /
//!     `net_*_bytes` in the scanner's cache),
//!   - host-wide host_*_per_sec rates (computed from successive deltas),
//!   - per-pid cumulative flow lists (consumed by `GetNetworkFlows`).
//!
//! All BPF map reads are blocking syscalls; they run on a `spawn_blocking`
//! worker so we don't stall the tokio runtime.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::warn;

use crate::bpf::maps::{io_stats_summed, net_flows_all, OwnedIoStats, OwnedNetFlows};
use crate::bpf::types::{IoStat, NetFlowKey, NetFlowStat};

/// Snapshot produced by the rates poller every 5 seconds. Cloned by the gRPC
/// service (`ListProcesses`, `GetNetworkFlows`) and the scanner task.
#[derive(Clone, Debug, Default)]
pub struct RateSnapshot {
    /// Per-pid cumulative byte counters (summed across CPUs).
    pub cumulative_io: HashMap<u32, IoStat>,
    /// Host-wide per-second rates (the `host_*_per_sec` proto fields).
    pub host_rates: HostIoRates,
    /// Per-pid cumulative flow stats (the BPF map values verbatim).
    pub flows: HashMap<u32, Vec<(NetFlowKey, NetFlowStat)>>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HostIoRates {
    pub io_read_bytes_per_sec: u64,
    pub io_write_bytes_per_sec: u64,
    pub net_rx_bytes_per_sec: u64,
    pub net_tx_bytes_per_sec: u64,
}

/// Owned BPF maps retained for the lifetime of the daemon. Wrapped here so
/// the spawn_blocking closure can hold them by `Arc<Mutex<..>>` (BPF maps
/// are not `Sync`).
pub struct BpfStateMaps {
    pub io_stats: Arc<std::sync::Mutex<OwnedIoStats>>,
    pub net_flows: Arc<std::sync::Mutex<OwnedNetFlows>>,
}

/// Spawn the 5s rates poller task.
pub fn spawn(maps: Arc<BpfStateMaps>, snapshot: Arc<RwLock<RateSnapshot>>, period_secs: u64) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(period_secs.max(1)));
        // Previous cumulative counters per pid (summed across CPUs) for
        // computing per-pid delta/sec and the host aggregate rate.
        let mut prev_io: HashMap<u32, IoStat> = HashMap::new();
        let mut prev_at: Option<Instant> = None;
        loop {
            ticker.tick().await;

            let maps_io = maps.io_stats.clone();
            let maps_net = maps.net_flows.clone();
            let (new_io, new_flows) = tokio::task::spawn_blocking(move || {
                read_bpf_maps(&maps_io, &maps_net)
            })
            .await
            .unwrap_or_default();

            let now = Instant::now();
            let (rates, host_rates) = compute_rates(&prev_io, &new_io, prev_at, now);
            prev_io = new_io;
            prev_at = Some(now);

            let snap = RateSnapshot {
                cumulative_io: rates,
                host_rates,
                flows: new_flows,
            };

            *snapshot.write().await = snap;
        }
    });
}

/// Pull the latest cumulative values from the BPF maps.
fn read_bpf_maps(
    io_stats: &Arc<std::sync::Mutex<OwnedIoStats>>,
    net_flows: &Arc<std::sync::Mutex<OwnedNetFlows>>,
) -> (HashMap<u32, IoStat>, HashMap<u32, Vec<(NetFlowKey, NetFlowStat)>>) {
    let mut io = HashMap::new();
    if let Ok(stats) = io_stats.lock() {
        match io_stats_summed(&stats) {
            Ok(v) => {
                for (pid, stat) in v {
                    io.insert(pid, stat);
                }
            }
            Err(e) => warn!(error = %e, "io_stats summed() failed"),
        }
    }

    let mut flows: HashMap<u32, Vec<(NetFlowKey, NetFlowStat)>> = HashMap::new();
    if let Ok(nf) = net_flows.lock() {
        match net_flows_all(&nf) {
            Ok(v) => {
                for (k, stat) in v {
                    flows.entry(k.pid).or_default().push((k, stat));
                }
            }
            Err(e) => warn!(error = %e, "net_flows all() failed"),
        }
    }

    (io, flows)
}

/// Compute per-pid cumulative counters (returned as-is; the proto exposes
/// cumulative `io_*_bytes` per process) plus host aggregate per-second rates
/// from deltas of the per-pid cumulative counters.
fn compute_rates(
    prev_io: &HashMap<u32, IoStat>,
    new_io: &HashMap<u32, IoStat>,
    prev_at: Option<Instant>,
    now: Instant,
) -> (HashMap<u32, IoStat>, HostIoRates) {
    let cumulative: HashMap<u32, IoStat> = new_io
        .iter()
        .map(|(pid, stat)| (*pid, *stat))
        .collect();

    let host_rates = if let Some(prev_at) = prev_at {
        let elapsed = now.duration_since(prev_at).as_secs_f32().max(0.0001);
        let (mut rd, mut wr, mut rx, mut tx) = (0u64, 0u64, 0u64, 0u64);
        for (pid, new) in new_io {
            // Delta vs previous cumulative for this pid. If the pid wasn't
            // seen before (or was evicted from the LRU map), the current
            // cumulative value is the entire delta — BPF map reads reset per-LRU-evict.
            let prev = prev_io.get(pid).copied().unwrap_or_default();
            // u64 saturating delta; the BPF map only ever increases these counters.
            rd += new.file_read_bytes.saturating_sub(prev.file_read_bytes);
            wr += new.file_write_bytes.saturating_sub(prev.file_write_bytes);
            rx += new.net_rx_bytes.saturating_sub(prev.net_rx_bytes);
            tx += new.net_tx_bytes.saturating_sub(prev.net_tx_bytes);
        }
        HostIoRates {
            io_read_bytes_per_sec: (rd as f32 / elapsed) as u64,
            io_write_bytes_per_sec: (wr as f32 / elapsed) as u64,
            net_rx_bytes_per_sec: (rx as f32 / elapsed) as u64,
            net_tx_bytes_per_sec: (tx as f32 / elapsed) as u64,
        }
    } else {
        // First sample — no delta yet. The proto documents `0 means the BPF
        // map is cold`, so this is the legitimate cold-warmup value too.
        HostIoRates::default()
    };

    (cumulative, host_rates)
}