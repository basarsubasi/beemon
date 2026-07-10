//! 5-second rates poller. Reads the BPF `process_io_stats` LRU_PERCPU_HASH
//! and `process_net_flow_stats` HASH maps, then publishes:
//!   - per-pid cumulative `IoStat` (retained for delta computation),
//!   - per-pid per-second rates (for filling `Process.io_*_bytes` /
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
    pub cumulative_io: HashMap<u32, IoStat>,
    pub per_pid_rates: HashMap<u32, IoStat>,
    pub host_rates: HostIoRates,
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
pub fn spawn(maps: Arc<BpfStateMaps>, snapshot: Arc<RwLock<RateSnapshot>>, period_millis: u64) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_millis(period_millis.max(500)));
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
            let (rates, per_pid_rates, host_rates) = compute_rates(&prev_io, &new_io, prev_at, now);
            prev_io = new_io;
            prev_at = Some(now);

            let snap = RateSnapshot {
                cumulative_io: rates,
                per_pid_rates,
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
) -> (HashMap<u32, IoStat>, HashMap<u32, IoStat>, HostIoRates) {
    let cumulative: HashMap<u32, IoStat> = new_io
        .iter()
        .map(|(pid, stat)| (*pid, *stat))
        .collect();

    let (per_pid_rates, host_rates) = if let Some(prev_at) = prev_at {
        let elapsed = now.duration_since(prev_at).as_secs_f32().max(0.0001);
        let (mut rd, mut wr, mut rx, mut tx) = (0u64, 0u64, 0u64, 0u64);
        let mut pid_rates: HashMap<u32, IoStat> = HashMap::new();
        for (pid, new) in new_io {
            let prev = prev_io.get(pid).copied().unwrap_or_default();
            let d_rd = new.file_read_bytes.saturating_sub(prev.file_read_bytes);
            let d_wr = new.file_write_bytes.saturating_sub(prev.file_write_bytes);
            let d_rx = new.net_rx_bytes.saturating_sub(prev.net_rx_bytes);
            let d_tx = new.net_tx_bytes.saturating_sub(prev.net_tx_bytes);
            rd += d_rd;
            wr += d_wr;
            rx += d_rx;
            tx += d_tx;
            pid_rates.insert(*pid, IoStat {
                file_read_bytes: (d_rd as f32 / elapsed) as u64,
                file_write_bytes: (d_wr as f32 / elapsed) as u64,
                net_rx_bytes: (d_rx as f32 / elapsed) as u64,
                net_tx_bytes: (d_tx as f32 / elapsed) as u64,
            });
        }
        (
            pid_rates,
            HostIoRates {
                io_read_bytes_per_sec: (rd as f32 / elapsed) as u64,
                io_write_bytes_per_sec: (wr as f32 / elapsed) as u64,
                net_rx_bytes_per_sec: (rx as f32 / elapsed) as u64,
                net_tx_bytes_per_sec: (tx as f32 / elapsed) as u64,
            },
        )
    } else {
        (HashMap::new(), HostIoRates::default())
    };

    (cumulative, per_pid_rates, host_rates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::types::IoStat;
    use std::time::{Duration, Instant};

    #[test]
    fn test_host_io_rates_default() {
        let rates = HostIoRates::default();
        assert_eq!(rates.io_read_bytes_per_sec, 0);
        assert_eq!(rates.io_write_bytes_per_sec, 0);
        assert_eq!(rates.net_rx_bytes_per_sec, 0);
        assert_eq!(rates.net_tx_bytes_per_sec, 0);
    }

    #[test]
    fn test_rate_snapshot_default() {
        let snap = RateSnapshot::default();
        assert!(snap.cumulative_io.is_empty());
        assert!(snap.flows.is_empty());
        assert_eq!(snap.host_rates.io_read_bytes_per_sec, 0);
    }

    #[test]
    fn test_compute_rates_first_sample() {
        let prev_io = HashMap::new();
        let mut new_io = HashMap::new();
        new_io.insert(1234, IoStat {
            file_read_bytes: 1000,
            file_write_bytes: 500,
            net_rx_bytes: 2000,
            net_tx_bytes: 1000,
        });

        let now = Instant::now();
        let (cumulative, per_pid_rates, rates) = compute_rates(&prev_io, &new_io, None, now);

        assert_eq!(rates.io_read_bytes_per_sec, 0);
        assert_eq!(rates.io_write_bytes_per_sec, 0);
        assert_eq!(rates.net_rx_bytes_per_sec, 0);
        assert_eq!(rates.net_tx_bytes_per_sec, 0);

        assert!(per_pid_rates.is_empty());

        assert_eq!(cumulative.len(), 1);
        let stat = cumulative.get(&1234).unwrap();
        assert_eq!(stat.file_read_bytes, 1000);
        assert_eq!(stat.file_write_bytes, 500);
    }

    #[test]
    fn test_compute_rates_with_delta() {
        let mut prev_io = HashMap::new();
        prev_io.insert(1234, IoStat {
            file_read_bytes: 1000,
            file_write_bytes: 500,
            net_rx_bytes: 2000,
            net_tx_bytes: 1000,
        });

        let mut new_io = HashMap::new();
        new_io.insert(1234, IoStat {
            file_read_bytes: 2000,
            file_write_bytes: 1500,
            net_rx_bytes: 4000,
            net_tx_bytes: 3000,
        });

        let prev_at = Instant::now();
        let now = prev_at + Duration::from_secs(1);

        let (cumulative, per_pid_rates, rates) = compute_rates(&prev_io, &new_io, Some(prev_at), now);

        assert_eq!(rates.io_read_bytes_per_sec, 1000);
        assert_eq!(rates.io_write_bytes_per_sec, 1000);
        assert_eq!(rates.net_rx_bytes_per_sec, 2000);
        assert_eq!(rates.net_tx_bytes_per_sec, 2000);

        let pid_stat = per_pid_rates.get(&1234).unwrap();
        assert_eq!(pid_stat.file_read_bytes, 1000);
        assert_eq!(pid_stat.file_write_bytes, 1000);
        assert_eq!(pid_stat.net_rx_bytes, 2000);
        assert_eq!(pid_stat.net_tx_bytes, 2000);

        let stat = cumulative.get(&1234).unwrap();
        assert_eq!(stat.file_read_bytes, 2000);
    }

    #[test]
    fn test_compute_rates_multiple_pids() {
        let mut prev_io = HashMap::new();
        prev_io.insert(1234, IoStat {
            file_read_bytes: 1000,
            file_write_bytes: 500,
            net_rx_bytes: 2000,
            net_tx_bytes: 1000,
        });
        prev_io.insert(5678, IoStat {
            file_read_bytes: 2000,
            file_write_bytes: 1000,
            net_rx_bytes: 4000,
            net_tx_bytes: 2000,
        });

        let mut new_io = HashMap::new();
        new_io.insert(1234, IoStat {
            file_read_bytes: 2000,
            file_write_bytes: 1500,
            net_rx_bytes: 4000,
            net_tx_bytes: 3000,
        });
        new_io.insert(5678, IoStat {
            file_read_bytes: 3000,
            file_write_bytes: 2000,
            net_rx_bytes: 6000,
            net_tx_bytes: 4000,
        });

        let prev_at = Instant::now();
        let now = prev_at + Duration::from_secs(1);

        let (cumulative, per_pid_rates, rates) = compute_rates(&prev_io, &new_io, Some(prev_at), now);

        assert_eq!(rates.io_read_bytes_per_sec, 2000);
        assert_eq!(rates.io_write_bytes_per_sec, 2000);
        assert_eq!(rates.net_rx_bytes_per_sec, 4000);
        assert_eq!(rates.net_tx_bytes_per_sec, 4000);

        let pid1234 = per_pid_rates.get(&1234).unwrap();
        assert_eq!(pid1234.file_read_bytes, 1000);
        let pid5678 = per_pid_rates.get(&5678).unwrap();
        assert_eq!(pid5678.file_read_bytes, 1000);

        assert_eq!(cumulative.len(), 2);
    }

    #[test]
    fn test_compute_rates_new_pid() {
        let prev_io = HashMap::new();
        let mut new_io = HashMap::new();
        new_io.insert(1234, IoStat {
            file_read_bytes: 1000,
            file_write_bytes: 500,
            net_rx_bytes: 2000,
            net_tx_bytes: 1000,
        });

        let prev_at = Instant::now();
        let now = prev_at + Duration::from_secs(1);

        let (cumulative, per_pid_rates, rates) = compute_rates(&prev_io, &new_io, Some(prev_at), now);

        assert_eq!(rates.io_read_bytes_per_sec, 1000);
        assert_eq!(rates.io_write_bytes_per_sec, 500);
        assert_eq!(rates.net_rx_bytes_per_sec, 2000);
        assert_eq!(rates.net_tx_bytes_per_sec, 1000);

        let pid_stat = per_pid_rates.get(&1234).unwrap();
        assert_eq!(pid_stat.file_read_bytes, 1000);

        assert_eq!(cumulative.len(), 1);
    }

    #[test]
    fn test_compute_rates_pid_disappeared() {
        let mut prev_io = HashMap::new();
        prev_io.insert(1234, IoStat {
            file_read_bytes: 1000,
            file_write_bytes: 500,
            net_rx_bytes: 2000,
            net_tx_bytes: 1000,
        });

        let new_io = HashMap::new();

        let prev_at = Instant::now();
        let now = prev_at + Duration::from_secs(1);

        let (cumulative, per_pid_rates, rates) = compute_rates(&prev_io, &new_io, Some(prev_at), now);

        assert_eq!(rates.io_read_bytes_per_sec, 0);
        assert_eq!(rates.io_write_bytes_per_sec, 0);
        assert_eq!(rates.net_rx_bytes_per_sec, 0);
        assert_eq!(rates.net_tx_bytes_per_sec, 0);

        assert!(per_pid_rates.is_empty());
        assert!(cumulative.is_empty());
    }

    #[test]
    fn test_compute_rates_saturating_subtraction() {
        let mut prev_io = HashMap::new();
        prev_io.insert(1234, IoStat {
            file_read_bytes: 5000,
            file_write_bytes: 3000,
            net_rx_bytes: 8000,
            net_tx_bytes: 4000,
        });

        let mut new_io = HashMap::new();
        new_io.insert(1234, IoStat {
            file_read_bytes: 1000,
            file_write_bytes: 500,
            net_rx_bytes: 2000,
            net_tx_bytes: 1000,
        });

        let prev_at = Instant::now();
        let now = prev_at + Duration::from_secs(1);

        let (_cumulative, _per_pid_rates, rates) = compute_rates(&prev_io, &new_io, Some(prev_at), now);

        assert_eq!(rates.io_read_bytes_per_sec, 0);
        assert_eq!(rates.io_write_bytes_per_sec, 0);
        assert_eq!(rates.net_rx_bytes_per_sec, 0);
        assert_eq!(rates.net_tx_bytes_per_sec, 0);
    }

    #[test]
    fn test_compute_rates_fractional_elapsed() {
        let mut prev_io = HashMap::new();
        prev_io.insert(1234, IoStat {
            file_read_bytes: 0,
            file_write_bytes: 0,
            net_rx_bytes: 0,
            net_tx_bytes: 0,
        });

        let mut new_io = HashMap::new();
        new_io.insert(1234, IoStat {
            file_read_bytes: 1000,
            file_write_bytes: 500,
            net_rx_bytes: 2000,
            net_tx_bytes: 1000,
        });

        let prev_at = Instant::now();
        let now = prev_at + Duration::from_millis(500);

        let (_cumulative, per_pid_rates, rates) = compute_rates(&prev_io, &new_io, Some(prev_at), now);

        assert_eq!(rates.io_read_bytes_per_sec, 2000);
        assert_eq!(rates.io_write_bytes_per_sec, 1000);
        assert_eq!(rates.net_rx_bytes_per_sec, 4000);
        assert_eq!(rates.net_tx_bytes_per_sec, 2000);

        let pid_stat = per_pid_rates.get(&1234).unwrap();
        assert_eq!(pid_stat.file_read_bytes, 2000);
        assert_eq!(pid_stat.file_write_bytes, 1000);
    }

    #[test]
    fn test_compute_rates_very_small_elapsed() {
        let mut prev_io = HashMap::new();
        prev_io.insert(1234, IoStat {
            file_read_bytes: 0,
            file_write_bytes: 0,
            net_rx_bytes: 0,
            net_tx_bytes: 0,
        });

        let mut new_io = HashMap::new();
        new_io.insert(1234, IoStat {
            file_read_bytes: 1000,
            file_write_bytes: 500,
            net_rx_bytes: 2000,
            net_tx_bytes: 1000,
        });

        let prev_at = Instant::now();
        let now = prev_at + Duration::from_micros(1);

        let (_cumulative, _per_pid_rates, rates) = compute_rates(&prev_io, &new_io, Some(prev_at), now);

        assert!(rates.io_read_bytes_per_sec > 0);
        assert!(rates.io_write_bytes_per_sec > 0);
    }
}
