//! Typed accessors over the BPF hash maps the daemon polls for cumulative
//! counters and per-flow stats. The `events` ringbuf is consumed by the
//! [`crate::ringbuf`] task directly via `aya::maps::RingBuf`.

use anyhow::{anyhow, Result};
use aya::maps::{HashMap, Map, MapData, PerCpuHashMap, PerCpuValues};

use super::types::{IoStat, NetFlowKey, NetFlowStat};

// Owned (taken-out-of-Ebpf) map wrappers. Maps taken by `Ebpf::take_map`
// are fully owned, so their lifetime is independent of any `&'a` borrow.
// Putting them behind `Mutex<..>` lets multiple tokio tasks share access.
pub type OwnedTargetPids = HashMap<MapData, u32, u8>;
pub type OwnedIoStats   = PerCpuHashMap<MapData, u32, IoStat>;
pub type OwnedNetFlows  = HashMap<MapData, NetFlowKey, NetFlowStat>;

/// Sum of all per-CPU `IoStat` counters for one PID.
pub struct IoStats<'a> {
    inner: PerCpuHashMap<&'a mut MapData, u32, IoStat>,
}

impl<'a> IoStats<'a> {
    /// Wrap the `process_io_stats` map fetched via `Ebpf::map_mut`.
    pub fn new(map: &'a mut Map) -> Result<Self> {
        Ok(Self { inner: PerCpuHashMap::try_from(map)? })
    }

    /// Iterate the entire map, returning `(pid, summed_io_stat)` for every PID
    /// the BPF side currently tracks. Values are summed across all CPUs.
    pub fn summed(&self) -> Result<Vec<(u32, IoStat)>> {
        let mut out = Vec::new();
        for entry in self.inner.iter() {
            let (pid, per_cpu) = entry.map_err(|e| anyhow!("io_stats iter: {e}"))?;
            let sum = sum_per_cpu(&per_cpu);
            out.push((pid, sum));
        }
        Ok(out)
    }

    /// Summed counters for a single PID, if present in the map.
    pub fn get_summed(&self, pid: u32) -> Result<Option<IoStat>> {
        match self.inner.get(&pid, 0) {
            Ok(per_cpu) => Ok(Some(sum_per_cpu(&per_cpu))),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(e) => Err(anyhow!("io_stats get({pid}): {e}")),
        }
    }
}

fn sum_per_cpu(values: &PerCpuValues<IoStat>) -> IoStat {
    let mut acc = IoStat::default();
    for v in values.iter() {
        acc.file_read_bytes += v.file_read_bytes;
        acc.file_write_bytes += v.file_write_bytes;
        acc.net_rx_bytes += v.net_rx_bytes;
        acc.net_tx_bytes += v.net_tx_bytes;
    }
    acc
}

/// Wraps `target_pids` (`BPF_MAP_TYPE_HASH<u32,u8>`).
pub struct TargetPids<'a> {
    inner: HashMap<&'a mut MapData, u32, u8>,
}

impl<'a> TargetPids<'a> {
    pub fn new(map: &'a mut Map) -> Result<Self> {
        Ok(Self { inner: HashMap::try_from(map)? })
    }
    pub fn insert(&mut self, pid: u32, flags: u8) -> Result<()> {
        self.inner
            .insert(pid, flags, 0)
            .map_err(|e| anyhow!("insert target_pids[{pid}]: {e}"))
    }
    pub fn remove(&mut self, pid: u32) -> Result<()> {
        self.inner
            .remove(&pid)
            .map_err(|e| anyhow!("remove target_pids[{pid}]: {e}"))
    }
}

/// Wraps `process_net_flow_stats` (`BPF_MAP_TYPE_HASH<NetFlowKey, NetFlowStat>`).
pub struct NetFlows<'a> {
    inner: HashMap<&'a mut MapData, NetFlowKey, NetFlowStat>,
}

impl<'a> NetFlows<'a> {
    pub fn new(map: &'a mut Map) -> Result<Self> {
        Ok(Self { inner: HashMap::try_from(map)? })
    }

    /// Iterate every flow whose PID matches.
    pub fn for_pid(&self, pid: u32) -> Result<Vec<(NetFlowKey, NetFlowStat)>> {
        let mut out = Vec::new();
        for entry in self.inner.iter() {
            let (k, v) = entry.map_err(|e| anyhow!("net_flow iter: {e}"))?;
            if k.pid == pid {
                out.push((k, v));
            }
        }
        Ok(out)
    }
}

// ------------------------------------------------------------------
// Standalone helpers operating on owned maps (used by the rates poller,
// which holds `OwnedIoStats` / `OwnedNetFlows` directly behind a `Mutex`).
// ------------------------------------------------------------------

/// Sum per-CPU `IoStat` values for every PID in the owned IO stats map.
pub fn io_stats_summed(map: &OwnedIoStats) -> Result<Vec<(u32, IoStat)>> {
    let mut out = Vec::new();
    for entry in map.iter() {
        let (pid, per_cpu) = entry.map_err(|e| anyhow!("io_stats iter: {e}"))?;
        let sum = sum_per_cpu(&per_cpu);
        out.push((pid, sum));
    }
    Ok(out)
}

/// Collect every (key, stat) pair from the owned net-flow map.
pub fn net_flows_all(map: &OwnedNetFlows) -> Result<Vec<(NetFlowKey, NetFlowStat)>> {
    let mut out = Vec::new();
    for entry in map.iter() {
        let (k, v) = entry.map_err(|e| anyhow!("net_flow iter: {e}"))?;
        out.push((k, v));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    
    use crate::bpf::types::{IoStat, NetFlowKey, NetFlowStat};

    #[test]
    fn test_io_stat_default() {
        let stat = IoStat::default();
        assert_eq!(stat.file_read_bytes, 0);
        assert_eq!(stat.file_write_bytes, 0);
        assert_eq!(stat.net_rx_bytes, 0);
        assert_eq!(stat.net_tx_bytes, 0);
    }

    #[test]
    fn test_net_flow_key_equality() {
        let key1 = NetFlowKey {
            pid: 1234,
            saddr: 0x0100007f, // 127.0.0.1
            daddr: 0x08080808, // 8.8.8.8
            sport: 12345,
            dport: 80,
            family: 2, // AF_INET
            protocol: 6, // TCP
        };

        let key2 = NetFlowKey {
            pid: 1234,
            saddr: 0x0100007f,
            daddr: 0x08080808,
            sport: 12345,
            dport: 80,
            family: 2,
            protocol: 6,
        };

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_net_flow_key_inequality() {
        let key1 = NetFlowKey {
            pid: 1234,
            saddr: 0x0100007f,
            daddr: 0x08080808,
            sport: 12345,
            dport: 80,
            family: 2,
            protocol: 6,
        };

        let key2 = NetFlowKey {
            pid: 5678, // Different PID
            saddr: 0x0100007f,
            daddr: 0x08080808,
            sport: 12345,
            dport: 80,
            family: 2,
            protocol: 6,
        };

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_net_flow_stat_default() {
        let stat = NetFlowStat {
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
        };
        assert_eq!(stat.rx_bytes, 0);
        assert_eq!(stat.tx_bytes, 0);
        assert_eq!(stat.rx_packets, 0);
        assert_eq!(stat.tx_packets, 0);
    }

    #[test]
    fn test_net_flow_stat_accumulation() {
        let stat1 = NetFlowStat {
            rx_bytes: 1000,
            tx_bytes: 500,
            rx_packets: 10,
            tx_packets: 5,
        };

        let stat2 = NetFlowStat {
            rx_bytes: 2000,
            tx_bytes: 1500,
            rx_packets: 20,
            tx_packets: 15,
        };

        let total = NetFlowStat {
            rx_bytes: stat1.rx_bytes + stat2.rx_bytes,
            tx_bytes: stat1.tx_bytes + stat2.tx_bytes,
            rx_packets: stat1.rx_packets + stat2.rx_packets,
            tx_packets: stat1.tx_packets + stat2.tx_packets,
        };

        assert_eq!(total.rx_bytes, 3000);
        assert_eq!(total.tx_bytes, 2000);
        assert_eq!(total.rx_packets, 30);
        assert_eq!(total.tx_packets, 20);
    }

    #[test]
    fn test_io_stat_accumulation() {
        let stat1 = IoStat {
            file_read_bytes: 1024,
            file_write_bytes: 512,
            net_rx_bytes: 2048,
            net_tx_bytes: 1024,
        };

        let stat2 = IoStat {
            file_read_bytes: 2048,
            file_write_bytes: 1024,
            net_rx_bytes: 4096,
            net_tx_bytes: 2048,
        };

        let total = IoStat {
            file_read_bytes: stat1.file_read_bytes + stat2.file_read_bytes,
            file_write_bytes: stat1.file_write_bytes + stat2.file_write_bytes,
            net_rx_bytes: stat1.net_rx_bytes + stat2.net_rx_bytes,
            net_tx_bytes: stat1.net_tx_bytes + stat2.net_tx_bytes,
        };

        assert_eq!(total.file_read_bytes, 3072);
        assert_eq!(total.file_write_bytes, 1536);
        assert_eq!(total.net_rx_bytes, 6144);
        assert_eq!(total.net_tx_bytes, 3072);
    }

    #[test]
    fn test_net_flow_key_hash() {
        use std::collections::HashSet;

        let key1 = NetFlowKey {
            pid: 1234,
            saddr: 0x0100007f,
            daddr: 0x08080808,
            sport: 12345,
            dport: 80,
            family: 2,
            protocol: 6,
        };

        let key2 = NetFlowKey {
            pid: 1234,
            saddr: 0x0100007f,
            daddr: 0x08080808,
            sport: 12345,
            dport: 80,
            family: 2,
            protocol: 6,
        };

        let mut set = HashSet::new();
        set.insert(key1);
        set.insert(key2);

        // Should only have one entry since key1 == key2
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_net_flow_key_different_protocols() {
        let tcp_key = NetFlowKey {
            pid: 1234,
            saddr: 0x0100007f,
            daddr: 0x08080808,
            sport: 12345,
            dport: 80,
            family: 2,
            protocol: 6, // TCP
        };

        let udp_key = NetFlowKey {
            pid: 1234,
            saddr: 0x0100007f,
            daddr: 0x08080808,
            sport: 12345,
            dport: 53,
            family: 2,
            protocol: 17, // UDP
        };

        assert_ne!(tcp_key, udp_key);
    }
}
