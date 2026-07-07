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