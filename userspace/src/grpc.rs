//! gRPC service implementation. Wraps the snapshot cache (via `Arc<RwLock<>>`),
//! the rates snapshot, the stream registry, plus the proc/cgroup/namespace
//! caches; the five BeemonService RPCs read from these shared structures.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::RwLock;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

use crate::bpf::maps::OwnedNetFlows;
use crate::bpf::types::{NetFlowKey, NetFlowStat};
use crate::config::Config;
use crate::pb::pb::beemon_service_server::BeemonService;
use crate::pb::pb::{
    GetNamespaceDetailsRequest, GetNamespaceDetailsResponse, GetNetworkFlowsRequest,
    GetNetworkFlowsResponse, GetProcessMetadataRequest, GetProcessMetadataResponse,
    ListProcessesRequest, ListProcessesResponse, NetworkFlow, Process,
};
use crate::rates::RateSnapshot;
use crate::snapshot::cache::SnapshotCache;
use crate::snapshot::details;
use crate::snapshot::namespace_tree_cache::NamespaceTreeCache;
use crate::stream::StreamRegistry;

#[derive(Clone)]
pub struct BeemonServiceImpl {
    pub snapshot: Arc<RwLock<SnapshotCache>>,
    pub rates: Arc<RwLock<RateSnapshot>>,
    pub registry: StreamRegistry,
    pub net_flows: Arc<std::sync::Mutex<OwnedNetFlows>>,
    pub namespace_tree: Arc<std::sync::Mutex<NamespaceTreeCache>>,
    pub config: Config,
}

impl BeemonServiceImpl {
    fn build_process_index(snap: &SnapshotCache) -> HashMap<u32, Process> {
        snap.processes
            .iter()
            .map(|p| (p.pid, p.clone()))
            .collect()
    }
}

#[tonic::async_trait]
impl BeemonService for BeemonServiceImpl {
    async fn list_processes(
        &self,
        req: Request<ListProcessesRequest>,
    ) -> Result<Response<ListProcessesResponse>, Status> {
        let filter = req.into_inner().filter_name;
        let snap = self.snapshot.read().await.clone();
        let rates = self.rates.read().await.clone();

        let processes: Vec<Process> = if filter.is_empty() {
            snap.processes.clone()
        } else {
            let filter_pid = filter.parse::<u32>().ok();
            snap.processes
                .iter()
                .filter(|p| {
                    p.name.contains(&filter)
                        || filter_pid.map_or(false, |pid| p.pid == pid)
                })
                .cloned()
                .collect()
        };

        Ok(Response::new(ListProcessesResponse {
            processes,
            host_memory_total_bytes: snap.host_memory_total_bytes,
            host_namespaces: snap.host_namespaces.clone(),
            host_cpu_per_core_percent: snap.host_cpu_per_core_percent.clone(),
            host_io_read_bytes_per_sec: rates.host_rates.io_read_bytes_per_sec,
            host_io_write_bytes_per_sec: rates.host_rates.io_write_bytes_per_sec,
            host_net_rx_bytes_per_sec: rates.host_rates.net_rx_bytes_per_sec,
            host_net_tx_bytes_per_sec: rates.host_rates.net_tx_bytes_per_sec,
        }))
    }

    async fn get_process_metadata(
        &self,
        req: Request<GetProcessMetadataRequest>,
    ) -> Result<Response<GetProcessMetadataResponse>, Status> {
        let pid = req.into_inner().pid;
        if pid == 0 {
            return Err(Status::invalid_argument("pid must be > 0"));
        }
        let snap = self.snapshot.read().await.clone();
        let idx = Self::build_process_index(&snap);

        let process = idx
            .get(&pid)
            .ok_or_else(|| Status::not_found(format!("process {pid} not found")))?;

        let mut process = process.clone();
        // Enrich with open_files/active_connections (synthesizes the
        // expensive /proc walk here, only for the user-selected detail view).
        // Avoid `details::enrich` clone overhead:
        let open_files = details::read_open_files_pub(pid);
        let active_connections = details::read_active_connections_pub(pid);
        process.open_files = open_files;
        process.active_connections = active_connections;

        let parent = idx
            .get(&process.ppid)
            .cloned()
            .or_else(|| Some(Process::default()));
        let children = details::resolve_children(pid, &idx);

        Ok(Response::new(GetProcessMetadataResponse {
            process: Some(process),
            parent,
            children,
            host_namespaces: snap.host_namespaces.clone(),
        }))
    }

    type StreamEventsStream = std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<crate::pb::pb::EventBatch, Status>> + Send>>;

    async fn stream_events(
        &self,
        req: Request<crate::pb::pb::StreamEventsRequest>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        let pid = req.into_inner().pid;
        if pid == 0 {
            return Err(Status::invalid_argument("pid must be > 0"));
        }
        let sub = self
            .registry
            .subscribe(pid, self.config.event_limit)
            .map_err(|e| Status::internal(format!("subscribe failed: {e}")))?;

        let stream = BroadcastStream::new(sub.rx)
            .filter_map(|res| match res {
                Ok(ev) => Some(ev),
                Err(_) => None, // drop lagged events rather than closing stream
            })
            .chunks_timeout(200, std::time::Duration::from_millis(50))
            .map(|events| Ok(crate::pb::pb::EventBatch { events }));

        // Drop `guard` lazily when the client disconnects: we wrap the
        // stream + guard in a custom adapter that on drop releases both.
        let guarded = GuardedStream {
            inner: Box::pin(stream),
            _guard: sub.guard,
        };

        Ok(Response::new(Box::pin(guarded)))
    }

    async fn get_namespace_details(
        &self,
        req: Request<GetNamespaceDetailsRequest>,
    ) -> Result<Response<GetNamespaceDetailsResponse>, Status> {
        let GetNamespaceDetailsRequest {
            ns_type,
            ns_inode,
            reference_pid,
        } = req.into_inner();

        let ns_tree = self.namespace_tree.lock().expect("namespace_tree lock poisoned");
        let resp = details::read_namespace_details(&ns_type, &ns_inode, reference_pid, &ns_tree);
        drop(ns_tree);

        Ok(Response::new(resp))
    }

    async fn get_network_flows(
        &self,
        req: Request<GetNetworkFlowsRequest>,
    ) -> Result<Response<GetNetworkFlowsResponse>, Status> {
        let pid = req.into_inner().pid;
        let flows = read_flows_for_pid(&self.net_flows, pid)
            .map_err(|e| Status::internal(format!("net_flows read: {e}")))?;
        Ok(Response::new(GetNetworkFlowsResponse {
            flows: flows.into_iter().map(|(k, v)| flow_to_pb(&k, &v)).collect(),
        }))
    }
}

fn flow_to_pb(k: &NetFlowKey, v: &NetFlowStat) -> NetworkFlow {
    let local_address = Ipv4Addr::from(k.saddr.to_ne_bytes()).to_string();
    let remote_address = Ipv4Addr::from(k.daddr.to_ne_bytes()).to_string();
    let protocol = match k.protocol {
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        other => format!("proto{other}"),
    };
    NetworkFlow {
        local_address,
        remote_address,
        local_port: k.sport as u32,
        remote_port: k.dport as u32,
        protocol,
        rx_bytes: v.rx_bytes,
        tx_bytes: v.tx_bytes,
        rx_packets: v.rx_packets,
        tx_packets: v.tx_packets,
    }
}

fn read_flows_for_pid(
    net_flows: &Arc<std::sync::Mutex<OwnedNetFlows>>,
    pid: u32,
) -> anyhow::Result<Vec<(NetFlowKey, NetFlowStat)>> {
    let m = net_flows
        .lock()
        .map_err(|e| anyhow::anyhow!("net_flows lock: {e}"))?;
    // Iterate and filter by pid. We can't reuse `NetFlows::for_pid` because that
    // constructs a typed map from `&mut Map`, not from an owned typed map.
    let mut out = Vec::new();
    for entry in m.iter() {
        let (k, v) = entry.map_err(|e| anyhow::anyhow!("net_flow iter: {e}"))?;
        if k.pid == pid {
            out.push((k, v));
        }
    }
    Ok(out)
}

/// A Stream that holds the subscription guard alive for the lifetime of the
/// stream. When the gRPC client disconnects, tonic drops the stream, which
/// drops `guard`, which decrements the registry refcount and (if it's the
/// last subscriber) removes the pid from `target_pids` on the BPF side.
struct GuardedStream {
    inner: std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<crate::pb::pb::EventBatch, Status>> + Send>>,
    _guard: crate::stream::SubscriptionGuard,
}

impl tokio_stream::Stream for GuardedStream {
    type Item = Result<crate::pb::pb::EventBatch, Status>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::pb::Process;

    fn make_process(pid: u32, name: &str) -> Process {
        Process {
            pid,
            name: name.to_string(),
            ..Default::default()
        }
    }

    fn filter_processes(processes: &[Process], filter: &str) -> Vec<Process> {
        if filter.is_empty() {
            return processes.to_vec();
        }
        let filter_pid = filter.parse::<u32>().ok();
        processes
            .iter()
            .filter(|p| {
                p.name.contains(filter)
                    || filter_pid.map_or(false, |pid| p.pid == pid)
            })
            .cloned()
            .collect()
    }

    #[test]
    fn filter_empty_returns_all() {
        let procs = vec![
            make_process(1, "systemd"),
            make_process(42, "nginx"),
        ];
        let result = filter_processes(&procs, "");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn filter_by_name_substring() {
        let procs = vec![
            make_process(1, "systemd"),
            make_process(42, "nginx"),
            make_process(100, "nginx-worker"),
        ];
        let result = filter_processes(&procs, "nginx");
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|p| p.name.contains("nginx")));
    }

    #[test]
    fn filter_by_pid_exact() {
        let procs = vec![
            make_process(1, "systemd"),
            make_process(42, "nginx"),
            make_process(100, "worker"),
        ];
        let result = filter_processes(&procs, "42");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pid, 42);
    }

    #[test]
    fn filter_by_pid_no_name_match() {
        let procs = vec![
            make_process(1234, "bash"),
            make_process(5678, "top"),
        ];
        let result = filter_processes(&procs, "1234");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pid, 1234);
        assert_eq!(result[0].name, "bash");
    }

    #[test]
    fn filter_pid_and_name_both_match() {
        let procs = vec![
            make_process(42, "nginx"),
            make_process(100, "nginx-worker"),
        ];
        let result = filter_processes(&procs, "nginx");
        assert_eq!(result.len(), 2);

        let result = filter_processes(&procs, "42");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pid, 42);
    }

    #[test]
    fn filter_no_match_returns_empty() {
        let procs = vec![
            make_process(1, "systemd"),
            make_process(42, "nginx"),
        ];
        let result = filter_processes(&procs, "nonexistent");
        assert!(result.is_empty());

        let result = filter_processes(&procs, "9999");
        assert!(result.is_empty());
    }

    #[test]
    fn filter_numeric_string_not_a_pid() {
        let procs = vec![
            make_process(1, "process123"),
            make_process(42, "nginx"),
        ];
        let result = filter_processes(&procs, "123");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "process123");
    }
}