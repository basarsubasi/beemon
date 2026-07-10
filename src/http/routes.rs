use std::collections::HashMap;
use std::net::Ipv4Addr;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::Json;
use serde::Deserialize;
use tokio_stream::StreamExt;

use crate::bpf::maps::OwnedNetFlows;
use crate::bpf::types::{NetFlowKey, NetFlowStat};
use crate::http::AppState;
use crate::pb::pb::{
    GetNamespaceDetailsResponse, GetNetworkFlowsResponse, GetProcessMetadataResponse,
    ListProcessesResponse, NetworkFlow, Process,
};
use crate::snapshot::details;

#[derive(Deserialize)]
pub struct ListQuery {
    pub filter_name: Option<String>,
}

pub async fn list_processes(
    Query(query): Query<ListQuery>,
    State(state): State<AppState>,
) -> Result<Json<ListProcessesResponse>, StatusCode> {
    let filter = query.filter_name.unwrap_or_default();
    let snap = state.snapshot.read().await.clone();
    let rates = state.rates.read().await.clone();

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

    Ok(Json(ListProcessesResponse {
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

pub async fn get_process_metadata(
    Path(pid): Path<u32>,
    State(state): State<AppState>,
) -> Result<Json<GetProcessMetadataResponse>, StatusCode> {
    if pid == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let snap = state.snapshot.read().await.clone();
    let idx: HashMap<u32, Process> = snap.processes.iter().map(|p| (p.pid, p.clone())).collect();

    let process = idx.get(&pid).ok_or(StatusCode::NOT_FOUND)?;
    let mut process = process.clone();
    process.open_files = details::read_open_files_pub(pid);
    process.active_connections = details::read_active_connections_pub(pid);

    let parent = idx.get(&process.ppid).cloned().or_else(|| Some(Process::default()));
    let children = details::resolve_children(pid, &idx);

    Ok(Json(GetProcessMetadataResponse {
        process: Some(process),
        parent,
        children,
        host_namespaces: snap.host_namespaces.clone(),
    }))
}

pub async fn stream_events(
    Path(pid): Path<u32>,
    State(state): State<AppState>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, std::convert::Infallible>>>, StatusCode>
{
    if pid == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let sub = state
        .registry
        .subscribe(pid, state.event_limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let stream = tokio_stream::wrappers::BroadcastStream::new(sub.rx)
        .filter_map(|res| res.ok())
        .chunks_timeout(200, std::time::Duration::from_millis(50))
        .map(|events| {
            let batch = crate::pb::pb::EventBatch { events };
            let json = serde_json::to_string(&batch).unwrap_or_default();
            Ok::<_, std::convert::Infallible>(Event::default().data(json))
        });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

pub async fn get_network_flows(
    Path(pid): Path<u32>,
    State(state): State<AppState>,
) -> Result<Json<GetNetworkFlowsResponse>, StatusCode> {
    let flows = read_flows_for_pid(&state.net_flows, pid)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(GetNetworkFlowsResponse {
        flows: flows.into_iter().map(|(k, v)| flow_to_pb(&k, &v)).collect(),
    }))
}

pub async fn get_namespace_details(
    Path((ns_type, ns_inode)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Json<GetNamespaceDetailsResponse>, StatusCode> {
    let ns_tree = state
        .namespace_tree
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let resp = details::read_namespace_details(&ns_type, &ns_inode, 0, &ns_tree);
    Ok(Json(resp))
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
    net_flows: &std::sync::Arc<std::sync::Mutex<OwnedNetFlows>>,
    pid: u32,
) -> anyhow::Result<Vec<(NetFlowKey, NetFlowStat)>> {
    let m = net_flows
        .lock()
        .map_err(|e| anyhow::anyhow!("net_flows lock: {e}"))?;
    let mut out = Vec::new();
    for entry in m.iter() {
        let (k, v) = entry.map_err(|e| anyhow::anyhow!("net_flow iter: {e}"))?;
        if k.pid == pid {
            out.push((k, v));
        }
    }
    Ok(out)
}
