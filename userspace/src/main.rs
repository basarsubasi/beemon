//! beemon-daemon entry point. Boots tokio, loads BPF, takes ownership of the
//! long-lived maps (ringbuf + state), spawns scanner/rates/ringbuf tasks,
//! registers the gRPC service, and serves until SIGINT/SIGTERM.

#![allow(clippy::too_many_arguments)]

mod bpf;
mod config;
mod convert;
mod grpc;
mod pb;
mod rates;
mod ringbuf;
mod snapshot;
mod stream;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::RwLock;
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

use crate::bpf::loader::BpfHandle;
use crate::config::Config;
use crate::grpc::BeemonServiceImpl;
use crate::pb::pb::beemon_service_server::BeemonServiceServer;
use crate::rates::{spawn as spawn_rates, BpfStateMaps};
use crate::snapshot::cgroup_tree_cache::CgroupTreeCache;
use crate::snapshot::namespace_tree_cache::NamespaceTreeCache;
use crate::snapshot::proc_cache::ProcCache;
use crate::snapshot::scanner;
use crate::snapshot::CacheInvalidators;
use crate::stream::StreamRegistry;

fn main() -> Result<()> {
    let cfg = Config::from_env();

    // tracing_subscriber: honor BEEMON_LOG_LEVEL / RUST_LOG.
    let directive = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cfg.log_directive));
    tracing_subscriber::fmt()
        .with_env_filter(directive)
        .with_target(false)
        .init();

    // Tokio multi-thread runtime. We need it for the gRPC server, ringbuf
    // AsyncFd, broadcast channels, and the scanner/rates timers.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    rt.block_on(async_main(cfg))
}

async fn async_main(cfg: Config) -> Result<()> {
    // --- 1. Load + attach BPF ----------------------------------------
    tracing::info!("loading BPF programs");
    let mut bpf = BpfHandle::load_and_attach().context("loading BPF programs")?;
    tracing::info!("BPF attached: ok");

    // --- 2. Take ownership of the long-lived maps ---------------------
    let events_ringbuf = bpf.take_events_ringbuf().context("taking events ringbuf")?;
    let (target_pids, io_stats, net_flows) = bpf
        .take_owned_state_maps()
        .context("taking target_pids/io_stats/net_flows maps")?;

    // --- 3. Build shared state ---------------------------------------
    let snapshot_cache: Arc<RwLock<snapshot::SnapshotCache>> =
        Arc::new(RwLock::new(snapshot::SnapshotCache::default()));
    let rates_snapshot: Arc<RwLock<crate::rates::RateSnapshot>> =
        Arc::new(RwLock::new(crate::rates::RateSnapshot::default()));

    let proc_cache = Arc::new(Mutex::new(ProcCache::new(Duration::from_secs(10))));
    let cgroup_tree = Arc::new(Mutex::new(CgroupTreeCache::new(Duration::from_secs(10))));
    let namespace_tree = Arc::new(Mutex::new(NamespaceTreeCache::new(Duration::from_secs(10))));

    let registry = StreamRegistry::new(target_pids);

    // Wrap the io_stats / net_flows owned maps behind Arc<Mutex> so both the
    // rates poller and the gRPC `GetNetworkFlows` RPC can share them.
    let net_flows_arc = Arc::new(Mutex::new(net_flows));
    let state_maps = Arc::new(BpfStateMaps {
        io_stats: Arc::new(Mutex::new(io_stats)),
        net_flows: net_flows_arc.clone(),
    });

    // --- 4. Spawn background tasks -----------------------------------
    scanner::spawn(
        snapshot_cache.clone(),
        rates_snapshot.clone(),
        proc_cache.clone(),
        cgroup_tree.clone(),
        namespace_tree.clone(),
        2, // 2s scanner cadence
    );
    spawn_rates(state_maps.clone(), rates_snapshot.clone(), cfg.rates_poll_secs);

    let invalidators = CacheInvalidators {
        proc_cache: proc_cache.clone(),
        namespace_tree: namespace_tree.clone(),
    };
    crate::ringbuf::spawn(events_ringbuf, registry.clone(), invalidators);

    // --- 5. gRPC server ----------------------------------------------
    let bind_addr: std::net::SocketAddr = cfg.bind_addr().parse()?;
    tracing::info!("gRPC listening on {bind_addr}");
    let svc = BeemonServiceImpl {
        snapshot: snapshot_cache,
        rates: rates_snapshot,
        registry,
        net_flows: net_flows_arc,
        namespace_tree,
        config: cfg,
    };

    Server::builder()
        .add_service(BeemonServiceServer::new(svc))
        .serve(bind_addr)
        .await?;

    Ok(())
}