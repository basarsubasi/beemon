#![allow(clippy::too_many_arguments)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::RwLock;
use tokio::signal::unix::SignalKind;
use tracing_subscriber::EnvFilter;

use beemon::{
    bpf::loader::BpfHandle,
    config::Config,
    http::{AppState, router},
    rates::{spawn as spawn_rates, BpfStateMaps, RateSnapshot},
    ringbuf,
    snapshot::{
        cgroup_tree_cache::CgroupTreeCache, namespace_tree_cache::NamespaceTreeCache,
        proc_cache::ProcCache, scanner, CacheInvalidators, SnapshotCache,
    },
    stream::StreamRegistry,
};

fn main() -> Result<()> {
    let cfg = Config::from_env();

    let directive =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.log_directive));
    tracing_subscriber::fmt()
        .with_env_filter(directive)
        .with_target(false)
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    rt.block_on(async_main(cfg))
}

async fn async_main(cfg: Config) -> Result<()> {
    eprintln!("starting beemon...");

    eprintln!("  loading BPF programs...");
    let mut bpf = BpfHandle::load_and_attach().context("loading BPF programs")?;
    eprintln!("  BPF programs attached");

    let events_ringbuf = bpf.take_events_ringbuf().context("taking events ringbuf")?;
    let (target_pids, io_stats, net_flows) = bpf
        .take_owned_state_maps()
        .context("taking target_pids/io_stats/net_flows maps")?;

    let snapshot_cache: Arc<RwLock<SnapshotCache>> = Arc::new(RwLock::new(SnapshotCache::default()));
    let rates_snapshot: Arc<RwLock<RateSnapshot>> = Arc::new(RwLock::new(RateSnapshot::default()));

    let proc_cache = Arc::new(Mutex::new(ProcCache::new(Duration::from_secs(10))));
    let cgroup_tree = Arc::new(Mutex::new(CgroupTreeCache::new(Duration::from_secs(10))));
    let namespace_tree = Arc::new(Mutex::new(NamespaceTreeCache::new(Duration::from_secs(10))));

    let registry = StreamRegistry::new(target_pids);

    let net_flows_arc = Arc::new(Mutex::new(net_flows));
    let state_maps = Arc::new(BpfStateMaps {
        io_stats: Arc::new(Mutex::new(io_stats)),
        net_flows: net_flows_arc.clone(),
    });

    eprintln!("  starting scanner & rate poller...");
    scanner::spawn(
        snapshot_cache.clone(),
        rates_snapshot.clone(),
        proc_cache.clone(),
        cgroup_tree.clone(),
        namespace_tree.clone(),
        cfg.scanner_period_secs,
    );
    spawn_rates(state_maps.clone(), rates_snapshot.clone(), cfg.rates_poll_millis);

    let invalidators = CacheInvalidators {
        proc_cache: proc_cache.clone(),
        namespace_tree: namespace_tree.clone(),
    };
    eprintln!("  spawning ringbuf consumer...");
    ringbuf::spawn(events_ringbuf, registry.clone(), invalidators);

    let state = AppState {
        snapshot: snapshot_cache,
        rates: rates_snapshot,
        registry,
        net_flows: net_flows_arc,
        namespace_tree,
        event_limit: cfg.event_limit,
    };

    let app = router(state);
    let addr = format!("0.0.0.0:{}", cfg.http_port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("binding HTTP listener")?;
    eprintln!("beemon is running on http://localhost:{}", cfg.http_port);

    let server = axum::serve(listener, app);

    tokio::select! {
        result = server => {
            result.context("HTTP server error")?;
        }
        _ = shutdown_signal() => {
            tracing::info!("shutting down");
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())
        .expect("installing SIGTERM handler");

    tokio::select! {
        _ = ctrl_c => {}
        _ = sigterm.recv() => {}
    }
}
