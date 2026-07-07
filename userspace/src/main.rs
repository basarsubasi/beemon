//! beemon-daemon entry point. Minimal stub: just enough to validate the
//! build pipeline; the real bootstrap (BPF load, gRPC server, ringbuf task,
//! rates poller, signal handling) is wired in once the scaffolding compiles.

mod bpf;
mod config;

use anyhow::Result;

fn main() -> Result<()> {
    let cfg = config::Config::from_env();
    eprintln!("beemon-daemon starting; bind={}", cfg.bind_addr());
    Ok(())
}