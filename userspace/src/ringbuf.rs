//! Ring-buffer drain task. Owns the `events` `RingBuf` map (taken out of the
//! Aya `Ebpf` instance so it's independent of any other reference), polls the
//! fd via `tokio::io::AsyncFd`, and converts/distributes each sample via the
//! [`StreamRegistry`].
//!
//! Aya 0.14's `RingBuf::next` is synchronous; we wrap the RingBuf fd with
//! `AsyncFd` so the task sleeps when the kernel signalled the buffer is empty
//! (edge-triggered semantics: drain until None, then await readiness again).

use aya::maps::{MapData, RingBuf};
use tokio::io::AsyncFd;
use tracing::{error, warn};

use crate::bpf::types::{self as bpf, event_from_bytes};
use crate::convert::convert;
use crate::stream::StreamRegistry;

/// Spawn the drain task for the events ring buffer. The task owns `ringbuf`
/// (which was taken out of the owning `Ebpf` so it lives independently of any
/// other reference) and runs until the runtime is dropped or a fatal error
/// arises.
pub fn spawn(ringbuf: RingBuf<MapData>, registry: StreamRegistry) {
    tokio::spawn(async move {
        if let Err(e) = run(ringbuf, registry).await {
            error!(error = %e, "ringbuf drain task exited with error");
        }
    });
}

async fn run(ringbuf: RingBuf<MapData>, registry: StreamRegistry) -> std::io::Result<()> {
    // Aya's RingBuf is non-blocking; we wrap it with `AsyncFd` (which owns the
    // RingBuf), wait for readability, then drain all currently-available items
    // until `next()` returns `None`, then sleep again. Edge-triggered.
    let async_fd = AsyncFd::new(ringbuf)?;

    loop {
        // Drain currently-available samples. `get_mut` borrows `async_fd`
        // exclusively; the borrow ends at the end of each inner-iteration
        // block (when `item` goes out of scope), so we can re-enter and also
        // call `readable()` mutably/immuably afterwards.
        loop {
            let item = async_fd.get_mut().next();
            match item {
                Some(buf) => handle_sample(&buf, &registry),
                None => break,
            }
        }

        // Wait for the kernel to signal more data.
        let mut guard = async_fd.readable().await?;
        guard.clear_ready();
    }
}

fn handle_sample(bytes: &[u8], registry: &StreamRegistry) {
    if bytes.len() < std::mem::size_of::<bpf::EventT>() {
        warn!(len = bytes.len(), "ringbuf sample smaller than EventT");
        return;
    }
    // SAFETY: bytes.len() >= size_of::<EventT>() just checked, and
    // `#[repr(C)]` makes Rust match the BPF C layout byte-for-byte. Padding
    // bytes are unused/stale but never read.
    let ev = unsafe { event_from_bytes(bytes) };
    let pb_event = convert(ev);
    if let Err(e) = registry.forward(pb_event) {
        warn!(error = ?e, pid = ev.pid, "stream forward dropped event");
    }
}