//! Per-PID subscription registry. Maps each monitored PID to a
//! `tokio::sync::broadcast` channel. The first subscriber inserts the PID
//! into the BPF `target_pids` map (turning on BPF event emission); the last
//! subscriber to drop removes it again.
//!
//! The registry is shared between the ringbuf drain task (which calls
//! `forward`) and gRPC `stream_events` handlers (which call `subscribe`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::sync::broadcast;
use tracing::warn;

use crate::bpf::maps::OwnedTargetPids;
use crate::bpf::types::TRACE_FLAG_ALL;
use crate::pb::pb::Event;

/// The shared registry. Cloneable so it can be passed to many tasks.
#[derive(Clone)]
pub struct StreamRegistry {
    inner: Arc<Inner>,
}

struct Inner {
    /// PID -> broadcast sender. Removed when the last receiver drops.
    streams: Mutex<HashMap<u32, broadcast::Sender<Event>>>,
    /// Owned `target_pids` BPF map behind a mutex. BPF maps are not `Sync`.
    target_pids: Mutex<OwnedTargetPids>,
}

/// The result of `subscribe`. Holds the public `rx` plus a drop-guard that
/// removes the PID from `target_pids` when the last subscriber goes away.
///
/// The `rx` is declared before `guard`, so `rx` is dropped first (decrementing
/// the broadcast sender's `receiver_count`) before `guard::drop` checks. At
/// that point if `receiver_count() == 0`, the PID is unmapped and the
/// broadcast entry evicted.
pub struct Subscription {
    pub rx: broadcast::Receiver<Event>,
    pub guard: SubscriptionGuard,
}

pub struct SubscriptionGuard {
    pid: u32,
    inner: Arc<Inner>,
}

impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        let mut streams = self.inner.streams.lock().expect("streams lock poisoned");
        let mut should_unmap = false;
        if let Some(sender) = streams.get(&self.pid) {
            // Our `rx` was dropped just before this guard by field-drop order,
            // so `receiver_count` already reflects our absence.
            if sender.receiver_count() == 0 {
                streams.remove(&self.pid);
                should_unmap = true;
            }
        }
        drop(streams);
        if should_unmap {
            if let Ok(mut tp) = self.inner.target_pids.lock() {
                if let Err(e) = tp.remove(&self.pid) {
                    warn!(pid = self.pid, error = %e, "failed to delete from target_pids");
                }
            }
        }
    }
}

// Note: Unit tests for StreamRegistry require a real BPF map (OwnedTargetPids)
// which cannot be easily mocked. Stream registry behavior is tested via
// integration tests in tests/bpf_integration.rs that load actual BPF programs.

impl StreamRegistry {
    pub fn new(target_pids: OwnedTargetPids) -> Self {
        Self {
            inner: Arc::new(Inner {
                streams: Mutex::new(HashMap::new()),
                target_pids: Mutex::new(target_pids),
            }),
        }
    }

    /// Subscribe to `pid`. The first subscriber inserts the PID into the BPF
    /// `target_pids` map; the last one to drop removes it.
    pub fn subscribe(&self, pid: u32, event_limit: usize) -> Result<Subscription> {
        let cap = event_limit.max(1);
        let mut streams = self.inner.streams.lock().expect("streams lock poisoned");

        let needs_arm = streams
            .get(&pid)
            .map(|s| s.receiver_count() == 0)
            .unwrap_or(true);

        let sender = streams
            .entry(pid)
            .or_insert_with(|| broadcast::channel::<Event>(cap).0);

        if needs_arm {
            if let Ok(mut tp) = self.inner.target_pids.lock() {
                if let Err(e) = tp.insert(pid, TRACE_FLAG_ALL, 0) {
                    warn!(pid, error = %e, "insert target_pids failed");
                }
            }
        }

        let rx = sender.subscribe();
        Ok(Subscription {
            rx,
            guard: SubscriptionGuard {
                pid,
                inner: self.inner.clone(),
            },
        })
    }

    /// Forward an event to every subscriber registered for `event.pid`.
    /// Returns `Ok(())` on success; `Err` only if events were lost to lag.
    /// A PID with no subscribers is silently dropped (no events back-pressured).
    pub fn forward(&self, event: Event) -> Result<(), ()> {
        let streams = self.inner.streams.lock().expect("streams lock poisoned");
        if let Some(sender) = streams.get(&event.pid) {
            // Tolerant send: lag is surfaced to the lagged subscriber only.
            match sender.send(event) {
                Ok(_n_receivers) => Ok(()),
                Err(broadcast::error::SendError(_)) => {
                    // No active receivers; the Subscription Drop will tidy up.
                    Ok(())
                }
            }
        } else {
            tracing::trace!(pid = event.pid, "forward: no subscriber for pid, dropping event");
            Ok(())
        }
    }
}
