//! Library facade for the beemon-daemon. Re-exports the public modules so
//! integration tests (under `tests/`) can import pieces like
//! `beemon_daemon::convert::convert`, `beemon_daemon::bpf::types`, and so on
//! without depending on internal path layout.
//!
//! `main.rs` is the thin binary entry-point that wires up the runtime; the
//! bulk of the bootstrap lives here as library functions so tests can drive
//! pieces in isolation (loading BPF, subscribing to a stream, asserting a
//! converted `Event`, etc.).

#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

pub mod bpf;
pub mod config;
pub mod convert;
pub mod grpc;
pub mod pb;
pub mod rates;
pub mod ringbuf;
pub mod snapshot;
pub mod stream;