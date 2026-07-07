//! Loads the architecture-appropriate BPF ELF embedded at compile time and
//! attaches every program by name. Returns a `BpfHandle` that owns the Aya
//! `Ebpf` instance plus a small list of attached link IDs (so they get
//! detached on drop).
//!
//! We don't use `EbpfLoader::load_file` because we want a single self-contained
//! binary; the ELF is embedded via `aya::include_bytes_aligned!` so it satisfies
//! Aya's 4-byte alignment requirement.

use std::collections::HashSet;

use anyhow::{anyhow, Context, Result};
use aya::{
    Ebpf,
    programs::{KProbe, TracePoint, ProgramError},
};
use tracing::{info, warn};

use super::types::TRACE_FLAG_ALL;

/// Attach a single BPF program by name. Records the program in `attached` on
/// success; records the (name, error) pair in `failed` on failure so we can
/// still start the daemon when only a subset of hooks attach.
///
/// Note: Aya 0.14 has a single `KProbe` type whose `kind` field distinguishes
/// kprobe from kretprobe (parsed from the ELF section name).
fn attach_one(ebpf: &mut Ebpf, name: &'static str, kind: &ProgramKind) -> Result<(), ProgramError> {
    let prog = ebpf
        .program_mut(name)
        .ok_or(ProgramError::InvalidName { name: name.into() })?;
    match kind {
        ProgramKind::Tracepoint { category, name: tp } => {
            let tp_prog: &mut TracePoint = prog.try_into()?;
            tp_prog.load()?;
            tp_prog.attach(category, tp)?;
        }
        ProgramKind::Kprobe { fn_name } => {
            // `kind: ProbeKind::Entry` already set by the loader from the
            // `kprobe/...` section name.
            let k: &mut KProbe = prog.try_into()?;
            k.load()?;
            k.attach(fn_name, 0)?;
        }
        ProgramKind::Kretprobe { fn_name } => {
            // `kind: ProbeKind::Return` set from the `kretprobe/...` section.
            let k: &mut KProbe = prog.try_into()?;
            k.load()?;
            k.attach(fn_name, 0)?;
        }
    }
    Ok(())
}

/// Which BPF ELF we ship depends on the host architecture at compile time.
#[cfg(target_arch = "x86_64")]
const BPF_OBJ: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/beemon_x86.o"));
#[cfg(target_arch = "aarch64")]
const BPF_OBJ: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/beemon_arm64.o"));

/// Discriminator for the three Aya program variants we attach.
pub enum ProgramKind {
    Tracepoint { category: &'static str, name: &'static str },
    Kprobe { fn_name: &'static str },
    Kretprobe { fn_name: &'static str },
}

const PROGRAMS: &[(&str, ProgramKind)] = &[
    // --- Process lifecycle (tracepoints) ---
    ("trace_sys_enter_execve",        ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_execve" }),
    ("trace_sched_process_fork",      ProgramKind::Tracepoint { category: "sched",   name: "sched_process_fork" }),
    ("trace_sched_process_exit",      ProgramKind::Tracepoint { category: "sched",   name: "sched_process_exit" }),

    // --- File I/O (tracepoints) ---
    ("trace_sys_enter_read",          ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_read" }),
    ("trace_sys_enter_write",         ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_write" }),
    ("trace_sys_enter_close",         ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_close" }),
    ("trace_sys_enter_openat",        ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_openat" }),

    // --- Namespace ops (tracepoints) ---
    ("trace_sys_enter_chroot",        ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_chroot" }),
    ("trace_sys_enter_pivot_root",    ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_pivot_root" }),
    ("trace_sys_enter_setns",         ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_setns" }),
    ("trace_sys_enter_unshare",       ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_unshare" }),

    // --- Extended syscall events (tracepoints gated by TRACE_FLAG_EVENTS) ---
    ("trace_sys_enter_wait4",         ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_wait4" }),
    ("trace_sys_enter_mmap",          ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_mmap" }),
    ("trace_sys_enter_munmap",        ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_munmap" }),
    ("trace_sys_enter_mprotect",      ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_mprotect" }),
    ("trace_sys_enter_brk",           ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_brk" }),
    ("trace_sys_enter_accept",        ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_accept" }),
    ("trace_sys_enter_accept4",       ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_accept4" }),
    ("trace_sys_enter_bind",          ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_bind" }),
    ("trace_sys_enter_sendto",        ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_sendto" }),
    ("trace_sys_enter_recvfrom",      ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_recvfrom" }),
    ("trace_sys_enter_unlinkat",      ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_unlinkat" }),
    ("trace_sys_enter_rename",        ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_rename" }),
    ("trace_sys_enter_renameat",      ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_renameat" }),
    ("trace_sys_enter_renameat2",     ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_renameat2" }),
    ("trace_sys_enter_futex",         ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_futex" }),
    ("trace_sys_enter_epoll_wait",    ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_epoll_wait" }),
    ("trace_sys_enter_select",        ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_select" }),
    ("trace_sys_enter_poll",          ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_poll" }),
    ("trace_sys_enter_ptrace",        ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_ptrace" }),
    ("trace_sys_enter_bpf",           ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_bpf" }),
    ("trace_sys_enter_capset",        ProgramKind::Tracepoint { category: "syscalls", name: "sys_enter_capset" }),

    // --- Network + I/O stat accounting (kprobes/kretprobes) ---
    ("tcp_v4_connect",                ProgramKind::Kprobe   { fn_name: "tcp_v4_connect" }),
    ("inet_csk_accept",               ProgramKind::Kretprobe { fn_name: "inet_csk_accept" }),
    ("trace_vfs_read_ret",            ProgramKind::Kretprobe { fn_name: "vfs_read" }),
    ("trace_vfs_write_ret",           ProgramKind::Kretprobe { fn_name: "vfs_write" }),
    ("trace_tcp_sendmsg",             ProgramKind::Kprobe   { fn_name: "tcp_sendmsg" }),
    ("trace_tcp_cleanup_rbuf",        ProgramKind::Kprobe   { fn_name: "tcp_cleanup_rbuf" }),
    ("trace_udp_sendmsg",             ProgramKind::Kprobe   { fn_name: "udp_sendmsg" }),
    ("trace_udp_recvmsg",             ProgramKind::Kprobe   { fn_name: "udp_recvmsg" }),
    ("trace_udp_recvmsg_ret",         ProgramKind::Kretprobe { fn_name: "udp_recvmsg" }),
];

/// Owns the loaded Aya `Ebpf` and survives for the lifetime of the daemon.
pub struct BpfHandle {
    pub ebpf: Ebpf,
    /// Names of programs that we successfully attached, for diagnostics.
    pub attached: HashSet<&'static str>,
    /// Programs we could not attach (e.g. symbol missing on this kernel).
    pub failed: Vec<(&'static str, ProgramError)>,
}

impl BpfHandle {
    /// Load the ELF embedded for this architecture and attach every program
    /// listed in `PROGRAMS`. Programs whose attach target is missing on the
    /// running kernel are recorded in `failed` rather than aborting startup;
    /// this matches the Go daemon's prior tolerance for partial attachment
    /// (the README notes the project pins to specific kernels).
    pub fn load_and_attach() -> Result<Self> {
        bump_memlock()?;

        let mut ebpf = Ebpf::load(BPF_OBJ)
            .map_err(|e| anyhow!("Aya Ebpf::load failed: {e}"))
            .context("Loading embedded BPF object")?;

        let mut attached = HashSet::new();
        let mut failed = Vec::new();

        for (name, kind) in PROGRAMS {
            match attach_one(&mut ebpf, name, kind) {
                Ok(_) => {
                    attached.insert(*name);
                }
                Err(e) => {
                    warn!(program = name, error = %e, "failed to attach BPF program");
                    failed.push((*name, e));
                }
            }
        }
        info!(
            attached = attached.len(),
            failed = failed.len(),
            "BPF programs attached"
        );
        Ok(Self { ebpf, attached, failed })
    }

    /// Convenience: insert a PID into `target_pids` with all trace flags.
    pub fn add_target_pid(&mut self, pid: u32) -> Result<()> {
        use aya::maps::HashMap;
        let mut m: HashMap<_, u32, u8> = self
            .ebpf
            .map_mut("target_pids")
            .ok_or_else(|| anyhow!("target_pids map missing"))?
            .try_into()?;
        m.insert(pid, TRACE_FLAG_ALL, 0)
            .map_err(|e| anyhow!("insert target_pids[{pid}]: {e}"))?;
        Ok(())
    }

    /// Convenience: delete a PID from `target_pids`.
    pub fn remove_target_pid(&mut self, pid: u32) -> Result<()> {
        use aya::maps::HashMap;
        let mut m: HashMap<_, u32, u8> = self
            .ebpf
            .map_mut("target_pids")
            .ok_or_else(|| anyhow!("target_pids map missing"))?
            .try_into()?;
        let _ = m.remove(&pid);
        Ok(())
    }

    /// Take ownership of the three daemon-shared BPF maps (target_pids,
    /// process_io_stats, process_net_flow_stats) so the long-lived tasks
    /// (registry, rates poller) can hold them independently of any `&mut Ebpf`
    /// borrow. The `events` RingBuf is taken separately via
    /// [`take_events_ringbuf`].
    pub fn take_owned_state_maps(&mut self) -> Result<(
        super::maps::OwnedTargetPids,
        super::maps::OwnedIoStats,
        super::maps::OwnedNetFlows,
    )> {
        use aya::maps::{HashMap, PerCpuHashMap};
        let target_pids = self
            .ebpf
            .take_map("target_pids")
            .ok_or_else(|| anyhow!("target_pids map missing"))?;
        let target_pids: super::maps::OwnedTargetPids = HashMap::try_from(target_pids)?;
        let io_stats = self
            .ebpf
            .take_map("process_io_stats")
            .ok_or_else(|| anyhow!("process_io_stats map missing"))?;
        let io_stats: super::maps::OwnedIoStats = PerCpuHashMap::try_from(io_stats)?;
        let net_flows = self
            .ebpf
            .take_map("process_net_flow_stats")
            .ok_or_else(|| anyhow!("process_net_flow_stats map missing"))?;
        let net_flows: super::maps::OwnedNetFlows = HashMap::try_from(net_flows)?;
        Ok((target_pids, io_stats, net_flows))
    }

    /// Take the events ringbuf map (consuming it from `Ebpf`).
    pub fn take_events_ringbuf(&mut self) -> Result<aya::maps::RingBuf<aya::maps::MapData>> {
        use aya::maps::RingBuf;
        let map = self
            .ebpf
            .take_map("events")
            .ok_or_else(|| anyhow!("events map missing"))?;
        Ok(RingBuf::try_from(map)?)
    }
}

/// Raise `RLIMIT_MEMLOCK` to infinity so we can load BPF programs without
/// requiring CAP_BPF/CAP_SYS_ADMIN on kernels that still gate loading on
/// memlock (5.10 and earlier).
fn bump_memlock() -> Result<()> {
    use nix::sys::resource::{setrlimit, Resource};
    let lim = libc::RLIM_INFINITY;
    setrlimit(Resource::RLIMIT_MEMLOCK, lim, lim)
        .map_err(|e| anyhow!("setrlimit(RLIMIT_MEMLOCK) failed: {e}"))
        .context("Bumping RLIMIT_MEMLOCK")
}