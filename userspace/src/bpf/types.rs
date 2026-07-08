//! Hand-written `#[repr(C)]` Rust mirrors of the BPF-side structs in
//! `kernelspace/{x86_64,arm64}/beemon.bpf.c`.
//!
//! Targets have no BTF, so we can't use bpf2go or aya-tool for codegen. We
//! mirror the C layout by declaring fields in identical order with matching
//! types, and `#[repr(C)]` performs the same natural padding the C ABI does —
//! meaning the Rust layout is byte-for-byte identical to the BPF C struct.
//!
//! We never `derive(bytemuck::Pod)` on `EventT` or any of its inner payloads:
//! those structs contain implicit padding bytes that Pod (correctly) rejects.
//! Instead we raw-cast the ringbuffer slice via `event_from_bytes`.
//!
//! `bytemuck::Pod` is only derived on the three types Aya's typed maps need it
//! on (`IoStat`, `NetFlowKey`, `NetFlowStat`) — none of those contain padding.
//!
//! A `static_assert!` in `tests/bytemuck_layout.rs` guards our size assumption.

#![allow(dead_code)]

// ------------------------------------------------------------------
// Event type IDs — must match `#define EVENT_TYPE_*` in beemon.bpf.c
// ------------------------------------------------------------------
pub const EVENT_TYPE_SYSCALL: u32 = 1;
pub const EVENT_TYPE_FILE_OPEN: u32 = 2;
pub const EVENT_TYPE_NET_CONN: u32 = 3;
pub const EVENT_TYPE_PROCESS: u32 = 4;
pub const EVENT_TYPE_FILE_READ: u32 = 5;
pub const EVENT_TYPE_FILE_WRITE: u32 = 6;
pub const EVENT_TYPE_FILE_CLOSE: u32 = 7;
pub const EVENT_TYPE_CHROOT: u32 = 8;
pub const EVENT_TYPE_PIVOT_ROOT: u32 = 9;
pub const EVENT_TYPE_SETNS: u32 = 10;
pub const EVENT_TYPE_UNSHARE: u32 = 11;
pub const EVENT_TYPE_WAIT4: u32 = 12;
pub const EVENT_TYPE_MMAP: u32 = 13;
pub const EVENT_TYPE_MUNMAP: u32 = 14;
pub const EVENT_TYPE_MPROTECT: u32 = 15;
pub const EVENT_TYPE_BRK: u32 = 16;
pub const EVENT_TYPE_ACCEPT: u32 = 17;
pub const EVENT_TYPE_BIND: u32 = 18;
pub const EVENT_TYPE_SENDTO: u32 = 19;
pub const EVENT_TYPE_RECVFROM: u32 = 20;
pub const EVENT_TYPE_UNLINKAT: u32 = 21;
pub const EVENT_TYPE_RENAME: u32 = 22;
pub const EVENT_TYPE_FUTEX: u32 = 23;
pub const EVENT_TYPE_EPOLL_WAIT: u32 = 24;
pub const EVENT_TYPE_SELECT: u32 = 25;
pub const EVENT_TYPE_POLL: u32 = 26;
pub const EVENT_TYPE_PTRACE: u32 = 27;
pub const EVENT_TYPE_BPF: u32 = 28;
pub const EVENT_TYPE_CAPSET: u32 = 29;
pub const EVENT_TYPE_NET_ACCEPT: u32 = 30;
pub const EVENT_TYPE_SIGNAL: u32 = 31;
pub const EVENT_TYPE_IOCTL: u32 = 33;
pub const EVENT_TYPE_FCNTL: u32 = 34;
pub const EVENT_TYPE_LSEEK: u32 = 35;
pub const EVENT_TYPE_SOCKET: u32 = 36;
pub const EVENT_TYPE_SOCKOPT: u32 = 37;
pub const EVENT_TYPE_PIPE: u32 = 38;
pub const EVENT_TYPE_PIPE2: u32 = 39;
pub const EVENT_TYPE_GETPID: u32 = 40;
pub const EVENT_TYPE_GETUID: u32 = 41;
pub const EVENT_TYPE_UNAME: u32 = 42;
pub const EVENT_TYPE_STAT: u32 = 32;
pub const EVENT_TYPE_LSTAT: u32 = 43;
pub const EVENT_TYPE_FSTAT: u32 = 44;
pub const EVENT_TYPE_ACCESS: u32 = 45;

// ------------------------------------------------------------------
// Trace flags written to the `target_pids` BPF hash map values.
// ------------------------------------------------------------------
pub const TRACE_FLAG_METRICS: u8 = 1;
pub const TRACE_FLAG_EVENTS: u8 = 2;
pub const TRACE_FLAG_ALL: u8 = TRACE_FLAG_METRICS | TRACE_FLAG_EVENTS;

// ------------------------------------------------------------------
// Payload sub-structs — mirror the C inline anonymous structs from
// `beemon.bpf.c`. Field order + types are the contract; `#[repr(C)]`
// handles all alignment/padding.
// ------------------------------------------------------------------

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SyscallPayload {
    pub syscall_id: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct FilePayload {
    pub filename: [u8; 256],
    pub flags: i32,
    pub fd: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct NetPayload {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ProcessPayload {
    pub child_pid: u32,
    pub exit_code: i32,
    pub comm: [u8; 16],
    pub is_exit: u8,
    pub is_exec: u8,
    pub is_fork: u8,
    pub arg_count: u8,
    pub filename: [u8; 256],
    pub args: [[u8; 64]; 6],
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct RwPayload {
    pub fd: u32,
    pub count: u64,
    pub data: [u8; 256],
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ClosePayload {
    pub fd: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct IsolatePayload {
    /// chroot path1 / pivot_root new_root (setns.fd as raw u32 lives in val1).
    pub path1: [u8; 256],
    /// pivot_root put_old (only PivotRootEvent uses this).
    pub path2: [u8; 256],
    /// Setns fd / Unshare flags as u32.
    pub val1: u32,
    /// Setns nstype as i32 (Unshare does not use this).
    pub val2: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Wait4Payload {
    pub pid: u32,
    pub options: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct MmapPayload {
    pub addr: u64,
    pub len: u64,
    pub prot: i32,
    pub flags: i32,
    pub fd: i32,
    pub off: u64,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct MunmapPayload {
    pub addr: u64,
    pub len: u64,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct MprotectPayload {
    pub start: u64,
    pub len: u64,
    pub prot: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct BrkPayload {
    pub brk: u64,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct AcceptPayload {
    pub fd: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct BindPayload {
    pub fd: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct NetRwPayload {
    pub fd: i32,
    pub len: u64,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct UnlinkatPayload {
    pub dfd: i32,
    pub pathname: [u8; 256],
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct RenamePayload {
    pub oldname: [u8; 256],
    pub newname: [u8; 256],
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct FutexPayload {
    pub uaddr: u64,
    pub op: i32,
    pub val: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct EpollWaitPayload {
    pub epfd: i32,
    pub maxevents: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SelectPollPayload {
    pub nfds: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct PtracePayload {
    pub request: i64,
    pub target_pid: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct BpfPayload {
    pub cmd: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct CapsetPayload {
    pub target_pid: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SignalPayload {
    pub target_pid: u32,
    pub target_tid: u32,
    pub sig: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct FileMetaPayload {
    pub pathname: [u8; 256],
    pub fd: u32,
    pub mode: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct IoctlFcntlPayload {
    pub fd: i32,
    pub cmd: u64,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct LseekPayload {
    pub fd: i32,
    pub offset: u64,
    pub whence: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SocketPayload {
    pub family: i32,
    pub type_: i32,
    pub protocol: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SockOptPayload {
    pub fd: i32,
    pub level: i32,
    pub optname: i32,
}

// ------------------------------------------------------------------
// The full event_t (flat; sequential sub-structs as named fields).
// Field order with matching types is the only contract -- #[repr(C)]
// matches the C struct layout byte-for-byte, including implicit
// alignment padding between u64 sub-structs and u32 ones.
// ------------------------------------------------------------------
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct EventT {
    pub pid: u32,
    pub tgid: u32,
    pub r#type: u32,
    pub ts: u64,
    pub syscall: SyscallPayload,
    pub file: FilePayload,
    pub net: NetPayload,
    pub process: ProcessPayload,
    pub rw: RwPayload,
    pub close: ClosePayload,
    pub isolate: IsolatePayload,
    pub wait4: Wait4Payload,
    pub mmap: MmapPayload,
    pub munmap: MunmapPayload,
    pub mprotect: MprotectPayload,
    pub brk: BrkPayload,
    pub accept: AcceptPayload,
    pub bind: BindPayload,
    pub net_rw: NetRwPayload,
    pub unlinkat: UnlinkatPayload,
    pub rename: RenamePayload,
    pub futex: FutexPayload,
    pub epoll_wait: EpollWaitPayload,
    pub select_poll: SelectPollPayload,
    pub ptrace: PtracePayload,
    pub bpf: BpfPayload,
    pub capset: CapsetPayload,
    pub signal: SignalPayload,
    pub file_meta: FileMetaPayload,
    pub ioctl_fcntl: IoctlFcntlPayload,
    pub lseek: LseekPayload,
    pub socket: SocketPayload,
    pub sockopt: SockOptPayload,
}

// ------------------------------------------------------------------
// `process_io_stats` value type (`BPF_MAP_TYPE_LRU_PERCPU_HASH`).
// 32 bytes total; userspace sums per-CPU values.
// ------------------------------------------------------------------
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct IoStat {
    pub file_read_bytes: u64,
    pub file_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}
// SAFETY: IoStat is a plain old data type (4 × u64), no padding.
unsafe impl aya::Pod for IoStat {}

// ------------------------------------------------------------------
// `process_net_flow_stats` key/value (`BPF_MAP_TYPE_HASH`).
// No internal padding: pid/saddr/daddr u32 → sport/dport/family/protocol u16
// → 20 bytes total, 4-aligned, no tail pad.
// ------------------------------------------------------------------
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct NetFlowKey {
    pub pid: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub protocol: u16,
}
// SAFETY: NetFlowKey is a packed-looking P.O.D.: 4×u32 + 4×u16 = 20 bytes,
// 4-byte aligned, no padding.
unsafe impl aya::Pod for NetFlowKey {}

impl PartialEq for NetFlowKey {
    fn eq(&self, o: &Self) -> bool {
        self.pid == o.pid
            && self.saddr == o.saddr
            && self.daddr == o.daddr
            && self.sport == o.sport
            && self.dport == o.dport
            && self.family == o.family
            && self.protocol == o.protocol
    }
}
impl Eq for NetFlowKey {}

impl std::hash::Hash for NetFlowKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pid.hash(state);
        self.saddr.hash(state);
        self.daddr.hash(state);
        self.sport.hash(state);
        self.dport.hash(state);
        self.family.hash(state);
        self.protocol.hash(state);
    }
}

// ------------------------------------------------------------------
// `process_net_flow_stat` value (`BPF_MAP_TYPE_HASH`).
// No internal padding: 4×u64 (32 bytes) + char[256] (256 bytes) = 288,
// 8-aligned, 288 % 8 == 0, no tail pad.
// ------------------------------------------------------------------
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct NetFlowStat {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub dns_query: [u8; 256],
}
// SAFETY: NetFlowStat is 4×u64 + [u8;256] = 288 bytes, no padding.
unsafe impl aya::Pod for NetFlowStat {}

// ------------------------------------------------------------------
// Helpers.
// ------------------------------------------------------------------

/// Trim a NUL-terminated C char array to a `&str`.
pub fn cstr(data: &[u8]) -> &str {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    core::str::from_utf8(&data[..end]).unwrap_or("")
}

/// Interpret a raw ringbuffer byte slice as `&EventT`.
///
/// # Safety
/// `#[repr(C)]` makes Rust's struct layout identical to the C ABI layout.
/// The caller guarantees `buf.len() >= size_of::<EventT>()`. Padding bytes
/// may carry stale values; we never read them.
pub unsafe fn event_from_bytes(buf: &[u8]) -> &EventT {
    assert!(
        buf.len() >= std::mem::size_of::<EventT>(),
        "ringbuf sample too small for EventT ({} < {})",
        buf.len(),
        std::mem::size_of::<EventT>()
    );
    &*(buf.as_ptr() as *const EventT)
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- struct size guards ----------------------------------------

    #[test]
    fn io_stat_size_is_32() {
        assert_eq!(std::mem::size_of::<IoStat>(), 32);
    }

    #[test]
    fn net_flow_key_size_is_20() {
        assert_eq!(std::mem::size_of::<NetFlowKey>(), 20);
    }

    #[test]
    fn net_flow_stat_size_is_288() {
        assert_eq!(std::mem::size_of::<NetFlowStat>(), 288);
    }

    /// EventT size is large (~2700 bytes); we just assert it's in a sane
    /// range so accidental layout drift (e.g., dropping a payload struct)
    /// is caught.
    #[test]
    fn event_t_size_is_within_expected_range() {
        let s = std::mem::size_of::<EventT>();
        assert!(
            (2400..=3200).contains(&s),
            "EventT is {s} bytes; expected ~2700-2900. Inspect the C source if this drifts."
        );
    }

    /// Sanity: EventT layout starts with the header fields (pid, tgid, type,
    /// ts) at byte offsets 0/4/8/16 — these are the values the ringbuf
    /// reader dispatches on.
    #[test]
    fn event_t_header_field_offsets() {
        assert_eq!(std::mem::offset_of!(EventT, pid), 0);
        assert_eq!(std::mem::offset_of!(EventT, tgid), 4);
        assert_eq!(std::mem::offset_of!(EventT, r#type), 8);
        // ts is u64; aligned to 8 bytes → offset 16 (4 bytes of padding after
        // the three u32s).
        assert_eq!(std::mem::offset_of!(EventT, ts), 16);
    }

    // ---- cstr edge cases --------------------------------------------

    #[test]
    fn cstr_null_terminated() {
        let buf: &[u8; 8] = b"hello\0wo";
        assert_eq!(cstr(buf), "hello");
    }

    #[test]
    fn cstr_no_null_returns_full_slice() {
        let buf: &[u8; 5] = b"hello";
        assert_eq!(cstr(buf), "hello");
    }

    #[test]
    fn cstr_empty() {
        let buf: &[u8; 1] = b"\0";
        assert_eq!(cstr(buf), "");
    }

    #[test]
    fn cstr_first_byte_null() {
        let buf: &[u8; 4] = b"\0abc";
        assert_eq!(cstr(buf), "");
    }

    // ---- event_from_bytes safety guards ----------------------------

    #[test]
    #[should_panic(expected = "ringbuf sample too small")]
    fn event_from_bytes_empty_buffer_panics() {
        let _ = unsafe { event_from_bytes(&[]) };
    }

    #[test]
    #[should_panic(expected = "ringbuf sample too small")]
    fn event_from_bytes_short_buffer_panics() {
        let buf = vec![0u8; 16]; // way smaller than EventT
        let _ = unsafe { event_from_bytes(&buf) };
    }

    #[test]
    fn event_from_bytes_full_buffer_succeeds() {
        let buf = vec![0u8; std::mem::size_of::<EventT>()];
        let ev = unsafe { event_from_bytes(&buf) };
        assert_eq!(ev.pid, 0);
        assert_eq!(ev.tgid, 0);
        assert_eq!(ev.r#type, 0);
    }

    // ---- NetFlowKey / NetFlowStat equality + hash --------------------

    #[test]
    fn net_flow_key_eq_and_hash() {
        use std::collections::HashSet;
        let a = NetFlowKey {
            pid: 100,
            saddr: 0x0a000001,
            daddr: 0x0a000002,
            sport: 5000,
            dport: 443,
            family: 2,
            protocol: 6,
        };
        let b = a;
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    // ---- Event type IDs are sequential starting at 1 -----------------

    #[test]
    fn event_type_ids_sequential_1_through_30() {
        assert_eq!(EVENT_TYPE_SYSCALL, 1);
        assert_eq!(EVENT_TYPE_FILE_OPEN, 2);
        assert_eq!(EVENT_TYPE_NET_CONN, 3);
        assert_eq!(EVENT_TYPE_PROCESS, 4);
        assert_eq!(EVENT_TYPE_FILE_READ, 5);
        assert_eq!(EVENT_TYPE_FILE_WRITE, 6);
        assert_eq!(EVENT_TYPE_FILE_CLOSE, 7);
        assert_eq!(EVENT_TYPE_CHROOT, 8);
        assert_eq!(EVENT_TYPE_PIVOT_ROOT, 9);
        assert_eq!(EVENT_TYPE_SETNS, 10);
        assert_eq!(EVENT_TYPE_UNSHARE, 11);
        assert_eq!(EVENT_TYPE_WAIT4, 12);
        assert_eq!(EVENT_TYPE_MMAP, 13);
        assert_eq!(EVENT_TYPE_MUNMAP, 14);
        assert_eq!(EVENT_TYPE_MPROTECT, 15);
        assert_eq!(EVENT_TYPE_SOCKET, 36);
        assert_eq!(EVENT_TYPE_SOCKOPT, 37);
        assert_eq!(EVENT_TYPE_PIPE, 38);
        assert_eq!(EVENT_TYPE_PIPE2, 39);
        assert_eq!(EVENT_TYPE_GETPID, 40);
        assert_eq!(EVENT_TYPE_GETUID, 41);
        assert_eq!(EVENT_TYPE_UNAME, 42);
        assert_eq!(EVENT_TYPE_BRK, 16);
        assert_eq!(EVENT_TYPE_ACCEPT, 17);
        assert_eq!(EVENT_TYPE_BIND, 18);
        assert_eq!(EVENT_TYPE_SENDTO, 19);
        assert_eq!(EVENT_TYPE_RECVFROM, 20);
        assert_eq!(EVENT_TYPE_UNLINKAT, 21);
        assert_eq!(EVENT_TYPE_RENAME, 22);
        assert_eq!(EVENT_TYPE_FUTEX, 23);
        assert_eq!(EVENT_TYPE_EPOLL_WAIT, 24);
        assert_eq!(EVENT_TYPE_SELECT, 25);
        assert_eq!(EVENT_TYPE_POLL, 26);
        assert_eq!(EVENT_TYPE_PTRACE, 27);
        assert_eq!(EVENT_TYPE_BPF, 28);
        assert_eq!(EVENT_TYPE_CAPSET, 29);
        assert_eq!(EVENT_TYPE_NET_ACCEPT, 30);
    }

    #[test]
    fn trace_flag_all_is_metrics_or_events() {
        assert_eq!(TRACE_FLAG_ALL, TRACE_FLAG_METRICS | TRACE_FLAG_EVENTS);
        assert_eq!(TRACE_FLAG_METRICS, 1);
        assert_eq!(TRACE_FLAG_EVENTS, 2);
        assert_eq!(TRACE_FLAG_ALL, 3);
    }
}