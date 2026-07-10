// Manual Rust types matching protobuf/api/v1/beemon.proto.
// Kept in sync by hand — proto file is documentation only.

use prost::Message;

// ── Responses ─────────────────────────────────────────────────────

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct ListProcessesResponse {
    #[prost(message, repeated, tag = "1")]
    pub processes: Vec<Process>,
    #[prost(uint64, tag = "2")]
    pub host_memory_total_bytes: u64,
    #[prost(string, repeated, tag = "3")]
    pub host_namespaces: Vec<String>,
    #[prost(float, repeated, tag = "4")]
    pub host_cpu_per_core_percent: Vec<f32>,
    #[prost(uint64, tag = "5")]
    pub host_io_read_bytes_per_sec: u64,
    #[prost(uint64, tag = "6")]
    pub host_io_write_bytes_per_sec: u64,
    #[prost(uint64, tag = "7")]
    pub host_net_rx_bytes_per_sec: u64,
    #[prost(uint64, tag = "8")]
    pub host_net_tx_bytes_per_sec: u64,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct GetProcessMetadataResponse {
    #[prost(message, optional, tag = "1")]
    pub process: Option<Process>,
    #[prost(message, optional, tag = "2")]
    pub parent: Option<Process>,
    #[prost(message, repeated, tag = "3")]
    pub children: Vec<Process>,
    #[prost(string, repeated, tag = "4")]
    pub host_namespaces: Vec<String>,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct GetNamespaceDetailsResponse {
    #[prost(string, tag = "1")]
    pub ns_type: String,
    #[prost(string, tag = "2")]
    pub ns_inode: String,
    #[prost(string, tag = "3")]
    pub mount_info: String,
    #[prost(string, tag = "4")]
    pub net_links: String,
    #[prost(string, tag = "5")]
    pub net_routes: String,
    #[prost(string, tag = "6")]
    pub uts_info: String,
    #[prost(string, tag = "7")]
    pub user_maps: String,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct GetNetworkFlowsResponse {
    #[prost(message, repeated, tag = "1")]
    pub flows: Vec<NetworkFlow>,
}

// ── Domain types ──────────────────────────────────────────────────

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct Process {
    #[prost(uint32, tag = "1")]
    pub pid: u32,
    #[prost(uint32, tag = "2")]
    pub ppid: u32,
    #[prost(string, tag = "3")]
    pub name: String,
    #[prost(string, tag = "4")]
    pub state: String,
    #[prost(uint64, tag = "5")]
    pub memory_usage_bytes: u64,
    #[prost(float, tag = "6")]
    pub cpu_usage_percent: f32,
    #[prost(uint64, tag = "7")]
    pub memory_limit_bytes: u64,
    #[prost(uint64, tag = "8")]
    pub cpu_quota_us: u64,
    #[prost(uint64, tag = "9")]
    pub cpu_period_us: u64,
    #[prost(uint64, tag = "10")]
    pub pids_limit: u64,
    #[prost(string, repeated, tag = "11")]
    pub namespaces: Vec<String>,
    #[prost(message, repeated, tag = "12")]
    pub open_files: Vec<OpenFile>,
    #[prost(message, repeated, tag = "13")]
    pub active_connections: Vec<NetworkConnection>,
    #[prost(uint64, tag = "14")]
    pub io_read_bytes: u64,
    #[prost(uint64, tag = "15")]
    pub io_write_bytes: u64,
    #[prost(uint64, tag = "16")]
    pub net_rx_bytes: u64,
    #[prost(uint64, tag = "17")]
    pub net_tx_bytes: u64,
    #[prost(string, tag = "18")]
    pub managed_by: String,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct OpenFile {
    #[prost(uint32, tag = "1")]
    pub fd: u32,
    #[prost(string, tag = "2")]
    pub path: String,
    #[prost(string, tag = "3")]
    pub r#type: String,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct NetworkConnection {
    #[prost(string, tag = "1")]
    pub local_address: String,
    #[prost(string, tag = "2")]
    pub remote_address: String,
    #[prost(string, tag = "3")]
    pub state: String,
    #[prost(string, tag = "4")]
    pub direction: String,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct NetworkFlow {
    #[prost(string, tag = "1")]
    pub local_address: String,
    #[prost(string, tag = "2")]
    pub remote_address: String,
    #[prost(uint32, tag = "3")]
    pub local_port: u32,
    #[prost(uint32, tag = "4")]
    pub remote_port: u32,
    #[prost(string, tag = "5")]
    pub protocol: String,
    #[prost(uint64, tag = "6")]
    pub rx_bytes: u64,
    #[prost(uint64, tag = "7")]
    pub tx_bytes: u64,
    #[prost(uint64, tag = "8")]
    pub rx_packets: u64,
    #[prost(uint64, tag = "9")]
    pub tx_packets: u64,
}

// ── Event stream ──────────────────────────────────────────────────

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct EventBatch {
    #[prost(message, repeated, tag = "1")]
    pub events: Vec<Event>,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct Event {
    #[prost(uint64, tag = "1")]
    pub timestamp_ns: u64,
    #[prost(uint32, tag = "2")]
    pub pid: u32,
    #[prost(oneof = "event::Event", tags = "3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47")]
    pub event: Option<event::Event>,
}

pub mod event {
    #[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, ::prost::Oneof)]
    pub enum Event {
        #[prost(message, tag = "3")]
        Syscall(super::SyscallEvent),
        #[prost(message, tag = "4")]
        FileOpen(super::FileOpenEvent),
        #[prost(message, tag = "5")]
        NetworkConnect(super::NetworkConnectEvent),
        #[prost(message, tag = "6")]
        Process(super::ProcessEvent),
        #[prost(message, tag = "7")]
        FileRead(super::FileReadEvent),
        #[prost(message, tag = "8")]
        FileWrite(super::FileWriteEvent),
        #[prost(message, tag = "9")]
        FileClose(super::FileCloseEvent),
        #[prost(message, tag = "10")]
        Chroot(super::ChrootEvent),
        #[prost(message, tag = "11")]
        PivotRoot(super::PivotRootEvent),
        #[prost(message, tag = "12")]
        Setns(super::SetnsEvent),
        #[prost(message, tag = "13")]
        Unshare(super::UnshareEvent),
        #[prost(message, tag = "14")]
        Wait4(super::Wait4Event),
        #[prost(message, tag = "15")]
        Mmap(super::MmapEvent),
        #[prost(message, tag = "16")]
        Munmap(super::MunmapEvent),
        #[prost(message, tag = "17")]
        Mprotect(super::MprotectEvent),
        #[prost(message, tag = "18")]
        Brk(super::BrkEvent),
        #[prost(message, tag = "19")]
        Accept(super::AcceptEvent),
        #[prost(message, tag = "20")]
        Bind(super::BindEvent),
        #[prost(message, tag = "21")]
        Sendto(super::SendtoEvent),
        #[prost(message, tag = "22")]
        Recvfrom(super::RecvfromEvent),
        #[prost(message, tag = "23")]
        Unlinkat(super::UnlinkatEvent),
        #[prost(message, tag = "24")]
        Rename(super::RenameEvent),
        #[prost(message, tag = "26")]
        EpollWait(super::EpollWaitEvent),
        #[prost(message, tag = "27")]
        Select(super::SelectEvent),
        #[prost(message, tag = "28")]
        Poll(super::PollEvent),
        #[prost(message, tag = "29")]
        Ptrace(super::PtraceEvent),
        #[prost(message, tag = "30")]
        Bpf(super::BpfEvent),
        #[prost(message, tag = "31")]
        Capset(super::CapsetEvent),
        #[prost(message, tag = "32")]
        NetworkAccept(super::NetworkAcceptEvent),
        #[prost(message, tag = "33")]
        Signal(super::SignalEvent),
        #[prost(message, tag = "34")]
        Stat(super::FileMetaEvent),
        #[prost(message, tag = "35")]
        Ioctl(super::IoctlEvent),
        #[prost(message, tag = "36")]
        Fcntl(super::FcntlEvent),
        #[prost(message, tag = "37")]
        Lseek(super::LseekEvent),
        #[prost(message, tag = "38")]
        Socket(super::SocketEvent),
        #[prost(message, tag = "39")]
        SocketOpt(super::SocketOptEvent),
        #[prost(message, tag = "40")]
        Pipe(super::PipeEvent),
        #[prost(message, tag = "41")]
        Pipe2(super::Pipe2Event),
        #[prost(message, tag = "42")]
        Getpid(super::GetpidEvent),
        #[prost(message, tag = "43")]
        Getuid(super::GetuidEvent),
        #[prost(message, tag = "44")]
        Uname(super::UnameEvent),
        #[prost(message, tag = "45")]
        Fstat(super::FileMetaEvent),
        #[prost(message, tag = "46")]
        Lstat(super::FileMetaEvent),
        #[prost(message, tag = "47")]
        Access(super::FileMetaEvent),
    }
}

// ── Event payloads ────────────────────────────────────────────────

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct SyscallEvent {
    #[prost(uint32, tag = "1")]
    pub syscall_id: u32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct FileOpenEvent {
    #[prost(string, tag = "1")]
    pub filename: String,
    #[prost(int32, tag = "2")]
    pub flags: i32,
    #[prost(uint32, tag = "3")]
    pub fd: u32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct NetworkConnectEvent {
    #[prost(uint32, tag = "1")]
    pub saddr: u32,
    #[prost(uint32, tag = "2")]
    pub daddr: u32,
    #[prost(uint32, tag = "3")]
    pub sport: u32,
    #[prost(uint32, tag = "4")]
    pub dport: u32,
    #[prost(uint32, tag = "5")]
    pub family: u32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct NetworkAcceptEvent {
    #[prost(uint32, tag = "1")]
    pub saddr: u32,
    #[prost(uint32, tag = "2")]
    pub daddr: u32,
    #[prost(uint32, tag = "3")]
    pub sport: u32,
    #[prost(uint32, tag = "4")]
    pub dport: u32,
    #[prost(uint32, tag = "5")]
    pub family: u32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct ProcessEvent {
    #[prost(bool, tag = "1")]
    pub is_exec: bool,
    #[prost(bool, tag = "2")]
    pub is_fork: bool,
    #[prost(bool, tag = "3")]
    pub is_exit: bool,
    #[prost(string, tag = "4")]
    pub comm: String,
    #[prost(uint32, tag = "5")]
    pub child_pid: u32,
    #[prost(int32, tag = "6")]
    pub exit_code: i32,
    #[prost(string, tag = "7")]
    pub filename: String,
    #[prost(string, repeated, tag = "8")]
    pub args: Vec<String>,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct FileReadEvent {
    #[prost(uint32, tag = "1")]
    pub fd: u32,
    #[prost(uint64, tag = "2")]
    pub count: u64,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct FileWriteEvent {
    #[prost(uint32, tag = "1")]
    pub fd: u32,
    #[prost(uint64, tag = "2")]
    pub count: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct FileCloseEvent {
    #[prost(uint32, tag = "1")]
    pub fd: u32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct ChrootEvent {
    #[prost(string, tag = "1")]
    pub path: String,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct PivotRootEvent {
    #[prost(string, tag = "1")]
    pub new_root: String,
    #[prost(string, tag = "2")]
    pub put_old: String,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct SetnsEvent {
    #[prost(uint32, tag = "1")]
    pub fd: u32,
    #[prost(int32, tag = "2")]
    pub nstype: i32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct UnshareEvent {
    #[prost(uint32, tag = "1")]
    pub flags: u32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct Wait4Event {
    #[prost(uint32, tag = "1")]
    pub pid: u32,
    #[prost(int32, tag = "2")]
    pub options: i32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct MmapEvent {
    #[prost(uint64, tag = "1")]
    pub addr: u64,
    #[prost(uint64, tag = "2")]
    pub len: u64,
    #[prost(int32, tag = "3")]
    pub prot: i32,
    #[prost(int32, tag = "4")]
    pub flags: i32,
    #[prost(int32, tag = "5")]
    pub fd: i32,
    #[prost(uint64, tag = "6")]
    pub offset: u64,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct MunmapEvent {
    #[prost(uint64, tag = "1")]
    pub addr: u64,
    #[prost(uint64, tag = "2")]
    pub len: u64,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct MprotectEvent {
    #[prost(uint64, tag = "1")]
    pub start: u64,
    #[prost(uint64, tag = "2")]
    pub len: u64,
    #[prost(int32, tag = "3")]
    pub prot: i32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct BrkEvent {
    #[prost(uint64, tag = "1")]
    pub brk: u64,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct AcceptEvent {
    #[prost(int32, tag = "1")]
    pub fd: i32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct BindEvent {
    #[prost(int32, tag = "1")]
    pub fd: i32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct SendtoEvent {
    #[prost(int32, tag = "1")]
    pub fd: i32,
    #[prost(uint64, tag = "2")]
    pub len: u64,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct RecvfromEvent {
    #[prost(int32, tag = "1")]
    pub fd: i32,
    #[prost(uint64, tag = "2")]
    pub len: u64,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct UnlinkatEvent {
    #[prost(int32, tag = "1")]
    pub dfd: i32,
    #[prost(string, tag = "2")]
    pub pathname: String,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct RenameEvent {
    #[prost(string, tag = "1")]
    pub oldname: String,
    #[prost(string, tag = "2")]
    pub newname: String,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct EpollWaitEvent {
    #[prost(int32, tag = "1")]
    pub epfd: i32,
    #[prost(int32, tag = "2")]
    pub maxevents: i32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct SelectEvent {
    #[prost(int32, tag = "1")]
    pub nfds: i32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct PollEvent {
    #[prost(int32, tag = "1")]
    pub nfds: i32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct PtraceEvent {
    #[prost(int64, tag = "1")]
    pub request: i64,
    #[prost(uint32, tag = "2")]
    pub target_pid: u32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct BpfEvent {
    #[prost(int32, tag = "1")]
    pub cmd: i32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct CapsetEvent {
    #[prost(uint32, tag = "1")]
    pub target_pid: u32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct SignalEvent {
    #[prost(uint32, tag = "1")]
    pub target_pid: u32,
    #[prost(uint32, tag = "2")]
    pub target_tid: u32,
    #[prost(int32, tag = "3")]
    pub sig: i32,
    #[prost(uint32, tag = "4")]
    pub source_pid: u32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct FileMetaEvent {
    #[prost(string, tag = "1")]
    pub pathname: String,
    #[prost(int32, tag = "2")]
    pub fd: i32,
    #[prost(int32, tag = "3")]
    pub mode: i32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct IoctlEvent {
    #[prost(int32, tag = "1")]
    pub fd: i32,
    #[prost(uint64, tag = "2")]
    pub cmd: u64,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct FcntlEvent {
    #[prost(int32, tag = "1")]
    pub fd: i32,
    #[prost(int32, tag = "2")]
    pub cmd: i32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct LseekEvent {
    #[prost(int32, tag = "1")]
    pub fd: i32,
    #[prost(uint64, tag = "2")]
    pub offset: u64,
    #[prost(int32, tag = "3")]
    pub whence: i32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct SocketEvent {
    #[prost(int32, tag = "1")]
    pub family: i32,
    #[prost(int32, tag = "2")]
    pub r#type: i32,
    #[prost(int32, tag = "3")]
    pub protocol: i32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct SocketOptEvent {
    #[prost(int32, tag = "1")]
    pub fd: i32,
    #[prost(int32, tag = "2")]
    pub level: i32,
    #[prost(int32, tag = "3")]
    pub optname: i32,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct PipeEvent {}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct Pipe2Event {}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct GetpidEvent {}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct GetuidEvent {}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize, Message)]
pub struct UnameEvent {}
