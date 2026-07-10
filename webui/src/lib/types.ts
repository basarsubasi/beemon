export interface Process {
  pid: number;
  ppid: number;
  name: string;
  state: string;
  memoryUsageBytes: string;
  cpuUsagePercent: number;
  memoryLimitBytes: string;
  cpuQuotaUs: string;
  cpuPeriodUs: string;
  pidsLimit: string;
  namespaces?: string[];
  openFiles?: { fd: number; path: string; type: string }[];
  activeConnections?: NetworkConnection[];
  ioReadBytesPerSec?: string;
  ioWriteBytesPerSec?: string;
  netRxBytes?: string;
  netTxBytes?: string;
  managedBy?: string;
}

export interface NetworkConnection {
  localAddress: string;
  remoteAddress: string;
  state: string;
  direction: string;
}

export interface ListProcessesResponse {
  processes: Process[];
  hostMemoryTotalBytes: string;
  hostNamespaces: string[];
  hostCpuPerCorePercent?: number[];
  // Host-wide per-second I/O totals summed from BPF process_io_stats.
  hostIoReadBytesPerSec?: string;
  hostIoWriteBytesPerSec?: string;
  hostNetRxBytesPerSec?: string;
  hostNetTxBytesPerSec?: string;
}

export interface GetProcessMetadataResponse {
  process: Process;
  parent?: Process;
  children: Process[];
  hostNamespaces: string[];
}


export interface NamespaceDetailsResponse {
  nsType: string;
  nsInode: string;
  mountInfo?: string;
  netLinks?: string;
  netRoutes?: string;
  utsInfo?: string;
  userMaps?: string;
}

export interface BeemonEvent {
  timestampNs: string;
  pid: number;
  syscall?: { syscallId: number };
  fileOpen?: {
    filename: string;
    flags: number;
    fd: number;
  };
  fileRead?: {
    fd: number;
    count: string;
  };
  fileWrite?: {
    fd: number;
    count: string;
    data?: Uint8Array;
  };
  fileClose?: {
    fd: number;
  };
  networkConnect?: {
    saddr: number;
    daddr: number;
    sport: number;
    dport: number;
    family: number;
  };
  networkAccept?: {
    saddr: number;
    daddr: number;
    sport: number;
    dport: number;
    family: number;
  };
  process?: {
    isExit: boolean;
    isExec: boolean;
    isFork: boolean;
    childPid: number;
    exitCode: number;
    filename: string;
    args?: string[];
  };
  limitChanged?: {
    memoryLimitBytes: string;
    cpuQuotaUs: string;
    cpuPeriodUs: string;
    pidsLimit: string;
  };
  chroot?: {
    path: string;
  };
  pivotRoot?: {
    newRoot: string;
    putOld: string;
  };
  setns?: {
    fd: number;
    nstype: number;
  };
  unshare?: {
    flags: number;
  };
  wait4?: { pid: number; options: number };
  mmap?: { addr: string; len: string; prot: number; flags: number; fd: number; offset: string };
  munmap?: { addr: string; len: string };
  mprotect?: { start: string; len: string; prot: number };
  brk?: { brk: string };
  accept?: { fd: number };
  bind?: { fd: number };
  sendto?: { fd: number; len: string };
  recvfrom?: { fd: number; len: string };
  unlinkat?: { dfd: number; pathname: string };
  rename?: { oldname: string; newname: string };
  futex?: { uaddr: string; op: number; val: number };
  epollWait?: { epfd: number; maxevents: number };
  select?: { nfds: number };
  poll?: { nfds: number };
  ptrace?: { request: string; targetPid: number };
  bpf?: { cmd: number };
  capset?: { targetPid: number };
  signal?: { targetPid: number; targetTid?: number; sig: number; sourcePid?: number };
  stat?: { pathname: string; fd: number; mode: number };
  fstat?: { pathname: string; fd: number; mode: number };
  lstat?: { pathname: string; fd: number; mode: number };
  access?: { pathname: string; fd: number; mode: number };
  ioctl?: { fd: number; cmd: string | number };
  fcntl?: { fd: number; cmd: string | number };
  lseek?: { fd: number; offset: string | number };
  socket?: { family: number; type: number; protocol: number };
  socketOpt?: { fd: number; level: number; optname: number; optval?: string; optlen?: number };
  pipe?: {};
  pipe2?: {};
  getpid?: {};
  getuid?: {};
  uname?: {};
}

export interface WSPing {
  type: "ping";
  timestamp: number;
}

export interface BeemonEventBatch {
  events?: BeemonEvent[];
}

export type WSMessage = WSPing | BeemonEventBatch;

export interface NetworkFlow {
  localAddress: string;
  remoteAddress: string;
  localPort: number;
  remotePort: number;
  protocol: string;
  rxBytes: string;
  txBytes: string;
  rxPackets: string;
  txPackets: string;
}

export interface GetNetworkFlowsResponse {
  flows: NetworkFlow[];
}
