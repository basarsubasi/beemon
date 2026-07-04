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
}

export interface ListProcessesResponse {
  processes: Process[];
}

export interface BeemonEvent {
  timestampNs: string;
  pid: number;
  syscall?: { syscallId: number };
  fileOpen?: {
    filename: string;
    flags: number;
  };
  fileRead?: {
    fd: number;
    count: string;
  };
  fileWrite?: {
    fd: number;
    count: string;
    data: string;
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
}

export interface WSPing {
  type: "ping";
  timestamp: number;
}

export type WSMessage = WSPing | BeemonEvent;
