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
}

export interface ListProcessesResponse {
  processes: Process[];
}

export interface BeemonEvent {
  timestampNs: string;
  pid: number;
  syscall?: { syscallId: number };
  fileOpen?: { filename: string; flags: number };
  fileRead?: { fd: number; count: string };
  fileWrite?: { fd: number; count: string };
  fileClose?: { fd: number };
  networkConnect?: {
    saddr: number;
    daddr: number;
    sport: number;
    dport: number;
    family: number;
  };
  process?: {
    isExec: boolean;
    isFork: boolean;
    isExit: boolean;
    comm: string;
    childPid: number;
    exitCode: number;
    filename: string;
  };
  limitChanged?: {
    memoryLimitBytes: string;
    cpuQuotaUs: string;
    cpuPeriodUs: string;
    pidsLimit: string;
  };
}
