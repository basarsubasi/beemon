import { useEffect, useState, useMemo, useRef } from "react";
import { useNavigate } from "react-router-dom";
import type { Process, ListProcessesResponse } from "../lib/types";
import { Input } from "./ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import { Badge } from "./ui/badge";
import { StateBadge } from "./StateBadge";
import { ManagerBadge, ALL_MANAGERS } from "./ManagerBadge";
import { ThemeToggle } from "./ThemeToggle";
import { Progress } from "./ui/progress";
import { Card } from "./ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { ArrowUpDown, ArrowUp, ArrowDown, Cpu, MemoryStick, Box, Layers, HardDrive, Filter, X } from "lucide-react";

type SortKey = 'pid' | 'name' | 'memory' | 'memLimit' | 'pidsLimit' | 'cpu' | 'cpuLimit' | 'file_read' | 'file_write' | 'net_rx' | 'net_tx';
type SortDirection = 'asc' | 'desc';

const getProgressColorClass = (value: number, defaultClass: string = "[&>div>div]:bg-green-500 dark:[&>div>div]:bg-green-400") => {
  if (value >= 90) return "[&>div>div]:bg-red-500 dark:[&>div>div]:bg-red-400";
  if (value >= 70) return "[&>div>div]:bg-yellow-500 dark:[&>div>div]:bg-yellow-400";
  return defaultClass;
};

export function Dashboard() {
  const [processes, setProcesses] = useState<Process[]>([]);
  const [hostMem, setHostMem] = useState<string>("0");
  const [hostCpuPerCore, setHostCpuPerCore] = useState<number[]>([]);
  const [hostIo, setHostIo] = useState({ read: "0", write: "0", netRx: "0", netTx: "0" });
  const [hostNamespaces, setHostNamespaces] = useState<string[]>([]);
  const [filter, setFilter] = useState("");
  const [managerFilter, setManagerFilter] = useState<string[]>([]);
  const [stateFilter, setStateFilter] = useState<string[]>([]);
  const [filterOpen, setFilterOpen] = useState(false);
  const filterRef = useRef<HTMLDivElement>(null);
  const [sortKey, setSortKey] = useState<SortKey>('memory');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [activeTab, setActiveTab] = useState(() => localStorage.getItem("dashboardTab") || "processes");
  
  const handleTabChange = (val: string) => {
    setActiveTab(val);
    localStorage.setItem("dashboardTab", val);
  };

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (filterRef.current && !filterRef.current.contains(e.target as Node)) {
        setFilterOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const toggleManagerFilter = (manager: string) => {
    setManagerFilter(prev =>
      prev.includes(manager)
        ? prev.filter(m => m !== manager)
        : [...prev, manager]
    );
  };

  const toggleStateFilter = (state: string) => {
    setStateFilter(prev =>
      prev.includes(state)
        ? prev.filter(s => s !== state)
        : [...prev, state]
    );
  };

  const navigate = useNavigate();

  useEffect(() => {
    const fetchProcesses = async () => {
      try {
        const url = filter ? `/api/v1/processes?filter_name=${encodeURIComponent(filter)}` : `/api/v1/processes`;
        const res = await fetch(url);
        const data = (await res.json()) as ListProcessesResponse;
        setProcesses(data.processes || []);
        if (data.hostMemoryTotalBytes) {
          setHostMem(data.hostMemoryTotalBytes);
        }
        if (data.hostCpuPerCorePercent) {
          setHostCpuPerCore(data.hostCpuPerCorePercent);
        }
        // Host-level I/O totals come straight from the cached BPF sum. Cold
        // start (BPF map not yet populated) -> proto emits "0" -> we fall
        // back to a client-side per-process sum so the gauge is never blank
        // during the first second.
        const hasHostIo = data.hostIoReadBytesPerSec !== undefined ||
          data.hostIoWriteBytesPerSec !== undefined ||
          data.hostNetRxBytesPerSec !== undefined ||
          data.hostNetTxBytesPerSec !== undefined;
        if (hasHostIo) {
          setHostIo({
            read: data.hostIoReadBytesPerSec ?? "0",
            write: data.hostIoWriteBytesPerSec ?? "0",
            netRx: data.hostNetRxBytesPerSec ?? "0",
            netTx: data.hostNetTxBytesPerSec ?? "0",
          });
        } else {
          setHostIo({
            read: (data.processes || []).reduce((a, p) => a + (parseInt(p.ioReadBytes || "0") || 0), 0).toString(),
            write: (data.processes || []).reduce((a, p) => a + (parseInt(p.ioWriteBytes || "0") || 0), 0).toString(),
            netRx: (data.processes || []).reduce((a, p) => a + (parseInt(p.netRxBytes || "0") || 0), 0).toString(),
            netTx: (data.processes || []).reduce((a, p) => a + (parseInt(p.netTxBytes || "0") || 0), 0).toString(),
          });
        }
        if (data.hostNamespaces) {
          setHostNamespaces(data.hostNamespaces);
        }
      } catch (err) {
        console.error("Failed to fetch processes:", err);
      }
    };
    
    fetchProcesses();
    const interval = setInterval(fetchProcesses, 1000);
    return () => clearInterval(interval);
  }, [filter]);

  const formatBytes = (bytesStr: string) => {
    const bytes = parseInt(bytesStr);
    if (isNaN(bytes)) return "N/A";
    if (bytes === 0) return "0 B";
    
    const gb = bytes / (1024 * 1024 * 1024);
    if (gb >= 1) return `${gb.toFixed(2)} GB`;
    
    const mb = bytes / (1024 * 1024);
    if (mb >= 1) return `${mb.toFixed(1)} MB`;
    
    const kb = bytes / 1024;
    if (kb >= 1) return `${kb.toFixed(1)} KB`;
    
    return `${bytes} B`;
  };

  const formatIoBytes = (bytesStr?: string) => {
    if (!bytesStr) return '0 B/s';
    return formatBytes(bytesStr) + '/s';
  };

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDirection('desc'); // Default to desc for metrics
    }
  };

  const getSortedProcesses = () => {
    return [...processes].sort((a, b) => {
      let aVal: any = a.pid;
      let bVal: any = b.pid;

      if (sortKey === 'name') {
        aVal = a.name.toLowerCase();
        bVal = b.name.toLowerCase();
      } else if (sortKey === 'memory') {
        aVal = parseInt(a.memoryUsageBytes);
        bVal = parseInt(b.memoryUsageBytes);
      } else if (sortKey === 'memLimit') {
        aVal = a.memoryLimitBytes === "0" ? Infinity : parseInt(a.memoryLimitBytes);
        bVal = b.memoryLimitBytes === "0" ? Infinity : parseInt(b.memoryLimitBytes);
      } else if (sortKey === 'pidsLimit') {
        aVal = a.pidsLimit === "0" ? Infinity : parseInt(a.pidsLimit);
        bVal = b.pidsLimit === "0" ? Infinity : parseInt(b.pidsLimit);
      } else if (sortKey === 'cpu') {
        aVal = a.cpuUsagePercent || 0;
        bVal = b.cpuUsagePercent || 0;
      } else if (sortKey === 'cpuLimit') {
        aVal = a.cpuQuotaUs === "0" ? Infinity : parseInt(a.cpuQuotaUs);
        bVal = b.cpuQuotaUs === "0" ? Infinity : parseInt(b.cpuQuotaUs);
      } else if (sortKey === 'file_read') {
        aVal = parseInt(a.ioReadBytes || '0');
        bVal = parseInt(b.ioReadBytes || '0');
      } else if (sortKey === 'file_write') {
        aVal = parseInt(a.ioWriteBytes || '0');
        bVal = parseInt(b.ioWriteBytes || '0');
      } else if (sortKey === 'net_rx') {
        aVal = parseInt(a.netRxBytes || '0');
        bVal = parseInt(b.netRxBytes || '0');
      } else if (sortKey === 'net_tx') {
        aVal = parseInt(a.netTxBytes || '0');
        bVal = parseInt(b.netTxBytes || '0');
      }

      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  };

  const renderSortIcon = (key: SortKey) => {
    if (sortKey !== key) return <ArrowUpDown className="ml-1 h-3 w-3 opacity-50" />;
    return sortDirection === 'asc' ? <ArrowUp className="ml-1 h-3 w-3" /> : <ArrowDown className="ml-1 h-3 w-3" />;
  };

  const availableStates = [
    "Dead",
    "DiskSleep",
    "Idle",
    "Parked",
    "Running",
    "Sleeping",
    "Stopped",
    "Unknown",
    "Zombie",
  ];

  const sortedProcesses = useMemo(() => {
    const sorted = getSortedProcesses();
    return sorted.filter(p => {
      if (managerFilter.length > 0) {
        const hasNoManager = managerFilter.includes("__none__");
        const hasMatchingManager = p.managedBy && managerFilter.includes(p.managedBy);
        if (hasNoManager && hasMatchingManager) {
          // Both "no manager" and specific managers selected
        } else if (hasNoManager && !hasMatchingManager) {
          // Only "no manager" selected
          if (p.managedBy) return false;
        } else if (!hasNoManager && !hasMatchingManager) {
          // Only specific managers selected, but this process doesn't match
          return false;
        }
      }
      if (stateFilter.length > 0 && !stateFilter.includes(p.state)) return false;
      return true;
    });
  }, [processes, sortKey, sortDirection, managerFilter, stateFilter]);

  const namespaces = useMemo(() => {
    const nsMap = new Map<string, { type: string, inode: string, count: number, isHost: boolean }>();
    
    processes.forEach(p => {
      p.namespaces?.forEach(ns => {
        if (ns.startsWith('cgroup:')) return; // exclude cgroups from general namespaces tab
        if (!nsMap.has(ns)) {
          const actualNs = ns.replace('_for_children', '');
          const isHost = hostNamespaces.includes(ns) || hostNamespaces.includes(actualNs);
          const inodeMatch = ns.match(/\[(\d+)\]/);
          nsMap.set(ns, {
            type: ns.split(":")[0],
            inode: inodeMatch ? inodeMatch[1] : "",
            count: 1,
            isHost
          });
        } else {
          nsMap.get(ns)!.count++;
        }
      });
    });

    return Array.from(nsMap.values()).sort((a, b) => {
      if (b.count !== a.count) return b.count - a.count;
      if (a.type !== b.type) return a.type.localeCompare(b.type);
      return a.inode.localeCompare(b.inode);
    });
  }, [processes, hostNamespaces]);

  const cgroups = useMemo(() => {
    const cgMap = new Map<string, { inode: string, count: number, isHost: boolean, memoryLimit: string, pidsLimit: string, cpuQuota: string, cpuPeriod: string }>();
    
    processes.forEach(p => {
      const cgroupNs = p.namespaces?.find(ns => ns.startsWith('cgroup:'));
      if (cgroupNs) {
        if (!cgMap.has(cgroupNs)) {
          const isHost = hostNamespaces.includes(cgroupNs);
          const inodeMatch = cgroupNs.match(/\[(\d+)\]/);
          cgMap.set(cgroupNs, {
            inode: inodeMatch ? inodeMatch[1] : "",
            count: 1,
            isHost,
            memoryLimit: p.memoryLimitBytes,
            pidsLimit: p.pidsLimit,
            cpuQuota: p.cpuQuotaUs,
            cpuPeriod: p.cpuPeriodUs
          });
        } else {
          cgMap.get(cgroupNs)!.count++;
        }
      }
    });

    return Array.from(cgMap.values()).sort((a, b) => {
      if (b.count !== a.count) return b.count - a.count;
      return a.inode.localeCompare(b.inode);
    });
  }, [processes, hostNamespaces]);

  const totalMemory = processes.reduce((acc, p) => acc + (parseInt(p.memoryUsageBytes) || 0), 0);
  const totalCpu = processes.reduce((acc, p) => acc + (p.cpuUsagePercent || 0), 0) / (hostCpuPerCore.length || 1);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex justify-between items-start">
        <div>
          <div className="flex items-center gap-4 mb-2">
            <div className="flex items-center gap-3">
              <img src="/logo.png" alt="Beemon Logo" className="h-10 w-auto object-contain" />
              <h1 className="text-3xl font-bold tracking-tight text-zinc-900 dark:text-white">beemon dashboard</h1>
            </div>
            <ThemeToggle />
          </div>
          <p className="text-zinc-500 dark:text-zinc-400">Real-time eBPF Linux process monitoring.</p>
        </div>
        
        <div className="flex flex-wrap items-start gap-4">
          <Card className="bg-white dark:bg-zinc-950/50 border-zinc-200 dark:border-zinc-800 p-4 flex-1 min-w-[250px] flex items-center gap-6 shadow-sm">
            <div className="flex items-center gap-4 shrink-0">
              <div className="p-3 bg-green-50 dark:bg-zinc-900 rounded-full">
                <Cpu className="text-green-600 dark:text-green-400 h-6 w-6" />
              </div>
              <div>
                <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-1">Total CPU</p>
                <p className="text-xl font-mono text-zinc-900 dark:text-white leading-none">{totalCpu.toFixed(1)}%</p>
              </div>
            </div>
            
            {hostCpuPerCore.length > 0 && (
              <div className={`flex-1 grid gap-x-4 gap-y-1.5 ${hostCpuPerCore.length > 8 ? 'grid-cols-2' : 'grid-cols-1'}`}>
                {hostCpuPerCore.map((pct, i) => (
                  <div key={i} className="flex items-center gap-2 text-[10px]">
                    <span className="w-7 font-mono text-zinc-500 font-medium">c{i}</span>
                    <Progress value={pct} className={`h-1.5 flex-1 min-w-[80px] ${getProgressColorClass(pct)}`} />
                    <span className="w-7 font-mono text-right text-zinc-500">{pct.toFixed(0)}%</span>
                  </div>
                ))}
              </div>
            )}
          </Card>
          <Card className="bg-white dark:bg-zinc-950/50 border-zinc-200 dark:border-zinc-800 p-4 flex-1 min-w-[220px] flex items-center gap-4 shadow-sm">
            <div className="p-3 bg-blue-50 dark:bg-zinc-900 rounded-full shrink-0">
              <MemoryStick className="text-blue-500 dark:text-blue-400 h-6 w-6" />
            </div>
            <div className="flex-1">
              <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-2">Total Memory</p>
              <div className="flex items-baseline gap-2 mb-1.5">
                <p className="text-xl font-mono text-zinc-900 dark:text-white leading-none">{formatBytes(totalMemory.toString())}</p>
                {hostMem !== "0" && <p className="text-xs text-zinc-500 font-mono">/ {formatBytes(hostMem)}</p>}
              </div>
              {hostMem !== "0" && (() => {
                const memPct = (totalMemory / parseInt(hostMem)) * 100;
                return (
                  <div className="flex items-center gap-2 text-[10px]">
                    <Progress 
                      value={memPct} 
                      className={`h-1.5 flex-1 ${getProgressColorClass(memPct, "[&>div>div]:bg-blue-500 dark:[&>div>div]:bg-blue-400")}`} 
                    />
                    <span className="w-8 font-mono text-right text-zinc-500">
                      {memPct.toFixed(1)}%
                    </span>
                  </div>
                );
              })()}
            </div>
          </Card>
          <Card className="bg-white dark:bg-zinc-950/50 border-zinc-200 dark:border-zinc-800 p-4 flex-1 min-w-[220px] flex items-center gap-4 shadow-sm">
            <div className="p-3 bg-zinc-100 dark:bg-zinc-800 rounded-full shrink-0">
              <HardDrive className="text-zinc-900 dark:text-white h-6 w-6" />
            </div>
            <div className="flex-1">
              <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-2">Total I/O</p>
              <div className="grid grid-cols-2 gap-x-2 gap-y-1 text-[11px] font-mono">
                <span className="text-blue-500 dark:text-blue-400 w-[95px] inline-block whitespace-nowrap">R: {formatBytes(hostIo.read)}/s</span>
                <span className="text-orange-500 dark:text-orange-400 w-[95px] inline-block whitespace-nowrap">W: {formatBytes(hostIo.write)}/s</span>
                <span className="text-green-500 dark:text-green-400 w-[95px] inline-block whitespace-nowrap">Rx: {formatBytes(hostIo.netRx)}/s</span>
                <span className="text-purple-600 dark:text-purple-400 w-[95px] inline-block whitespace-nowrap">Tx: {formatBytes(hostIo.netTx)}/s</span>
              </div>
            </div>
          </Card>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={handleTabChange} className="w-full">
        <TabsList className="bg-zinc-100 dark:bg-zinc-900/50 border border-zinc-200 dark:border-zinc-800 p-1">
          <TabsTrigger value="processes" className="data-[state=active]:bg-white dark:data-[state=active]:bg-zinc-800 data-[state=active]:text-zinc-900 dark:data-[state=active]:text-white text-zinc-500">Processes</TabsTrigger>
          <TabsTrigger value="namespaces" className="data-[state=active]:bg-white dark:data-[state=active]:bg-zinc-800 data-[state=active]:text-zinc-900 dark:data-[state=active]:text-white text-zinc-500">Namespaces</TabsTrigger>
          <TabsTrigger value="cgroups" className="data-[state=active]:bg-white dark:data-[state=active]:bg-zinc-800 data-[state=active]:text-zinc-900 dark:data-[state=active]:text-white text-zinc-500">Cgroups</TabsTrigger>
        </TabsList>

        <TabsContent value="processes" className="space-y-4 mt-6">
          <div className="flex items-center gap-2 flex-wrap">
            <Input 
              placeholder="Filter by name or PID..." 
              className="max-w-md bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800 p-6 text-md"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <div className="relative" ref={filterRef}>
              <button
                onClick={() => setFilterOpen(prev => !prev)}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors ${
                  managerFilter.length > 0 || stateFilter.length > 0
                    ? "border-blue-300 dark:border-blue-700 bg-blue-50 dark:bg-blue-950/30 text-blue-700 dark:text-blue-400"
                    : "border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white"
                }`}
              >
                <Filter className="h-4 w-4" />
                {(managerFilter.length > 0 || stateFilter.length > 0) && (
                  <Badge variant="outline" className="border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-400 text-[10px] px-1.5">
                    {managerFilter.length + stateFilter.length}
                  </Badge>
                )}
              </button>
              {filterOpen && (
                <div className="absolute top-full left-0 mt-1 z-50 min-w-[220px] rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-lg p-3 space-y-4">
                  <div className="space-y-1">
                    <div className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider px-2 mb-2">Manager</div>
                    {ALL_MANAGERS.map(manager => {
                      const isActive = managerFilter.includes(manager);
                      return (
                        <button
                          key={manager}
                          onClick={() => toggleManagerFilter(manager)}
                          className={`flex items-center gap-2 w-full px-2 py-1.5 rounded-md text-sm transition-colors text-left ${
                            isActive
                              ? "bg-zinc-100 dark:bg-zinc-800"
                              : "hover:bg-zinc-50 dark:hover:bg-zinc-800/50"
                          }`}
                        >
                          <div className={`w-4 h-4 rounded border flex items-center justify-center text-[10px] ${
                            isActive
                              ? "border-blue-500 bg-blue-500 text-white"
                              : "border-zinc-300 dark:border-zinc-600"
                          }`}>
                            {isActive && "✓"}
                          </div>
                          <ManagerBadge manager={manager} />
                        </button>
                      );
                    })}
                    <button
                      onClick={() => toggleManagerFilter("__none__")}
                      className={`flex items-center gap-2 w-full px-2 py-1.5 rounded-md text-sm transition-colors text-left ${
                        managerFilter.includes("__none__")
                          ? "bg-zinc-100 dark:bg-zinc-800"
                          : "hover:bg-zinc-50 dark:hover:bg-zinc-800/50"
                      }`}
                    >
                      <div className={`w-4 h-4 rounded border flex items-center justify-center text-[10px] ${
                        managerFilter.includes("__none__")
                          ? "border-blue-500 bg-blue-500 text-white"
                          : "border-zinc-300 dark:border-zinc-600"
                      }`}>
                        {managerFilter.includes("__none__") && "✓"}
                      </div>
                      <span className="text-xs text-zinc-500 dark:text-zinc-400 italic">no manager</span>
                    </button>
                  </div>
                  <div className="border-t border-zinc-200 dark:border-zinc-800 pt-4 space-y-1">
                    <div className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider px-2 mb-2">State</div>
                    {availableStates.map(state => {
                      const isActive = stateFilter.includes(state);
                      return (
                        <button
                          key={state}
                          onClick={() => toggleStateFilter(state)}
                          className={`flex items-center gap-2 w-full px-2 py-1.5 rounded-md text-sm transition-colors text-left ${
                            isActive
                              ? "bg-zinc-100 dark:bg-zinc-800"
                              : "hover:bg-zinc-50 dark:hover:bg-zinc-800/50"
                          }`}
                        >
                          <div className={`w-4 h-4 rounded border flex items-center justify-center text-[10px] ${
                            isActive
                              ? "border-blue-500 bg-blue-500 text-white"
                              : "border-zinc-300 dark:border-zinc-600"
                          }`}>
                            {isActive && "✓"}
                          </div>
                          <StateBadge state={state} />
                        </button>
                      );
                    })}
                  </div>
                  {(managerFilter.length > 0 || stateFilter.length > 0) && (
                    <div className="border-t border-zinc-200 dark:border-zinc-800 pt-2">
                      <button
                        onClick={() => {
                          setManagerFilter([]);
                          setStateFilter([]);
                        }}
                        className="flex items-center gap-1.5 w-full px-2 py-1.5 rounded-md text-sm text-zinc-500 hover:text-zinc-900 dark:hover:text-white hover:bg-zinc-50 dark:hover:bg-zinc-800/50 transition-colors"
                      >
                        <X className="h-3 w-3" />
                        Clear all filters
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
            {managerFilter.filter(m => m !== "__none__").map(manager => (
              <ManagerBadge key={manager} manager={manager} />
            ))}
            {managerFilter.includes("__none__") && (
              <Badge variant="outline" className="border-zinc-300 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-900/50 text-zinc-600 dark:text-zinc-400 text-xs italic">
                no manager
              </Badge>
            )}
            {stateFilter.map(state => (
              <StateBadge key={state} state={state} />
            ))}
          </div>

      <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 overflow-hidden shadow-sm dark:shadow-2xl">
        <Table>
          <TableHeader className="bg-zinc-50 dark:bg-zinc-900/80">
            <TableRow className="border-zinc-200 dark:border-zinc-800 hover:bg-transparent">
              <TableHead 
                className="w-[90px] max-w-[90px] text-zinc-500 dark:text-zinc-400 cursor-pointer hover:text-zinc-900 dark:hover:text-white transition-colors py-4 px-6"
                onClick={() => handleSort('pid')}
              >
                <div className="flex items-center">PID {renderSortIcon('pid')}</div>
              </TableHead>
              <TableHead 
                className="w-[200px] max-w-[200px] text-zinc-500 dark:text-zinc-400 cursor-pointer hover:text-zinc-900 dark:hover:text-white transition-colors py-4 px-6"
                onClick={() => handleSort('name')}
              >
                <div className="flex items-center">Name {renderSortIcon('name')}</div>
              </TableHead>
              <TableHead 
                className="w-[100px] max-w-[100px] text-zinc-500 dark:text-zinc-400 cursor-pointer hover:text-zinc-900 dark:hover:text-white transition-colors py-4 px-6 text-right"
                onClick={() => handleSort('cpu')}
              >
                <div className="flex items-center justify-end">CPU {renderSortIcon('cpu')}</div>
              </TableHead>
              <TableHead 
                className="w-[150px] max-w-[150px] text-zinc-500 dark:text-zinc-400 cursor-pointer hover:text-zinc-900 dark:hover:text-white transition-colors py-4 px-6 text-right"
                onClick={() => handleSort('memory')}
              >
                <div className="flex items-center justify-end">Memory {renderSortIcon('memory')}</div>
              </TableHead>
              <TableHead className="w-[120px] max-w-[120px] text-zinc-500 dark:text-zinc-400 py-4 px-6 text-right">
                <div className="flex flex-col items-end gap-1 text-[10px] uppercase font-semibold">
                  <div className="flex items-center cursor-pointer hover:text-blue-600 transition-colors" onClick={() => handleSort('file_read')}>
                    R {renderSortIcon('file_read')}
                  </div>
                  <div className="flex items-center cursor-pointer hover:text-orange-600 transition-colors" onClick={() => handleSort('file_write')}>
                    W {renderSortIcon('file_write')}
                  </div>
                </div>
              </TableHead>
              <TableHead className="w-[120px] max-w-[120px] text-zinc-500 dark:text-zinc-400 py-4 px-6 text-right">
                <div className="flex flex-col items-end gap-1 text-[10px] uppercase font-semibold">
                  <div className="flex items-center cursor-pointer hover:text-green-600 transition-colors" onClick={() => handleSort('net_rx')}>
                    Rx {renderSortIcon('net_rx')}
                  </div>
                  <div className="flex items-center cursor-pointer hover:text-purple-600 transition-colors" onClick={() => handleSort('net_tx')}>
                    Tx {renderSortIcon('net_tx')}
                  </div>
                </div>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sortedProcesses.map((proc) => (
              <TableRow 
                key={proc.pid} 
                className="cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/80 border-zinc-200 dark:border-zinc-800/50 transition-colors group"
                onClick={() => navigate(`/process/${proc.pid}`)}
              >
                <TableCell className="w-[90px] max-w-[90px] font-mono text-zinc-600 dark:text-zinc-300 py-4 px-6">
                  <span className="block truncate" title={String(proc.pid)}>{proc.pid}</span>
                </TableCell>
                <TableCell className="w-[240px] max-w-[240px] font-medium text-zinc-900 dark:text-zinc-300 py-4 px-6 group-hover:text-black dark:group-hover:text-white transition-colors">
                  <div className="flex items-center gap-2 overflow-hidden">
                    <span className="block truncate" title={proc.name}>{proc.name}</span>
                    {proc.managedBy && <ManagerBadge manager={proc.managedBy} className="flex-shrink-0" />}
                  </div>
                </TableCell>
                <TableCell className="w-[100px] max-w-[100px] text-right font-mono text-zinc-600 dark:text-zinc-300 py-4 px-6">
                  <span className="block truncate text-right">{(proc.cpuUsagePercent || 0).toFixed(1)}%</span>
                </TableCell>
                <TableCell className="w-[150px] max-w-[150px] text-right font-mono text-zinc-600 dark:text-zinc-300 py-4 px-6">
                  <div className="flex flex-col gap-1 items-end">
                    <span className="block truncate">{formatBytes(proc.memoryUsageBytes)}</span>
                    {proc.memoryLimitBytes !== "0" && (() => {
                      const limitPct = (parseInt(proc.memoryUsageBytes) / parseInt(proc.memoryLimitBytes)) * 100;
                      return (
                        <Progress 
                          value={limitPct} 
                          className={`h-1.5 w-24 ${getProgressColorClass(limitPct, "[&>div>div]:bg-blue-500 dark:[&>div>div]:bg-blue-400")}`}
                        />
                      );
                    })()}
                  </div>
                </TableCell>
                <TableCell className="w-[120px] max-w-[120px] text-right font-mono text-zinc-600 dark:text-zinc-300 py-4 px-6">
                  <div className="flex flex-col gap-1 items-end text-[10px]">
                    <span className="text-blue-500">R: {formatIoBytes(proc.ioReadBytes)}</span>
                    <span className="text-orange-500">W: {formatIoBytes(proc.ioWriteBytes)}</span>
                  </div>
                </TableCell>
                <TableCell className="w-[120px] max-w-[120px] text-right font-mono text-zinc-600 dark:text-zinc-300 py-4 px-6">
                  <div className="flex flex-col gap-1 items-end text-[10px]">
                    <span className="text-green-500">Rx: {formatIoBytes(proc.netRxBytes)}</span>
                    <span className="text-purple-500">Tx: {formatIoBytes(proc.netTxBytes)}</span>
                  </div>
                </TableCell>
              </TableRow>
            ))}
            {processes.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="h-32 text-center text-zinc-400 dark:text-zinc-500">
                  No processes found matching your filter.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
        </TabsContent>

        <TabsContent value="namespaces" className="mt-6">
          <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 overflow-hidden shadow-sm dark:shadow-2xl">
            <Table>
              <TableHeader className="bg-zinc-50 dark:bg-zinc-900/80">
                <TableRow className="border-zinc-200 dark:border-zinc-800 hover:bg-transparent">
                  <TableHead className="text-zinc-500 dark:text-zinc-400 py-4 px-6">Type</TableHead>
                  <TableHead className="text-zinc-500 dark:text-zinc-400 py-4 px-6">ID</TableHead>
                  <TableHead className="text-zinc-500 dark:text-zinc-400 py-4 px-6">Scope</TableHead>
                  <TableHead className="text-zinc-500 dark:text-zinc-400 py-4 px-6 text-right">Process Count</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {namespaces.map((ns) => (
                  <TableRow 
                    key={ns.inode} 
                    className="cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/80 border-zinc-200 dark:border-zinc-800/50 transition-colors group"
                    onClick={() => navigate(`/namespace/${ns.type}/${ns.inode}`)}
                  >
                    <TableCell className="font-medium text-zinc-900 dark:text-white py-4 px-6 uppercase flex items-center gap-2">
                      <Box className="w-4 h-4 text-blue-500 dark:text-blue-400" />
                      {ns.type}
                    </TableCell>
                    <TableCell className="font-mono text-zinc-600 dark:text-zinc-300 py-4 px-6">{ns.type}:[{ns.inode}]</TableCell>
                    <TableCell className="py-4 px-6">
                      {ns.isHost ? (
                        <Badge variant="outline" className="border-green-300 dark:border-green-800 text-green-700 dark:text-green-400 bg-green-50 dark:bg-green-950/30">Host</Badge>
                      ) : (
                        <Badge variant="outline" className="border-orange-300 dark:border-orange-800 text-orange-700 dark:text-orange-400 bg-orange-50 dark:bg-orange-950/30">Isolated</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right font-mono text-zinc-600 dark:text-zinc-300 py-4 px-6">{ns.count}</TableCell>
                  </TableRow>
                ))}
                {namespaces.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} className="h-32 text-center text-zinc-400 dark:text-zinc-500">
                      No namespaces discovered yet.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </TabsContent>

        <TabsContent value="cgroups" className="mt-6">
          <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 overflow-hidden shadow-sm dark:shadow-2xl">
            <Table>
              <TableHeader className="bg-zinc-50 dark:bg-zinc-900/80">
                <TableRow className="border-zinc-200 dark:border-zinc-800 hover:bg-transparent">
                  <TableHead className="text-zinc-500 dark:text-zinc-400 py-4 px-6 w-[200px]">Cgroup ID</TableHead>
                  <TableHead className="text-zinc-500 dark:text-zinc-400 py-4 px-6">Scope</TableHead>
                  <TableHead className="text-right text-zinc-500 dark:text-zinc-400 py-4 px-6">Mem Limit</TableHead>
                  <TableHead className="text-right text-zinc-500 dark:text-zinc-400 py-4 px-6">CPU Quota</TableHead>
                  <TableHead className="text-right text-zinc-500 dark:text-zinc-400 py-4 px-6">PIDs Limit</TableHead>
                  <TableHead className="text-right text-zinc-500 dark:text-zinc-400 py-4 px-6">Process Count</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {cgroups.map((cg) => (
                  <TableRow 
                    key={cg.inode} 
                    className="cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/80 border-zinc-200 dark:border-zinc-800/50 transition-colors group"
                    onClick={() => navigate(`/namespace/cgroup/${cg.inode}`)}
                  >
                    <TableCell className="font-mono text-zinc-900 dark:text-white py-4 px-6 flex items-center gap-2 group-hover:text-black dark:group-hover:text-white transition-colors">
                      <Layers className="w-4 h-4 text-orange-500 dark:text-orange-400" />
                      [{cg.inode}]
                    </TableCell>
                    <TableCell className="py-4 px-6">
                      {cg.isHost ? (
                        <Badge variant="outline" className="border-green-300 dark:border-green-800 text-green-700 dark:text-green-400 bg-green-50 dark:bg-green-950/30">Host</Badge>
                      ) : (
                        <Badge variant="outline" className="border-orange-300 dark:border-orange-800 text-orange-700 dark:text-orange-400 bg-orange-50 dark:bg-orange-950/30">Isolated</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right font-mono text-zinc-600 dark:text-zinc-300 py-4 px-6">
                      {cg.memoryLimit !== "0" ? formatBytes(cg.memoryLimit) : "Max"}
                    </TableCell>
                    <TableCell className="text-right font-mono text-zinc-600 dark:text-zinc-300 py-4 px-6">
                      {cg.cpuQuota !== "0" ? cg.cpuQuota : "Max"}
                    </TableCell>
                    <TableCell className="text-right font-mono text-zinc-600 dark:text-zinc-300 py-4 px-6">
                      {cg.pidsLimit !== "0" ? cg.pidsLimit : "Max"}
                    </TableCell>
                    <TableCell className="text-right font-mono text-zinc-600 dark:text-zinc-300 py-4 px-6">
                      {cg.count}
                    </TableCell>
                  </TableRow>
                ))}
                {cgroups.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="h-32 text-center text-zinc-400 dark:text-zinc-500">
                      No cgroups discovered yet.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
