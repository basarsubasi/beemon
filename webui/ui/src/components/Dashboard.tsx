import { useEffect, useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import type { Process, ListProcessesResponse } from "../lib/types";
import { Input } from "./ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import { Badge } from "./ui/badge";
import { StateBadge } from "./StateBadge";
import { ThemeToggle } from "./ThemeToggle";
import { Progress } from "./ui/progress";
import { Card } from "./ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { ArrowUpDown, ArrowUp, ArrowDown, Cpu, MemoryStick, Box, Layers } from "lucide-react";

type SortKey = 'pid' | 'name' | 'state' | 'memory' | 'memLimit' | 'pidsLimit' | 'cpu' | 'cpuLimit';
type SortDirection = 'asc' | 'desc';

export function Dashboard() {
  const [processes, setProcesses] = useState<Process[]>([]);
  const [hostMem, setHostMem] = useState<string>("0");
  const [hostNamespaces, setHostNamespaces] = useState<string[]>([]);
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>('memory');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [activeTab, setActiveTab] = useState(() => localStorage.getItem("dashboardTab") || "processes");
  
  const handleTabChange = (val: string) => {
    setActiveTab(val);
    localStorage.setItem("dashboardTab", val);
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
    if (!bytes || bytes === 0) return "N/A";
    const gb = bytes / 1024 / 1024 / 1024;
    if (gb >= 1) return `${gb.toFixed(2)} GB`;
    const mb = bytes / 1024 / 1024;
    return `${mb.toFixed(1)} MB`;
  };

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDirection('asc');
    }
  };

  const getSortedProcesses = () => {
    return [...processes].sort((a, b) => {
      let aVal: any = a.pid;
      let bVal: any = b.pid;

      if (sortKey === 'name') {
        aVal = a.name.toLowerCase();
        bVal = b.name.toLowerCase();
      } else if (sortKey === 'state') {
        aVal = a.state;
        bVal = b.state;
      } else if (sortKey === 'memory') {
        aVal = parseInt(a.memoryUsageBytes);
        bVal = parseInt(b.memoryUsageBytes);
      } else if (sortKey === 'memLimit') {
        aVal = parseInt(a.memoryLimitBytes);
        bVal = parseInt(b.memoryLimitBytes);
      } else if (sortKey === 'pidsLimit') {
        aVal = parseInt(a.pidsLimit);
        bVal = parseInt(b.pidsLimit);
      } else if (sortKey === 'cpu') {
        aVal = a.cpuUsagePercent || 0;
        bVal = b.cpuUsagePercent || 0;
      } else if (sortKey === 'cpuLimit') {
        aVal = parseInt(a.cpuQuotaUs) || 0;
        bVal = parseInt(b.cpuQuotaUs) || 0;
      }

      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  };

  const renderSortIcon = (key: SortKey) => {
    if (sortKey !== key) return <ArrowUpDown className="ml-2 h-4 w-4 opacity-50" />;
    return sortDirection === 'asc' ? <ArrowUp className="ml-2 h-4 w-4" /> : <ArrowDown className="ml-2 h-4 w-4" />;
  };

  const sortedProcesses = getSortedProcesses();

  const namespaces = useMemo(() => {
    const nsMap = new Map<string, { type: string, inode: string, count: number, isHost: boolean }>();
    
    processes.forEach(p => {
      p.namespaces?.forEach(ns => {
        if (ns.startsWith('cgroup:')) return; // exclude cgroups from general namespaces tab
        if (!nsMap.has(ns)) {
          const isHost = hostNamespaces.includes(ns);
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

    return Array.from(nsMap.values()).sort((a, b) => b.count - a.count);
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

    return Array.from(cgMap.values()).sort((a, b) => b.count - a.count);
  }, [processes, hostNamespaces]);

  const totalMemory = processes.reduce((acc, p) => acc + (parseInt(p.memoryUsageBytes) || 0), 0);
  const totalCpu = processes.reduce((acc, p) => acc + (p.cpuUsagePercent || 0), 0);

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
        
        <div className="flex gap-4">
          <Card className="bg-white dark:bg-zinc-950/50 border-zinc-200 dark:border-zinc-800 p-4 min-w-[200px] flex items-center gap-4 shadow-sm">
            <div className="p-3 bg-blue-50 dark:bg-zinc-900 rounded-full">
              <MemoryStick className="text-blue-500 dark:text-blue-400 h-6 w-6" />
            </div>
            <div>
              <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider">Total Memory</p>
              <div className="flex items-baseline gap-2">
                <p className="text-xl font-mono text-zinc-900 dark:text-white">{formatBytes(totalMemory.toString())}</p>
                {hostMem !== "0" && <p className="text-xs text-zinc-500 font-mono">/ {formatBytes(hostMem)}</p>}
              </div>
            </div>
          </Card>
          <Card className="bg-white dark:bg-zinc-950/50 border-zinc-200 dark:border-zinc-800 p-4 min-w-[200px] flex items-center gap-4 shadow-sm">
            <div className="p-3 bg-green-50 dark:bg-zinc-900 rounded-full">
              <Cpu className="text-green-600 dark:text-green-400 h-6 w-6" />
            </div>
            <div className="text-center">
              <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider">Total CPU</p>
              <p className="text-xl font-mono text-zinc-900 dark:text-white">{totalCpu.toFixed(1)}%</p>
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
          <div className="flex items-center space-x-2">
            <Input 
              placeholder="Filter by name or PID..." 
              className="max-w-md bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800 p-6 text-md"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
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
                className="w-[140px] max-w-[140px] text-zinc-500 dark:text-zinc-400 cursor-pointer hover:text-zinc-900 dark:hover:text-white transition-colors py-4 px-6"
                onClick={() => handleSort('state')}
              >
                <div className="flex items-center">State {renderSortIcon('state')}</div>
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
              <TableHead 
                className="w-[130px] max-w-[130px] text-zinc-500 dark:text-zinc-400 cursor-pointer hover:text-zinc-900 dark:hover:text-white transition-colors py-4 px-6 text-right"
                onClick={() => handleSort('memLimit')}
              >
                <div className="flex items-center justify-end">Mem Limit {renderSortIcon('memLimit')}</div>
              </TableHead>
              <TableHead 
                className="w-[130px] max-w-[130px] text-zinc-500 dark:text-zinc-400 cursor-pointer hover:text-zinc-900 dark:hover:text-white transition-colors py-4 px-6 text-right"
                onClick={() => handleSort('cpuLimit')}
              >
                <div className="flex items-center justify-end">CPU Limit {renderSortIcon('cpuLimit')}</div>
              </TableHead>
              <TableHead 
                className="w-[120px] max-w-[120px] text-zinc-500 dark:text-zinc-400 cursor-pointer hover:text-zinc-900 dark:hover:text-white transition-colors py-4 px-6 text-right"
                onClick={() => handleSort('pidsLimit')}
              >
                <div className="flex items-center justify-end">PIDs Limit {renderSortIcon('pidsLimit')}</div>
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
                <TableCell className="w-[200px] max-w-[200px] font-medium text-zinc-900 dark:text-zinc-300 py-4 px-6 group-hover:text-black dark:group-hover:text-white transition-colors">
                  <span className="block truncate" title={proc.name}>{proc.name}</span>
                </TableCell>
                <TableCell className="w-[140px] max-w-[140px] py-4 px-6">
                  <StateBadge state={proc.state} />
                </TableCell>
                <TableCell className="w-[100px] max-w-[100px] text-right font-mono text-zinc-600 dark:text-zinc-300 py-4 px-6">
                  <span className="block truncate text-right">{(proc.cpuUsagePercent || 0).toFixed(1)}%</span>
                </TableCell>
                <TableCell className="w-[150px] max-w-[150px] text-right font-mono text-zinc-600 dark:text-zinc-300 py-4 px-6">
                  <div className="flex flex-col gap-1 items-end">
                    <span className="block truncate">{formatBytes(proc.memoryUsageBytes)}</span>
                    {proc.memoryLimitBytes !== "0" && (
                      <Progress 
                        value={(parseInt(proc.memoryUsageBytes) / parseInt(proc.memoryLimitBytes)) * 100} 
                        className="h-1.5 w-24"
                      />
                    )}
                  </div>
                </TableCell>
                <TableCell className="w-[130px] max-w-[130px] text-right font-mono text-zinc-600 dark:text-zinc-500 py-4 px-6">
                  <span className="block truncate text-right">{proc.memoryLimitBytes !== "0" ? formatBytes(proc.memoryLimitBytes) : "Max"}</span>
                </TableCell>
                <TableCell className="w-[130px] max-w-[130px] text-right font-mono text-zinc-600 dark:text-zinc-500 py-4 px-6">
                  <span className="block truncate text-right">{proc.cpuQuotaUs !== "0" ? `${proc.cpuQuotaUs}us` : "Max"}</span>
                </TableCell>
                <TableCell className="w-[120px] max-w-[120px] text-right font-mono text-zinc-600 dark:text-zinc-500 py-4 px-6">
                  <span className="block truncate text-right">{proc.pidsLimit !== "0" ? proc.pidsLimit : "Max"}</span>
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
