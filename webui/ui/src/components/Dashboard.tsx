import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { Process, ListProcessesResponse } from "../lib/types";
import { Input } from "./ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import { Badge } from "./ui/badge";
import { Progress } from "./ui/progress";
import { Card } from "./ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { ArrowUpDown, ArrowUp, ArrowDown, Cpu, MemoryStick, Box } from "lucide-react";

type SortKey = 'pid' | 'name' | 'state' | 'memory' | 'memLimit' | 'pidsLimit';
type SortDirection = 'asc' | 'desc';

export function Dashboard() {
  const [processes, setProcesses] = useState<Process[]>([]);
  const [hostMem, setHostMem] = useState<string>("0");
  const [hostNamespaces, setHostNamespaces] = useState<string[]>([]);
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>('memory');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  
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
    const interval = setInterval(fetchProcesses, 2000);
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

  // Aggregate namespaces
  const nsMap = new Map<string, { type: string, inode: string, count: number, isHost: boolean }>();
  processes.forEach(p => {
    if (p.namespaces) {
      p.namespaces.forEach(nsStr => {
        if (!nsMap.has(nsStr)) {
          const inodeMatch = nsStr.match(/\[(\d+)\]/);
          if (inodeMatch) {
            nsMap.set(nsStr, { 
              type: nsStr.split(":")[0], 
              inode: inodeMatch[1], 
              count: 1,
              isHost: hostNamespaces.includes(nsStr)
            });
          }
        } else {
          nsMap.get(nsStr)!.count++;
        }
      });
    }
  });
  const namespaces = Array.from(nsMap.values()).sort((a,b) => b.count - a.count);
  
  const totalMemory = processes.reduce((acc, p) => acc + (parseInt(p.memoryUsageBytes) || 0), 0);
  const totalCpu = processes.reduce((acc, p) => acc + (p.cpuUsagePercent || 0), 0);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex justify-between items-start">
        <div>
          <h1 className="text-3xl font-bold tracking-tight mb-2 text-white">beemon dashboard</h1>
          <p className="text-zinc-400">Real-time eBPF Linux process monitoring.</p>
        </div>
        
        <div className="flex gap-4">
          <Card className="bg-zinc-950/50 border-zinc-800 p-4 min-w-[200px] flex items-center gap-4">
            <div className="p-3 bg-zinc-900 rounded-full">
              <MemoryStick className="text-blue-400 h-6 w-6" />
            </div>
            <div>
              <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider">Total Memory</p>
              <div className="flex items-baseline gap-2">
                <p className="text-xl font-mono text-white">{formatBytes(totalMemory.toString())}</p>
                {hostMem !== "0" && <p className="text-xs text-zinc-500 font-mono">/ {formatBytes(hostMem)}</p>}
              </div>
            </div>
          </Card>
          <Card className="bg-zinc-950/50 border-zinc-800 p-4 min-w-[200px] flex items-center gap-4">
            <div className="p-3 bg-zinc-900 rounded-full">
              <Cpu className="text-green-400 h-6 w-6" />
            </div>
            <div>
              <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider">Total CPU</p>
              <p className="text-xl font-mono text-white">{totalCpu.toFixed(1)}%</p>
            </div>
          </Card>
        </div>
      </div>

      <Tabs defaultValue="processes" className="w-full">
        <TabsList className="grid w-[400px] grid-cols-2 bg-zinc-900 border border-zinc-800">
          <TabsTrigger value="processes">Processes</TabsTrigger>
          <TabsTrigger value="namespaces">Namespaces</TabsTrigger>
        </TabsList>

        <TabsContent value="processes" className="space-y-4 mt-6">
          <div className="flex items-center space-x-2">
            <Input 
          placeholder="Filter by name or PID..." 
          className="max-w-md bg-zinc-900 border-zinc-800 text-white p-6 text-md"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>

      <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 overflow-hidden backdrop-blur-xl shadow-2xl">
        <Table>
          <TableHeader className="bg-zinc-900/80">
            <TableRow className="border-zinc-800 hover:bg-transparent">
              <TableHead 
                className="w-[120px] text-zinc-400 cursor-pointer hover:text-white transition-colors py-4 px-6"
                onClick={() => handleSort('pid')}
              >
                <div className="flex items-center">PID {renderSortIcon('pid')}</div>
              </TableHead>
              <TableHead 
                className="text-zinc-400 cursor-pointer hover:text-white transition-colors py-4 px-6"
                onClick={() => handleSort('name')}
              >
                <div className="flex items-center">Name {renderSortIcon('name')}</div>
              </TableHead>
              <TableHead 
                className="text-zinc-400 cursor-pointer hover:text-white transition-colors py-4 px-6 w-[150px]"
                onClick={() => handleSort('state')}
              >
                <div className="flex items-center">State {renderSortIcon('state')}</div>
              </TableHead>
              <TableHead 
                className="text-zinc-400 cursor-pointer hover:text-white transition-colors py-4 px-6 text-right w-[150px]"
                onClick={() => handleSort('memory')}
              >
                <div className="flex items-center justify-end">Memory {renderSortIcon('memory')}</div>
              </TableHead>
              <TableHead 
                className="text-zinc-400 cursor-pointer hover:text-white transition-colors py-4 px-6 text-right w-[150px]"
                onClick={() => handleSort('memLimit')}
              >
                <div className="flex items-center justify-end">Mem Limit {renderSortIcon('memLimit')}</div>
              </TableHead>
              <TableHead 
                className="text-zinc-400 cursor-pointer hover:text-white transition-colors py-4 px-6 text-right w-[150px]"
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
                className="cursor-pointer hover:bg-zinc-800/80 border-zinc-800/50 transition-colors group"
                onClick={() => navigate(`/process/${proc.pid}`)}
              >
                <TableCell className="font-mono text-zinc-300 py-4 px-6">{proc.pid}</TableCell>
                <TableCell className="font-medium text-white py-4 px-6 group-hover:text-blue-400 transition-colors">
                  {proc.name}
                </TableCell>
                <TableCell className="py-4 px-6">
                  <Badge variant="outline" className="border-zinc-700 text-zinc-300">
                    {proc.state}
                  </Badge>
                </TableCell>
                <TableCell className="text-right font-mono text-zinc-300 py-4 px-6 w-[200px]">
                  <div className="flex flex-col gap-1 items-end">
                    <span>{formatBytes(proc.memoryUsageBytes)}</span>
                    {proc.memoryLimitBytes !== "0" && (
                      <Progress 
                        value={(parseInt(proc.memoryUsageBytes) / parseInt(proc.memoryLimitBytes)) * 100} 
                        className="h-1.5 w-24"
                      />
                    )}
                  </div>
                </TableCell>
                <TableCell className="text-right font-mono text-zinc-500 py-4 px-6">
                  {proc.memoryLimitBytes !== "0" ? formatBytes(proc.memoryLimitBytes) : "Max"}
                </TableCell>
                <TableCell className="text-right font-mono text-zinc-500 py-4 px-6">
                  {proc.pidsLimit !== "0" ? proc.pidsLimit : "Max"}
                </TableCell>
              </TableRow>
            ))}
            {processes.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="h-32 text-center text-zinc-500">
                  No processes found matching your filter.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
        </TabsContent>

        <TabsContent value="namespaces" className="mt-6">
          <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 overflow-hidden backdrop-blur-xl shadow-2xl">
            <Table>
              <TableHeader className="bg-zinc-900/80">
                <TableRow className="border-zinc-800 hover:bg-transparent">
                  <TableHead className="text-zinc-400 py-4 px-6">Type</TableHead>
                  <TableHead className="text-zinc-400 py-4 px-6">ID</TableHead>
                  <TableHead className="text-zinc-400 py-4 px-6">Scope</TableHead>
                  <TableHead className="text-zinc-400 py-4 px-6 text-right">Process Count</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {namespaces.map((ns) => (
                  <TableRow 
                    key={ns.inode} 
                    className="cursor-pointer hover:bg-zinc-800/80 border-zinc-800/50 transition-colors group"
                    onClick={() => navigate(`/namespace/${ns.type}/${ns.inode}`)}
                  >
                    <TableCell className="font-medium text-white py-4 px-6 uppercase flex items-center gap-2">
                      <Box className="w-4 h-4 text-blue-400" />
                      {ns.type}
                    </TableCell>
                    <TableCell className="font-mono text-zinc-300 py-4 px-6">{ns.type}:[{ns.inode}]</TableCell>
                    <TableCell className="py-4 px-6">
                      {ns.isHost ? (
                        <Badge variant="outline" className="border-green-800 text-green-400 bg-green-950/30">Host</Badge>
                      ) : (
                        <Badge variant="outline" className="border-orange-800 text-orange-400 bg-orange-950/30">Isolated</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right font-mono text-zinc-300 py-4 px-6">{ns.count}</TableCell>
                  </TableRow>
                ))}
                {namespaces.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} className="h-32 text-center text-zinc-500">
                      No namespaces discovered yet.
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
