import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { Process, ListProcessesResponse } from "../lib/types";
import { Input } from "./ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import { Badge } from "./ui/badge";
import { ArrowUpDown, ArrowUp, ArrowDown } from "lucide-react";

type SortKey = 'pid' | 'name' | 'state' | 'memory' | 'memLimit' | 'pidsLimit';
type SortDirection = 'asc' | 'desc';

export function Dashboard() {
  const [processes, setProcesses] = useState<Process[]>([]);
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>('pid');
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc');
  
  const navigate = useNavigate();

  useEffect(() => {
    const fetchProcesses = async () => {
      try {
        const url = filter ? `/api/v1/processes?filter_name=${encodeURIComponent(filter)}` : `/api/v1/processes`;
        const res = await fetch(url);
        const data = (await res.json()) as ListProcessesResponse;
        setProcesses(data.processes || []);
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

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight mb-2 text-white">Beemon Dashboard</h1>
        <p className="text-zinc-400">Real-time eBPF Linux process monitoring.</p>
      </div>

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
                <TableCell className="text-right font-mono text-zinc-300 py-4 px-6">
                  {formatBytes(proc.memoryUsageBytes)}
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
    </div>
  );
}
