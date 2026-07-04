import { useEffect, useState } from "react";
import type { Process, ListProcessesResponse } from "../lib/types";
import { Input } from "./ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import { Badge } from "./ui/badge";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "./ui/sheet";
import { ProcessStream } from "./ProcessStream";

export function Dashboard() {
  const [processes, setProcesses] = useState<Process[]>([]);
  const [filter, setFilter] = useState("");
  const [selectedPid, setSelectedPid] = useState<number | null>(null);

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

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight mb-2 text-white">Beemon Dashboard</h1>
        <p className="text-zinc-400">Real-time eBPF Linux process monitoring.</p>
      </div>

      <div className="flex items-center space-x-2">
        <Input 
          placeholder="Filter by process name..." 
          className="max-w-sm bg-zinc-900 border-zinc-800 text-white"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>

      <div className="rounded-md border border-zinc-800 bg-black/50 overflow-hidden backdrop-blur-xl">
        <Table>
          <TableHeader className="bg-zinc-900">
            <TableRow className="border-zinc-800 hover:bg-zinc-900">
              <TableHead className="w-[100px] text-zinc-400">PID</TableHead>
              <TableHead className="text-zinc-400">Name</TableHead>
              <TableHead className="text-zinc-400">State</TableHead>
              <TableHead className="text-right text-zinc-400">Memory</TableHead>
              <TableHead className="text-right text-zinc-400">Mem Limit</TableHead>
              <TableHead className="text-right text-zinc-400">PIDs Limit</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {processes.map((proc) => (
              <TableRow 
                key={proc.pid} 
                className="cursor-pointer hover:bg-zinc-800/50 border-zinc-800 transition-colors"
                onClick={() => setSelectedPid(proc.pid)}
              >
                <TableCell className="font-mono text-zinc-300">{proc.pid}</TableCell>
                <TableCell className="font-medium text-white">{proc.name}</TableCell>
                <TableCell>
                  <Badge variant="outline" className="border-zinc-700 text-zinc-300">
                    {proc.state}
                  </Badge>
                </TableCell>
                <TableCell className="text-right font-mono text-zinc-400">
                  {formatBytes(proc.memoryUsageBytes)}
                </TableCell>
                <TableCell className="text-right font-mono text-zinc-500">
                  {proc.memoryLimitBytes !== "0" ? formatBytes(proc.memoryLimitBytes) : "Max"}
                </TableCell>
                <TableCell className="text-right font-mono text-zinc-500">
                  {proc.pidsLimit !== "0" ? proc.pidsLimit : "Max"}
                </TableCell>
              </TableRow>
            ))}
            {processes.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center text-zinc-500">
                  No processes found.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      <Sheet open={selectedPid !== null} onOpenChange={(open) => !open && setSelectedPid(null)}>
        <SheetContent side="right" className="w-[800px] sm:max-w-none border-zinc-800 bg-zinc-950 p-6">
          <SheetHeader className="mb-6">
            <SheetTitle className="text-white">Live Process Tracing</SheetTitle>
          </SheetHeader>
          {selectedPid && <ProcessStream pid={selectedPid} />}
        </SheetContent>
      </Sheet>
    </div>
  );
}
