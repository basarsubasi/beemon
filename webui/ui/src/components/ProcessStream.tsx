import { useEffect, useState, useRef } from "react";
import type { BeemonEvent, WSMessage } from "../lib/types";
import { Badge } from "./ui/badge";
import { Card } from "./ui/card";
import { Activity } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, Legend } from "recharts";

export function ProcessStream({ pid, process }: { pid: number, process?: import("../lib/types").Process }) {
  const [events, setEvents] = useState<BeemonEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [lastPing, setLastPing] = useState<number | null>(null);
  const [limits, setLimits] = useState({ memory: "Max", cpu: "Max" });
  const [syscallCounts, setSyscallCounts] = useState<Record<string, number>>({});
  const scrollRef = useRef<HTMLDivElement>(null);
  
  useEffect(() => {
    setEvents([]);
    setIsConnected(false);
    setLastPing(null);
    setSyscallCounts({});

    // Determine the WS protocol based on current location protocol
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    // Connect to the vite proxy (which is on the same host)
    const wsUrl = `${protocol}//${window.location.host}/api/v1/processes/${pid}/stream/ws`;
    
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => setIsConnected(true);
    
    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data) as WSMessage;

        // Connectivity Test (Ping)
        if ("type" in msg && msg.type === "ping") {
          setLastPing(Date.now());
          return;
        }

        const data = msg as BeemonEvent;

        // Handle LimitChanged uniquely to update local state
        if (data.limitChanged) {
          setLimits({
            memory: formatBytes(data.limitChanged.memoryLimitBytes),
            cpu: data.limitChanged.cpuQuotaUs !== "0" ? `${data.limitChanged.cpuQuotaUs}us` : "Max"
          });
        }

        const type = data.fileOpen ? 'open' : data.fileRead ? 'read' : data.fileWrite ? 'write' : data.fileClose ? 'close' : data.networkConnect ? 'connect' : data.process ? (data.process.isExec ? 'exec' : data.process.isExit ? 'exit' : 'fork') : data.chroot ? 'chroot' : data.pivotRoot ? 'pivot_root' : data.setns ? 'setns' : data.unshare ? 'unshare' : 'syscall';

        setSyscallCounts((prev) => ({
          ...prev,
          [type]: (prev[type] || 0) + 1
        }));

        setEvents((prev) => {
          const newEvents = [...prev, data];
          if (newEvents.length > 500) return newEvents.slice(newEvents.length - 500); // Keep last 500
          return newEvents;
        });
      } catch (err) {
        console.error("Failed to parse WS data", err);
      }
    };

    ws.onerror = () => {
      setIsConnected(false);
    };

    ws.onclose = () => {
      setIsConnected(false);
    };

    return () => {
      ws.close();
    };
  }, [pid]);

  useEffect(() => {
    // Auto-scroll to bottom
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events]);

  const formatBytes = (bytesStr: string) => {
    if (bytesStr === "0" || bytesStr === "max") return "Max";
    const bytes = parseInt(bytesStr);
    if (!bytes) return "N/A";
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  };

  const decodePayload = (b64: string | undefined, totalBytes: string) => {
    if (!b64) return `"..."`;
    try {
      const decoded = atob(b64);
      let safeStr = "";
      for (let i = 0; i < decoded.length; i++) {
        const code = decoded.charCodeAt(i);
        if (code >= 32 && code <= 126) safeStr += decoded[i];
        else if (code === 10) safeStr += "\\n";
        else if (code === 9) safeStr += "\\t";
        else if (code === 13) safeStr += "\\r";
        else if (code === 0) { break; } // stop at null terminator
        else safeStr += ".";
      }
      
      const total = parseInt(totalBytes);
      if (total > decoded.length) {
        return `"${safeStr}..." /* ${total} bytes total */`;
      }
      return `"${safeStr}"`;
    } catch {
      return `"<binary data>"`;
    }
  };

  const intToIP = (ipInt: number | undefined) => {
    if (ipInt === undefined) return "0.0.0.0";
    // network byte order: first byte is the first octet
    const part1 = ipInt & 255;
    const part2 = ((ipInt >> 8) & 255);
    const part3 = ((ipInt >> 16) & 255);
    const part4 = ((ipInt >>> 24) & 255);
    return `${part1}.${part2}.${part3}.${part4}`;
  };

  const renderEventDetails = (ev: BeemonEvent) => {
    if (ev.fileOpen) return <span className="text-blue-400">openat("{ev.fileOpen.filename}", {ev.fileOpen.flags})</span>;
    if (ev.fileRead) return <span className="text-gray-400">read({ev.fileRead.fd}, {ev.fileRead.count})</span>;
    if (ev.fileWrite) return <span className="text-green-400">write({ev.fileWrite.fd}, {decodePayload(ev.fileWrite.data, ev.fileWrite.count)}, {ev.fileWrite.count})</span>;
    if (ev.fileClose) return <span className="text-gray-500">close({ev.fileClose.fd})</span>;
    if (ev.networkConnect) return <span className="text-purple-400">connect({intToIP(ev.networkConnect.saddr)}:{ev.networkConnect.sport} {"->"} {intToIP(ev.networkConnect.daddr)}:{ev.networkConnect.dport})</span>;
    if (ev.process) {
      if (ev.process.isExec) {
        const argsStr = ev.process.args && ev.process.args.length > 0 
          ? `[${ev.process.args.map(a => `"${a}"`).join(", ")}]` 
          : "[]";
        return <span className="text-yellow-400">execve("{ev.process.filename}", {argsStr})</span>;
      }
      if (ev.process.isExit) return <span className="text-red-400">exit({ev.process.exitCode})</span>;
      if (ev.process.isFork) return <span className="text-yellow-400">fork() {"->"} {ev.process.childPid}</span>;
    }
    if (ev.chroot) return <span className="text-red-500 font-bold bg-red-950/50 px-1 py-0.5 rounded">chroot("{ev.chroot.path}")</span>;
    if (ev.pivotRoot) return <span className="text-red-500 font-bold bg-red-950/50 px-1 py-0.5 rounded">pivot_root("{ev.pivotRoot.newRoot}", "{ev.pivotRoot.putOld}")</span>;
    if (ev.setns) return <span className="text-orange-500 font-bold bg-orange-950/50 px-1 py-0.5 rounded">setns(fd: {ev.setns.fd}, nstype: {ev.setns.nstype})</span>;
    if (ev.unshare) return <span className="text-orange-500 font-bold bg-orange-950/50 px-1 py-0.5 rounded">unshare(flags: {ev.unshare.flags})</span>;

    if (ev.limitChanged) return <span className="text-orange-400">cgroup_limits_changed()</span>;
    return <span className="text-gray-600">syscall({ev.syscall?.syscallId})</span>;
  };

  const formatTimestamp = (ts: string | undefined) => {
    try {
      if (!ts) return "00:00:00.000";
      return new Date(parseInt(ts) / 1000000).toISOString().split('T')[1].slice(0, -1);
    } catch {
      return "00:00:00.000";
    }
  };

  // Render time ago for ping
  const getPingStatus = () => {
    if (!isConnected) return "Disconnected";
    if (!lastPing) return "Waiting for ping...";
    const secondsAgo = Math.floor((Date.now() - lastPing) / 1000);
    return `Last Ping: ${secondsAgo}s ago`;
  };

  const pieData = Object.entries(syscallCounts).map(([name, value]) => ({ name, value })).sort((a,b) => b.value - a.value);
  
  const SYSCALL_COLORS: Record<string, string> = {
    open: '#60a5fa', // text-blue-400
    read: '#9ca3af', // text-gray-400
    write: '#4ade80', // text-green-400
    close: '#6b7280', // text-gray-500
    connect: '#c084fc', // text-purple-400
    exec: '#facc15', // text-yellow-400
    exit: '#f87171', // text-red-400
    fork: '#facc15', // text-yellow-400
    chroot: '#ef4444', // text-red-500
    pivot_root: '#ef4444', // text-red-500
    setns: '#f97316', // text-orange-500
    unshare: '#f97316', // text-orange-500
    syscall: '#4b5563', // text-gray-600
  };

  return (
    <div className="flex flex-col h-full gap-4">
      <div className="flex items-center justify-between">
        <div className="flex gap-4 items-center">
          <Badge variant={isConnected ? "default" : "destructive"}>
            {isConnected ? "LIVE" : "DISCONNECTED"}
          </Badge>
          
          <div className="flex items-center gap-2 text-xs font-mono bg-zinc-100 dark:bg-zinc-900 px-3 py-1.5 rounded-full border border-zinc-200 dark:border-zinc-800">
            <Activity size={14} className={isConnected && lastPing && (Date.now() - lastPing < 5000) ? "text-green-600 dark:text-green-500 animate-pulse" : "text-zinc-500"} />
            <span className="text-zinc-500 dark:text-zinc-400">{getPingStatus()}</span>
          </div>

          <span className="text-sm text-zinc-500 ml-2">Monitoring PID {pid}</span>
        </div>
        <div className="flex gap-4 text-xs font-mono text-zinc-500 dark:text-zinc-400">
          <span>MEM USAGE: <span className="text-zinc-900 dark:text-white">{process ? formatBytes(process.memoryUsageBytes) : "Loading..."}</span></span>
          <span>MEM LIMIT: <span className="text-zinc-900 dark:text-white">{limits.memory}</span></span>
          <span>CPU LIMIT: <span className="text-zinc-900 dark:text-white">{limits.cpu}</span></span>
        </div>
      </div>
      
      <div className="flex gap-6 h-full pb-6 flex-col md:flex-row">
        <Card className="flex-1 bg-white dark:bg-black overflow-hidden border-zinc-200 dark:border-zinc-800 shadow-sm dark:shadow-xl flex flex-col h-[500px]">
          <div ref={scrollRef} className="flex-1 overflow-y-auto custom-scrollbar p-4 font-mono text-xs">
            {events.map((ev, i) => (
              <div key={i} className="mb-1 opacity-90 hover:opacity-100 transition-opacity">
                <span className="text-zinc-500 mr-4">
                  {formatTimestamp(ev.timestampNs || (ev as any).timestamp_ns)}
                </span>
                {renderEventDetails(ev)}
              </div>
            ))}
            {events.length === 0 && (
              <div className="text-zinc-600 flex flex-col items-center justify-center mt-20 italic">
                <Activity className="opacity-20 mb-4 h-12 w-12" />
                <span>Waiting for eBPF events...</span>
                <span className="text-[10px] mt-2 opacity-50">Ping connectivity is active. Safe to idle.</span>
              </div>
            )}
          </div>
        </Card>

        <Card className="w-full md:w-[300px] bg-zinc-50 dark:bg-zinc-950 border-zinc-200 dark:border-zinc-800 shadow-sm dark:shadow-xl p-4 flex flex-col h-[300px] md:h-[500px]">
          <h3 className="text-zinc-900 dark:text-white font-semibold text-sm mb-4">Syscall Distribution</h3>
          {pieData.length > 0 ? (
            <div className="flex-1 min-h-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                    stroke="none"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={SYSCALL_COLORS[entry.name] || '#ffffff'} />
                    ))}
                  </Pie>
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', color: '#fff', fontSize: '12px' }}
                    itemStyle={{ color: '#fff' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '12px', color: '#a1a1aa' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
             <div className="text-zinc-600 flex-1 flex items-center justify-center italic text-sm text-center">
                Waiting for syscalls...
             </div>
          )}
        </Card>
      </div>
    </div>
  );
}
