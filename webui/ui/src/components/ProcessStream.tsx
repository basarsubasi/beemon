import { useEffect, useState, useRef } from "react";
import type { BeemonEvent, WSMessage } from "../lib/types";
import { Badge } from "./ui/badge";
import { Card } from "./ui/card";
import { Activity } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, Legend } from "recharts";
import { StateBadge } from "./StateBadge";

export function ProcessStream({ pid, process }: { pid: number, process?: import("../lib/types").Process }) {
  const [isConnected, setIsConnected] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [timeFilter, setTimeFilter] = useState<'all' | '5s' | '1s'>('all');
  const [lastPing, setLastPing] = useState<number | null>(null);
  const [limits, setLimits] = useState({ memory: "Max", cpu: "Max" });
  
  const [renderState, setRenderState] = useState({
    displayedEvents: [] as BeemonEvent[],
    pieData: [] as { name: string, value: number }[],
    totalSyscalls: 0
  });

  const scrollRef = useRef<HTMLDivElement>(null);
  
  const allEventsRef = useRef<(BeemonEvent & { _localTs?: number, _type?: string })[]>([]);
  const globalCountsRef = useRef<Record<string, number>>({});

  useEffect(() => {
    // Reset state on PID change
    setIsConnected(false);
    setLastPing(null);
    setRenderState({ displayedEvents: [], pieData: [], totalSyscalls: 0 });
    allEventsRef.current = [];
    globalCountsRef.current = {};
    setIsPaused(false);
  }, [pid]);

  // Render loop - decoupled from WebSocket frequency
  useEffect(() => {
    const interval = setInterval(() => {
      const now = Date.now();
      let cutoff = 0;
      if (timeFilter === '5s') cutoff = now - 5000;
      if (timeFilter === '1s') cutoff = now - 1000;

      const validEvents = timeFilter === 'all' 
        ? allEventsRef.current 
        : allEventsRef.current.filter(e => e._localTs && e._localTs >= cutoff);

      const displayedEvents = validEvents.slice(-500);

      let currentPieData: {name: string, value: number}[];
      
      if (timeFilter === 'all') {
        currentPieData = Object.entries(globalCountsRef.current)
          .map(([name, value]) => ({ name, value }))
          .sort((a,b) => b.value - a.value);
      } else {
        const counts: Record<string, number> = {};
        validEvents.forEach(e => {
          if (e._type) counts[e._type] = (counts[e._type] || 0) + 1;
        });
        currentPieData = Object.entries(counts)
          .map(([name, value]) => ({ name, value }))
          .sort((a,b) => b.value - a.value);
      }

      const totalSyscalls = currentPieData.reduce((acc, entry) => acc + entry.value, 0);

      setRenderState({ displayedEvents, pieData: currentPieData, totalSyscalls });
    }, 500);
    return () => clearInterval(interval);
  }, [timeFilter]);

  // WebSocket Connection
  useEffect(() => {
    if (isPaused) {
      setIsConnected(false);
      return;
    }

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

        const data = msg as BeemonEvent & { _localTs?: number, _type?: string };

        // Handle LimitChanged uniquely to update local state
        if (data.limitChanged) {
          setLimits({
            memory: formatBytes(data.limitChanged.memoryLimitBytes),
            cpu: data.limitChanged.cpuQuotaUs !== "0" ? `${data.limitChanged.cpuQuotaUs}us` : "Max"
          });
        }

        const type = data.fileOpen ? 'open' : data.fileRead ? 'read' : data.fileWrite ? 'write' : data.fileClose ? 'close' : data.networkConnect ? 'connect' : data.process ? (data.process.isExec ? 'exec' : data.process.isExit ? 'exit' : 'fork') : data.chroot ? 'chroot' : data.pivotRoot ? 'pivot_root' : data.setns ? 'setns' : data.unshare ? 'unshare' : data.wait4 ? 'wait4' : data.mmap ? 'mmap' : data.munmap ? 'munmap' : data.mprotect ? 'mprotect' : data.brk ? 'brk' : data.accept ? 'accept' : data.bind ? 'bind' : data.sendto ? 'sendto' : data.recvfrom ? 'recvfrom' : data.unlinkat ? 'unlinkat' : data.rename ? 'rename' : data.futex ? 'futex' : data.epollWait ? 'epoll_wait' : data.select ? 'select' : data.poll ? 'poll' : data.ptrace ? 'ptrace' : data.bpf ? 'bpf' : data.capset ? 'capset' : 'syscall';

        data._localTs = Date.now();
        data._type = type;

        globalCountsRef.current[type] = (globalCountsRef.current[type] || 0) + 1;
        
        allEventsRef.current.push(data);
        if (allEventsRef.current.length > 5000) {
           allEventsRef.current = allEventsRef.current.slice(-5000);
        }
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
  }, [pid, isPaused]);

  useEffect(() => {
    // Auto-scroll to bottom
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [renderState.displayedEvents]);

  const formatBytes = (bytesStr: string | undefined) => {
    if (!bytesStr || bytesStr === "0" || bytesStr === "max") return "Max";
    const bytes = parseInt(bytesStr);
    if (!bytes) return "N/A";
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  };

  useEffect(() => {
    if (process) {
      setLimits({
        memory: formatBytes(process.memoryLimitBytes),
        cpu: process.cpuQuotaUs && process.cpuQuotaUs !== "0" ? `${process.cpuQuotaUs}us` : "Max"
      });
    }
  }, [process?.memoryLimitBytes, process?.cpuQuotaUs]);

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

    if (ev.wait4) return <span className="text-gray-400">wait4(pid: {ev.wait4.pid}, options: {ev.wait4.options})</span>;
    if (ev.mmap) return <span className="text-pink-400">mmap(addr: {ev.mmap.addr}, len: {ev.mmap.len}, prot: {ev.mmap.prot}, flags: {ev.mmap.flags}, fd: {ev.mmap.fd})</span>;
    if (ev.munmap) return <span className="text-pink-400">munmap(addr: {ev.munmap.addr}, len: {ev.munmap.len})</span>;
    if (ev.mprotect) return <span className="text-pink-400">mprotect(start: {ev.mprotect.start}, len: {ev.mprotect.len}, prot: {ev.mprotect.prot})</span>;
    if (ev.brk) return <span className="text-pink-400">brk({ev.brk.brk})</span>;
    
    if (ev.accept) return <span className="text-purple-400">accept(fd: {ev.accept.fd})</span>;
    if (ev.bind) return <span className="text-purple-400">bind(fd: {ev.bind.fd})</span>;
    if (ev.sendto) return <span className="text-purple-400">sendto(fd: {ev.sendto.fd}, len: {ev.sendto.len})</span>;
    if (ev.recvfrom) return <span className="text-purple-400">recvfrom(fd: {ev.recvfrom.fd}, len: {ev.recvfrom.len})</span>;
    
    if (ev.unlinkat) return <span className="text-red-400">unlinkat(dfd: {ev.unlinkat.dfd}, "{ev.unlinkat.pathname}")</span>;
    if (ev.rename) return <span className="text-blue-400">rename("{ev.rename.oldname}", "{ev.rename.newname}")</span>;
    
    if (ev.futex) return <span className="text-teal-400">futex(uaddr: {ev.futex.uaddr}, op: {ev.futex.op}, val: {ev.futex.val})</span>;
    if (ev.epollWait) return <span className="text-teal-400">epoll_wait(epfd: {ev.epollWait.epfd}, maxevents: {ev.epollWait.maxevents})</span>;
    if (ev.select) return <span className="text-teal-400">select(nfds: {ev.select.nfds})</span>;
    if (ev.poll) return <span className="text-teal-400">poll(nfds: {ev.poll.nfds})</span>;
    
    if (ev.ptrace) return <span className="text-red-500 font-bold bg-red-950/50 px-1 py-0.5 rounded">ptrace(request: {ev.ptrace.request}, pid: {ev.ptrace.targetPid})</span>;
    if (ev.bpf) return <span className="text-red-500 font-bold bg-red-950/50 px-1 py-0.5 rounded">bpf(cmd: {ev.bpf.cmd})</span>;
    if (ev.capset) return <span className="text-red-500 font-bold bg-red-950/50 px-1 py-0.5 rounded">capset(pid: {ev.capset.targetPid})</span>;
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
    
    wait4: '#9ca3af',
    mmap: '#f472b6', // text-pink-400
    munmap: '#f472b6',
    mprotect: '#f472b6',
    brk: '#f472b6',
    
    accept: '#c084fc',
    bind: '#c084fc',
    sendto: '#c084fc',
    recvfrom: '#c084fc',
    
    unlinkat: '#f87171',
    rename: '#60a5fa',
    
    futex: '#2dd4bf', // text-teal-400
    epoll_wait: '#2dd4bf',
    select: '#2dd4bf',
    poll: '#2dd4bf',
    
    ptrace: '#ef4444',
    bpf: '#ef4444',
    capset: '#ef4444',

    syscall: '#4b5563', // text-gray-600
  };

  return (
    <div className="flex flex-col h-full gap-4">
      <div className="flex items-center justify-between">
        <div className="flex gap-4 items-center">
          <Badge variant={isConnected ? "default" : "destructive"}>
            {isConnected ? "LIVE" : "DISCONNECTED"}
          </Badge>

          <button 
            onClick={() => setIsPaused(!isPaused)}
            className="px-3 py-1 text-xs font-semibold bg-zinc-200 dark:bg-zinc-800 text-zinc-900 dark:text-white rounded-md hover:bg-zinc-300 dark:hover:bg-zinc-700 transition-colors"
          >
            {isPaused ? "Resume Streaming" : "Pause Streaming"}
          </button>
          
          <div className="flex gap-1 border border-zinc-200 dark:border-zinc-800 rounded-md p-1 bg-white dark:bg-black">
            <button onClick={() => setTimeFilter('all')} className={`px-2 py-0.5 text-xs rounded-sm font-medium transition-colors ${timeFilter === 'all' ? 'bg-zinc-200 dark:bg-zinc-800 text-zinc-900 dark:text-white' : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'}`}>All Time</button>
            <button onClick={() => setTimeFilter('5s')} className={`px-2 py-0.5 text-xs rounded-sm font-medium transition-colors ${timeFilter === '5s' ? 'bg-zinc-200 dark:bg-zinc-800 text-zinc-900 dark:text-white' : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'}`}>Last 5s</button>
            <button onClick={() => setTimeFilter('1s')} className={`px-2 py-0.5 text-xs rounded-sm font-medium transition-colors ${timeFilter === '1s' ? 'bg-zinc-200 dark:bg-zinc-800 text-zinc-900 dark:text-white' : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'}`}>Last 1s</button>
          </div>
          
          <div className="flex items-center gap-2 text-xs font-mono bg-zinc-100 dark:bg-zinc-900 px-3 py-1.5 rounded-full border border-zinc-200 dark:border-zinc-800">
            <Activity size={14} className={isConnected && lastPing && (Date.now() - lastPing < 5000) ? "text-green-600 dark:text-green-500 animate-pulse" : "text-zinc-500"} />
            <span className="text-zinc-500 dark:text-zinc-400">{getPingStatus()}</span>
          </div>

          <span className="text-sm text-zinc-500 ml-2">Monitoring PID {pid}</span>
        </div>
        <div className="flex gap-4 items-center text-xs font-mono text-zinc-500 dark:text-zinc-400">
          <div className="flex items-center gap-2">
            <span>STATE:</span>
            {process ? <StateBadge state={process.state} className="text-[10px] py-0" /> : <span className="text-zinc-900 dark:text-white">Loading...</span>}
          </div>
          <span>CPU USAGE: <span className="text-zinc-900 dark:text-white">{process ? `${(process.cpuUsagePercent || 0).toFixed(1)}%` : "Loading..."}</span></span>
          <span>MEM USAGE: <span className="text-zinc-900 dark:text-white">{process ? formatBytes(process.memoryUsageBytes) : "Loading..."}</span></span>
          <span>MEM LIMIT: <span className="text-zinc-900 dark:text-white">{limits.memory}</span></span>
          <span>CPU LIMIT: <span className="text-zinc-900 dark:text-white">{limits.cpu}</span></span>
        </div>
      </div>
      
      <div className="flex gap-6 h-full pb-6 flex-col md:flex-row">
        <Card className="flex-1 bg-white dark:bg-black overflow-hidden border-zinc-200 dark:border-zinc-800 shadow-sm dark:shadow-xl flex flex-col h-[500px]">
          <div ref={scrollRef} className="flex-1 overflow-y-auto custom-scrollbar p-4 font-mono text-xs">
            {renderState.displayedEvents.map((ev, i) => (
              <div key={i} className="mb-1 opacity-90 hover:opacity-100 transition-opacity">
                <span className="text-zinc-500 mr-4">
                  {formatTimestamp(ev.timestampNs || (ev as any).timestamp_ns)}
                </span>
                {renderEventDetails(ev)}
              </div>
            ))}
            {renderState.displayedEvents.length === 0 && (
              <div className="text-zinc-600 flex flex-col items-center justify-center mt-20 italic">
                <Activity className="opacity-20 mb-4 h-12 w-12" />
                <span>Waiting for eBPF events...</span>
                <span className="text-[10px] mt-2 opacity-50">Ping connectivity is active. Safe to idle.</span>
              </div>
            )}
          </div>
        </Card>

        <Card className="w-full md:w-[300px] bg-zinc-50 dark:bg-zinc-950 border-zinc-200 dark:border-zinc-800 shadow-sm dark:shadow-xl p-4 flex flex-col h-[300px] md:h-[500px]">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-zinc-900 dark:text-white font-semibold text-sm">Syscall Distribution</h3>
            {renderState.totalSyscalls > 0 && (
              <span className="text-xs text-zinc-500 font-mono border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-2 py-0.5 rounded-md shadow-sm">
                Total: {renderState.totalSyscalls.toLocaleString()}
              </span>
            )}
          </div>
          {renderState.pieData.length > 0 ? (
            <div className="flex-1 min-h-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={renderState.pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                    stroke="none"
                    isAnimationActive={false}
                  >
                    {renderState.pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={SYSCALL_COLORS[entry.name] || '#ffffff'} />
                    ))}
                  </Pie>
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', color: '#fff', fontSize: '12px' }}
                    itemStyle={{ color: '#fff' }}
                  />
                  <Legend 
                    wrapperStyle={{ fontSize: '12px', color: '#a1a1aa' }} 
                    formatter={(value, entry: any) => `${value} (${entry.payload?.value})`}
                  />
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
