import { useEffect, useState, useRef } from "react";
import type { BeemonEvent, WSMessage } from "../lib/types";
import { Badge } from "./ui/badge";
import { Card } from "./ui/card";
import { ScrollArea } from "./ui/scroll-area";
import { Activity } from "lucide-react";

export function ProcessStream({ pid }: { pid: number }) {
  const [events, setEvents] = useState<BeemonEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [lastPing, setLastPing] = useState<number | null>(null);
  const [limits, setLimits] = useState({ memory: "N/A", cpu: "N/A" });
  
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setEvents([]);
    setIsConnected(false);
    setLastPing(null);

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
      const scrollContainer = scrollRef.current.querySelector('[data-radix-scroll-area-viewport]');
      if (scrollContainer) {
        scrollContainer.scrollTop = scrollContainer.scrollHeight;
      }
    }
  }, [events]);

  const formatBytes = (bytesStr: string) => {
    if (bytesStr === "0" || bytesStr === "max") return "Max";
    const bytes = parseInt(bytesStr);
    if (!bytes) return "N/A";
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  };

  const renderEventDetails = (ev: BeemonEvent) => {
    if (ev.fileOpen) return <span className="text-blue-400">OPEN: {ev.fileOpen.filename}</span>;
    if (ev.fileRead) return <span className="text-gray-400">READ: fd {ev.fileRead.fd} ({ev.fileRead.count} bytes)</span>;
    if (ev.fileWrite) return <span className="text-green-400">WRITE: fd {ev.fileWrite.fd} ({ev.fileWrite.count} bytes)</span>;
    if (ev.fileClose) return <span className="text-gray-500">CLOSE: fd {ev.fileClose.fd}</span>;
    if (ev.networkConnect) return <span className="text-purple-400">CONNECT: port {ev.networkConnect.dport}</span>;
    if (ev.process) {
      if (ev.process.isExec) return <span className="text-yellow-400">EXEC: {ev.process.filename}</span>;
      if (ev.process.isExit) return <span className="text-red-400">EXIT: {ev.process.exitCode}</span>;
      if (ev.process.isFork) return <span className="text-yellow-400">FORK: child {ev.process.childPid}</span>;
    }
    if (ev.limitChanged) return <span className="text-orange-400">CGROUP LIMITS CHANGED</span>;
    return <span className="text-gray-600">SYSCALL: {ev.syscall?.syscallId}</span>;
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

  return (
    <div className="flex flex-col h-full gap-4">
      <div className="flex items-center justify-between">
        <div className="flex gap-4 items-center">
          <Badge variant={isConnected ? "default" : "destructive"}>
            {isConnected ? "LIVE" : "DISCONNECTED"}
          </Badge>
          
          <div className="flex items-center gap-2 text-xs font-mono bg-zinc-900 px-3 py-1.5 rounded-full border border-zinc-800">
            <Activity size={14} className={isConnected && lastPing && (Date.now() - lastPing < 5000) ? "text-green-500 animate-pulse" : "text-zinc-500"} />
            <span className="text-zinc-400">{getPingStatus()}</span>
          </div>

          <span className="text-sm text-zinc-500 ml-2">Monitoring PID {pid}</span>
        </div>
        <div className="flex gap-4 text-xs font-mono text-zinc-400">
          <span>MEM LIMIT: <span className="text-white">{limits.memory}</span></span>
          <span>CPU LIMIT: <span className="text-white">{limits.cpu}</span></span>
        </div>
      </div>
      
      <Card className="flex-1 bg-black overflow-hidden border-zinc-800 shadow-xl">
        <ScrollArea className="h-[400px] w-full p-4 font-mono text-xs" ref={scrollRef}>
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
        </ScrollArea>
      </Card>
    </div>
  );
}
