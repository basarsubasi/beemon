import { useEffect, useState, useRef } from "react";
import type { BeemonEvent } from "../lib/types";
import { Badge } from "./ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { ScrollArea } from "./ui/scroll-area";

export function ProcessStream({ pid }: { pid: number }) {
  const [events, setEvents] = useState<BeemonEvent[]>([]);
  const [limits, setLimits] = useState({
    memory: "N/A",
    cpu: "N/A",
    pids: "N/A"
  });
  const [isConnected, setIsConnected] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setEvents([]);
    const eventSource = new EventSource(`/api/v1/processes/${pid}/events/sse`);

    eventSource.onopen = () => setIsConnected(true);
    
    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as BeemonEvent;
        
        // Handle LimitChanged uniquely to update local state
        if (data.limitChanged) {
          setLimits({
            memory: data.limitChanged.memoryLimitBytes !== "0" ? `${(parseInt(data.limitChanged.memoryLimitBytes) / 1024 / 1024).toFixed(1)} MB` : "Max",
            cpu: data.limitChanged.cpuQuotaUs !== "0" ? `${(parseInt(data.limitChanged.cpuQuotaUs) / parseInt(data.limitChanged.cpuPeriodUs) * 100).toFixed(0)}%` : "Max",
            pids: data.limitChanged.pidsLimit !== "0" ? data.limitChanged.pidsLimit : "Max",
          });
        }

        setEvents((prev) => {
          const newEvents = [...prev, data];
          if (newEvents.length > 500) return newEvents.slice(newEvents.length - 500); // Keep last 500
          return newEvents;
        });
      } catch (err) {
        console.error("Failed to parse SSE data", err);
      }
    };

    eventSource.onerror = () => {
      setIsConnected(false);
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [pid]);

  // Auto-scroll logic
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events]);

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

  return (
    <div className="flex flex-col h-full gap-4">
      <div className="flex items-center justify-between">
        <div className="flex gap-2 items-center">
          <Badge variant={isConnected ? "default" : "destructive"}>
            {isConnected ? "LIVE" : "DISCONNECTED"}
          </Badge>
          <span className="text-sm text-muted-foreground">Monitoring PID {pid}</span>
        </div>
        <div className="flex gap-4 text-xs font-mono text-muted-foreground">
          <span>MEM LIMIT: <span className="text-foreground">{limits.memory}</span></span>
          <span>CPU LIMIT: <span className="text-foreground">{limits.cpu}</span></span>
        </div>
      </div>
      
      <Card className="flex-1 bg-black overflow-hidden border-zinc-800">
        <ScrollArea className="h-[400px] w-full p-4 font-mono text-xs" ref={scrollRef}>
          {events.map((ev, i) => (
            <div key={i} className="mb-1 opacity-90 hover:opacity-100 transition-opacity">
              <span className="text-zinc-500 mr-4">
                {new Date(parseInt(ev.timestampNs) / 1000000).toISOString().split('T')[1].slice(0, -1)}
              </span>
              {renderEventDetails(ev)}
            </div>
          ))}
          {events.length === 0 && (
            <div className="text-zinc-600 text-center mt-10 italic">
              Waiting for eBPF events...
            </div>
          )}
        </ScrollArea>
      </Card>
    </div>
  );
}
