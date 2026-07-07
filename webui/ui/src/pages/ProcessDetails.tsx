import { useEffect, useState, useMemo, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ProcessStream } from "../components/ProcessStream";
import { ArrowLeft, Users, Box, Terminal, FileText, Maximize2, X, PanelLeftOpen, ArrowUp, ArrowDown, ArrowUpDown, Network } from "lucide-react";
import { ThemeToggle } from "../components/ThemeToggle";
import type { Process, GetProcessMetadataResponse } from "../lib/types";
import { Card } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../components/ui/table";

export function ProcessDetails() {
  const { pid } = useParams();
  const navigate = useNavigate();
  
  const [process, setProcess] = useState<Process | null>(null);
  const [children, setChildren] = useState<Process[]>([]);
  const [parentProcess, setParentProcess] = useState<Process | null>(null);
  const [hostNamespaces, setHostNamespaces] = useState<string[]>([]);
  const [sidePanelExpanded, setSidePanelExpanded] = useState(false);
  const [sidePanelWide, setSidePanelWide] = useState(false);
  const [sidePanelTab, setSidePanelTab] = useState<'files' | 'network'>('files');
  const [networkFlowStates, setNetworkFlowStates] = useState<Record<string, { flow: import("../lib/types").NetworkFlow, lastSeenTs: number }>>({});
  const [openFilesState, setOpenFilesState] = useState<Record<number, { fd: number; path: string; type: string; isClosed: boolean }>>({});

  const [networkSubTab, setNetworkSubTab] = useState<'connections' | 'dns'>('connections');
  const [openFilesSortConfig, setOpenFilesSortConfig] = useState<{key: 'fd' | 'type' | 'path', direction: 'asc' | 'desc'} | null>({key: 'fd', direction: 'asc'});
  const [networkSortConfig, setNetworkSortConfig] = useState<{key: 'rxBytes' | 'txBytes' | 'rxPackets' | 'txPackets', direction: 'asc' | 'desc'} | null>({key: 'rxBytes', direction: 'desc'});
  const infoBarRef = useRef<HTMLDivElement>(null);

  const sortedOpenFiles = useMemo(() => {
    let sortableItems = Object.values(openFilesState);
    if (openFilesSortConfig !== null) {
      sortableItems.sort((a, b) => {
        if (a[openFilesSortConfig.key] < b[openFilesSortConfig.key]) {
          return openFilesSortConfig.direction === 'asc' ? -1 : 1;
        }
        if (a[openFilesSortConfig.key] > b[openFilesSortConfig.key]) {
          return openFilesSortConfig.direction === 'asc' ? 1 : -1;
        }
        return 0;
      });
    }
    return sortableItems;
  }, [openFilesState, openFilesSortConfig]);


  const sortedNetworkFlows = useMemo(() => {
    const flows = (Object.values(networkFlowStates) as Array<{ flow: import("../lib/types").NetworkFlow, lastSeenTs: number }>)
      .filter(s => (Date.now() - s.lastSeenTs) <= 5000)
      .map(s => {
        // Annotate visually if it hasn't been seen in the last 2 seconds
        const isClosed = (Date.now() - s.lastSeenTs) > 2000;
        return { ...s.flow, isClosed };
      });
    let sortableItems = flows.filter(f => networkSubTab === 'dns' ? !!f.dnsQuery : !f.dnsQuery);
    if (networkSortConfig !== null) {
      sortableItems.sort((a, b) => {
        const valA = parseInt(a[networkSortConfig.key as keyof typeof a] as string) || 0;
        const valB = parseInt(b[networkSortConfig.key as keyof typeof b] as string) || 0;
        if (valA < valB) return networkSortConfig.direction === 'asc' ? -1 : 1;
        if (valA > valB) return networkSortConfig.direction === 'asc' ? 1 : -1;
        return 0;
      });
    }
    return sortableItems;
  }, [networkFlowStates, networkSortConfig, networkSubTab]);


  const requestSort = (key: 'fd' | 'type' | 'path') => {
    let direction: 'asc' | 'desc' = 'asc';
    if (openFilesSortConfig && openFilesSortConfig.key === key && openFilesSortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setOpenFilesSortConfig({ key, direction });
  };

  const requestNetworkSort = (key: 'rxBytes' | 'txBytes' | 'rxPackets' | 'txPackets') => {
    let direction: 'desc' | 'asc' = 'desc';
    if (networkSortConfig && networkSortConfig.key === key && networkSortConfig.direction === 'desc') {
      direction = 'asc';
    }
    setNetworkSortConfig({ key, direction });
  };

  const STDIO_NAMES: Record<number, string> = { 0: 'stdin', 1: 'stdout', 2: 'stderr' };

  const getDisplayPath = (fd: number, path: string): string => {
    if (fd in STDIO_NAMES) {
      // Strip " (deleted)" suffix for standard streams — they are not real files
      return path.replace(/ \(deleted\)$/, '');
    }
    return path;
  };

  useEffect(() => {
    if (!pid) return;
    
    const fetchMetadata = async () => {
      try {
        const metaRes = await fetch(`/api/v1/processes/${pid}/metadata`);
        const data = (await metaRes.json()) as GetProcessMetadataResponse;
        if (data.process) {
          setHostNamespaces(data.hostNamespaces || []);
          setProcess(data.process);
          setChildren(data.children || []);
          setParentProcess(data.parent || null);
          
          // Initialize openFilesState only on first fetch or missing files
          setOpenFilesState(prev => {
            const next = { ...prev };
            let changed = false;
            data.process!.openFiles?.forEach(f => {
              if (!next[f.fd]) {
                next[f.fd] = { fd: f.fd, path: f.path, type: f.type, isClosed: false };
                changed = true;
              }
            });
            return changed ? next : prev;
          });
        }
      } catch (err) {
        console.error("Failed to fetch process metadata:", err);
      }
    };

    const fetchFlows = async () => {
      try {
        const flowsRes = await fetch(`/api/v1/processes/${pid}/network_flows`);
        if (flowsRes.ok) {
          const flowsData = await flowsRes.json() as import("../lib/types").GetNetworkFlowsResponse;
          const now = Date.now();
          setNetworkFlowStates(prev => {
            const next = { ...prev };
            flowsData.flows?.forEach(f => {
              const key = `${f.localAddress}:${f.localPort}-${f.remoteAddress}:${f.remotePort}-${f.protocol}`;
              const prevFlow = prev[key];
              if (!prevFlow || prevFlow.flow.txBytes !== f.txBytes || prevFlow.flow.rxBytes !== f.rxBytes) {
                next[key] = { flow: f, lastSeenTs: now };
              } else {
                next[key] = { flow: f, lastSeenTs: prevFlow.lastSeenTs };
              }
            });
            return next;
          });
        }
      } catch (err) {
        console.error("Failed to fetch network flows:", err);
      }
    };
    
    fetchMetadata();
    fetchFlows();
    
    const metaInterval = setInterval(fetchMetadata, 5000);
    const flowsInterval = setInterval(fetchFlows, 500);
    
    // Connect to Event stream
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/api/v1/processes/${pid}/stream/ws`;
    const ws = new WebSocket(wsUrl);
    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data) as any;
            if (msg.type === "ping") return;
            const beemonEvent = msg as import("../lib/types").BeemonEvent;
            
            if (beemonEvent.fileOpen && beemonEvent.fileOpen.fd !== undefined) {
                const fd = beemonEvent.fileOpen.fd;
                setOpenFilesState(prev => ({
                    ...prev,
                    [fd]: {
                        fd: fd,
                        path: beemonEvent.fileOpen!.filename,
                        type: 'regular',
                        isClosed: false
                    }
                }));
            } else if (beemonEvent.fileClose) {
                const fd = beemonEvent.fileClose.fd;
                setOpenFilesState(prev => {
                    if (!prev[fd]) return prev;
                    return {
                        ...prev,
                        [fd]: { ...prev[fd], isClosed: true }
                    };
                });
            }
        } catch (e) {}
    };

    return () => {
        clearInterval(metaInterval);
        clearInterval(flowsInterval);
        ws.close();
    };
  }, [pid]);

  if (!pid) return <div>No PID provided</div>;

  return (
    <div className="px-4 pt-8 pb-24 max-w-5xl mx-auto space-y-6">
      <div className="flex items-center gap-4 mb-2">
        <button 
          onClick={() => navigate(-1)} 
          className="text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white transition-colors flex items-center justify-center p-2 rounded-full hover:bg-zinc-200 dark:hover:bg-zinc-800"
        >
          <ArrowLeft size={24} />
        </button>
        <div className="flex-1 flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-zinc-900 dark:text-white flex items-center gap-3">
              {process ? process.name : "Loading..."} 
              <Badge variant="outline" className="border-zinc-300 dark:border-zinc-700 font-mono text-zinc-600 dark:text-zinc-300">PID {pid}</Badge>
              <img src="/logo.png" alt="Beemon Logo" className="h-8 w-auto object-contain" />
            </h1>
            <p className="text-zinc-500 dark:text-zinc-400 mt-1">Live Process Tracing & Resource Monitoring</p>
          </div>
          <div className="flex items-center gap-4">
            <ThemeToggle />
          </div>
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card className="col-span-2 bg-white dark:bg-zinc-950/50 border-zinc-200 dark:border-zinc-800 p-6 rounded-xl shadow-sm dark:shadow-xl flex flex-col">
          <h2 className="text-lg font-semibold text-zinc-900 dark:text-white flex items-center gap-2 mb-4">
            <Box size={18} className="text-purple-500"/> Namespaces
          </h2>
          <div className="flex flex-wrap gap-2">
            {[...(process?.namespaces || [])].sort().map(ns => {
                const inodeMatch = ns.match(/\[(\d+)\]/);
                const type = ns.split(":")[0];
                const inode = inodeMatch ? inodeMatch[1] : '';
                const actualNs = ns.replace('_for_children', '');
                const isHost = hostNamespaces.includes(ns) || hostNamespaces.includes(actualNs);
                
                return (
                  <Badge 
                    key={ns} 
                    variant="outline" 
                    className="border-zinc-300 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 font-mono text-zinc-600 dark:text-zinc-400 cursor-pointer hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
                    onClick={() => navigate(`/namespace/${type}/${inode}`)}
                  >
                    {ns} {isHost && <span className="ml-1 text-green-600 dark:text-green-500 text-[10px]">(Host)</span>}
                  </Badge>
                );
              }) || <span className="text-zinc-600 italic text-sm">No namespaces detected</span>}
          </div>
        </Card>

        <Card className="bg-white dark:bg-zinc-950/50 border-zinc-200 dark:border-zinc-800 p-6 rounded-xl shadow-sm dark:shadow-xl flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-zinc-900 dark:text-white flex items-center gap-2">
              <Terminal size={18} className="text-blue-500"/> Parent Process
            </h2>
          </div>
          <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-2 max-h-[120px]">
            {parentProcess ? (
              <div 
                className="flex justify-between items-center text-sm p-2 bg-zinc-50 dark:bg-zinc-900/50 rounded border border-zinc-200 dark:border-zinc-800 cursor-pointer hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
                onClick={() => navigate(`/process/${parentProcess.pid}`)}
              >
                <span className="font-mono text-zinc-500 dark:text-zinc-400">{parentProcess.pid}</span>
                <span className="text-zinc-700 dark:text-zinc-200 truncate ml-2">{parentProcess.name}</span>
              </div>
            ) : process?.ppid ? (
              <div className="text-zinc-500 italic text-sm text-center py-4">
                Parent (PID {process.ppid}) not found
              </div>
            ) : (
              <div className="text-zinc-500 italic text-sm text-center py-4">No parent process</div>
            )}
          </div>
        </Card>
        
        <Card className="bg-white dark:bg-zinc-950/50 border-zinc-200 dark:border-zinc-800 p-6 rounded-xl shadow-sm dark:shadow-xl flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-zinc-900 dark:text-white flex items-center gap-2">
              <Users size={18} className="text-orange-500"/> Child Processes
            </h2>
            <div className="text-right">
              <span className="text-2xl font-bold text-zinc-900 dark:text-white">{children.length}</span>
              <span className="text-zinc-500 dark:text-zinc-500 text-xs ml-1">/ {process?.pidsLimit !== "0" ? process?.pidsLimit : "Max"}</span>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-2 max-h-[120px]">
            {children.length > 0 ? (
              children.map(child => (
                <div 
                  key={child.pid} 
                  className="flex justify-between items-center text-sm p-2 bg-zinc-50 dark:bg-zinc-900/50 rounded border border-zinc-200 dark:border-zinc-800 cursor-pointer hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
                  onClick={() => navigate(`/process/${child.pid}`)}
                >
                  <span className="font-mono text-zinc-500 dark:text-zinc-400">{child.pid}</span>
                  <span className="text-zinc-700 dark:text-zinc-200 truncate ml-2">{child.name}</span>
                </div>
              ))
            ) : (
              <div className="text-zinc-500 italic text-sm text-center py-4">No child processes</div>
            )}
          </div>
        </Card>
      </div>

      {/* Infobar - decoupled into its own full-width row */}
      <div ref={infoBarRef} className="w-full" />

      <div className="relative transition-all duration-300">
        {/* Side Panel - overlays on top of the event stream when expanded */}
        <div className="absolute left-0 top-0 bottom-0 z-20 flex items-start" style={{ paddingBottom: '24px' }}>
          {!sidePanelExpanded ? (
            <Button 
              variant="outline" 
              className="h-[500px] px-2 py-4 flex flex-col items-center justify-start gap-4 border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 hover:bg-zinc-100 dark:hover:bg-zinc-900 shadow-sm transition-colors"
              onClick={() => { setSidePanelExpanded(true); }}
              title="Show Process Resources"
            >
              <PanelLeftOpen size={18} className="text-zinc-500" />
              <div className="flex items-center gap-3 text-zinc-500 font-medium tracking-widest mt-4" style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)' }}>
                PROCESS I/O
                <div className="flex items-center gap-1 mt-2">
                  <Badge variant="secondary" className="px-1 text-[10px] transform rotate-90 flex gap-1 items-center bg-green-100/50 text-green-700 dark:bg-green-900/30 dark:text-green-400">{Object.keys(networkFlowStates).length}</Badge>
                  <Badge variant="secondary" className="px-1 text-[10px] transform rotate-90 flex gap-1 items-center bg-blue-100/50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">{Object.keys(openFilesState).length}</Badge>
                </div>
              </div>
            </Button>
          ) : (
            <Card className={`${sidePanelWide ? 'w-[90vw] max-w-5xl' : 'w-[450px]'} h-[500px] flex-shrink-0 bg-white dark:bg-zinc-950/50 border-zinc-200 dark:border-zinc-800 shadow-sm dark:shadow-xl flex flex-col overflow-hidden transition-all duration-300`}>
              <div className="p-3 border-b border-zinc-200 dark:border-zinc-800 flex justify-between items-center bg-zinc-50/50 dark:bg-zinc-900/50">
                <div className="flex gap-4 items-center">
                  <h2 
                    className={`font-semibold text-sm flex items-center gap-2 cursor-pointer ${sidePanelTab === 'files' ? 'text-zinc-900 dark:text-white' : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'}`}
                    onClick={() => setSidePanelTab('files')}
                  >
                    <FileText size={16} className={sidePanelTab === 'files' ? "text-blue-500" : ""} /> Files
                    <Badge variant="secondary" className="ml-1 px-1.5 py-0.5 text-[10px]">{Object.keys(openFilesState).length}</Badge>
                  </h2>
                  <h2 
                    className={`font-semibold text-sm flex items-center gap-2 cursor-pointer ${sidePanelTab === 'network' ? 'text-zinc-900 dark:text-white' : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'}`}
                    onClick={() => setSidePanelTab('network')}
                  >
                    <Network size={16} className={sidePanelTab === 'network' ? "text-green-500" : ""} /> Network
                    <Badge variant="secondary" className="ml-1 px-1.5 py-0.5 text-[10px]">{Object.keys(networkFlowStates).length}</Badge>
                  </h2>
                </div>
                <div className="flex items-center gap-1">
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-zinc-500 hover:text-zinc-900 dark:hover:text-white" onClick={() => setSidePanelWide(!sidePanelWide)} title={sidePanelWide ? "Collapse Width" : "Expand Table Width"}>
                    {sidePanelWide ? <X size={14} /> : <Maximize2 size={14} />}
                  </Button>
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-zinc-500 hover:text-zinc-900 dark:hover:text-white" onClick={() => { setSidePanelExpanded(false); setSidePanelWide(false); }} title="Close Panel">
                    <PanelLeftOpen size={14} className="transform rotate-180" />
                  </Button>
                </div>
              </div>
              <div className="flex-1 overflow-auto custom-scrollbar">
                {sidePanelTab === 'files' ? (
                  <Table>
                    <TableHeader className="sticky top-0 bg-white dark:bg-zinc-950/90 backdrop-blur z-10">
                      <TableRow className="border-zinc-200 dark:border-zinc-800 hover:bg-transparent">
                        <TableHead className="w-[80px] text-xs h-8 py-1 cursor-pointer select-none hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors" onClick={() => requestSort('fd')}>
                          <div className="flex items-center gap-1">FD {openFilesSortConfig?.key === 'fd' ? (openFilesSortConfig.direction === 'asc' ? <ArrowUp size={12}/> : <ArrowDown size={12}/>) : <ArrowUpDown size={12} className="text-zinc-300 dark:text-zinc-700"/>}</div>
                        </TableHead>
                        <TableHead className="w-[100px] text-xs h-8 py-1 cursor-pointer select-none hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors" onClick={() => requestSort('type')}>
                          <div className="flex items-center gap-1">Type {openFilesSortConfig?.key === 'type' ? (openFilesSortConfig.direction === 'asc' ? <ArrowUp size={12}/> : <ArrowDown size={12}/>) : <ArrowUpDown size={12} className="text-zinc-300 dark:text-zinc-700"/>}</div>
                        </TableHead>
                        <TableHead className="text-xs h-8 py-1 cursor-pointer select-none hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors" onClick={() => requestSort('path')}>
                          <div className="flex items-center gap-1">Path {openFilesSortConfig?.key === 'path' ? (openFilesSortConfig.direction === 'asc' ? <ArrowUp size={12}/> : <ArrowDown size={12}/>) : <ArrowUpDown size={12} className="text-zinc-300 dark:text-zinc-700"/>}</div>
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {sortedOpenFiles.length ? (
                        sortedOpenFiles.map(f => (
                          <TableRow key={f.fd} className="border-zinc-200 dark:border-zinc-800/50 border-b last:border-0 hover:bg-zinc-100 dark:hover:bg-zinc-800 cursor-default transition-colors">
                            <TableCell className="font-mono text-xs py-2 px-4">
                              {f.fd}
                              {f.fd in STDIO_NAMES && (
                                <span className="ml-1.5 text-[9px] text-zinc-400 dark:text-zinc-500 font-sans">{STDIO_NAMES[f.fd]}</span>
                              )}
                            </TableCell>
                            <TableCell className="py-2 px-4">
                              <Badge variant="outline" className="text-[9px] px-1 py-0 border-zinc-300 dark:border-zinc-700 whitespace-nowrap">
                                {f.type}
                              </Badge>
                            </TableCell>
                            <TableCell className={`font-mono text-[11px] text-zinc-600 dark:text-zinc-300 py-2 px-4 truncate ${sidePanelWide ? 'max-w-[800px]' : 'max-w-[200px]'}`} title={getDisplayPath(f.fd, f.path)}>
                              <div className="flex items-center gap-2">
                                <span className={`truncate block max-w-xs md:max-w-md ${f.isClosed ? 'text-zinc-400 line-through' : ''}`} title={getDisplayPath(f.fd, f.path)}>
                                  {getDisplayPath(f.fd, f.path)}
                                </span>
                                {f.isClosed && (
                                  <Badge variant="outline" className="text-[10px] py-0 px-1 border-zinc-200 dark:border-zinc-800 text-zinc-500">closed</Badge>
                                )}
                              </div>
                            </TableCell>
                          </TableRow>
                        ))
                      ) : (
                        <TableRow className="hover:bg-transparent">
                          <TableCell colSpan={3} className="text-center py-8 text-sm text-zinc-500 italic">
                            No open files
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                ) : (
                  <div className="flex flex-col h-full">
                    <div className="flex gap-2 p-2 border-b border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/90 sticky top-0 z-20">
                      <Button 
                        variant={networkSubTab === 'connections' ? 'default' : 'ghost'} 
                        size="sm" 
                        onClick={() => setNetworkSubTab('connections')}
                        className="text-xs h-7"
                      >
                        Connections
                      </Button>
                      <Button 
                        variant={networkSubTab === 'dns' ? 'default' : 'ghost'} 
                        size="sm" 
                        onClick={() => setNetworkSubTab('dns')}
                        className="text-xs h-7"
                      >
                        DNS Queries
                      </Button>
                    </div>
                    <div className="flex-1 overflow-auto">
                      <Table>
                        <TableHeader className="sticky top-0 bg-white dark:bg-zinc-950/90 backdrop-blur z-10">
                      <TableRow className="border-zinc-200 dark:border-zinc-800 hover:bg-transparent">
                        <TableHead className="w-[50px] text-xs h-8 py-1 select-none">Proto</TableHead>
                        <TableHead className="text-xs h-8 py-1 select-none">Local</TableHead>
                        <TableHead className="text-xs h-8 py-1 select-none">Remote</TableHead>
                        <TableHead className="w-[80px] text-xs h-8 py-1 cursor-pointer select-none hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors" onClick={() => requestNetworkSort('rxBytes')}>
                          <div className="flex items-center gap-1 justify-end">Rx {networkSortConfig?.key === 'rxBytes' ? (networkSortConfig.direction === 'asc' ? <ArrowUp size={12}/> : <ArrowDown size={12}/>) : <ArrowUpDown size={12} className="text-zinc-300 dark:text-zinc-700"/>}</div>
                        </TableHead>
                        <TableHead className="w-[80px] text-xs h-8 py-1 cursor-pointer select-none hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors" onClick={() => requestNetworkSort('txBytes')}>
                          <div className="flex items-center gap-1 justify-end">Tx {networkSortConfig?.key === 'txBytes' ? (networkSortConfig.direction === 'asc' ? <ArrowUp size={12}/> : <ArrowDown size={12}/>) : <ArrowUpDown size={12} className="text-zinc-300 dark:text-zinc-700"/>}</div>
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                        <TableBody>
                          {sortedNetworkFlows.length ? (
                            sortedNetworkFlows.map((f, i) => (
                              <TableRow key={i} className="border-zinc-200 dark:border-zinc-800/50 border-b last:border-0 hover:bg-zinc-100 dark:hover:bg-zinc-800 cursor-default transition-colors">
                                <TableCell className="py-2 px-4">
                                  <Badge variant="outline" className="text-[9px] px-1 py-0 border-zinc-300 dark:border-zinc-700">
                                    {f.protocol}
                                  </Badge>
                                </TableCell>
                                <TableCell className={`font-mono text-[11px] text-zinc-600 dark:text-zinc-300 py-2 px-4 truncate ${sidePanelWide ? 'max-w-[300px]' : 'max-w-[100px]'}`} title={`${f.localAddress}:${f.localPort}`}>{f.localAddress}:{f.localPort}</TableCell>
                                <TableCell className={`font-mono text-[11px] text-zinc-600 dark:text-zinc-300 py-2 px-4 truncate ${sidePanelWide ? 'max-w-[300px]' : 'max-w-[100px]'}`} title={`${f.remoteAddress}:${f.remotePort}`}>
                                  {networkSubTab === 'dns' ? <span className="text-yellow-600 dark:text-yellow-500 font-bold">{f.dnsQuery}</span> : `${f.remoteAddress}:${f.remotePort}`}
                                </TableCell>
                                <TableCell className="py-2 px-4 font-mono text-[10px] text-green-500 text-right">{f.rxBytes !== "0" ? `${(parseInt(f.rxBytes)/1024).toFixed(1)}K` : "-"}</TableCell>
                                <TableCell className="py-2 px-4 font-mono text-[10px] text-purple-500 text-right">{f.txBytes !== "0" ? `${(parseInt(f.txBytes)/1024).toFixed(1)}K` : "-"}</TableCell>
                              </TableRow>
                            ))
                          ) : (
                            <TableRow className="hover:bg-transparent">
                              <TableCell colSpan={5} className="text-center py-8 text-sm text-zinc-500 italic">
                                {networkSubTab === 'dns' ? "No DNS queries found" : "No active network flows"}
                              </TableCell>
                            </TableRow>
                          )}
                        </TableBody>
                      </Table>
                    </div>
                  </div>
                )}
              </div>
            </Card>
          )}
        </div>

        {/* Event Stream - always takes full width, with left padding for the button */}
        <div className={`${sidePanelExpanded && !sidePanelWide ? 'pl-[470px]' : 'pl-[52px]'} transition-all duration-300`}>
          <ProcessStream pid={parseInt(pid)} process={process || undefined} infoBarRef={infoBarRef} />
        </div>
      </div>
    </div>
  );
}
