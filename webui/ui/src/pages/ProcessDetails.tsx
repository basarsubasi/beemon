import { useEffect, useState, useMemo, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ProcessStream } from "../components/ProcessStream";
import { ArrowLeft, Users, Box, Terminal, FileText, Maximize2, X, PanelLeftOpen, ArrowUp, ArrowDown, ArrowUpDown } from "lucide-react";
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
  const [isOpenFilesExpanded, setIsOpenFilesExpanded] = useState(false);
  const [isOpenFilesWide, setIsOpenFilesWide] = useState(false);
  const [openFilesSortConfig, setOpenFilesSortConfig] = useState<{key: 'fd' | 'type' | 'path', direction: 'asc' | 'desc'} | null>({key: 'fd', direction: 'asc'});
  const infoBarRef = useRef<HTMLDivElement>(null);

  const sortedOpenFiles = useMemo(() => {
    if (!process?.openFiles) return [];
    let sortableItems = [...process.openFiles];
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
  }, [process?.openFiles, openFilesSortConfig]);

  const requestSort = (key: 'fd' | 'type' | 'path') => {
    let direction: 'asc' | 'desc' = 'asc';
    if (openFilesSortConfig && openFilesSortConfig.key === key && openFilesSortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setOpenFilesSortConfig({ key, direction });
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
    
    const fetchProcesses = async () => {
      try {
        const res = await fetch(`/api/v1/processes/${pid}/metadata`);
        const data = (await res.json()) as GetProcessMetadataResponse;
        if (!data.process) return;
        
        setHostNamespaces(data.hostNamespaces || []);
        setProcess(data.process);
        setChildren(data.children || []);
        setParentProcess(data.parent || null);
      } catch (err) {
        console.error("Failed to fetch process:", err);
      }
    };
    
    fetchProcesses();
    const interval = setInterval(fetchProcesses, 2000);
    return () => clearInterval(interval);
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
            {process?.namespaces?.map(ns => {
                const inodeMatch = ns.match(/\[(\d+)\]/);
                const type = ns.split(":")[0];
                const inode = inodeMatch ? inodeMatch[1] : '';
                const isHost = hostNamespaces.includes(ns);
                
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
        {/* Open Files - overlays on top of the event stream when expanded */}
        <div className="absolute left-0 top-0 bottom-0 z-20 flex items-start" style={{ paddingBottom: '24px' }}>
          {!isOpenFilesExpanded ? (
            <Button 
              variant="outline" 
              className="h-[500px] px-2 py-4 flex flex-col items-center justify-start gap-4 border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 hover:bg-zinc-100 dark:hover:bg-zinc-900 shadow-sm transition-colors"
              onClick={() => setIsOpenFilesExpanded(true)}
              title="Show Open Files"
            >
              <PanelLeftOpen size={18} className="text-zinc-500" />
              <div className="flex items-center gap-2 text-zinc-500 font-medium tracking-widest mt-4" style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)' }}>
                <FileText size={14} className="transform rotate-90" /> OPEN FILES <Badge variant="secondary" className="px-1 text-[10px] transform rotate-90">{process?.openFiles?.length || 0}</Badge>
              </div>
            </Button>
          ) : (
            <Card className={`${isOpenFilesWide ? 'w-[90vw] max-w-5xl' : 'w-[450px]'} h-[500px] flex-shrink-0 bg-white dark:bg-zinc-950/50 border-zinc-200 dark:border-zinc-800 shadow-sm dark:shadow-xl flex flex-col overflow-hidden transition-all duration-300`}>
              <div className="p-3 border-b border-zinc-200 dark:border-zinc-800 flex justify-between items-center bg-zinc-50/50 dark:bg-zinc-900/50">
                <h2 className="font-semibold text-sm text-zinc-900 dark:text-white flex items-center gap-2">
                  <FileText size={16} className="text-blue-500" /> Open Files
                  <Badge variant="secondary" className="ml-1 px-1.5 py-0.5 text-[10px]">{process?.openFiles?.length || 0}</Badge>
                </h2>
                <div className="flex items-center gap-1">
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-zinc-500 hover:text-zinc-900 dark:hover:text-white" onClick={() => setIsOpenFilesWide(!isOpenFilesWide)} title={isOpenFilesWide ? "Collapse Width" : "Expand Table Width"}>
                    {isOpenFilesWide ? <X size={14} /> : <Maximize2 size={14} />}
                  </Button>
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-zinc-500 hover:text-zinc-900 dark:hover:text-white" onClick={() => { setIsOpenFilesExpanded(false); setIsOpenFilesWide(false); }} title="Close Panel">
                    <PanelLeftOpen size={14} className="transform rotate-180" />
                  </Button>
                </div>
              </div>
              <div className="flex-1 overflow-auto custom-scrollbar">
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
                          <TableCell className={`font-mono text-[11px] text-zinc-600 dark:text-zinc-300 py-2 px-4 truncate ${isOpenFilesWide ? 'max-w-[800px]' : 'max-w-[200px]'}`} title={getDisplayPath(f.fd, f.path)}>
                            {getDisplayPath(f.fd, f.path)}
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
              </div>
            </Card>
          )}
        </div>

        {/* Event Stream - always takes full width, with left padding for the button */}
        <div className={`${isOpenFilesExpanded && !isOpenFilesWide ? 'pl-[470px]' : 'pl-[52px]'} transition-all duration-300`}>
          <ProcessStream pid={parseInt(pid)} process={process || undefined} infoBarRef={infoBarRef} />
        </div>
      </div>
    </div>
  );
}
