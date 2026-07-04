import { useEffect, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { ProcessStream } from "../components/ProcessStream";
import { ArrowLeft, Users, Box, Terminal } from "lucide-react";
import { ThemeToggle } from "../components/ThemeToggle";
import type { Process, ListProcessesResponse } from "../lib/types";
import { Card } from "../components/ui/card";
import { Badge } from "../components/ui/badge";

export function ProcessDetails() {
  const { pid } = useParams();
  const navigate = useNavigate();
  
  const [process, setProcess] = useState<Process | null>(null);
  const [children, setChildren] = useState<Process[]>([]);
  const [parentProcess, setParentProcess] = useState<Process | null>(null);
  const [hostNamespaces, setHostNamespaces] = useState<string[]>([]);

  useEffect(() => {
    if (!pid) return;
    
    const fetchProcesses = async () => {
      try {
        const res = await fetch(`/api/v1/processes`);
        const data = (await res.json()) as ListProcessesResponse;
        if (!data.processes) return;
        
        setHostNamespaces(data.hostNamespaces || []);
        const target = data.processes.find(p => p.pid.toString() === pid);
        if (target) {
          setProcess(target);
          setChildren(data.processes.filter(p => p.ppid === target.pid));
          setParentProcess(data.processes.find(p => p.pid === target.ppid) || null);
        }
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
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div className="flex items-center gap-4 mb-2">
        <Link 
          to="/" 
          className="text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white transition-colors flex items-center justify-center p-2 rounded-full hover:bg-zinc-200 dark:hover:bg-zinc-800"
        >
          <ArrowLeft size={20} />
        </Link>
        <div className="flex-1 flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-zinc-900 dark:text-white flex items-center gap-3">
              {process ? process.name : "Loading..."} 
              <Badge variant="outline" className="border-zinc-300 dark:border-zinc-700 font-mono text-zinc-600 dark:text-zinc-300">PID {pid}</Badge>
            </h1>
            <p className="text-zinc-500 dark:text-zinc-400 mt-1">Live Process Tracing & Resource Monitoring</p>
          </div>
          <ThemeToggle />
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

      <div className="h-[700px]">
        <ProcessStream pid={parseInt(pid)} process={process || undefined} />
      </div>
    </div>
  );
}
