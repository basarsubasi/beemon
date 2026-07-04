import { useEffect, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { ProcessStream } from "../components/ProcessStream";
import { ArrowLeft, Users, Shield } from "lucide-react";
import type { Process, ListProcessesResponse } from "../lib/types";
import { Card } from "../components/ui/card";
import { Badge } from "../components/ui/badge";

export function ProcessDetails() {
  const { pid } = useParams();
  const navigate = useNavigate();
  
  const [process, setProcess] = useState<Process | null>(null);
  const [children, setChildren] = useState<Process[]>([]);

  useEffect(() => {
    if (!pid) return;
    
    const fetchProcesses = async () => {
      try {
        const res = await fetch(`/api/v1/processes`);
        const data = (await res.json()) as ListProcessesResponse;
        if (!data.processes) return;
        
        const target = data.processes.find(p => p.pid.toString() === pid);
        if (target) {
          setProcess(target);
          setChildren(data.processes.filter(p => p.ppid === target.pid));
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
          className="text-zinc-400 hover:text-white transition-colors flex items-center justify-center p-2 rounded-full hover:bg-zinc-800"
        >
          <ArrowLeft size={20} />
        </Link>
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            {process ? process.name : "Loading..."} 
            <Badge variant="outline" className="border-zinc-700 font-mono text-zinc-300">PID {pid}</Badge>
          </h1>
          <p className="text-zinc-400 mt-1">Live Process Tracing & Resource Monitoring</p>
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="col-span-2 bg-zinc-950 border-zinc-800 p-6 rounded-xl shadow-xl flex flex-col">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
            <Shield size={18} className="text-blue-400"/> Namespaces
          </h2>
          <div className="flex flex-wrap gap-2">
            {process?.namespaces && process.namespaces.length > 0 ? (
              process.namespaces.map(ns => (
                <Badge key={ns} variant="secondary" className="bg-zinc-900 text-zinc-300 hover:bg-zinc-800 border border-zinc-800 py-1.5 px-3">
                  {ns}
                </Badge>
              ))
            ) : (
              <span className="text-zinc-500 italic text-sm">No namespaces detected</span>
            )}
          </div>
        </Card>
        
        <Card className="bg-zinc-950 border-zinc-800 p-6 rounded-xl shadow-xl flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Users size={18} className="text-orange-400"/> Child Processes
            </h2>
            <div className="text-right">
              <span className="text-2xl font-bold text-white">{children.length}</span>
              <span className="text-zinc-500 text-xs ml-1">/ {process?.pidsLimit !== "0" ? process?.pidsLimit : "Max"}</span>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-2 max-h-[120px]">
            {children.length > 0 ? (
              children.map(child => (
                <div 
                  key={child.pid} 
                  className="flex justify-between items-center text-sm p-2 bg-zinc-900 rounded border border-zinc-800 cursor-pointer hover:bg-zinc-800 transition-colors"
                  onClick={() => navigate(`/process/${child.pid}`)}
                >
                  <span className="font-mono text-zinc-400">{child.pid}</span>
                  <span className="text-zinc-200 truncate ml-2">{child.name}</span>
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
