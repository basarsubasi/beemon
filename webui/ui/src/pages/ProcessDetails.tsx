import { useParams, Link } from "react-router-dom";
import { ProcessStream } from "../components/ProcessStream";
import { ArrowLeft } from "lucide-react";

export function ProcessDetails() {
  const { pid } = useParams();

  if (!pid) return <div>No PID provided</div>;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div className="flex items-center gap-4 mb-6">
        <Link 
          to="/" 
          className="text-zinc-400 hover:text-white transition-colors flex items-center justify-center p-2 rounded-full hover:bg-zinc-800"
        >
          <ArrowLeft size={20} />
        </Link>
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white">Live Process Tracing</h1>
          <p className="text-zinc-400">Monitoring real-time events for PID {pid}</p>
        </div>
      </div>
      
      <div className="h-[600px] border border-zinc-800 rounded-lg p-6 bg-zinc-950">
        <ProcessStream pid={parseInt(pid)} />
      </div>
    </div>
  );
}
