import { useEffect, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { ArrowLeft, Box } from "lucide-react";
import type { NamespaceDetailsResponse, Process, ListProcessesResponse } from "../lib/types";
import { Card } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

export function NamespaceDetails() {
  const { type, inode } = useParams();
  const navigate = useNavigate();
  const [details, setDetails] = useState<NamespaceDetailsResponse | null>(null);
  const [processes, setProcesses] = useState<Process[]>([]);
  const [hostNamespaces, setHostNamespaces] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Fetch processes first to find a reference PID and populate the table
        const procsRes = await fetch(`/api/v1/processes`);
        const procsData = (await procsRes.json()) as ListProcessesResponse;
        
        const targetNsStr = `${type}:${type}:[${inode}]`;
        const inNs = (procsData.processes || []).filter(p => p.namespaces?.includes(targetNsStr));
        setProcesses(inNs);
        setHostNamespaces(procsData.hostNamespaces || []);

        if (inNs.length > 0) {
          const refPid = inNs[0].pid;
          const detailsRes = await fetch(`/api/v1/namespaces/${type}/${inode}?pid=${refPid}`);
          const detailsData = (await detailsRes.json()) as NamespaceDetailsResponse;
          setDetails(detailsData);
          setError(null);
        } else {
          setError("No running processes found in this namespace. Introspection is unavailable.");
          setDetails(null);
        }
      } catch (err: any) {
        setError(err.message);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, [type, inode]);

  const isHost = hostNamespaces.includes(`${type}:${type}:[${inode}]`);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6 flex flex-col h-screen">
      <div className="flex items-center gap-4">
        <Link 
          to="/" 
          className="p-2 hover:bg-zinc-800 rounded-full transition-colors text-zinc-400 hover:text-white"
        >
          <ArrowLeft size={20} />
        </Link>
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3 uppercase">
            <Box className="w-8 h-8 text-blue-400" />
            {type} Namespace
          </h1>
          <p className="text-zinc-400 font-mono text-sm mt-1">Inode: {inode}</p>
        </div>
        <div className="ml-auto">
           {isHost ? (
             <Badge variant="outline" className="border-green-800 text-green-400 bg-green-950/30 text-sm px-3 py-1">Host Scope</Badge>
           ) : (
             <Badge variant="outline" className="border-orange-800 text-orange-400 bg-orange-950/30 text-sm px-3 py-1">Isolated Scope</Badge>
           )}
        </div>
      </div>

      {error && (
        <Card className="bg-red-950/20 border-red-900/50 p-4 text-red-400">
          {error}
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 flex-1 min-h-0">
        <Card className="bg-zinc-950/50 border-zinc-800 shadow-xl flex flex-col overflow-hidden">
          <div className="p-4 bg-zinc-900/50 border-b border-zinc-800 flex justify-between items-center">
            <h2 className="text-white font-semibold">Associated Processes</h2>
            <Badge variant="secondary" className="bg-zinc-800">{processes.length} total</Badge>
          </div>
          <div className="flex-1 overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800">
                  <TableHead className="text-zinc-400">PID</TableHead>
                  <TableHead className="text-zinc-400">Name</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {processes.map(proc => (
                  <TableRow 
                    key={proc.pid} 
                    className="border-zinc-800/50 cursor-pointer hover:bg-zinc-800/80 transition-colors"
                    onClick={() => navigate(`/process/${proc.pid}`)}
                  >
                    <TableCell className="font-mono text-zinc-300">{proc.pid}</TableCell>
                    <TableCell className="text-white">{proc.name}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </Card>

        <Card className="bg-black border-zinc-800 shadow-xl flex flex-col overflow-hidden">
          <div className="p-4 bg-zinc-900/50 border-b border-zinc-800">
            <h2 className="text-white font-semibold">Namespace Properties</h2>
          </div>
          <div className="flex-1 overflow-y-auto custom-scrollbar p-4 font-mono text-xs text-zinc-300 whitespace-pre-wrap">
            {details?.mountInfo && (
              <>
                <div className="text-blue-400 font-bold mb-2">--- MOUNT TABLE ---</div>
                {details.mountInfo}
              </>
            )}
            {details?.netLinks && (
              <>
                <div className="text-blue-400 font-bold mb-2">--- NETWORK LINKS ---</div>
                {details.netLinks}
                <div className="text-blue-400 font-bold mt-4 mb-2">--- ROUTES ---</div>
                {details.netRoutes}
              </>
            )}
            {details?.utsInfo && (
              <>
                <div className="text-blue-400 font-bold mb-2">--- UTS INFO ---</div>
                {details.utsInfo}
              </>
            )}
            {details?.userMaps && (
              <>
                <div className="text-blue-400 font-bold mb-2">--- USER NAMESPACE MAPS ---</div>
                {details.userMaps}
              </>
            )}
            {!details?.mountInfo && !details?.netLinks && !details?.utsInfo && !details?.userMaps && !error && (
              <span className="text-zinc-500 italic">No specific introspection logic available for '{type}' namespaces yet.</span>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
