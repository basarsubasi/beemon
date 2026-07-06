import { useEffect, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { ArrowLeft, Box, Layers, Maximize2, Minimize2 } from "lucide-react";
import { ThemeToggle } from "../components/ThemeToggle";
import type { NamespaceDetailsResponse, Process, ListProcessesResponse } from "../lib/types";
import { Card } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

function renderMountInfo(mountInfo?: string) {
  if (!mountInfo) return null;
  if (mountInfo.startsWith("Error")) {
    return <div className="text-red-500">{mountInfo}</div>;
  }
  
  const lines = mountInfo.trim().split('\n');
  if (lines.length === 0 || !lines[0]) return null;

  return (
    <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 mt-2 mb-6 overflow-hidden">
      <Table>
        <TableHeader className="bg-zinc-50 dark:bg-zinc-900/80">
          <TableRow className="border-zinc-200 dark:border-zinc-800 hover:bg-transparent">
            <TableHead className="text-zinc-500 dark:text-zinc-400">Target</TableHead>
            <TableHead className="text-zinc-500 dark:text-zinc-400">Type</TableHead>
            <TableHead className="text-zinc-500 dark:text-zinc-400">Source</TableHead>
            <TableHead className="text-zinc-500 dark:text-zinc-400">Options</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {lines.map((line, i) => {
            const parts = line.split(' ');
            if (parts.length < 7) return null;
            const target = parts[4];
            const options = parts[5];
            
            const sepIdx = parts.indexOf('-');
            if (sepIdx === -1 || sepIdx + 2 >= parts.length) return null;
            
            const fstype = parts[sepIdx + 1];
            const source = parts[sepIdx + 2];
            
            return (
              <TableRow key={i} className="border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800/50">
                <TableCell className="font-mono text-zinc-900 dark:text-zinc-100 max-w-[250px] truncate" title={target}>{target}</TableCell>
                <TableCell>
                  <Badge variant="outline" className="border-zinc-300 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800/50 text-zinc-700 dark:text-zinc-300 whitespace-nowrap">
                    {fstype}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-zinc-600 dark:text-zinc-400 max-w-[200px] truncate" title={source}>{source}</TableCell>
                <TableCell className="font-mono text-xs text-zinc-500 dark:text-zinc-500 max-w-[300px] truncate" title={options}>{options}</TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

function renderUtsInfo(utsInfo?: string) {
  if (!utsInfo) return null;
  if (utsInfo.startsWith("Error")) return <div className="text-red-500">{utsInfo}</div>;
  const lines = utsInfo.trim().split('\n');
  const hostname = lines[0]?.replace('Hostname: ', '') || 'N/A';
  const domainname = lines[1]?.replace('Domainname: ', '') || 'N/A';
  return (
    <div className="grid grid-cols-2 gap-4 bg-white dark:bg-zinc-950/50 p-4 rounded-xl border border-zinc-200 dark:border-zinc-800 mt-2 mb-6">
      <div>
        <div className="text-zinc-500 text-[10px] uppercase font-bold tracking-wider mb-1">Hostname</div>
        <div className="text-lg font-mono text-zinc-900 dark:text-white">{hostname}</div>
      </div>
      <div>
        <div className="text-zinc-500 text-[10px] uppercase font-bold tracking-wider mb-1">Domainname</div>
        <div className="text-lg font-mono text-zinc-900 dark:text-white">{domainname === '(none)' ? 'None' : domainname}</div>
      </div>
    </div>
  );
}

function renderUserMaps(userMaps?: string) {
  if (!userMaps) return null;
  if (userMaps.startsWith("Error")) return <div className="text-red-500">{userMaps}</div>;
  const parts = userMaps.split('GID Map:');
  const uidPart = parts[0].replace('UID Map:', '').trim();
  const gidPart = parts[1]?.trim() || '';

  const renderMapTable = (mapData: string, title: string) => {
    const lines = mapData.split('\n').filter(l => l.trim() && !l.includes('ID-in-NS'));
    if (lines.length === 0) return null;
    return (
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-zinc-700 dark:text-zinc-300 mb-2">{title}</h3>
        <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 overflow-hidden">
          <Table>
            <TableHeader className="bg-zinc-50 dark:bg-zinc-900/80">
              <TableRow className="border-zinc-200 dark:border-zinc-800 hover:bg-transparent">
                <TableHead className="text-zinc-500 dark:text-zinc-400">ID in Namespace</TableHead>
                <TableHead className="text-zinc-500 dark:text-zinc-400">ID in Host</TableHead>
                <TableHead className="text-zinc-500 dark:text-zinc-400">Range Length</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {lines.map((line, i) => {
                const tokens = line.trim().split(/\s+/);
                if (tokens.length < 3) return null;
                return (
                  <TableRow key={i} className="border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800/50">
                    <TableCell className="font-mono text-zinc-900 dark:text-zinc-100">{tokens[0]}</TableCell>
                    <TableCell className="font-mono text-zinc-600 dark:text-zinc-400">{tokens[1]}</TableCell>
                    <TableCell className="font-mono text-zinc-600 dark:text-zinc-400">{tokens[2]}</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      </div>
    );
  };

  return (
    <div className="mt-2 mb-6">
      {renderMapTable(uidPart, "UID Map")}
      {renderMapTable(gidPart, "GID Map")}
    </div>
  );
}

function renderNetRoutes(netRoutes?: string) {
  if (!netRoutes) return null;
  if (netRoutes.startsWith("Error")) return <div className="text-red-500">{netRoutes}</div>;
  const lines = netRoutes.trim().split('\n').filter(l => l.trim());
  if (lines.length === 0) return <div className="text-zinc-500 italic mt-2 mb-6">No routes found</div>;

  return (
    <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 mt-2 mb-6 overflow-hidden">
      <Table>
        <TableHeader className="bg-zinc-50 dark:bg-zinc-900/80">
          <TableRow className="border-zinc-200 dark:border-zinc-800 hover:bg-transparent">
            <TableHead className="text-zinc-500 dark:text-zinc-400">Destination</TableHead>
            <TableHead className="text-zinc-500 dark:text-zinc-400">Device</TableHead>
            <TableHead className="text-zinc-500 dark:text-zinc-400">Details</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {lines.map((line, i) => {
            const tokens = line.trim().split(/\s+/);
            const dest = tokens[0];
            const devIdx = tokens.indexOf('dev');
            const dev = devIdx !== -1 ? tokens[devIdx + 1] : 'N/A';
            const details = tokens.slice(1).filter((_, idx) => idx !== devIdx - 1 && idx !== devIdx).join(' ');
            
            return (
              <TableRow key={i} className="border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800/50">
                <TableCell className="font-mono font-medium text-zinc-900 dark:text-zinc-100">{dest}</TableCell>
                <TableCell>
                  {dev !== 'N/A' ? (
                    <Badge variant="outline" className="border-zinc-300 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800/50 text-zinc-700 dark:text-zinc-300">
                      {dev}
                    </Badge>
                  ) : <span className="text-zinc-500 italic">None</span>}
                </TableCell>
                <TableCell className="font-mono text-zinc-600 dark:text-zinc-400 text-xs">{details}</TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

function renderNetLinks(netLinks?: string) {
  if (!netLinks) return null;
  if (netLinks.startsWith("Error")) return <div className="text-red-500">{netLinks}</div>;
  const lines = netLinks.trim().split('\n');
  const interfaces: any[] = [];
  let currentIf: any = null;

  lines.forEach(line => {
    if (/^\d+:/.test(line)) {
      if (currentIf) interfaces.push(currentIf);
      const match = line.match(/^\d+:\s+([^:]+):\s+<([^>]+)>\s+(.*)/);
      if (match) {
        currentIf = { name: match[1], flags: match[2], details: match[3], ips: [] };
      } else {
        currentIf = { name: line.split(':')[1]?.trim() || 'unknown', flags: '', details: '', ips: [] };
      }
    } else if (currentIf) {
      const trimmed = line.trim();
      if (trimmed.startsWith('inet ') || trimmed.startsWith('inet6 ')) {
        const parts = trimmed.split(' ');
        currentIf.ips.push(parts[1]);
      }
    }
  });
  if (currentIf) interfaces.push(currentIf);

  if (interfaces.length === 0) return <div className="text-zinc-500 italic mt-2 mb-6">No network links found</div>;

  return (
    <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 mt-2 mb-6 overflow-hidden">
      <Table>
        <TableHeader className="bg-zinc-50 dark:bg-zinc-900/80">
          <TableRow className="border-zinc-200 dark:border-zinc-800 hover:bg-transparent">
            <TableHead className="text-zinc-500 dark:text-zinc-400">Interface</TableHead>
            <TableHead className="text-zinc-500 dark:text-zinc-400">State & Flags</TableHead>
            <TableHead className="text-zinc-500 dark:text-zinc-400">IP Addresses</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {interfaces.map((intf, i) => {
            const isUp = intf.flags.includes('UP');
            return (
              <TableRow key={i} className="border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800/50">
                <TableCell className="font-mono font-medium text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${isUp ? 'bg-green-500' : 'bg-red-500'}`} title={isUp ? 'UP' : 'DOWN'}></div>
                  {intf.name}
                </TableCell>
                <TableCell>
                  <div className="flex gap-1 flex-wrap max-w-[200px]">
                    {intf.flags.split(',').filter((f: string) => f).slice(0, 3).map((f: string) => (
                      <Badge key={f} variant="outline" className="text-[10px] py-0 border-zinc-300 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800/50 text-zinc-600 dark:text-zinc-400">
                        {f}
                      </Badge>
                    ))}
                  </div>
                </TableCell>
                <TableCell className="font-mono text-zinc-600 dark:text-zinc-400 text-xs">
                  {intf.ips.length > 0 ? (
                    <div className="flex flex-col gap-1">
                      {intf.ips.map((ip: string) => <span key={ip}>{ip}</span>)}
                    </div>
                  ) : <span className="italic text-zinc-500">No IPs</span>}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

export function NamespaceDetails() {
  const { type, inode } = useParams();
  const navigate = useNavigate();
  const [details, setDetails] = useState<NamespaceDetailsResponse | null>(null);
  const [processes, setProcesses] = useState<Process[]>([]);
  const [hostNamespaces, setHostNamespaces] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [expandedSection, setExpandedSection] = useState<'none' | 'processes' | 'properties'>('none');

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
          const detailsRes = await fetch(`/api/v1/namespaces/${type}/${inode}?reference_pid=${refPid}`);
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

  const formatBytes = (bytesStr: string) => {
    const bytes = parseInt(bytesStr);
    if (!bytes || bytes === 0) return "N/A";
    const gb = bytes / 1024 / 1024 / 1024;
    if (gb >= 1) return `${gb.toFixed(2)} GB`;
    const mb = bytes / 1024 / 1024;
    return `${mb.toFixed(1)} MB`;
  };

  const isHost = hostNamespaces.includes(`${type}:${type}:[${inode}]`);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6 flex flex-col h-screen">
      <div className="flex items-center gap-4">
        <Link 
          to="/" 
          className="p-2 hover:bg-zinc-200 dark:hover:bg-zinc-800 rounded-full transition-colors text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white"
        >
          <ArrowLeft size={20} />
        </Link>
        <div className="flex-1 flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-zinc-900 dark:text-white flex items-center gap-3 uppercase">
              {type === "cgroup" ? (
                <Layers className="w-8 h-8 text-orange-500 dark:text-orange-400" />
              ) : (
                <Box className="w-8 h-8 text-blue-500 dark:text-blue-400" />
              )}
              {type === "cgroup" ? type : `${type} Namespace`}
            </h1>
            <p className="text-zinc-500 dark:text-zinc-400 font-mono text-sm mt-1">Inode: {inode}</p>
          </div>
          <div className="flex items-center gap-4">
             {isHost ? (
               <Badge variant="outline" className="border-green-300 dark:border-green-800 text-green-700 dark:text-green-400 bg-green-50 dark:bg-green-950/30 text-sm px-3 py-1">Host Scope</Badge>
             ) : (
               <Badge variant="outline" className="border-orange-300 dark:border-orange-800 text-orange-700 dark:text-orange-400 bg-orange-50 dark:bg-orange-950/30 text-sm px-3 py-1">Isolated Scope</Badge>
             )}
             <img src="/logo.png" alt="Beemon Logo" className="h-10 w-auto object-contain" />
             <ThemeToggle />
          </div>
        </div>
      </div>

      {error && (
        <Card className="bg-red-950/20 border-red-900/50 p-4 text-red-400">
          {error}
        </Card>
      )}

      <div className={`grid grid-cols-1 ${expandedSection === 'none' ? 'lg:grid-cols-2' : 'lg:grid-cols-1'} gap-6 flex-1 min-h-0`}>
        {(expandedSection === 'none' || expandedSection === 'processes') && (
          <Card className="bg-white dark:bg-zinc-950/50 border-zinc-200 dark:border-zinc-800 shadow-sm dark:shadow-xl flex flex-col overflow-hidden">
            <div className="p-4 border-b border-zinc-200 dark:border-zinc-800 flex justify-between items-center">
              <div className="flex items-center gap-3">
                <h2 className="text-zinc-900 dark:text-white font-semibold">Associated Processes</h2>
                <Badge variant="secondary" className="bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300">{processes.length} total</Badge>
              </div>
              <button 
                onClick={() => setExpandedSection(expandedSection === 'processes' ? 'none' : 'processes')}
                className="p-1.5 text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-200 dark:hover:bg-zinc-800 rounded-md transition-colors"
                title={expandedSection === 'processes' ? "Collapse" : "Expand"}
              >
                {expandedSection === 'processes' ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
              </button>
            </div>
            <div className="flex-1 overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-200 dark:border-zinc-800">
                  <TableHead className="text-zinc-500 dark:text-zinc-400">PID</TableHead>
                  <TableHead className="text-zinc-500 dark:text-zinc-400">Name</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {processes.map(proc => (
                  <TableRow 
                    key={proc.pid} 
                    className="border-zinc-200 dark:border-zinc-800/50 cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/80 transition-colors"
                    onClick={() => navigate(`/process/${proc.pid}`)}
                  >
                    <TableCell className="font-mono text-zinc-600 dark:text-zinc-300">{proc.pid}</TableCell>
                    <TableCell className="text-zinc-900 dark:text-white">{proc.name}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </Card>
        )}

        {(expandedSection === 'none' || expandedSection === 'properties') && (
        <Card className="bg-white dark:bg-black border-zinc-200 dark:border-zinc-800 shadow-sm dark:shadow-xl flex flex-col overflow-hidden">
          <div className="p-4 border-b border-zinc-200 dark:border-zinc-800 flex justify-between items-center">
            <h2 className="text-zinc-900 dark:text-white font-semibold">Namespace Properties</h2>
            <button 
              onClick={() => setExpandedSection(expandedSection === 'properties' ? 'none' : 'properties')}
              className="p-1.5 text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-200 dark:hover:bg-zinc-800 rounded-md transition-colors"
              title={expandedSection === 'properties' ? "Collapse" : "Expand"}
            >
              {expandedSection === 'properties' ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
            </button>
          </div>
          <div className="flex-1 overflow-y-auto custom-scrollbar p-4 font-mono text-xs text-zinc-800 dark:text-zinc-300 whitespace-pre-wrap">
            {details?.mountInfo && (
              <>
                <div className="text-blue-400 font-bold mb-2">--- MOUNT TABLE ---</div>
                {renderMountInfo(details.mountInfo)}
              </>
            )}
            {details?.netLinks && (
              <>
                <div className="text-blue-400 font-bold mb-2">--- NETWORK LINKS ---</div>
                {renderNetLinks(details.netLinks)}
                <div className="text-blue-400 font-bold mt-4 mb-2">--- ROUTES ---</div>
                {renderNetRoutes(details.netRoutes)}
              </>
            )}
            {details?.utsInfo && (
              <>
                <div className="text-blue-400 font-bold mb-2">--- UTS INFO ---</div>
                {renderUtsInfo(details.utsInfo)}
              </>
            )}
            {details?.userMaps && (
              <>
                <div className="text-blue-400 font-bold mb-2">--- USER NAMESPACE MAPS ---</div>
                {renderUserMaps(details.userMaps)}
              </>
            )}
            {type === "cgroup" && processes.length > 0 && (
              <div className="space-y-4">
                <div className="text-blue-500 font-bold mb-2">--- CGROUP LIMITS ---</div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 bg-white dark:bg-zinc-900/50 p-4 rounded-xl border border-zinc-200 dark:border-zinc-800">
                  <div>
                    <div className="text-zinc-500 text-[10px] uppercase font-bold tracking-wider mb-1">Memory Limit</div>
                    <div className="text-lg font-mono text-zinc-900 dark:text-white">{processes[0].memoryLimitBytes !== "0" ? formatBytes(processes[0].memoryLimitBytes) : "Max"}</div>
                  </div>
                  <div>
                    <div className="text-zinc-500 text-[10px] uppercase font-bold tracking-wider mb-1">PIDs Limit</div>
                    <div className="text-lg font-mono text-zinc-900 dark:text-white">{processes[0].pidsLimit !== "0" ? processes[0].pidsLimit : "Max"}</div>
                  </div>
                  <div>
                    <div className="text-zinc-500 text-[10px] uppercase font-bold tracking-wider mb-1">CPU Quota (us)</div>
                    <div className="text-lg font-mono text-zinc-900 dark:text-white">{processes[0].cpuQuotaUs !== "0" ? processes[0].cpuQuotaUs : "Max"}</div>
                  </div>
                  <div>
                    <div className="text-zinc-500 text-[10px] uppercase font-bold tracking-wider mb-1">CPU Period (us)</div>
                    <div className="text-lg font-mono text-zinc-900 dark:text-white">{processes[0].cpuPeriodUs !== "0" ? processes[0].cpuPeriodUs : "Max"}</div>
                  </div>
                </div>
              </div>
            )}
            {!details?.mountInfo && !details?.netLinks && !details?.utsInfo && !details?.userMaps && type !== "cgroup" && !error && (
              <span className="text-zinc-500 italic">No specific introspection logic available for '{type}' namespaces yet.</span>
            )}
          </div>
        </Card>
        )}
      </div>
    </div>
  );
}
