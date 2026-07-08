import { Badge } from "./ui/badge";

const MANAGER_COLORS: Record<string, string> = {
  systemd: "border-green-300 dark:border-green-700 bg-green-50 dark:bg-green-950/30 text-green-700 dark:text-green-400",
  containerd: "border-blue-800 dark:border-blue-600 bg-blue-100 dark:bg-blue-950/30 text-blue-800 dark:text-blue-400",
  dockerd: "border-blue-300 dark:border-blue-700 bg-blue-50 dark:bg-blue-950/30 text-blue-700 dark:text-blue-400",
  podman: "border-orange-300 dark:border-orange-700 bg-orange-50 dark:bg-orange-950/30 text-orange-700 dark:text-orange-400",
  crio: "border-zinc-300 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-900/50 text-zinc-600 dark:text-zinc-400",
  conmon: "border-yellow-300 dark:border-yellow-700 bg-yellow-50 dark:bg-yellow-950/30 text-yellow-700 dark:text-yellow-400",
};

const MANAGER_LABELS: Record<string, string> = {
  systemd: "systemd",
  containerd: "containerd",
  dockerd: "docker",
  podman: "podman",
  crio: "cri-o",
  conmon: "conmon",
};

export const ALL_MANAGERS = Object.keys(MANAGER_COLORS);

export function getManagerLabel(manager: string): string {
  return MANAGER_LABELS[manager] ?? manager;
}

export function ManagerBadge({ manager, className = "" }: { manager: string, className?: string }) {
  const colorClass = MANAGER_COLORS[manager] ?? "border-zinc-300 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-900/50 text-zinc-600 dark:text-zinc-400";
  const label = getManagerLabel(manager);

  return (
    <Badge variant="outline" className={`text-xs ${colorClass} ${className}`}>
      {label}
    </Badge>
  );
}
