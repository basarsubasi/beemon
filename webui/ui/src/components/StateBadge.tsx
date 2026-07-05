import { Badge } from "./ui/badge";
import { Skull } from "lucide-react";

export function StateBadge({ state, className = "" }: { state: string, className?: string }) {
  const lowerState = state.toLowerCase();
  
  let colorClass = "border-zinc-300 dark:border-zinc-700 text-zinc-600 dark:text-zinc-300";
  let icon = null;

  if (lowerState.includes("running")) {
    colorClass = "border-green-300 dark:border-green-700 text-green-700 dark:text-green-400 bg-green-50 dark:bg-green-950/30";
  } else if (lowerState.includes("sleeping") || lowerState.includes("disk sleep")) {
    colorClass = "border-orange-300 dark:border-orange-700 text-orange-700 dark:text-orange-400 bg-orange-50 dark:bg-orange-950/30";
  } else if (lowerState.includes("frozen")) {
    colorClass = "border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-400 bg-blue-50 dark:bg-blue-950/30";
  } else if (lowerState.includes("zombie")) {
    colorClass = "border-zinc-300 dark:border-zinc-700 text-zinc-600 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-900";
    icon = <Skull className="w-3 h-3 mr-1 inline-flex items-center" />;
  } else if (lowerState.includes("idle") || lowerState.includes("stopped")) {
    colorClass = "border-zinc-300 dark:border-zinc-700 text-zinc-600 dark:text-zinc-400 bg-zinc-50 dark:bg-zinc-900/50";
  }

  return (
    <Badge variant="outline" className={`font-mono flex items-center w-fit ${colorClass} ${className}`}>
      {icon}
      <span>{state}</span>
    </Badge>
  );
}
