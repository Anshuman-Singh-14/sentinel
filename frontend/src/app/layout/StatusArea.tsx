import { useQuery } from "@tanstack/react-query";

import { cn } from "../../components/ui";
import { healthApi } from "../../lib/api/endpoints";

export const HEALTH_QUERY_KEY = ["health"] as const;
const HEALTH_POLL_MS = 30_000;

/** Sidebar footer: live API status and build version. */
export function StatusArea() {
  const health = useQuery({
    queryKey: HEALTH_QUERY_KEY,
    queryFn: ({ signal }) => healthApi.health(signal),
    refetchInterval: HEALTH_POLL_MS,
    retry: false,
  });

  const state = health.isPending ? "checking" : health.isError ? "down" : "up";
  const label = { checking: "Checking API…", up: "API online", down: "API unreachable" }[state];

  return (
    <div className="border-t border-border px-4 py-3 text-xs">
      <div role="status" aria-live="polite" className="flex items-center gap-2">
        <span
          aria-hidden="true"
          className={cn(
            "inline-block size-2 rounded-full",
            state === "up" && "bg-ok shadow-[0_0_6px] shadow-ok",
            state === "down" && "bg-fail",
            state === "checking" && "bg-muted",
          )}
        />
        <span className={state === "down" ? "text-fail" : "text-muted"}>{label}</span>
      </div>
      {health.data && <p className="mt-1 text-muted">v{health.data.version}</p>}
    </div>
  );
}
