/**
 * Live status of a playbook run: REST is the source of truth, the WebSocket
 * makes it live, polling covers a dropped socket (same pattern as runs).
 *
 * Playbook events carry overall progress and each step's status. Progress is
 * merged into the cache directly; when any step's status changes, the full
 * detail (step runs, unified findings, risk) is refetched.
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { playbooksApi } from "../../lib/api/endpoints";
import type { PlaybookEvent, PlaybookRunDetail } from "../../types/api";
import { isTerminal } from "../../types/api";
import type { Connection } from "../runs/useRunStatus";
import { wsUrl } from "../runs/useRunStatus";

export const playbookRunKey = (id: string) => ["playbook-runs", id] as const;
const POLL_MS = 2000;

function isPlaybookEvent(value: unknown): value is PlaybookEvent {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { type?: unknown }).type === "playbook.update" &&
    Array.isArray((value as { steps?: unknown }).steps)
  );
}

export function usePlaybookStatus(id: string) {
  const queryClient = useQueryClient();
  const [connection, setConnection] = useState<Connection>("connecting");

  const query = useQuery({
    queryKey: playbookRunKey(id),
    queryFn: ({ signal }) => playbooksApi.get(id, signal),
    refetchInterval: (q) => {
      const run = q.state.data;
      if (!run || isTerminal(run.status)) return false;
      return connection === "polling" ? POLL_MS : false;
    },
  });

  const status = query.data?.status;
  const active = status !== undefined && !isTerminal(status);

  useEffect(() => {
    if (!active) return;
    let socket: WebSocket | null = null;
    let finished = false;
    let disposed = false;
    const refetch = () => void queryClient.invalidateQueries({ queryKey: playbookRunKey(id) });

    void playbooksApi
      .wsTicket(id)
      .then(({ ticket }) => {
        if (disposed) return;
        socket = new WebSocket(
          wsUrl(`/ws/playbooks/${encodeURIComponent(id)}?ticket=${encodeURIComponent(ticket)}`),
        );
        socket.onopen = () => setConnection("live");
        socket.onmessage = (message) => {
          let data: unknown;
          try {
            data = JSON.parse(String(message.data));
          } catch {
            return;
          }
          if (!isPlaybookEvent(data) || data.playbook_run_id !== id) return;
          let stepChanged = false;
          queryClient.setQueryData<PlaybookRunDetail>(playbookRunKey(id), (current) => {
            if (!current) return current;
            const statuses = new Map(data.steps.map((s) => [s.step_id, s.status]));
            const steps = current.steps.map((step) => {
              const next = statuses.get(step.step_id);
              if (next && next !== step.status) {
                stepChanged = true;
                return { ...step, status: next };
              }
              return step;
            });
            return {
              ...current,
              status: data.status,
              progress_pct: data.progress_pct,
              current_step: data.current_step,
              steps,
            };
          });
          if (isTerminal(data.status)) {
            finished = true;
            refetch();
          } else if (stepChanged) {
            refetch(); // pick up the step's run link and new findings
          }
        };
        socket.onclose = () => {
          if (disposed) return;
          setConnection(finished ? "closed" : "polling");
          if (!finished) refetch();
        };
      })
      .catch(() => {
        if (!disposed) setConnection("polling");
      });

    return () => {
      disposed = true;
      socket?.close();
    };
  }, [active, id, queryClient]);

  return { ...query, run: query.data, connection: active ? connection : "closed" };
}
