/**
 * Live status of one run.
 *
 * The REST endpoint is the source of truth; the WebSocket only makes it live:
 *
 * 1. Load the run with `GET /runs/{id}` (TanStack Query).
 * 2. While it is not finished, get a single-use ticket and open
 *    `/ws/runs/{id}`. Each `run.update` event is merged into the cached run,
 *    so status and progress move without refetching.
 * 3. When an event reports a terminal status, refetch the full result
 *    (findings, raw data, errors), which events do not carry.
 * 4. If the socket cannot open or drops early, fall back to polling every
 *    2 s. Live updates are a convenience, never a dependency.
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { runsApi } from "../../lib/api/endpoints";
import type { RunDetail, RunEvent } from "../../types/api";
import { isTerminal } from "../../types/api";

export const runQueryKey = (runId: string) => ["runs", runId] as const;
const POLL_MS = 2000;

export type Connection = "connecting" | "live" | "polling" | "closed";

function isRunEvent(value: unknown): value is RunEvent {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { type?: unknown }).type === "run.update" &&
    typeof (value as { status?: unknown }).status === "string"
  );
}

export function wsUrl(path: string): string {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}${path}`;
}

export function useRunStatus(runId: string) {
  const queryClient = useQueryClient();
  const [connection, setConnection] = useState<Connection>("connecting");

  const query = useQuery({
    queryKey: runQueryKey(runId),
    queryFn: ({ signal }) => runsApi.get(runId, signal),
    // Poll only while the socket is not delivering and the run is active.
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

    const onTerminal = () => {
      finished = true;
      void queryClient.invalidateQueries({ queryKey: runQueryKey(runId) });
    };

    void runsApi
      .wsTicket(runId)
      .then(({ ticket }) => {
        if (disposed) return;
        socket = new WebSocket(
          wsUrl(`/ws/runs/${encodeURIComponent(runId)}?ticket=${encodeURIComponent(ticket)}`),
        );
        socket.onopen = () => setConnection("live");
        socket.onmessage = (message) => {
          let data: unknown;
          try {
            data = JSON.parse(String(message.data));
          } catch {
            return;
          }
          if (!isRunEvent(data) || data.run_id !== runId) return;
          queryClient.setQueryData<RunDetail>(runQueryKey(runId), (current) =>
            current
              ? {
                  ...current,
                  status: data.status,
                  progress_pct: data.progress_pct,
                  progress_message: data.progress_message,
                }
              : current,
          );
          if (isTerminal(data.status)) onTerminal();
        };
        socket.onclose = () => {
          if (disposed) return;
          setConnection(finished ? "closed" : "polling");
          // The run may have finished between our last event and the close.
          if (!finished) void queryClient.invalidateQueries({ queryKey: runQueryKey(runId) });
        };
      })
      .catch(() => {
        if (!disposed) setConnection("polling");
      });

    return () => {
      disposed = true;
      socket?.close();
    };
  }, [active, runId, queryClient]);

  return { ...query, run: query.data, connection: active ? connection : "closed" };
}
