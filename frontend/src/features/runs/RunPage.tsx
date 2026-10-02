import { useMutation, useQueryClient } from "@tanstack/react-query";
import { CircleAlert, Radio } from "lucide-react";
import { Link, useParams } from "react-router";

import { NotFoundPage } from "../../app/NotFoundPage";
import { Button, Card, JsonViewer, Spinner, Tabs, useToast } from "../../components/ui";
import { runsApi } from "../../lib/api/endpoints";
import { ApiError, errorMessage } from "../../lib/api/errors";
import { formatDateTime } from "../../lib/format";
import type { RunDetail } from "../../types/api";
import { isTerminal, roleAllows } from "../../types/api";
import { useUser } from "../auth/guards";
import { FindingCard, RunStatusBadge, RunTimeline, SeveritySummary } from "./components";
import { runQueryKey, useRunStatus } from "./useRunStatus";
import type { Connection } from "./useRunStatus";

function ConnectionIndicator({ connection }: { connection: Connection }) {
  if (connection === "closed") return null;
  const label = {
    connecting: "Connecting to live updates…",
    live: "Live",
    polling: "Live updates unavailable — refreshing every 2 s",
  }[connection];
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted">
      <Radio
        size={12}
        aria-hidden="true"
        className={connection === "live" ? "text-ok" : undefined}
      />
      {label}
    </span>
  );
}

function CancelButton({ run }: { run: RunDetail }) {
  const user = useUser();
  const toast = useToast();
  const queryClient = useQueryClient();
  const cancel = useMutation({
    mutationFn: () => runsApi.cancel(run.run_id),
    onSuccess: (updated) => {
      queryClient.setQueryData(runQueryKey(run.run_id), updated);
      toast.show({
        tone: "info",
        title: updated.status === "CANCELLED" ? "Run cancelled" : "Cancellation requested",
        description:
          updated.status === "CANCELLED" ? undefined : "The tool stops at its next checkpoint.",
      });
    },
    onError: (error) =>
      toast.show({ tone: "error", title: "Could not cancel", description: errorMessage(error) }),
  });
  const mayCancel =
    roleAllows(user.role, "analyst") && (run.user_id === user.id || roleAllows(user.role, "admin"));
  if (!mayCancel || isTerminal(run.status)) return null;
  return (
    <Button
      variant="danger"
      size="sm"
      loading={cancel.isPending}
      disabled={run.cancel_requested}
      onClick={() => cancel.mutate()}
    >
      {run.cancel_requested ? "Cancelling…" : "Cancel run"}
    </Button>
  );
}

function ErrorsPanel({ run }: { run: RunDetail }) {
  if (run.errors.length === 0) return null;
  const partial = run.status === "COMPLETED";
  return (
    <div
      role={partial ? "status" : "alert"}
      className={
        partial
          ? "rounded border border-warn/50 bg-warn/10 p-3 text-sm"
          : "rounded border border-fail/50 bg-fail/10 p-3 text-sm"
      }
    >
      <p className={`flex items-center gap-2 font-semibold ${partial ? "text-warn" : "text-fail"}`}>
        <CircleAlert size={16} aria-hidden="true" />
        {partial ? "Completed with partial results" : "The run did not complete"}
      </p>
      <ul className="mt-2 flex flex-col gap-1">
        {run.errors.map((e, i) => (
          <li key={`${e.code}-${i}`}>
            {e.message} <code className="text-xs text-muted">({e.code})</code>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function RunPage() {
  const { runId = "" } = useParams();
  const { run, isPending, isError, error, connection } = useRunStatus(runId);

  if (isPending) return <Spinner label="Loading run" />;
  if (isError) {
    if (error instanceof ApiError && (error.status === 404 || error.status === 422)) {
      return <NotFoundPage />;
    }
    return (
      <p role="alert" className="text-sm text-fail">
        {errorMessage(error)}
      </p>
    );
  }
  if (!run) return <NotFoundPage />;

  const active = !isTerminal(run.status);

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="text-[0.7rem] font-semibold tracking-[0.2em] text-muted uppercase">
            <Link to={`/tools/${encodeURIComponent(run.tool_id)}`} className="hover:text-accent">
              {run.tool_name}
            </Link>{" "}
            · v{run.tool_version}
          </p>
          <h1 className="mt-1 text-lg font-semibold break-all">{run.target ?? "Run"}</h1>
          <p className="mt-1 text-xs text-muted">
            Started by {run.initiated_by} · {formatDateTime(run.created_at)}
            {run.duration_ms !== null && ` · ${(run.duration_ms / 1000).toFixed(1)} s`}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <RunStatusBadge status={run.status} />
          <CancelButton run={run} />
        </div>
      </div>

      <Card title="Status" actions={<ConnectionIndicator connection={connection} />}>
        <div className="flex flex-col gap-3">
          <RunTimeline status={run.status} started={run.was_started} />
          {active && (
            <div className="flex items-center gap-3" aria-live="polite">
              <progress
                value={run.progress_pct}
                max={100}
                aria-label="Run progress"
                className="h-2 flex-1 accent-accent"
              />
              <span className="w-10 text-right text-xs tabular-nums">{run.progress_pct}%</span>
              <span className="min-w-0 flex-1 truncate text-xs text-muted">
                {run.progress_message ?? (run.status === "QUEUED" ? "Waiting for a worker" : "")}
              </span>
            </div>
          )}
          <ErrorsPanel run={run} />
        </div>
      </Card>

      {!active && (
        <Card title="Result">
          <Tabs
            label="Result views"
            items={[
              {
                id: "findings",
                label: `Findings (${run.summary.total})`,
                content: (
                  <div className="flex flex-col gap-4">
                    <SeveritySummary counts={run.summary.by_severity} />
                    {run.findings.length === 0 ? (
                      <p className="text-sm text-muted">This run produced no findings.</p>
                    ) : (
                      <ul className="flex flex-col gap-2">
                        {run.findings.map((finding) => (
                          <FindingCard key={finding.finding_id} finding={finding} />
                        ))}
                      </ul>
                    )}
                  </div>
                ),
              },
              {
                id: "raw",
                label: "Raw data",
                content: (
                  <JsonViewer value={run.raw_data} label="Raw tool output" defaultExpandDepth={2} />
                ),
              },
              {
                id: "params",
                label: "Parameters",
                content: <JsonViewer value={run.params} label="Run parameters" />,
              },
            ]}
          />
        </Card>
      )}
    </div>
  );
}
