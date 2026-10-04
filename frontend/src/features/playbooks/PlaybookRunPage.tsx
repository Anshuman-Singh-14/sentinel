import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Ban,
  CircleCheck,
  CircleDashed,
  CircleSlash,
  CircleX,
  LoaderCircle,
  Radio,
  Timer,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Link, useParams } from "react-router";

import { NotFoundPage } from "../../app/NotFoundPage";
import { Badge, Button, Card, JsonViewer, Spinner, cn, useToast } from "../../components/ui";
import { playbooksApi } from "../../lib/api/endpoints";
import { ApiError, errorMessage } from "../../lib/api/errors";
import { formatDateTime } from "../../lib/format";
import type { PlaybookRunDetail, PlaybookStepOut, StepStatus } from "../../types/api";
import { isTerminal, roleAllows } from "../../types/api";
import { useUser } from "../auth/guards";
import { ExportPanel } from "../reports/ExportPanel";
import { FindingCard, RunStatusBadge, SeveritySummary } from "../runs/components";
import type { Connection } from "../runs/useRunStatus";
import { playbookRunKey, usePlaybookStatus } from "./usePlaybookStatus";

const STEP_STYLE: Record<StepStatus, { icon: LucideIcon; className: string; label: string }> = {
  PENDING: { icon: CircleDashed, className: "text-muted", label: "Pending" },
  RUNNING: { icon: LoaderCircle, className: "text-accent", label: "Running" },
  COMPLETED: { icon: CircleCheck, className: "text-ok", label: "Completed" },
  FAILED: { icon: CircleX, className: "text-fail", label: "Failed" },
  SKIPPED: { icon: CircleSlash, className: "text-muted", label: "Skipped" },
  CANCELLED: { icon: Ban, className: "text-warn", label: "Cancelled" },
  TIMED_OUT: { icon: Timer, className: "text-fail", label: "Timed out" },
};

function StepRow({ step, current }: { step: PlaybookStepOut; current: boolean }) {
  const style = STEP_STYLE[step.status];
  const Icon = style.icon;
  return (
    <li
      aria-current={current ? "step" : undefined}
      className={cn(
        "relative flex gap-3 rounded border p-3",
        current ? "border-accent/60 bg-accent/5" : "border-border bg-surface",
      )}
    >
      <Icon
        size={20}
        aria-hidden="true"
        className={cn(
          "mt-0.5 shrink-0",
          style.className,
          step.status === "RUNNING" && "animate-spin",
        )}
      />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-semibold">
            {step.position + 1}. {step.name}
          </span>
          <span className={cn("text-xs font-semibold", style.className)}>{style.label}</span>
          {step.on_failure === "continue" && <Badge>continues on failure</Badge>}
          {step.run && (
            <Link to={`/runs/${step.run.run_id}`} className="text-xs text-accent hover:underline">
              Open tool run ({step.run.finding_count} findings)
            </Link>
          )}
        </div>
        {step.error && (
          <p className={cn("mt-1 text-xs", step.status === "SKIPPED" ? "text-muted" : "text-fail")}>
            {step.error.message} <code className="text-muted">({step.error.code})</code>
          </p>
        )}
        {step.resolved_params && (
          <details className="mt-2 text-xs">
            <summary className="cursor-pointer text-muted">Parameters used</summary>
            <JsonViewer
              value={step.resolved_params}
              label={`Parameters for ${step.name}`}
              className="mt-1"
            />
          </details>
        )}
      </div>
    </li>
  );
}

function ConnectionNote({ connection }: { connection: Connection }) {
  if (connection === "closed") return null;
  const text = {
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
      {text}
    </span>
  );
}

function CancelButton({ run }: { run: PlaybookRunDetail }) {
  const user = useUser();
  const toast = useToast();
  const queryClient = useQueryClient();
  const cancel = useMutation({
    mutationFn: () => playbooksApi.cancel(run.playbook_run_id),
    onSuccess: (updated) => {
      queryClient.setQueryData(playbookRunKey(run.playbook_run_id), updated);
      toast.show({
        tone: "info",
        title: updated.status === "CANCELLED" ? "Playbook cancelled" : "Cancellation requested",
        description:
          updated.status === "CANCELLED"
            ? undefined
            : "The current step stops at its next checkpoint.",
      });
    },
    onError: (e) =>
      toast.show({ tone: "error", title: "Could not cancel", description: errorMessage(e) }),
  });
  const allowed =
    roleAllows(user.role, "analyst") && (run.user_id === user.id || roleAllows(user.role, "admin"));
  if (!allowed || isTerminal(run.status)) return null;
  return (
    <Button
      variant="danger"
      size="sm"
      loading={cancel.isPending}
      disabled={run.cancel_requested}
      onClick={() => cancel.mutate()}
    >
      {run.cancel_requested ? "Cancelling…" : "Cancel playbook"}
    </Button>
  );
}

export function PlaybookRunPage() {
  const { playbookRunId = "" } = useParams();
  const { run, isPending, isError, error, connection } = usePlaybookStatus(playbookRunId);

  if (isPending) return <Spinner label="Loading playbook run" />;
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
  const stepNames = Object.fromEntries(run.steps.map((s) => [s.step_id, s.name]));

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="text-[0.7rem] font-semibold tracking-[0.2em] text-muted uppercase">
            <Link to="/playbooks" className="hover:text-accent">
              {run.playbook_name}
            </Link>{" "}
            · v{run.playbook_version}
          </p>
          <h1 className="mt-1 text-lg font-semibold break-all">{run.target ?? "Playbook run"}</h1>
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

      <Card title="Steps" actions={<ConnectionNote connection={connection} />}>
        <div className="flex flex-col gap-3">
          {active && (
            <div className="flex items-center gap-3" aria-live="polite">
              <progress
                value={run.progress_pct}
                max={100}
                aria-label="Playbook progress"
                className="h-2 flex-1 accent-accent"
              />
              <span className="w-10 text-right text-xs tabular-nums">{run.progress_pct}%</span>
            </div>
          )}
          {run.error && !active && (
            <p
              role={run.status === "CANCELLED" ? "status" : "alert"}
              className="rounded border border-fail/40 bg-fail/10 p-2 text-sm text-fail"
            >
              {run.error.message}
            </p>
          )}
          <ol className="flex flex-col gap-2" aria-label="Playbook steps">
            {run.steps.map((step) => (
              <StepRow key={step.step_id} step={step} current={step.step_id === run.current_step} />
            ))}
          </ol>
        </div>
      </Card>

      {!active && (
        <Card title="Unified findings" eyebrow="All steps, de-duplicated">
          <div className="flex flex-col gap-4">
            <p className="text-sm">{run.risk.headline}</p>
            <SeveritySummary counts={run.risk.by_severity} />
            {run.findings.length === 0 ? (
              <p className="text-sm text-muted">No findings.</p>
            ) : (
              <ul className="flex flex-col gap-2">
                {run.findings.map((finding) => (
                  <FindingCard
                    key={finding.finding_id}
                    finding={finding}
                    source={
                      <>
                        From{" "}
                        <span className="text-text">
                          {stepNames[finding.step_id] ?? finding.step_id}
                        </span>
                        {finding.also_reported_by.length > 0 &&
                          ` · also reported by ${finding.also_reported_by
                            .map((s) => stepNames[s] ?? s)
                            .join(", ")}`}
                      </>
                    }
                  />
                ))}
              </ul>
            )}
          </div>
        </Card>
      )}

      {!active && <ExportPanel sourceType="playbook_run" sourceId={run.playbook_run_id} />}
    </div>
  );
}
