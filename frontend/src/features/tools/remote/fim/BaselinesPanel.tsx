/**
 * File integrity baselines (Phase 11, ADR 0015), shown under the FIM tools'
 * run forms through the registry's `panel` hook.
 *
 * Baselines are created by running "FIM: Create Baseline" and checked with
 * "File Integrity Check"; this panel lists them and offers Check now, a check
 * schedule and Delete. The server enforces who may do what (analysts run
 * checks; only a baseline's creator or an admin changes or deletes it); the
 * buttons only mirror that so nobody is offered an action that will be refused.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router";

import { Button, Card, DataTable, Spinner, useToast } from "../../../../components/ui";
import type { Column } from "../../../../components/ui";
import { fimApi, runsApi } from "../../../../lib/api/endpoints";
import { errorMessage } from "../../../../lib/api/errors";
import { formatDateTime } from "../../../../lib/format";
import type { FimBaseline } from "../../../../types/api";
import { roleAllows } from "../../../../types/api";
import { useUser } from "../../../auth/guards";
import { runQueryKey } from "../../../runs/useRunStatus";

export const FIM_BASELINES_KEY = ["fim", "baselines"] as const;

function scheduleLabel(minutes: number | null): string {
  if (!minutes) return "Off";
  if (minutes < 60) return `Every ${minutes} min`;
  if (minutes < 1440) return `Every ${minutes / 60} h`;
  return "Daily";
}

function location(b: FimBaseline): string {
  return `${b.root}:/${b.path}`;
}

export default function BaselinesPanel({ toolId }: { toolId: string }) {
  const user = useUser();
  const toast = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const mayRun = roleAllows(user.role, "analyst");
  const mayChange = (b: FimBaseline) =>
    mayRun && (b.created_by === user.id || roleAllows(user.role, "admin"));

  const baselines = useQuery({
    queryKey: FIM_BASELINES_KEY,
    queryFn: ({ signal }) => fimApi.list(signal),
  });
  const refresh = () => void queryClient.invalidateQueries({ queryKey: FIM_BASELINES_KEY });

  const check = useMutation({
    mutationFn: (baselineId: string) => runsApi.create("fim_check", { baseline_id: baselineId }),
    onSuccess: (run) => {
      queryClient.setQueryData(runQueryKey(run.run_id), run);
      void queryClient.invalidateQueries({ queryKey: ["runs", "list"] });
      navigate(`/runs/${run.run_id}`);
    },
    onError: (error) =>
      toast.show({
        tone: "error",
        title: "Could not start the check",
        description: errorMessage(error),
      }),
  });
  const schedule = useMutation({
    mutationFn: ({ id, minutes }: { id: string; minutes: number | null }) =>
      fimApi.setSchedule(id, minutes),
    onSuccess: (b) => {
      refresh();
      toast.show({
        tone: "info",
        title: `Schedule for '${b.name}': ${scheduleLabel(b.schedule_minutes)}`,
      });
    },
    onError: (error) =>
      toast.show({
        tone: "error",
        title: "Could not change the schedule",
        description: errorMessage(error),
      }),
  });
  const remove = useMutation({
    mutationFn: (b: FimBaseline) => fimApi.remove(b.id),
    onSuccess: (_, b) => {
      refresh();
      toast.show({ tone: "info", title: `Baseline '${b.name}' deleted` });
    },
    onError: (error) =>
      toast.show({ tone: "error", title: "Could not delete", description: errorMessage(error) }),
  });

  const choices = baselines.data?.schedule_choices ?? [];
  const columns: Column<FimBaseline>[] = [
    {
      id: "name",
      header: "Baseline",
      sortValue: (b) => b.name,
      cell: (b) => (
        <div className="flex flex-col">
          <span className="font-medium">{b.name}</span>
          <span className="font-mono text-xs text-muted">{location(b)}</span>
        </div>
      ),
    },
    {
      id: "files",
      header: "Files",
      sortValue: (b) => b.file_count,
      cell: (b) => b.file_count.toLocaleString(),
    },
    {
      id: "created",
      header: "Created",
      sortValue: (b) => b.created_at,
      cell: (b) => (
        <div className="flex flex-col text-xs">
          <span>{formatDateTime(b.created_at)}</span>
          <span className="text-muted">by {b.created_by_username}</span>
        </div>
      ),
    },
    {
      id: "last",
      header: "Last check",
      sortValue: (b) => b.last_checked_at,
      cell: (b) =>
        b.last_check_run_id ? (
          <Link to={`/runs/${b.last_check_run_id}`} className="text-xs text-accent hover:underline">
            {b.last_check_changes === 0 ? "No changes" : `${b.last_check_changes ?? "?"} change(s)`}{" "}
            · {formatDateTime(b.last_checked_at)}
          </Link>
        ) : (
          <span className="text-xs text-muted">Never</span>
        ),
    },
    {
      id: "schedule",
      header: "Schedule",
      cell: (b) =>
        mayChange(b) ? (
          <select
            aria-label={`Check schedule for ${b.name}`}
            className="rounded border border-border-strong bg-surface px-2 py-1 text-xs text-text"
            value={b.schedule_minutes ?? ""}
            disabled={schedule.isPending}
            onChange={(event) =>
              schedule.mutate({
                id: b.id,
                minutes: event.target.value ? Number(event.target.value) : null,
              })
            }
          >
            <option value="">Off</option>
            {choices.map((m) => (
              <option key={m} value={m}>
                {scheduleLabel(m)}
              </option>
            ))}
          </select>
        ) : (
          <span className="text-xs">{scheduleLabel(b.schedule_minutes)}</span>
        ),
    },
    {
      id: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (b) => (
        <div className="flex justify-end gap-2">
          {mayRun && (
            <Button
              size="sm"
              variant="secondary"
              loading={check.isPending && check.variables === b.id}
              disabled={check.isPending}
              onClick={() => check.mutate(b.id)}
              aria-label={`Check ${b.name} now`}
            >
              Check now
            </Button>
          )}
          {mayChange(b) && (
            <Button
              size="sm"
              variant="ghost"
              disabled={remove.isPending}
              onClick={() => {
                if (
                  window.confirm(
                    `Delete baseline '${b.name}'? Its recorded file states are removed.`,
                  )
                ) {
                  remove.mutate(b);
                }
              }}
              aria-label={`Delete ${b.name}`}
            >
              Delete
            </Button>
          )}
        </div>
      ),
    },
  ];

  return (
    <Card title="Baselines" eyebrow="File integrity" aria-label="FIM baselines">
      {baselines.isPending ? (
        <Spinner label="Loading baselines" />
      ) : baselines.isError ? (
        <p role="alert" className="text-sm text-fail">
          {errorMessage(baselines.error)}
        </p>
      ) : (
        <DataTable
          caption="File integrity baselines"
          columns={columns}
          rows={baselines.data.baselines}
          getRowId={(b) => b.id}
          emptyMessage={
            toolId === "fim_baseline" ? (
              "No baselines yet. Create the first one with the form above."
            ) : (
              <>
                No baselines yet.{" "}
                <Link to="/tools/fim_baseline" className="text-accent hover:underline">
                  Create one
                </Link>{" "}
                first, then check it here.
              </>
            )
          }
        />
      )}
    </Card>
  );
}
