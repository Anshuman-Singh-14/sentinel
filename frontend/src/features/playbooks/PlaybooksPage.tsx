import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowDown, CircleSlash, Radar } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router";

import { Badge, Button, Card, DataTable, SeverityBadge, Spinner } from "../../components/ui";
import type { Column } from "../../components/ui";
import { playbooksApi } from "../../lib/api/endpoints";
import { ApiError, errorMessage } from "../../lib/api/errors";
import { formatDateTime } from "../../lib/format";
import type { PlaybookInfo, PlaybookRunSummary } from "../../types/api";
import { roleAllows } from "../../types/api";
import { useUser } from "../auth/guards";
import { RunStatusBadge } from "../runs/components";
import { ACK_QUERY_KEY, AuthorizationGate, ScopeSummary } from "../scope/AuthorizationGate";
import { SchemaForm } from "../tools/SchemaForm";
import type { ObjectSchema } from "../tools/SchemaForm";
import { fieldErrors } from "../tools/ToolPage";
import { playbookRunKey } from "./usePlaybookStatus";

function StepList({ playbook }: { playbook: PlaybookInfo }) {
  return (
    <ol className="flex flex-col gap-1" aria-label={`${playbook.name} steps`}>
      {playbook.steps.map((step, index) => (
        <li key={step.id} className="flex flex-col gap-1">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="w-5 text-right text-xs text-muted tabular-nums">{index + 1}.</span>
            <span className={step.available ? "" : "text-muted line-through"}>{step.name}</span>
            {step.is_active && <Badge tone="warn">active</Badge>}
            {!step.available && (
              <Badge tone="neutral">
                <CircleSlash size={10} aria-hidden="true" />
                {step.optional ? "not installed yet: skipped" : "not installed"}
              </Badge>
            )}
            {step.on_failure === "continue" && (
              <span className="text-xs text-muted">(continues on failure)</span>
            )}
          </div>
          {step.description && <p className="ml-7 text-xs text-muted">{step.description}</p>}
          {index < playbook.steps.length - 1 && (
            <ArrowDown size={12} aria-hidden="true" className="ml-5 text-border-strong" />
          )}
        </li>
      ))}
    </ol>
  );
}

function StartForm({ playbook }: { playbook: PlaybookInfo }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const start = useMutation({
    mutationFn: (inputs: Record<string, unknown>) => playbooksApi.start(playbook.id, inputs),
    onSuccess: (run) => {
      queryClient.setQueryData(playbookRunKey(run.playbook_run_id), run);
      void queryClient.invalidateQueries({ queryKey: ["playbook-runs", "list"] });
      navigate(`/playbook-runs/${run.playbook_run_id}`);
    },
    onError: (error) => {
      if (error instanceof ApiError && error.code === "authorization_required") {
        void queryClient.invalidateQueries({ queryKey: ACK_QUERY_KEY });
      }
    },
  });
  const errors = fieldErrors(start.error, "inputs");
  const general =
    start.isError && Object.keys(errors).length === 0 ? errorMessage(start.error) : null;
  return (
    <div className="flex flex-col gap-3">
      <SchemaForm
        schema={playbook.inputs_schema as ObjectSchema}
        submitLabel="Run playbook"
        busy={start.isPending}
        serverErrors={errors}
        onSubmit={(inputs) => start.mutate(inputs)}
      />
      {general && (
        <p role="alert" className="text-sm text-fail">
          {general}
        </p>
      )}
    </div>
  );
}

function PlaybookCard({ playbook }: { playbook: PlaybookInfo }) {
  const user = useUser();
  const [open, setOpen] = useState(false);
  const canRun = roleAllows(user.role, playbook.required_role);
  return (
    <Card
      eyebrow={`Playbook · v${playbook.version}`}
      title={
        <span className="flex items-center gap-2">
          <Radar size={16} aria-hidden="true" className="text-accent" />
          {playbook.name}
        </span>
      }
      actions={
        playbook.available && canRun && !open ? (
          <Button size="sm" onClick={() => setOpen(true)}>
            Configure run
          </Button>
        ) : undefined
      }
    >
      <div className="flex flex-col gap-4">
        <p className="text-sm text-muted">{playbook.description}</p>
        <StepList playbook={playbook} />
        {!playbook.available && <p className="text-sm text-warn">{playbook.unavailable_reason}</p>}
        {!canRun && (
          <p className="text-sm text-muted">
            Your role ({user.role}) can view playbook results but cannot run playbooks.
          </p>
        )}
        {open && (
          <div className="flex flex-col gap-4 border-t border-border pt-4">
            {playbook.requires_authorization ? (
              <>
                <ScopeSummary />
                <AuthorizationGate>
                  <StartForm playbook={playbook} />
                </AuthorizationGate>
              </>
            ) : (
              <StartForm playbook={playbook} />
            )}
          </div>
        )}
      </div>
    </Card>
  );
}

const RUN_COLUMNS: Column<PlaybookRunSummary>[] = [
  {
    id: "created",
    header: "Started",
    cell: (r) => <span className="whitespace-nowrap">{formatDateTime(r.created_at)}</span>,
  },
  { id: "playbook", header: "Playbook", cell: (r) => r.playbook_name },
  {
    id: "target",
    header: "Target",
    cell: (r) => <span className="break-all">{r.target ?? "—"}</span>,
  },
  { id: "status", header: "Status", cell: (r) => <RunStatusBadge status={r.status} /> },
  {
    id: "findings",
    header: "Findings",
    cell: (r) =>
      r.max_severity ? (
        <span className="inline-flex items-center gap-2">
          <SeverityBadge severity={r.max_severity} />
          <span className="text-muted">{r.finding_count} total</span>
        </span>
      ) : (
        <span className="text-muted">—</span>
      ),
  },
  { id: "by", header: "By", cell: (r) => r.initiated_by },
];

export function PlaybooksPage() {
  const navigate = useNavigate();
  const catalogue = useQuery({
    queryKey: ["playbooks"],
    queryFn: ({ signal }) => playbooksApi.list(signal),
  });
  const runs = useQuery({
    queryKey: ["playbook-runs", "list"],
    queryFn: ({ signal }) => playbooksApi.runs(false, undefined, signal),
    refetchInterval: (q) =>
      q.state.data?.runs.some((r) => r.status === "QUEUED" || r.status === "RUNNING")
        ? 5000
        : false,
  });

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <div>
        <h1 className="text-lg font-semibold">Playbooks</h1>
        <p className="mt-1 text-sm text-muted">
          Run several tools in order against one target and get a single, de-duplicated list of
          findings ranked by severity.
        </p>
      </div>
      {catalogue.isPending ? (
        <Spinner label="Loading playbooks" />
      ) : catalogue.isError ? (
        <p role="alert" className="text-sm text-fail">
          {errorMessage(catalogue.error)}
        </p>
      ) : (
        catalogue.data.map((playbook) => <PlaybookCard key={playbook.id} playbook={playbook} />)
      )}
      <section aria-labelledby="pb-history" className="flex flex-col gap-3">
        <h2 id="pb-history" className="text-sm font-semibold tracking-wider text-muted uppercase">
          Recent playbook runs
        </h2>
        <DataTable
          caption="Playbook runs, newest first"
          columns={RUN_COLUMNS}
          rows={runs.data?.runs ?? []}
          getRowId={(r) => r.playbook_run_id}
          loading={runs.isPending}
          emptyMessage="No playbook runs yet."
          onRowClick={(r) => navigate(`/playbook-runs/${r.playbook_run_id}`)}
          rowActionLabel={(r) =>
            `Open ${r.playbook_name} run on ${r.target ?? "unknown"}, ${r.status}`
          }
        />
      </section>
    </div>
  );
}
