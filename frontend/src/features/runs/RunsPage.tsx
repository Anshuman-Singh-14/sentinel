import { useInfiniteQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router";

import { Button, DataTable, SeverityBadge } from "../../components/ui";
import type { Column } from "../../components/ui";
import { runsApi } from "../../lib/api/endpoints";
import type { RunFilters } from "../../lib/api/endpoints";
import { errorMessage } from "../../lib/api/errors";
import { formatDateTime } from "../../lib/format";
import type { RunStatus, RunSummary } from "../../types/api";
import { RUN_STATUSES, isTerminal } from "../../types/api";
import { useToolCatalogue } from "../tools/useToolCatalogue";
import { RunStatusBadge } from "./components";

const selectClass =
  "rounded border border-border-strong bg-surface px-3 py-2 text-sm text-text focus:border-accent focus:outline-none";

const COLUMNS: Column<RunSummary>[] = [
  {
    id: "created",
    header: "Started",
    cell: (r) => <span className="whitespace-nowrap">{formatDateTime(r.created_at)}</span>,
  },
  { id: "tool", header: "Tool", cell: (r) => r.tool_name },
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
        <span className="text-muted">{isTerminal(r.status) ? "none" : "—"}</span>
      ),
  },
  { id: "user", header: "By", cell: (r) => r.initiated_by },
];

/** Run history: every authenticated role can read results (viewers included). */
export function RunsPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const catalogue = useToolCatalogue();
  const statusParam = params.get("status");
  const filters: RunFilters = {
    mine: params.get("mine") === "1",
    tool_id: params.get("tool_id") || undefined,
    status: RUN_STATUSES.includes(statusParam as RunStatus)
      ? (statusParam as RunStatus)
      : undefined,
  };

  const runs = useInfiniteQuery({
    queryKey: ["runs", "list", filters],
    queryFn: ({ pageParam, signal }) => runsApi.list(filters, pageParam, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_before ?? undefined,
    // Keep active runs moving in the list without a socket per row.
    refetchInterval: (q) =>
      q.state.data?.pages.some((p) => p.runs.some((r) => !isTerminal(r.status))) ? 5000 : false,
  });
  const rows = runs.data?.pages.flatMap((p) => p.runs) ?? [];

  const setFilter = (key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-lg font-semibold">Run history</h1>
        <p className="mt-1 text-sm text-muted">Every tool run, newest first.</p>
      </div>

      <div className="flex flex-wrap items-end gap-4 rounded border border-border bg-panel p-4">
        <label className="flex flex-col gap-1.5 text-xs font-semibold tracking-wider text-muted uppercase">
          Tool
          <select
            className={selectClass}
            value={filters.tool_id ?? ""}
            onChange={(e) => setFilter("tool_id", e.target.value || null)}
          >
            <option value="">All tools</option>
            {(catalogue.data ?? []).map((t) => (
              <option key={t.tool_id} value={t.tool_id}>
                {t.name}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1.5 text-xs font-semibold tracking-wider text-muted uppercase">
          Status
          <select
            className={selectClass}
            value={filters.status ?? ""}
            onChange={(e) => setFilter("status", e.target.value || null)}
          >
            <option value="">Any</option>
            {RUN_STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2 pb-2 text-sm">
          <input
            type="checkbox"
            className="accent-accent"
            checked={filters.mine}
            onChange={(e) => setFilter("mine", e.target.checked ? "1" : null)}
          />
          Only my runs
        </label>
      </div>

      {runs.isError && (
        <p role="alert" className="text-sm text-fail">
          {errorMessage(runs.error)}
        </p>
      )}

      <DataTable
        caption="Tool runs, newest first"
        columns={COLUMNS}
        rows={rows}
        getRowId={(r) => r.run_id}
        loading={runs.isPending}
        emptyMessage="No runs match these filters."
        onRowClick={(r) => navigate(`/runs/${r.run_id}`)}
        rowActionLabel={(r) =>
          `Open ${r.tool_name} run on ${r.target ?? "unknown target"}, ${r.status}`
        }
      />

      {runs.hasNextPage && (
        <div>
          <Button
            variant="secondary"
            size="sm"
            loading={runs.isFetchingNextPage}
            onClick={() => void runs.fetchNextPage()}
          >
            Load older runs
          </Button>
        </div>
      )}
    </div>
  );
}
