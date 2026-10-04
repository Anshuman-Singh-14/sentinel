import { useInfiniteQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router";

import { Button, DataTable } from "../../components/ui";
import type { Column } from "../../components/ui";
import { reportsApi } from "../../lib/api/endpoints";
import type { ReportFilters } from "../../lib/api/endpoints";
import { errorMessage } from "../../lib/api/errors";
import { formatDateTime } from "../../lib/format";
import type { Report } from "../../types/api";
import { isReportActive } from "../../types/api";
import { RunStatusBadge } from "../runs/components";
import { DownloadReportButton, formatBytes } from "./components";

function sourcePath(r: Report): string {
  return r.source_type === "playbook_run"
    ? `/playbook-runs/${r.source_id}`
    : `/runs/${r.source_id}`;
}

const COLUMNS: Column<Report>[] = [
  {
    id: "created",
    header: "Requested",
    cell: (r) => <span className="whitespace-nowrap">{formatDateTime(r.created_at)}</span>,
  },
  { id: "title", header: "Report", cell: (r) => r.title },
  {
    id: "target",
    header: "Target",
    cell: (r) => <span className="break-all">{r.target ?? "—"}</span>,
  },
  {
    id: "status",
    header: "Status",
    cell: (r) => (
      <span className="flex flex-col gap-1">
        <RunStatusBadge status={r.status} />
        {r.error && <span className="text-xs text-fail">{r.error.message}</span>}
      </span>
    ),
  },
  { id: "size", header: "Size", cell: (r) => formatBytes(r.size_bytes) },
  { id: "user", header: "By", cell: (r) => r.requested_by },
  {
    id: "download",
    header: <span className="sr-only">Download</span>,
    cell: (r) =>
      r.status === "COMPLETED" ? (
        <DownloadReportButton report={r} />
      ) : (
        <span className="text-xs font-semibold text-muted">{r.format.toUpperCase()}</span>
      ),
  },
];

/** Report history. Every role can read and download; analysts export from run pages. */
export function ReportsPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const filters: ReportFilters = { mine: params.get("mine") === "1" };

  const reports = useInfiniteQuery({
    queryKey: ["reports", "list", filters],
    queryFn: ({ pageParam, signal }) => reportsApi.list(filters, pageParam, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_before ?? undefined,
    refetchInterval: (q) =>
      q.state.data?.pages.some((p) => p.reports.some((r) => isReportActive(r.status)))
        ? 3000
        : false,
  });
  const rows = reports.data?.pages.flatMap((p) => p.reports) ?? [];

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-lg font-semibold">Reports</h1>
        <p className="mt-1 text-sm text-muted">
          Exported reports, newest first. Export a new one from a finished run or playbook run. Each
          file is checked against its SHA-256 before it is served.
        </p>
      </div>

      <div className="flex flex-wrap items-end gap-4 rounded border border-border bg-panel p-4">
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            className="accent-accent"
            checked={filters.mine}
            onChange={(e) => {
              const next = new URLSearchParams(params);
              if (e.target.checked) next.set("mine", "1");
              else next.delete("mine");
              setParams(next, { replace: true });
            }}
          />
          Only my reports
        </label>
      </div>

      {reports.isError && (
        <p role="alert" className="text-sm text-fail">
          {errorMessage(reports.error)}
        </p>
      )}

      <DataTable
        caption="Reports, newest first"
        columns={COLUMNS}
        rows={rows}
        getRowId={(r) => r.report_id}
        loading={reports.isPending}
        emptyMessage="No reports yet."
        onRowClick={(r) => navigate(sourcePath(r))}
        rowActionLabel={(r) => `Open the run behind ${r.title} (${r.format.toUpperCase()})`}
      />

      {reports.hasNextPage && (
        <div>
          <Button
            variant="secondary"
            size="sm"
            loading={reports.isFetchingNextPage}
            onClick={() => void reports.fetchNextPage()}
          >
            Load older reports
          </Button>
        </div>
      )}
    </div>
  );
}
