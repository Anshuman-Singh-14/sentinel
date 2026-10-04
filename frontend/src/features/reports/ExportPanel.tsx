import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileDown } from "lucide-react";

import { Button, Card, useToast } from "../../components/ui";
import { reportsApi } from "../../lib/api/endpoints";
import { errorMessage } from "../../lib/api/errors";
import { formatDateTime } from "../../lib/format";
import type { ReportSourceType } from "../../types/api";
import { isReportActive, roleAllows } from "../../types/api";
import { useUser } from "../auth/guards";
import { RunStatusBadge } from "../runs/components";
import { DownloadReportButton, formatBytes } from "./components";

export const reportsForSourceKey = (sourceId: string) => ["reports", "source", sourceId];

/**
 * Export a finished run (tool or playbook) as PDF/CSV/JSON/TXT.
 *
 * The buttons come from the server's exporter registry, so a new exporter
 * appears here without a frontend change. Generation runs in a worker; the
 * list polls every 2 s while a report is being generated. Viewers see and
 * download existing reports but cannot request new ones (server-enforced too).
 */
export function ExportPanel({
  sourceType,
  sourceId,
}: {
  sourceType: ReportSourceType;
  sourceId: string;
}) {
  const user = useUser();
  const toast = useToast();
  const queryClient = useQueryClient();
  const mayExport = roleAllows(user.role, "analyst");

  const formats = useQuery({
    queryKey: ["reports", "formats"],
    queryFn: ({ signal }) => reportsApi.formats(signal),
    staleTime: Infinity,
    enabled: mayExport,
  });
  const reports = useQuery({
    queryKey: reportsForSourceKey(sourceId),
    queryFn: ({ signal }) => reportsApi.list({ source_id: sourceId }, undefined, signal),
    refetchInterval: (q) =>
      q.state.data?.reports.some((r) => isReportActive(r.status)) ? 2000 : false,
  });
  const create = useMutation({
    mutationFn: (format: string) => reportsApi.create(sourceType, sourceId, format),
    onSuccess: (report) => {
      void queryClient.invalidateQueries({ queryKey: reportsForSourceKey(sourceId) });
      void queryClient.invalidateQueries({ queryKey: ["reports", "list"] });
      toast.show({
        tone: "info",
        title: `${report.format.toUpperCase()} report requested`,
        description: "It appears below when it is ready.",
      });
    },
    onError: (error) =>
      toast.show({ tone: "error", title: "Could not export", description: errorMessage(error) }),
  });

  const rows = reports.data?.reports ?? [];

  return (
    <Card title="Reports" eyebrow="Export" aria-label="Reports">
      <div className="flex flex-col gap-4">
        {mayExport && (
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm text-muted">Export as</span>
            {(formats.data ?? []).map((f) => (
              <Button
                key={f.format}
                variant="secondary"
                size="sm"
                loading={create.isPending && create.variables === f.format}
                disabled={create.isPending}
                onClick={() => create.mutate(f.format)}
              >
                <FileDown size={14} aria-hidden="true" />
                {f.label}
              </Button>
            ))}
            {formats.isError && (
              <span role="alert" className="text-xs text-fail">
                {errorMessage(formats.error)}
              </span>
            )}
          </div>
        )}
        {reports.isError && (
          <p role="alert" className="text-sm text-fail">
            {errorMessage(reports.error)}
          </p>
        )}
        {rows.length === 0 ? (
          <p className="text-sm text-muted">
            {mayExport ? "No reports yet." : "No reports have been exported for this run."}
          </p>
        ) : (
          <ul className="flex flex-col divide-y divide-border" aria-label="Reports for this run">
            {rows.map((report) => (
              <li
                key={report.report_id}
                className="flex flex-wrap items-center justify-between gap-3 py-2 text-sm"
              >
                <span className="flex min-w-0 flex-wrap items-center gap-2">
                  <span className="font-semibold">{report.format.toUpperCase()}</span>
                  <RunStatusBadge status={report.status} />
                  <span className="text-xs text-muted">
                    {formatDateTime(report.created_at)} · {report.requested_by}
                    {report.size_bytes !== null && ` · ${formatBytes(report.size_bytes)}`}
                  </span>
                </span>
                {report.status === "COMPLETED" && <DownloadReportButton report={report} />}
                {report.error && (
                  <span role="alert" className="w-full text-xs text-fail">
                    {report.error.message}
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
        <p className="text-xs text-muted">
          Reports contain the target and findings: share them only with people authorised to see
          this assessment. Every export and download is recorded in the audit log.
        </p>
      </div>
    </Card>
  );
}
