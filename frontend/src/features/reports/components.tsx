import { useMutation } from "@tanstack/react-query";
import { Download } from "lucide-react";

import { Button, useToast } from "../../components/ui";
import { saveBlob } from "../../lib/api/client";
import { reportsApi } from "../../lib/api/endpoints";
import { errorMessage } from "../../lib/api/errors";
import type { Report } from "../../types/api";

export function formatBytes(bytes: number | null): string {
  if (bytes === null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Downloads go through the API client (session refresh, timeout) rather than
 * a plain link. The filename comes from the server's report record, which
 * builds it from a strict ASCII slug.
 */
export function DownloadReportButton({ report }: { report: Report }) {
  const toast = useToast();
  const download = useMutation({
    mutationFn: () => reportsApi.download(report.report_id),
    onSuccess: ({ blob }) => saveBlob(blob, report.filename ?? `sentinel-report.${report.format}`),
    onError: (error) =>
      toast.show({ tone: "error", title: "Download failed", description: errorMessage(error) }),
  });
  return (
    <Button
      variant="secondary"
      size="sm"
      loading={download.isPending}
      onClick={(event) => {
        event.stopPropagation(); // inside clickable table rows
        download.mutate();
      }}
      aria-label={`Download ${report.format.toUpperCase()} report: ${report.title}`}
    >
      <Download size={14} aria-hidden="true" />
      {report.format.toUpperCase()}
    </Button>
  );
}
