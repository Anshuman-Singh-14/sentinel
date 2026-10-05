import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Suspense, useId, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { NotFoundPage } from "../../app/NotFoundPage";
import { Badge, Card, JsonViewer, Spinner, Tabs } from "../../components/ui";
import { runsApi } from "../../lib/api/endpoints";
import { ApiError, errorMessage } from "../../lib/api/errors";
import type { ProviderStatus, ToolDescriptor } from "../../types/api";
import { roleAllows } from "../../types/api";
import { useUser } from "../auth/guards";
import { ACK_QUERY_KEY, AuthorizationGate, ScopeSummary } from "../scope/AuthorizationGate";
import { runQueryKey } from "../runs/useRunStatus";
import { CATEGORY_LABELS, REMOTE_TOOL_META } from "./registry";
import { SchemaForm } from "./SchemaForm";
import type { ObjectSchema } from "./SchemaForm";
import { useToolCatalogue } from "./useToolCatalogue";

/**
 * Map a 422 from the API to per-field messages. Tool parameters arrive as
 * `loc: ["params", field]`, playbook inputs as `loc: ["inputs", field]`.
 */
export function fieldErrors(error: unknown, root = "params"): Record<string, string> {
  if (!(error instanceof ApiError) || error.code !== "validation_failed") return {};
  const errors = (error.details.errors ?? []) as Array<{ loc?: unknown[]; msg?: string }>;
  const out: Record<string, string> = {};
  for (const e of errors) {
    const field = e.loc?.[0] === root ? e.loc[1] : undefined;
    if (typeof field === "string" && e.msg) out[field] = e.msg.replace(/^Value error, /, "");
  }
  return out;
}

function formatMegabytes(bytes: number): string {
  const mb = 1024 * 1024;
  return bytes >= mb
    ? `${Math.round(bytes / mb)} MB`
    : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

/**
 * File picker for tools that accept uploads (ADR 0014). The file goes to the
 * server as the raw request body; its contents are never read or kept by the
 * browser app itself. The size limit is checked here for fast feedback and
 * enforced again by the server.
 */
function FilePicker({
  maxBytes,
  error,
  onChange,
}: {
  maxBytes: number | null | undefined;
  error: string | null;
  onChange: (file: File | null) => void;
}) {
  const id = useId();
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-xs font-semibold tracking-wider text-muted uppercase">
        Upload a file
      </label>
      <input
        id={id}
        type="file"
        aria-describedby={`${id}-hint`}
        aria-invalid={error ? true : undefined}
        className="text-sm text-text file:mr-3 file:rounded file:border file:border-border-strong file:bg-surface file:px-3 file:py-1.5 file:text-sm file:text-text"
        onChange={(event) => onChange(event.target.files?.[0] ?? null)}
      />
      <p id={`${id}-hint`} className="text-xs text-muted">
        Optional{maxBytes ? `, up to ${formatMegabytes(maxBytes)}` : ""}. Plain text or .gz. The
        file is analysed on the server and deleted when the run ends.
      </p>
      {error && (
        <p role="alert" className="text-xs text-fail">
          {error}
        </p>
      )}
    </div>
  );
}

function RunForm({ tool }: { tool: ToolDescriptor }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const start = useMutation({
    mutationFn: (params: Record<string, unknown>) =>
      file ? runsApi.upload(tool.tool_id, file, params) : runsApi.create(tool.tool_id, params),
    onSuccess: (run) => {
      queryClient.setQueryData(runQueryKey(run.run_id), run);
      void queryClient.invalidateQueries({ queryKey: ["runs", "list"] });
      navigate(`/runs/${run.run_id}`);
    },
    onError: (error) => {
      // The server is the authority: if it says the statement is needed
      // (e.g. a new version), show the gate again.
      if (error instanceof ApiError && error.code === "authorization_required") {
        void queryClient.invalidateQueries({ queryKey: ACK_QUERY_KEY });
      }
    },
  });
  const serverErrors = fieldErrors(start.error);
  const generalError =
    start.isError && Object.keys(serverErrors).length === 0 ? errorMessage(start.error) : null;

  function chooseFile(chosen: File | null) {
    const max = tool.max_upload_bytes;
    if (chosen && max && chosen.size > max) {
      setFile(null);
      setFileError(`That file is larger than the ${formatMegabytes(max)} limit.`);
      return;
    }
    setFileError(null);
    setFile(chosen);
  }

  return (
    <div className="flex flex-col gap-3">
      {tool.accepts_upload && (
        <FilePicker maxBytes={tool.max_upload_bytes} error={fileError} onChange={chooseFile} />
      )}
      <SchemaForm
        schema={tool.params_schema as ObjectSchema}
        submitLabel={file ? "Upload and run" : "Run"}
        busy={start.isPending}
        serverErrors={serverErrors}
        onSubmit={(params) => start.mutate(params)}
      />
      {generalError && (
        <p role="alert" className="text-sm text-fail">
          {generalError}
        </p>
      )}
    </div>
  );
}

/** Backend tool page: description, a generated run form and the tool contract. */
export function ToolPage() {
  const { toolId } = useParams();
  const user = useUser();
  const catalogue = useToolCatalogue();

  if (catalogue.isPending) return <Spinner label="Loading tool" />;
  if (catalogue.isError) {
    return (
      <p role="alert" className="text-sm text-fail">
        {errorMessage(catalogue.error)}
      </p>
    );
  }
  const tool = catalogue.data.find((t) => t.tool_id === toolId);
  if (!tool) return <NotFoundPage />;

  const canRun = roleAllows(user.role, tool.required_role);
  const configured = tool.available !== false;
  const providers = providerStatus(tool);
  // Optional tool-specific UI from the registry (a lazily loaded chunk).
  const Panel = REMOTE_TOOL_META[tool.tool_id]?.panel;

  return (
    <div className="flex max-w-4xl flex-col gap-6">
      <div>
        <p className="text-[0.7rem] font-semibold tracking-[0.2em] text-muted uppercase">
          {CATEGORY_LABELS[tool.category]}
        </p>
        <h1 className="mt-1 text-lg font-semibold">{tool.name}</h1>
        <p className="mt-1 text-sm text-muted">{tool.description}</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <Badge>v{tool.version}</Badge>
          {tool.is_active ? (
            <Badge tone="warn">Active: sends traffic to the target</Badge>
          ) : (
            <Badge tone="ok">Passive</Badge>
          )}
          <Badge tone={canRun ? "accent" : "fail"}>Requires {tool.required_role}</Badge>
          {!configured && <Badge tone="warn">Not configured</Badge>}
        </div>
        {providers.length > 0 && <ProviderList providers={providers} />}
      </div>

      <Card
        title="Run"
        actions={
          <Link
            to={`/runs?tool_id=${encodeURIComponent(tool.tool_id)}`}
            className="text-xs font-semibold text-accent hover:underline"
          >
            Previous runs
          </Link>
        }
      >
        {!configured ? (
          <p role="status" className="text-sm text-warn">
            {tool.unavailable_reason ?? "This tool is installed but not configured yet."}
          </p>
        ) : canRun && tool.is_active ? (
          <div className="flex flex-col gap-4">
            <ScopeSummary />
            <AuthorizationGate>
              <RunForm tool={tool} />
            </AuthorizationGate>
          </div>
        ) : canRun ? (
          <RunForm tool={tool} />
        ) : (
          <p className="text-sm text-muted">
            Your role ({user.role}) can view this tool's results but cannot run it.
          </p>
        )}
      </Card>

      {Panel && configured && (
        <Suspense fallback={<Spinner label="Loading" />}>
          <Panel toolId={tool.tool_id} />
        </Suspense>
      )}

      <Card title="Contract">
        <Tabs
          label="Tool contract"
          items={[
            {
              id: "params",
              label: "Parameters",
              content: (
                <JsonViewer
                  value={tool.params_schema}
                  label="Parameter JSON Schema"
                  defaultExpandDepth={2}
                />
              ),
            },
            {
              id: "descriptor",
              label: "Descriptor",
              content: <JsonViewer value={tool} label="Tool descriptor" />,
            },
          ]}
        />
      </Card>
    </div>
  );
}

function providerStatus(tool: ToolDescriptor): ProviderStatus[] {
  const providers = tool.status?.providers;
  return Array.isArray(providers) ? (providers as ProviderStatus[]) : [];
}

/** Which third-party providers back this tool. Status only: keys never reach the browser. */
function ProviderList({ providers }: { providers: ProviderStatus[] }) {
  return (
    <ul className="mt-3 flex flex-wrap gap-2" aria-label="Providers">
      {providers.map((p) => (
        <li key={p.id}>
          <Badge
            tone={p.configured ? "ok" : "neutral"}
            title={`Supports: ${p.supports.join(", ")}`}
          >
            {p.name}: {p.configured ? "configured" : `set ${p.env_var}`}
          </Badge>
        </li>
      ))}
    </ul>
  );
}
