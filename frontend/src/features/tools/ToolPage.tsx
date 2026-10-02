import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router";

import { NotFoundPage } from "../../app/NotFoundPage";
import { Badge, Card, JsonViewer, Spinner, Tabs } from "../../components/ui";
import { runsApi } from "../../lib/api/endpoints";
import { ApiError, errorMessage } from "../../lib/api/errors";
import type { ToolDescriptor } from "../../types/api";
import { roleAllows } from "../../types/api";
import { useUser } from "../auth/guards";
import { ACK_QUERY_KEY, AuthorizationGate, ScopeSummary } from "../scope/AuthorizationGate";
import { runQueryKey } from "../runs/useRunStatus";
import { CATEGORY_LABELS } from "./registry";
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

function RunForm({ tool }: { tool: ToolDescriptor }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const start = useMutation({
    mutationFn: (params: Record<string, unknown>) => runsApi.create(tool.tool_id, params),
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

  return (
    <div className="flex flex-col gap-3">
      <SchemaForm
        schema={tool.params_schema as ObjectSchema}
        submitLabel="Run"
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
        </div>
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
        {canRun && tool.is_active ? (
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
