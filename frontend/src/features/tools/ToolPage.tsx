import { useParams } from "react-router";

import { Badge, Card, JsonViewer, Spinner, Tabs } from "../../components/ui";
import { errorMessage } from "../../lib/api/errors";
import { roleAllows } from "../../types/api";
import { NotFoundPage } from "../../app/NotFoundPage";
import { useUser } from "../auth/guards";
import { CATEGORY_LABELS } from "./registry";
import { useToolCatalogue } from "./useToolCatalogue";

/**
 * Backend tool page. Phase 3 shows the catalogue entry; the run form, live
 * status and result viewer arrive with the task infrastructure in Phase 5.
 */
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

      <Card title="Run">
        <p className="text-sm text-muted">
          {canRun
            ? "Running tools from the console arrives with the task infrastructure in a later phase."
            : `Your role (${user.role}) can view this tool's results but cannot run it.`}
        </p>
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
