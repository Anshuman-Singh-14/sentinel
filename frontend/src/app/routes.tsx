import type { RouteObject } from "react-router";

import { AccountPage } from "../features/auth/AccountPage";
import { RequireAuth, RequireRole } from "../features/auth/guards";
import { LoginPage } from "../features/auth/LoginPage";
import { AuditPage } from "../features/audit/AuditPage";
import { DashboardPage } from "../features/dashboard/DashboardPage";
import { PlaybookRunPage } from "../features/playbooks/PlaybookRunPage";
import { PlaybooksPage } from "../features/playbooks/PlaybooksPage";
import { RunPage } from "../features/runs/RunPage";
import { RunsPage } from "../features/runs/RunsPage";
import { ScopePage } from "../features/scope/ScopePage";
import { LOCAL_TOOLS, localToolPath } from "../features/tools/registry";
import { ToolPage } from "../features/tools/ToolPage";
import { AppShell } from "./layout/AppShell";
import { NotFoundPage, RouteErrorPage } from "./NotFoundPage";

/**
 * Route table. Everything except /login sits behind RequireAuth; admin pages
 * add RequireRole. Exported separately from the browser router so tests can
 * mount it in a memory router.
 */
export const routes: RouteObject[] = [
  { path: "/login", element: <LoginPage />, errorElement: <RouteErrorPage /> },
  {
    element: <RequireAuth />,
    errorElement: <RouteErrorPage />,
    children: [
      {
        element: <AppShell />,
        children: [
          { index: true, element: <DashboardPage /> },
          { path: "tools/:toolId", element: <ToolPage /> },
          { path: "runs", element: <RunsPage /> },
          { path: "playbooks", element: <PlaybooksPage /> },
          { path: "playbook-runs/:playbookRunId", element: <PlaybookRunPage /> },
          { path: "runs/:runId", element: <RunPage /> },
          // One route per local tool, generated from the manifest. Each is
          // code-split; the router loads the chunk before navigating.
          ...LOCAL_TOOLS.filter((tool) => tool.available).map((tool): RouteObject => ({
            path: localToolPath(tool.id).slice(1),
            lazy: async () => ({ Component: (await tool.load()).default }),
          })),
          { path: "account", element: <AccountPage /> },
          {
            path: "admin",
            element: <RequireRole role="admin" />,
            children: [
              { path: "audit", element: <AuditPage /> },
              { path: "scope", element: <ScopePage /> },
            ],
          },
          { path: "*", element: <NotFoundPage /> },
        ],
      },
    ],
  },
];
