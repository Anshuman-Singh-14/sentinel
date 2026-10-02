import type { RouteObject } from "react-router";

import { AccountPage } from "../features/auth/AccountPage";
import { RequireAuth, RequireRole } from "../features/auth/guards";
import { LoginPage } from "../features/auth/LoginPage";
import { AuditPage } from "../features/audit/AuditPage";
import { DashboardPage } from "../features/dashboard/DashboardPage";
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
          { path: "account", element: <AccountPage /> },
          {
            path: "admin",
            element: <RequireRole role="admin" />,
            children: [{ path: "audit", element: <AuditPage /> }],
          },
          { path: "*", element: <NotFoundPage /> },
        ],
      },
    ],
  },
];
