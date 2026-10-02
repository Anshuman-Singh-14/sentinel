import { render } from "@testing-library/react";
import { QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { vi } from "vitest";

import { AppProviders } from "../app/providers";
import { routes } from "../app/routes";
import type { SessionInfo, ToolDescriptor, User } from "../types/api";

export function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

export function errorResponse(status: number, code: string, message = code) {
  return jsonResponse({ error: { code, message, request_id: "req-1", details: {} } }, status);
}

type Handler = (request: { url: string; init: RequestInit }) => Response | Promise<Response>;

/**
 * Stub `fetch` with a "METHOD /path" → handler table. Query strings are
 * ignored for matching. Unmatched requests fail loudly so a test cannot pass
 * by accident.
 */
export function mockFetch(routes: Record<string, Handler | Response>) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = typeof input === "string" ? input : input.toString();
    const method = (init.method ?? "GET").toUpperCase();
    const path = url.split("?")[0];
    const handler = routes[`${method} ${path}`];
    if (!handler) throw new Error(`Unexpected request: ${method} ${url}`);
    if (handler instanceof Response) return handler.clone();
    return handler({ url, init });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

export function makeUser(overrides: Partial<User> = {}): User {
  return {
    id: "00000000-0000-0000-0000-000000000001",
    username: "analyst01",
    role: "analyst",
    is_active: true,
    created_at: "2026-10-01T10:00:00Z",
    last_login_at: "2026-10-02T09:00:00Z",
    locked_until: null,
    ...overrides,
  };
}

export function makeSession(user: User): SessionInfo {
  return {
    user,
    session_id: "00000000-0000-0000-0000-0000000000aa",
    access_expires_at: "2026-10-02T10:15:00Z",
    refresh_expires_at: "2026-10-02T22:00:00Z",
  };
}

export const ECHO_TOOL: ToolDescriptor = {
  tool_id: "echo",
  name: "Echo",
  description: "Returns its input. Proves the tool contract.",
  version: "1.0.0",
  category: "DIAGNOSTIC",
  is_active: false,
  required_role: "analyst",
  params_schema: { type: "object", properties: { message: { type: "string" } } },
};

/** Mount the real route table in a memory router with fresh providers. */
export function renderApp(initialPath = "/") {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const router = createMemoryRouter(routes, { initialEntries: [initialPath] });
  const result = render(
    <AppProviders client={client}>
      <RouterProvider router={router} />
    </AppProviders>,
  );
  return { ...result, router, client };
}
