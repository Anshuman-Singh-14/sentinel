import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { __resetClientStateForTests } from "../../lib/api/client";
import { errorResponse, jsonResponse, makeUser, mockFetch, renderApp } from "../../test/utils";
import type { Acknowledgement, ScopeView, ToolDescriptor } from "../../types/api";

afterEach(() => __resetClientStateForTests());

const SCANNER: ToolDescriptor = {
  tool_id: "port_scanner",
  name: "Port Scanner & Banner Grabber",
  description: "TCP connect scan.",
  version: "1.0.0",
  category: "RECON",
  is_active: true,
  required_role: "analyst",
  params_schema: {
    type: "object",
    required: ["target"],
    properties: {
      target: { type: "string", title: "Target", maxLength: 253 },
      preset: {
        type: "string",
        title: "Preset",
        enum: ["top-100", "top-1000", "web", "custom"],
        default: "top-100",
      },
    },
  },
};

const STATEMENT =
  "I will only scan or test systems that I own or for which I have explicit, written permission.";
const NOT_ACKED: Acknowledgement = {
  acknowledged: false,
  version: 1,
  statement: STATEMENT,
  acknowledged_at: null,
};
const ACKED: Acknowledgement = {
  ...NOT_ACKED,
  acknowledged: true,
  acknowledged_at: "2026-10-02T12:00:00Z",
};

const SCOPE: ScopeView = {
  rules: [
    {
      id: null,
      kind: "cidr",
      value: "10.231.10.0/24",
      description: "Built-in (SCOPE_DEFAULT_ALLOW)",
      source: "builtin",
      enabled: true,
    },
    {
      id: "s1",
      kind: "domain",
      value: "example.org",
      description: "Owned",
      source: "admin",
      enabled: true,
    },
  ],
  hard_deny: null,
};

function base(user = makeUser(), extra: Parameters<typeof mockFetch>[0] = {}) {
  return mockFetch({
    "GET /api/v1/auth/me": jsonResponse(user),
    "GET /api/v1/tools": jsonResponse([SCANNER]),
    "GET /health": jsonResponse({ status: "ok", version: "0.6.0" }),
    "GET /api/v1/scope": jsonResponse(SCOPE),
    ...extra,
  });
}

describe("authorised-use gate on active tools", () => {
  it("requires accepting the statement before the run form appears", async () => {
    let acked = false;
    const fetchMock = base(makeUser(), {
      "GET /api/v1/scope/acknowledgement": () => jsonResponse(acked ? ACKED : NOT_ACKED),
      "POST /api/v1/scope/acknowledgement": () => {
        acked = true;
        return jsonResponse(ACKED);
      },
    });
    renderApp("/tools/port_scanner");

    expect(await screen.findByText(STATEMENT)).toBeInTheDocument();
    expect(screen.queryByLabelText("Target")).not.toBeInTheDocument();
    const accept = screen.getByRole("button", { name: /accept and continue/i });
    expect(accept).toBeDisabled();
    await userEvent.click(screen.getByLabelText(/i have read and accept/i));
    await userEvent.click(accept);

    expect(await screen.findByLabelText("Target")).toBeInTheDocument();
    const call = fetchMock.mock.calls.find(
      ([u, init]) =>
        u === "/api/v1/scope/acknowledgement" && (init as RequestInit).method === "POST",
    )!;
    expect(JSON.parse((call[1] as RequestInit).body as string)).toEqual({ statement_version: 1 });
  });

  it("shows the allowed targets and never-scanned note", async () => {
    base(makeUser(), { "GET /api/v1/scope/acknowledgement": jsonResponse(ACKED) });
    renderApp("/tools/port_scanner");
    await userEvent.click(await screen.findByText(/allowed targets \(2 rules\)/i));
    expect(screen.getByText("10.231.10.0/24")).toBeInTheDocument();
    expect(screen.getByText("*.example.org")).toBeInTheDocument();
    expect(screen.getByText(/always blocked/)).toBeInTheDocument();
  });

  it("explains a scope denial from the server", async () => {
    base(makeUser(), {
      "GET /api/v1/scope/acknowledgement": jsonResponse(ACKED),
      "POST /api/v1/tools/port_scanner/runs": errorResponse(
        403,
        "scope_denied",
        "postgres resolves to 10.231.0.2, inside a protected range (10.231.0.0/24) that Sentinel never scans.",
      ),
    });
    renderApp("/tools/port_scanner");
    await userEvent.type(await screen.findByLabelText("Target"), "postgres");
    await userEvent.click(screen.getByRole("button", { name: "Run" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/never scans/);
  });

  it("re-shows the gate if the server says the statement is required", async () => {
    let acked = true;
    base(makeUser(), {
      "GET /api/v1/scope/acknowledgement": () => jsonResponse(acked ? ACKED : NOT_ACKED),
      "POST /api/v1/tools/port_scanner/runs": () => {
        acked = false;
        return errorResponse(403, "authorization_required", "Accept the statement.");
      },
    });
    renderApp("/tools/port_scanner");
    await userEvent.type(await screen.findByLabelText("Target"), "lab-web");
    await userEvent.click(screen.getByRole("button", { name: "Run" }));
    expect(await screen.findByText(STATEMENT)).toBeInTheDocument();
  });

  it("does not gate passive tools", async () => {
    mockFetch({
      "GET /api/v1/auth/me": jsonResponse(makeUser()),
      "GET /api/v1/tools": jsonResponse([{ ...SCANNER, tool_id: "dns_lookup", is_active: false }]),
      "GET /health": jsonResponse({ status: "ok", version: "0.6.0" }),
    });
    renderApp("/tools/dns_lookup");
    expect(await screen.findByLabelText("Target")).toBeInTheDocument();
    expect(screen.queryByText(/authorised use only/i)).not.toBeInTheDocument();
  });
});

describe("admin scope page", () => {
  const ADMIN = makeUser({ role: "admin", username: "root" });
  const ADMIN_SCOPE: ScopeView = {
    rules: [
      ...SCOPE.rules,
      {
        id: "s2",
        kind: "cidr",
        value: "192.0.2.0/24",
        description: "Lab 2",
        source: "admin",
        enabled: false,
      },
    ],
    hard_deny: ["169.254.0.0/16", "10.231.0.0/24"],
  };

  it("lists rules and the hard denylist, and manages entries", async () => {
    const fetchMock = base(ADMIN, {
      "GET /api/v1/admin/scope": jsonResponse(ADMIN_SCOPE),
      "GET /api/v1/admin/alerts": jsonResponse([]),
      "POST /api/v1/admin/scope": jsonResponse(
        {
          id: "s3",
          kind: "cidr",
          value: "198.51.100.0/24",
          description: "",
          source: "admin",
          enabled: true,
        },
        201,
      ),
      "PATCH /api/v1/admin/scope/s2": jsonResponse({ ...ADMIN_SCOPE.rules[2], enabled: true }),
      "DELETE /api/v1/admin/scope/s1": new Response(null, { status: 204 }),
    });
    renderApp("/admin/scope");

    const table = await screen.findByRole("table", { name: "Scope policy rules" });
    expect(within(table).getByText("10.231.10.0/24")).toBeInTheDocument();
    expect(within(table).getByText("Always on")).toBeInTheDocument();
    expect(screen.getByText("169.254.0.0/16")).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("Address or range"), "198.51.100.7/24");
    await userEvent.click(screen.getByRole("button", { name: "Add to scope" }));
    expect(await screen.findByText("Added 198.51.100.0/24 to the scope")).toBeInTheDocument();
    const post = fetchMock.mock.calls.find(
      ([u, i]) => u === "/api/v1/admin/scope" && (i as RequestInit).method === "POST",
    )!;
    expect(JSON.parse((post[1] as RequestInit).body as string)).toEqual({
      kind: "cidr",
      value: "198.51.100.7/24",
      description: "",
    });

    await userEvent.click(screen.getByRole("button", { name: "Enable 192.0.2.0/24" }));
    await userEvent.click(screen.getByRole("button", { name: "Remove example.org" }));
    await waitFor(() => {
      const methods = fetchMock.mock.calls.map(
        ([u, i]) => `${(i as RequestInit).method ?? "GET"} ${u}`,
      );
      expect(methods).toContain("PATCH /api/v1/admin/scope/s2");
      expect(methods).toContain("DELETE /api/v1/admin/scope/s1");
    });
  });

  it("shows server validation errors on the field", async () => {
    base(ADMIN, {
      "GET /api/v1/admin/scope": jsonResponse(ADMIN_SCOPE),
      "GET /api/v1/admin/alerts": jsonResponse([]),
      "POST /api/v1/admin/scope": errorResponse(
        422,
        "validation_failed",
        "10.231.0.0/16 overlaps 10.231.0.0/24, which Sentinel never scans (its own infrastructure or a reserved range).",
      ),
    });
    renderApp("/admin/scope");
    await userEvent.type(await screen.findByLabelText("Address or range"), "10.231.0.0/16");
    await userEvent.click(screen.getByRole("button", { name: "Add to scope" }));
    expect(await screen.findByText(/overlaps 10.231.0.0\/24/)).toBeInTheDocument();
  });

  it("is admin-only", async () => {
    base(makeUser({ role: "analyst" }));
    renderApp("/admin/scope");
    expect(await screen.findByRole("heading", { name: "Access denied" })).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).queryByText("Scope policy")).not.toBeInTheDocument();
  });
});
