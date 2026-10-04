/**
 * Tools that need configuration (Phase 8 threat intel): the catalogue says
 * whether the tool is usable and which providers are configured, and the UI
 * explains what is missing instead of offering a form that would fail.
 */

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { __resetClientStateForTests } from "../../lib/api/client";
import { jsonResponse, makeUser, mockFetch, renderApp } from "../../test/utils";
import type { PlaybookInfo, ProviderStatus, ToolDescriptor } from "../../types/api";

const USER = makeUser();

function providers(configured: string[]): ProviderStatus[] {
  return [
    ["abuseipdb", "AbuseIPDB", "ABUSEIPDB_API_KEY", ["ip"]],
    ["virustotal", "VirusTotal", "VIRUSTOTAL_API_KEY", ["domain", "hash", "ip"]],
    ["shodan", "Shodan", "SHODAN_API_KEY", ["ip"]],
  ].map(([id, name, env_var, supports]) => ({
    id: id as string,
    name: name as string,
    env_var: env_var as string,
    supports: supports as string[],
    configured: configured.includes(id as string),
  }));
}

function intelTool(configured: string[]): ToolDescriptor {
  return {
    tool_id: "threat_intel",
    name: "Threat Intelligence",
    description: "Checks indicators against reputation services.",
    version: "1.0.0",
    category: "INTEL",
    is_active: false,
    required_role: "analyst",
    params_schema: {
      type: "object",
      required: ["indicators"],
      properties: { indicators: { type: "string", title: "Indicators", maxLength: 6000 } },
    },
    available: configured.length > 0,
    unavailable_reason: configured.length
      ? null
      : "No threat-intelligence provider is configured. An administrator must set ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY or SHODAN_API_KEY.",
    status: { providers: providers(configured) },
  };
}

afterEach(() => __resetClientStateForTests());

function api(tool: ToolDescriptor, extra: Parameters<typeof mockFetch>[0] = {}) {
  return mockFetch({
    "GET /api/v1/auth/me": jsonResponse(USER),
    "GET /api/v1/tools": jsonResponse([tool]),
    "GET /health": jsonResponse({ status: "ok", version: "0.8.0" }),
    ...extra,
  });
}

describe("a tool that is not configured", () => {
  it("explains what is missing, lists the providers and offers no form", async () => {
    api(intelTool([]));
    renderApp("/tools/threat_intel");
    expect(await screen.findByText(/An administrator must set ABUSEIPDB_API_KEY/)).toHaveAttribute(
      "role",
      "status",
    );
    expect(screen.getByText("Not configured")).toBeInTheDocument();
    const list = screen.getByRole("list", { name: "Providers" });
    expect(within(list).getByText("AbuseIPDB: set ABUSEIPDB_API_KEY")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Run" })).not.toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByText("setup")).toBeInTheDocument();
  });
});

describe("a configured tool", () => {
  it("shows which providers are on and submits indicators as text", async () => {
    const fetchMock = api(intelTool(["abuseipdb", "virustotal"]), {
      "POST /api/v1/tools/threat_intel/runs": jsonResponse(
        { error: { code: "conflict", message: "stop here", request_id: "r", details: {} } },
        409,
      ),
    });
    renderApp("/tools/threat_intel");
    const list = await screen.findByRole("list", { name: "Providers" });
    expect(within(list).getByText("AbuseIPDB: configured")).toBeInTheDocument();
    expect(within(list).getByText("Shodan: set SHODAN_API_KEY")).toBeInTheDocument();
    expect(screen.queryByText("Not configured")).not.toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("Indicators"), "45.33.32.156, example.com");
    await userEvent.click(screen.getByRole("button", { name: "Run" }));
    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([url]) => url === "/api/v1/tools/threat_intel/runs")).toBe(
        true,
      ),
    );
    const call = fetchMock.mock.calls.find(([url]) => url === "/api/v1/tools/threat_intel/runs")!;
    expect(JSON.parse((call[1] as RequestInit).body as string)).toEqual({
      params: { indicators: "45.33.32.156, example.com" },
    });
  });
});

describe("playbook steps whose tool is not configured", () => {
  it("say so and show the reason", async () => {
    const playbook: PlaybookInfo = {
      id: "web_defensive_audit",
      name: "Web Defensive Audit",
      version: "1.0.0",
      description: "A defensive health check.",
      available: true,
      unavailable_reason: null,
      requires_authorization: false,
      required_role: "analyst",
      inputs_schema: { type: "object", properties: {} },
      steps: [
        {
          id: "intel",
          name: "Threat intelligence",
          tool_id: "threat_intel",
          tool_name: "Threat Intelligence",
          available: false,
          unavailable_reason: "No threat-intelligence provider is configured.",
          optional: true,
          on_failure: "continue",
          is_active: false,
          description: "Reputation of the resolved IP addresses.",
        },
      ],
    };
    api(intelTool([]), {
      "GET /api/v1/playbooks": jsonResponse([playbook]),
      "GET /api/v1/playbook-runs": jsonResponse({ runs: [], next_before: null }),
    });
    renderApp("/playbooks");
    const steps = await screen.findByRole("list", { name: "Web Defensive Audit steps" });
    expect(within(steps).getByText(/not configured: skipped/)).toBeInTheDocument();
    expect(
      within(steps).getByText("No threat-intelligence provider is configured."),
    ).toBeInTheDocument();
  });
});
