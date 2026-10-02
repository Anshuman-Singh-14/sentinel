/**
 * Run flows through the real routes and API client: start a run from the
 * generated form, watch it go QUEUED -> RUNNING -> COMPLETED over a (mock)
 * WebSocket, fall back to polling, show failures, cancel, and browse history.
 */

import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { __resetClientStateForTests } from "../../lib/api/client";
import { errorResponse, jsonResponse, makeUser, mockFetch, renderApp } from "../../test/utils";
import type { RunDetail, RunEvent, RunSummary, ToolDescriptor } from "../../types/api";

const RUN_ID = "01a0fc7d-a029-7900-be78-7dae512de3d3";
const USER = makeUser();

const DNS_TOOL: ToolDescriptor = {
  tool_id: "dns_lookup",
  name: "DNS & Domain Intelligence",
  description: "DNS records and email security.",
  version: "1.0.0",
  category: "RECON",
  is_active: false,
  required_role: "analyst",
  params_schema: {
    type: "object",
    required: ["domain"],
    properties: {
      domain: { type: "string", title: "Domain", maxLength: 253 },
      include_reverse: { type: "boolean", title: "Include Reverse", default: true },
    },
  },
};

function makeRun(overrides: Partial<RunDetail> = {}): RunDetail {
  return {
    run_id: RUN_ID,
    tool_id: "dns_lookup",
    tool_name: "DNS & Domain Intelligence",
    tool_version: "1.0.0",
    target: "example.com",
    initiated_by: USER.username,
    status: "QUEUED",
    started_at: "2026-10-02T12:00:00Z",
    completed_at: null,
    duration_ms: null,
    summary: { total: 0, by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } },
    findings: [],
    errors: [],
    raw_data: {},
    params: { domain: "example.com", include_reverse: true },
    user_id: USER.id,
    created_at: "2026-10-02T12:00:00Z",
    progress_pct: 0,
    progress_message: null,
    cancel_requested: false,
    was_started: false,
    ...overrides,
  };
}

const COMPLETED = makeRun({
  status: "COMPLETED",
  was_started: true,
  duration_ms: 1200,
  progress_pct: 100,
  summary: { total: 2, by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 1, LOW: 0, INFO: 1 } },
  findings: [
    {
      finding_id: "f1",
      item: "No DMARC policy",
      category: "EMAIL_SECURITY",
      status: "MISSING",
      severity: "MEDIUM",
      severity_rationale: "Leaves the domain open to spoofing.",
      confidence: "HIGH",
      explanation: "There is no DMARC record.",
      remediation: "Publish v=DMARC1; p=none first.",
      evidence: { dmarc: [] },
      references: ["RFC 7489"],
      raw_data: {},
    },
    {
      finding_id: "f2",
      item: "DNS records collected",
      category: "DNS",
      status: "INFO",
      severity: "INFO",
      severity_rationale: "Informational.",
      confidence: "HIGH",
      explanation: "example.com resolves to 1 address.",
      remediation: "No action needed.",
      evidence: {},
      references: [],
      raw_data: {},
    },
  ],
  raw_data: { resolved_ips: ["93.184.216.34"], banner: "<script>alert(1)</script>" },
});

// --- a controllable WebSocket ---------------------------------------------------------------

class MockWebSocket {
  static instances: MockWebSocket[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  closed = false;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }
  open() {
    act(() => this.onopen?.());
  }
  send(event: Partial<RunEvent>) {
    const full: RunEvent = {
      type: "run.update",
      run_id: RUN_ID,
      status: "RUNNING",
      progress_pct: 0,
      progress_message: null,
      finding_count: 0,
      max_severity: null,
      ts: "2026-10-02T12:00:01Z",
      ...event,
    };
    act(() => this.onmessage?.({ data: JSON.stringify(full) }));
  }
  drop() {
    act(() => this.onclose?.());
  }
  close() {
    this.closed = true;
  }
}

beforeEach(() => {
  MockWebSocket.instances = [];
  // @ts-expect-error -- test double
  globalThis.WebSocket = MockWebSocket;
});

afterEach(() => {
  __resetClientStateForTests();
});

function api(extra: Parameters<typeof mockFetch>[0] = {}) {
  return mockFetch({
    "GET /api/v1/auth/me": jsonResponse(USER),
    "GET /api/v1/tools": jsonResponse([DNS_TOOL]),
    "GET /health": jsonResponse({ status: "ok", version: "0.5.0" }),
    [`POST /api/v1/runs/${RUN_ID}/ws-ticket`]: jsonResponse({ ticket: "t-1", expires_in: 30 }),
    ...extra,
  });
}

describe("starting a run", () => {
  it("submits the generated form and opens the run page", async () => {
    const fetchMock = api({
      "POST /api/v1/tools/dns_lookup/runs": jsonResponse(makeRun(), 202),
      [`GET /api/v1/runs/${RUN_ID}`]: jsonResponse(makeRun()),
    });
    const { router } = renderApp("/tools/dns_lookup");
    await userEvent.type(await screen.findByLabelText("Domain"), "example.com");
    await userEvent.click(screen.getByRole("button", { name: "Run" }));

    await waitFor(() => expect(router.state.location.pathname).toBe(`/runs/${RUN_ID}`));
    const call = fetchMock.mock.calls.find(([url]) => url === "/api/v1/tools/dns_lookup/runs")!;
    expect(JSON.parse((call[1] as RequestInit).body as string)).toEqual({
      params: { domain: "example.com", include_reverse: true },
    });
  });

  it("shows server validation errors on the field", async () => {
    api({
      "POST /api/v1/tools/dns_lookup/runs": jsonResponse(
        {
          error: {
            code: "validation_failed",
            message: "The tool parameters are invalid.",
            request_id: "r",
            details: {
              errors: [
                {
                  loc: ["params", "domain"],
                  msg: 'Value error, ".internal" names are reserved or private and cannot be looked up.',
                  type: "value_error",
                },
              ],
            },
          },
        },
        422,
      ),
    });
    renderApp("/tools/dns_lookup");
    await userEvent.type(await screen.findByLabelText("Domain"), "postgres.internal");
    await userEvent.click(screen.getByRole("button", { name: "Run" }));
    expect(await screen.findByText(/".internal" names are reserved/)).toBeInTheDocument();
    expect(screen.queryByText(/Value error/)).not.toBeInTheDocument();
  });

  it("explains a scope denial", async () => {
    api({
      "POST /api/v1/tools/dns_lookup/runs": errorResponse(
        403,
        "scope_denied",
        "Active tools are disabled until a scope policy is configured.",
      ),
    });
    renderApp("/tools/dns_lookup");
    await userEvent.type(await screen.findByLabelText("Domain"), "example.com");
    await userEvent.click(screen.getByRole("button", { name: "Run" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/scope policy/);
  });
});

describe("watching a run", () => {
  it("goes QUEUED -> RUNNING -> COMPLETED live over the WebSocket", async () => {
    let done = false;
    const fetchMock = api({
      [`GET /api/v1/runs/${RUN_ID}`]: () => jsonResponse(done ? COMPLETED : makeRun()),
    });
    renderApp(`/runs/${RUN_ID}`);
    expect(
      await screen.findByText("Queued", { selector: "[data-status] *, [data-status]" }),
    ).toBeInTheDocument();

    await waitFor(() => expect(MockWebSocket.instances).toHaveLength(1));
    const ws = MockWebSocket.instances[0]!;
    expect(ws.url).toBe(`ws://localhost:3000/ws/runs/${RUN_ID}?ticket=t-1`);
    ws.open();
    expect(screen.getByText("Live")).toBeInTheDocument();

    ws.send({ status: "RUNNING", progress_pct: 55, progress_message: "Records collected" });
    expect(await screen.findByText("55%")).toBeInTheDocument();
    expect(screen.getByText("Records collected")).toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: "Run progress" })).toHaveAttribute(
      "value",
      "55",
    );

    done = true;
    ws.send({ status: "COMPLETED", progress_pct: 100 });
    expect(await screen.findByText("No DMARC policy")).toBeInTheDocument();
    // The ticket endpoint was called with CSRF (a POST through the client).
    expect(fetchMock.mock.calls.some(([u]) => String(u).endsWith("/ws-ticket"))).toBe(true);
  });

  it("explains each finding and keeps raw data as escaped text", async () => {
    api({ [`GET /api/v1/runs/${RUN_ID}`]: jsonResponse(COMPLETED) });
    const { container } = renderApp(`/runs/${RUN_ID}`);
    const finding = await screen.findByRole("button", { name: /No DMARC policy/ });
    expect(finding).toHaveAttribute("aria-expanded", "true"); // non-INFO starts open
    expect(screen.getByText("There is no DMARC record.")).toBeInTheDocument();
    expect(screen.getByText("Leaves the domain open to spoofing.")).toBeInTheDocument();
    expect(screen.getByText("Publish v=DMARC1; p=none first.")).toBeInTheDocument();
    expect(screen.getByText("RFC 7489")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Findings by severity" })).toHaveTextContent("MEDIUM1");

    await userEvent.click(screen.getByRole("tab", { name: "Raw data" }));
    expect(screen.getByRole("tree", { name: "Raw tool output" })).toHaveTextContent("<script>");
    expect(container.querySelector("script")).toBeNull();
    // No WebSocket for a finished run.
    expect(MockWebSocket.instances).toHaveLength(0);
  });

  it("falls back to polling when the socket drops", async () => {
    let calls = 0;
    api({
      [`GET /api/v1/runs/${RUN_ID}`]: () =>
        jsonResponse(++calls < 3 ? makeRun({ status: "RUNNING", was_started: true }) : COMPLETED),
    });
    renderApp(`/runs/${RUN_ID}`);
    await waitFor(() => expect(MockWebSocket.instances).toHaveLength(1));
    MockWebSocket.instances[0]!.drop();
    expect(await screen.findByText(/refreshing every 2 s/)).toBeInTheDocument();
    expect(await screen.findByText("No DMARC policy", {}, { timeout: 8000 })).toBeInTheDocument();
  });

  it("shows a structured failure", async () => {
    api({
      [`GET /api/v1/runs/${RUN_ID}`]: jsonResponse(
        makeRun({
          status: "FAILED",
          was_started: true,
          errors: [
            {
              code: "provider_error",
              message: "No DNS resolver answered. Check the worker's network access.",
            },
          ],
        }),
      ),
    });
    renderApp(`/runs/${RUN_ID}`);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The run did not complete");
    expect(alert).toHaveTextContent("No DNS resolver answered");
    expect(alert).toHaveTextContent("(provider_error)");
  });

  it("lets the owner cancel a running run", async () => {
    const fetchMock = api({
      [`GET /api/v1/runs/${RUN_ID}`]: jsonResponse(
        makeRun({ status: "RUNNING", was_started: true }),
      ),
      [`POST /api/v1/runs/${RUN_ID}/cancel`]: jsonResponse(
        makeRun({ status: "RUNNING", was_started: true, cancel_requested: true }),
      ),
    });
    renderApp(`/runs/${RUN_ID}`);
    await userEvent.click(await screen.findByRole("button", { name: "Cancel run" }));
    expect(await screen.findByText("Cancellation requested")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /cancelling/i })).toBeDisabled();
    expect(fetchMock.mock.calls.some(([u]) => String(u).endsWith("/cancel"))).toBe(true);
  });

  it("hides cancel from viewers", async () => {
    mockFetch({
      "GET /api/v1/auth/me": jsonResponse(makeUser({ role: "viewer" })),
      "GET /api/v1/tools": jsonResponse([DNS_TOOL]),
      "GET /health": jsonResponse({ status: "ok", version: "0.5.0" }),
      [`GET /api/v1/runs/${RUN_ID}`]: jsonResponse(makeRun({ status: "RUNNING" })),
      [`POST /api/v1/runs/${RUN_ID}/ws-ticket`]: jsonResponse({ ticket: "t", expires_in: 30 }),
    });
    renderApp(`/runs/${RUN_ID}`);
    await screen.findByText("Running", { selector: "[data-status] *, [data-status]" });
    expect(screen.queryByRole("button", { name: "Cancel run" })).not.toBeInTheDocument();
  });

  it("shows not found for an unknown run", async () => {
    api({ [`GET /api/v1/runs/${RUN_ID}`]: errorResponse(404, "not_found", "Run not found.") });
    renderApp(`/runs/${RUN_ID}`);
    expect(await screen.findByRole("heading", { name: "Not found" })).toBeInTheDocument();
  });
});

describe("run history", () => {
  const summary: RunSummary = {
    run_id: RUN_ID,
    tool_id: "dns_lookup",
    tool_name: "DNS & Domain Intelligence",
    target: "example.com",
    status: "COMPLETED",
    initiated_by: "analyst01",
    created_at: "2026-10-02T12:00:00Z",
    started_at: "2026-10-02T12:00:01Z",
    completed_at: "2026-10-02T12:00:02Z",
    duration_ms: 1000,
    finding_count: 5,
    max_severity: "LOW",
  };

  it("lists runs, filters through the URL and opens a run", async () => {
    const fetchMock = api({
      "GET /api/v1/runs": jsonResponse({ runs: [summary], next_before: null }),
      [`GET /api/v1/runs/${RUN_ID}`]: jsonResponse(COMPLETED),
    });
    const { router } = renderApp("/runs");
    const row = await screen.findByRole("row", {
      name: /DNS & Domain Intelligence run on example.com/,
    });
    expect(within(row).getByText("5 total")).toBeInTheDocument();
    expect(within(row).getByText("LOW")).toBeInTheDocument();

    await userEvent.click(screen.getByLabelText("Only my runs"));
    await userEvent.selectOptions(screen.getByLabelText("Status"), "COMPLETED");
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([u]) => String(u) === "/api/v1/runs?mine=true&status=COMPLETED&limit=25",
        ),
      ).toBe(true),
    );
    expect(router.state.location.search).toBe("?mine=1&status=COMPLETED");

    await userEvent.click(screen.getByRole("row", { name: /DNS & Domain Intelligence run/ }));
    expect(router.state.location.pathname).toBe(`/runs/${RUN_ID}`);
  });

  it("is reachable from the sidebar", async () => {
    api({ "GET /api/v1/runs": jsonResponse({ runs: [], next_before: null }) });
    renderApp("/");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    await userEvent.click(within(nav).getByRole("link", { name: "Run history" }));
    expect(await screen.findByText("No runs match these filters.")).toBeInTheDocument();
  });
});
