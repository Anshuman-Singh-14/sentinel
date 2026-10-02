import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { __resetClientStateForTests } from "../../lib/api/client";
import { errorResponse, jsonResponse, makeUser, mockFetch, renderApp } from "../../test/utils";
import type {
  Acknowledgement,
  PlaybookEvent,
  PlaybookInfo,
  PlaybookRunDetail,
  PlaybookStepOut,
} from "../../types/api";

const PB_ID = "01a0fd00-0000-7000-8000-000000000001";
const USER = makeUser();
const ACKED: Acknowledgement = {
  acknowledged: true,
  version: 1,
  statement: "I will only scan systems I own or may test.",
  acknowledged_at: "2026-10-02T12:00:00Z",
};

const AUDIT: PlaybookInfo = {
  id: "web_defensive_audit",
  name: "Web Defensive Audit",
  version: "1.0.0",
  description: "A defensive health check of one web host.",
  available: true,
  unavailable_reason: null,
  requires_authorization: true,
  required_role: "analyst",
  inputs_schema: {
    type: "object",
    required: ["target"],
    properties: {
      target: { type: "string", title: "Target host", examples: ["lab-https"] },
      web_url: { type: "string", title: "Website URL" },
    },
  },
  steps: [
    {
      id: "dns",
      name: "DNS & email security",
      tool_id: "dns_lookup",
      tool_name: "DNS",
      available: true,
      optional: false,
      on_failure: "continue",
      is_active: false,
      description: "",
    },
    {
      id: "ports",
      name: "Web port scan",
      tool_id: "port_scanner",
      tool_name: "Port Scanner",
      available: true,
      optional: false,
      on_failure: "continue",
      is_active: true,
      description: "",
    },
    {
      id: "web",
      name: "Security headers & TLS",
      tool_id: "header_tls",
      tool_name: "Header",
      available: true,
      optional: false,
      on_failure: "continue",
      is_active: true,
      description: "",
    },
    {
      id: "intel",
      name: "Threat intelligence",
      tool_id: "threat_intel",
      tool_name: null,
      available: false,
      optional: true,
      on_failure: "continue",
      is_active: false,
      description: "",
    },
  ],
};

function step(
  step_id: string,
  name: string,
  position: number,
  extra: Partial<PlaybookStepOut> = {},
): PlaybookStepOut {
  return {
    position,
    step_id,
    name,
    tool_id: step_id,
    on_failure: "continue",
    status: "PENDING",
    run: null,
    resolved_params: null,
    error: null,
    started_at: null,
    completed_at: null,
    ...extra,
  };
}

function detail(extra: Partial<PlaybookRunDetail> = {}): PlaybookRunDetail {
  return {
    playbook_run_id: PB_ID,
    playbook_id: "web_defensive_audit",
    playbook_name: "Web Defensive Audit",
    target: "lab-https",
    status: "QUEUED",
    initiated_by: USER.username,
    created_at: "2026-10-02T12:00:00Z",
    completed_at: null,
    duration_ms: null,
    finding_count: 0,
    max_severity: null,
    playbook_version: "1.0.0",
    inputs: { target: "lab-https" },
    user_id: USER.id,
    started_at: null,
    progress_pct: 0,
    current_step: null,
    cancel_requested: false,
    error: null,
    steps: [
      step("dns", "DNS & email security", 0),
      step("ports", "Web port scan", 1),
      step("web", "Security headers & TLS", 2),
      step("intel", "Threat intelligence", 3),
    ],
    risk: {
      total: 0,
      by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      highest: null,
      headline: "",
    },
    findings: [],
    ...extra,
  };
}

const DONE = detail({
  status: "COMPLETED", progress_pct: 100, duration_ms: 1140, finding_count: 2, max_severity: "HIGH",
  steps: [
    step("dns", "DNS & email security", 0, { status: "FAILED", error: { code: "validation_failed", message: "The tool parameters are invalid. domain: Enter a fully qualified domain name." } }),
    step("ports", "Web port scan", 1, { status: "COMPLETED", run: { run_id: "r-ports", tool_id: "port_scanner", tool_name: "Port Scanner", target: "lab-https", status: "COMPLETED", initiated_by: "analyst01", created_at: "", started_at: null, completed_at: null, duration_ms: 10, finding_count: 3, max_severity: "LOW" } }),
    step("web", "Security headers & TLS", 2, { status: "COMPLETED" }),
    step("intel", "Threat intelligence", 3, { status: "SKIPPED", error: { code: "tool_not_installed", message: "The threat_intel tool is not installed yet." } }),
  ],
  risk: { total: 2, by_severity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 1, INFO: 0 }, highest: "HIGH",
          headline: "Highest severity HIGH: 1 high, 1 low finding(s) from 2 completed step(s)." },
  findings: [
    { finding_id: "f1", item: "Self-signed TLS certificate", category: "TLS", status: "FAIL", severity: "HIGH",
      severity_rationale: "CWE-295", confidence: "HIGH", explanation: "Signed by itself.", remediation: "Use a CA.",
      evidence: {}, references: [], raw_data: {}, step_id: "web", tool_id: "header_tls", run_id: "r-web",
      also_reported_by: [] },
    { finding_id: "f2", item: "HTTP on port 8080", category: "NETWORK", status: "DETECTED", severity: "LOW",
      severity_rationale: "CWE-319", confidence: "HIGH", explanation: "Clear text.", remediation: "Use TLS.",
      evidence: {}, references: [], raw_data: {}, step_id: "ports", tool_id: "port_scanner", run_id: "r-ports",
      also_reported_by: ["web"] },
  ],
}); // prettier-ignore

class MockWebSocket {
  static instances: MockWebSocket[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }
  open() {
    act(() => this.onopen?.());
  }
  send(event: Partial<PlaybookEvent>) {
    const full: PlaybookEvent = {
      type: "playbook.update", playbook_run_id: PB_ID, status: "RUNNING", progress_pct: 0,
      current_step: null, steps: [], ts: "", ...event,
    }; // prettier-ignore
    act(() => this.onmessage?.({ data: JSON.stringify(full) }));
  }
  close() {}
}

beforeEach(() => {
  MockWebSocket.instances = [];
  // @ts-expect-error -- test double
  globalThis.WebSocket = MockWebSocket;
});
afterEach(() => __resetClientStateForTests());

function api(extra: Parameters<typeof mockFetch>[0] = {}, user = USER) {
  return mockFetch({
    "GET /api/v1/auth/me": jsonResponse(user),
    "GET /api/v1/tools": jsonResponse([]),
    "GET /health": jsonResponse({ status: "ok", version: "0.12.0" }),
    "GET /api/v1/playbooks": jsonResponse([AUDIT]),
    "GET /api/v1/playbook-runs": jsonResponse({ runs: [], next_before: null }),
    "GET /api/v1/scope": jsonResponse({ rules: [], hard_deny: null }),
    "GET /api/v1/scope/acknowledgement": jsonResponse(ACKED),
    [`POST /api/v1/playbook-runs/${PB_ID}/ws-ticket`]: jsonResponse({
      ticket: "pt",
      expires_in: 30,
    }),
    ...extra,
  });
}

describe("playbook catalogue", () => {
  it("shows the steps, including a not-yet-installed optional one", async () => {
    api();
    renderApp("/playbooks");
    const steps = await screen.findByRole("list", { name: "Web Defensive Audit steps" });
    expect(within(steps).getAllByRole("listitem")).toHaveLength(4);
    expect(within(steps).getByText(/not installed yet: skipped/)).toBeInTheDocument();
    expect(within(steps).getAllByText("active")).toHaveLength(2);
  });

  it("starts a run from the generated form and opens it", async () => {
    const fetchMock = api({
      "POST /api/v1/playbooks/web_defensive_audit/runs": jsonResponse(detail(), 202),
      [`GET /api/v1/playbook-runs/${PB_ID}`]: jsonResponse(detail()),
    });
    const { router } = renderApp("/playbooks");
    await userEvent.click(await screen.findByRole("button", { name: "Configure run" }));
    await userEvent.type(await screen.findByLabelText("Target host"), "lab-https");
    await userEvent.type(screen.getByLabelText("Website URL (optional)"), "http://lab-https:8080/");
    await userEvent.click(screen.getByRole("button", { name: "Run playbook" }));
    await waitFor(() => expect(router.state.location.pathname).toBe(`/playbook-runs/${PB_ID}`));
    const call = fetchMock.mock.calls.find(([u]) =>
      String(u).endsWith("/web_defensive_audit/runs"),
    )!;
    expect(JSON.parse((call[1] as RequestInit).body as string)).toEqual({
      inputs: { target: "lab-https", web_url: "http://lab-https:8080/" },
    });
  });

  it("shows input errors from the server on the field", async () => {
    api({
      "POST /api/v1/playbooks/web_defensive_audit/runs": jsonResponse(
        { error: { code: "validation_failed", message: "The playbook inputs are invalid.", request_id: "r",
          details: { errors: [{ loc: ["inputs", "web_url"], msg: "Only http:// and https:// URLs can be checked.", type: "value_error" }] } } },
        422,
      ),
    }); // prettier-ignore
    renderApp("/playbooks");
    await userEvent.click(await screen.findByRole("button", { name: "Configure run" }));
    await userEvent.type(await screen.findByLabelText("Target host"), "lab-https");
    await userEvent.type(screen.getByLabelText("Website URL (optional)"), "gopher://x");
    await userEvent.click(screen.getByRole("button", { name: "Run playbook" }));
    expect(
      await screen.findByText("Only http:// and https:// URLs can be checked."),
    ).toBeInTheDocument();
  });

  it("does not offer runs to viewers", async () => {
    api({}, makeUser({ role: "viewer" }));
    renderApp("/playbooks");
    expect(await screen.findByText(/cannot run playbooks/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Configure run" })).not.toBeInTheDocument();
  });
});

describe("playbook run page", () => {
  it("follows the steps live and then shows unified findings", async () => {
    // The server's view advances with the events, as the real API's would.
    let phase: "queued" | "running" | "done" = "queued";
    const running = detail({
      status: "RUNNING",
      progress_pct: 50,
      current_step: "ports",
      steps: [
        step("dns", "DNS & email security", 0, { status: "FAILED" }),
        step("ports", "Web port scan", 1, { status: "RUNNING" }),
        step("web", "Security headers & TLS", 2),
        step("intel", "Threat intelligence", 3),
      ],
    });
    api({
      [`GET /api/v1/playbook-runs/${PB_ID}`]: () =>
        jsonResponse(phase === "done" ? DONE : phase === "running" ? running : detail()),
    });
    renderApp(`/playbook-runs/${PB_ID}`);
    const steps = await screen.findByRole("list", { name: "Playbook steps" });
    expect(within(steps).getAllByText("Pending")).toHaveLength(4);

    await waitFor(() => expect(MockWebSocket.instances).toHaveLength(1));
    const ws = MockWebSocket.instances[0]!;
    expect(ws.url).toContain(`/ws/playbooks/${PB_ID}?ticket=pt`);
    ws.open();
    phase = "running";
    ws.send({ status: "RUNNING", progress_pct: 50, current_step: "ports",
      steps: [{ step_id: "dns", status: "FAILED" }, { step_id: "ports", status: "RUNNING" },
              { step_id: "web", status: "PENDING" }, { step_id: "intel", status: "PENDING" }] }); // prettier-ignore
    expect(await screen.findByText("50%")).toBeInTheDocument();
    expect(within(steps).getByText("Running")).toBeInTheDocument();
    expect(within(steps).getByText("Failed")).toBeInTheDocument();

    phase = "done";
    ws.send({ status: "COMPLETED", progress_pct: 100, steps: [] });
    expect(await screen.findByText(/Highest severity HIGH/)).toBeInTheDocument();
    expect(screen.getByText(/Enter a fully qualified domain name/)).toBeInTheDocument();
    expect(screen.getByText(/threat_intel tool is not installed yet/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /open tool run \(3 findings\)/i })).toHaveAttribute(
      "href",
      "/runs/r-ports",
    );
    const lowFinding = screen.getByText("HTTP on port 8080").closest("li")!;
    expect(lowFinding).toHaveTextContent(
      "From Web port scan · also reported by Security headers & TLS",
    );
  });

  it("lets the owner cancel", async () => {
    const fetchMock = api({
      [`GET /api/v1/playbook-runs/${PB_ID}`]: jsonResponse(detail({ status: "RUNNING" })),
      [`POST /api/v1/playbook-runs/${PB_ID}/cancel`]: jsonResponse(detail({ status: "RUNNING", cancel_requested: true })),
    }); // prettier-ignore
    renderApp(`/playbook-runs/${PB_ID}`);
    await userEvent.click(await screen.findByRole("button", { name: "Cancel playbook" }));
    expect(await screen.findByText("Cancellation requested")).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([u]) => String(u).endsWith("/cancel"))).toBe(true);
  });

  it("shows not found for an unknown run", async () => {
    api({
      [`GET /api/v1/playbook-runs/${PB_ID}`]: errorResponse(
        404,
        "not_found",
        "Playbook run not found.",
      ),
    });
    renderApp(`/playbook-runs/${PB_ID}`);
    expect(await screen.findByRole("heading", { name: "Not found" })).toBeInTheDocument();
  });

  it("is reachable from the sidebar", async () => {
    api();
    renderApp("/");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    await userEvent.click(within(nav).getByRole("link", { name: "Playbooks" }));
    expect(await screen.findByRole("heading", { name: "Playbooks" })).toBeInTheDocument();
  });
});
