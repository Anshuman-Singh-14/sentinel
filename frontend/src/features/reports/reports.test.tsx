/**
 * Reports (Phase 13): export from a finished run, watch the report get
 * generated, download it through the API client, browse the history, and
 * export the audit trail as an admin.
 */

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { __resetClientStateForTests } from "../../lib/api/client";
import { errorResponse, jsonResponse, makeUser, mockFetch, renderApp } from "../../test/utils";
import type { Report, ReportFormat, RunDetail } from "../../types/api";
import { exportFilename } from "../audit/AuditPage";

const RUN_ID = "01a0fc7d-a029-7900-be78-7dae512de3d3";
const REPORT_ID = "01a0fc7d-a029-7900-be78-00000000r001";
const ANALYST = makeUser();
const VIEWER = makeUser({ role: "viewer", username: "viewer01" });

const FORMATS: ReportFormat[] = [
  { format: "csv", label: "CSV", media_type: "text/csv; charset=utf-8", extension: "csv" },
  { format: "json", label: "JSON", media_type: "application/json", extension: "json" },
  { format: "pdf", label: "PDF", media_type: "application/pdf", extension: "pdf" },
  { format: "txt", label: "Plain text", media_type: "text/plain", extension: "txt" },
];

const RUN: RunDetail = {
  run_id: RUN_ID,
  tool_id: "echo",
  tool_name: "Echo",
  tool_version: "1.0.0",
  target: "hello",
  initiated_by: ANALYST.username,
  status: "COMPLETED",
  started_at: "2026-10-04T09:00:00Z",
  completed_at: "2026-10-04T09:00:01Z",
  duration_ms: 900,
  summary: { total: 0, by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } },
  findings: [],
  errors: [],
  raw_data: {},
  params: { message: "hello" },
  user_id: ANALYST.id,
  created_at: "2026-10-04T09:00:00Z",
  progress_pct: 100,
  progress_message: null,
  cancel_requested: false,
  was_started: true,
};

function makeReport(overrides: Partial<Report> = {}): Report {
  return {
    report_id: REPORT_ID,
    source_type: "tool_run",
    source_id: RUN_ID,
    title: "Echo report",
    target: "hello",
    format: "pdf",
    status: "QUEUED",
    requested_by: ANALYST.username,
    user_id: ANALYST.id,
    created_at: "2026-10-04T09:01:00Z",
    started_at: null,
    completed_at: null,
    filename: null,
    media_type: null,
    size_bytes: null,
    sha256: null,
    error: null,
    ...overrides,
  };
}

const READY = makeReport({
  status: "COMPLETED",
  filename: "sentinel-run-Echo-hello-20261004-090100.pdf",
  media_type: "application/pdf",
  size_bytes: 24_576,
  sha256: "ab".repeat(32),
});

class SilentWebSocket {
  onopen = null;
  onmessage = null;
  onclose = null;
  close() {}
}

let saved: { name: string; href: string }[] = [];

beforeEach(() => {
  saved = [];
  // @ts-expect-error -- test double
  globalThis.WebSocket = SilentWebSocket;
  vi.stubGlobal(
    "URL",
    Object.assign(URL, { createObjectURL: () => "blob:x", revokeObjectURL() {} }),
  );
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    saved.push({ name: this.download, href: this.href });
  });
});

afterEach(() => {
  __resetClientStateForTests();
  vi.restoreAllMocks();
});

function api(user = ANALYST, extra: Parameters<typeof mockFetch>[0] = {}) {
  return mockFetch({
    "GET /api/v1/auth/me": jsonResponse(user),
    "GET /api/v1/tools": jsonResponse([]),
    "GET /health": jsonResponse({ status: "ok", version: "0.13.0" }),
    [`GET /api/v1/runs/${RUN_ID}`]: jsonResponse(RUN),
    [`POST /api/v1/runs/${RUN_ID}/ws-ticket`]: jsonResponse({ ticket: "t", expires_in: 30 }),
    "GET /api/v1/reports/formats": jsonResponse(FORMATS),
    ...extra,
  });
}

describe("exporting a run", () => {
  it("requests a report, polls until it is ready, then downloads it", async () => {
    let state: "none" | "queued" | "ready" = "none";
    const fetchMock = api(ANALYST, {
      "GET /api/v1/reports": () =>
        jsonResponse({
          reports: state === "none" ? [] : [state === "queued" ? makeReport() : READY],
          next_before: null,
        }),
      "POST /api/v1/reports": () => {
        state = "queued";
        return jsonResponse(makeReport(), 202);
      },
      [`GET /api/v1/reports/${REPORT_ID}/download`]: () =>
        new Response(new Blob(["%PDF-1.4"]), {
          status: 200,
          headers: { "Content-Type": "application/pdf" },
        }),
    });
    renderApp(`/runs/${RUN_ID}`);

    const panel = await screen.findByRole("region", { name: "Reports" });
    expect(await within(panel).findByText("No reports yet.")).toBeInTheDocument();
    await userEvent.click(within(panel).getByRole("button", { name: "PDF" }));

    const post = fetchMock.mock.calls.find(
      ([url, init]) => url === "/api/v1/reports" && init?.method === "POST",
    )!;
    expect(JSON.parse(post[1]!.body as string)).toEqual({
      source_type: "tool_run",
      source_id: RUN_ID,
      format: "pdf",
    });
    const list = await within(panel).findByRole("list", { name: "Reports for this run" });
    expect(within(list).getByText("Queued")).toBeInTheDocument();

    state = "ready";
    const download = await within(panel).findByRole(
      "button",
      { name: /Download PDF report/ },
      { timeout: 4000 },
    );
    expect(within(list).getByText(/24\.0 KB/)).toBeInTheDocument();
    await userEvent.click(download);
    await waitFor(() => expect(saved).toEqual([{ name: READY.filename, href: "blob:x" }]));
  });

  it("shows why a report failed", async () => {
    api(ANALYST, {
      "GET /api/v1/reports": jsonResponse({
        reports: [
          makeReport({
            status: "FAILED",
            error: { code: "render_timeout", message: "The report took too long to generate." },
          }),
        ],
        next_before: null,
      }),
    });
    renderApp(`/runs/${RUN_ID}`);
    expect(await screen.findByText("The report took too long to generate.")).toBeInTheDocument();
  });

  it("explains a refused export", async () => {
    api(ANALYST, {
      "GET /api/v1/reports": jsonResponse({ reports: [], next_before: null }),
      "POST /api/v1/reports": errorResponse(429, "rate_limited", "Too many reports."),
    });
    renderApp(`/runs/${RUN_ID}`);
    await userEvent.click(await screen.findByRole("button", { name: "CSV" }));
    expect(await screen.findByText("Too many reports.")).toBeInTheDocument();
  });

  it("lets viewers download existing reports but not request new ones", async () => {
    const fetchMock = api(VIEWER, {
      "GET /api/v1/reports": jsonResponse({ reports: [READY], next_before: null }),
    });
    renderApp(`/runs/${RUN_ID}`);
    const panel = await screen.findByRole("region", { name: "Reports" });
    expect(await within(panel).findByRole("button", { name: /Download PDF/ })).toBeInTheDocument();
    expect(within(panel).queryByRole("button", { name: "PDF" })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([u]) => u === "/api/v1/reports/formats")).toBe(false);
  });
});

describe("report history", () => {
  it("lists reports; download does not navigate, the row opens the run", async () => {
    api(ANALYST, {
      "GET /api/v1/reports": jsonResponse({ reports: [READY], next_before: null }),
      [`GET /api/v1/reports/${REPORT_ID}/download`]: () => new Response(new Blob(["x"])),
    });
    const { router } = renderApp("/reports");
    const row = await screen.findByRole("row", { name: /Open the run behind Echo report/ });
    expect(within(row).getByText("hello")).toBeInTheDocument();

    within(row)
      .getByRole("button", { name: /Download PDF/ })
      .focus();
    await userEvent.keyboard("{Enter}");
    await waitFor(() => expect(saved).toHaveLength(1));
    expect(router.state.location.pathname).toBe("/reports");

    await userEvent.click(row);
    await waitFor(() => expect(router.state.location.pathname).toBe(`/runs/${RUN_ID}`));
  });

  it("is in the main navigation", async () => {
    api(VIEWER, { "GET /api/v1/reports": jsonResponse({ reports: [], next_before: null }) });
    renderApp("/reports");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Reports" })).toHaveAttribute("href", "/reports");
  });
});

describe("audit export", () => {
  it("exports the applied filters and saves the server's filename", async () => {
    const admin = makeUser({ role: "admin", username: "admin" });
    const fetchMock = api(admin, {
      "GET /api/v1/admin/audit": jsonResponse({ events: [], next_before_id: null }),
      "GET /api/v1/admin/alerts": jsonResponse([]),
      "GET /api/v1/admin/audit/export": () =>
        new Response(new Blob(["id,action\r\n"]), {
          headers: {
            "Content-Disposition": 'attachment; filename="sentinel-audit-20261004-090000.csv"',
            "X-Export-Rows": "12",
            "X-Export-Truncated": "false",
          },
        }),
    });
    renderApp("/admin/audit");
    await userEvent.selectOptions(await screen.findByLabelText("Outcome"), "DENIED");
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await userEvent.click(screen.getByRole("button", { name: "CSV" }));

    await waitFor(() =>
      expect(saved).toEqual([{ name: "sentinel-audit-20261004-090000.csv", href: "blob:x" }]),
    );
    expect(
      fetchMock.mock.calls.some(
        ([url]) => url === "/api/v1/admin/audit/export?outcome=DENIED&format=csv",
      ),
    ).toBe(true);
    expect(await screen.findByText("Exported 12 events")).toBeInTheDocument();
  });

  it("never trusts an odd filename from the header", () => {
    expect(exportFilename('attachment; filename="../../evil.exe"', "csv")).toBe(
      "sentinel-audit.csv",
    );
    expect(exportFilename(null, "json")).toBe("sentinel-audit.json");
    expect(exportFilename('attachment; filename="sentinel-audit-1.json"', "json")).toBe(
      "sentinel-audit-1.json",
    );
  });
});
