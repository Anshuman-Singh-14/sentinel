/**
 * File integrity monitor UI (Phase 11, ADR 0015): the baselines panel under the
 * FIM tools, with Check now, schedules and delete offered only to the users the
 * server would allow.
 */

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { __resetClientStateForTests } from "../../lib/api/client";
import { jsonResponse, makeUser, mockFetch, renderApp } from "../../test/utils";
import type { FimBaseline, ToolDescriptor, User } from "../../types/api";

const ME = makeUser();
const STOP = jsonResponse(
  { error: { code: "conflict", message: "stop here", request_id: "r", details: {} } },
  409,
);

function tool(toolId: string, name: string): ToolDescriptor {
  return {
    tool_id: toolId,
    name,
    description: `${name} description.`,
    version: "1.0.0",
    category: "FORENSIC",
    is_active: false,
    required_role: "analyst",
    params_schema: { type: "object", properties: {} },
    available: true,
    status: { roots: ["demo"] },
  };
}

function baseline(overrides: Partial<FimBaseline>): FimBaseline {
  return {
    id: "b-1",
    name: "web config",
    root: "demo",
    path: "etc",
    excludes: [],
    file_count: 42,
    dir_count: 5,
    other_count: 0,
    total_bytes: 1234,
    created_by: ME.id,
    created_by_username: ME.username,
    created_run_id: "r-0",
    created_at: "2026-10-05T05:00:00Z",
    schedule_minutes: null,
    last_scheduled_at: null,
    last_checked_at: "2026-10-05T06:00:00Z",
    last_check_run_id: "r-9",
    last_check_changes: 3,
    ...overrides,
  };
}

const MINE = baseline({});
const THEIRS = baseline({
  id: "b-2",
  name: "someone else's",
  path: "",
  created_by: "00000000-0000-0000-0000-0000000000ff",
  created_by_username: "bob",
  schedule_minutes: 60,
  last_check_run_id: null,
  last_checked_at: null,
  last_check_changes: null,
});

afterEach(() => {
  __resetClientStateForTests();
  vi.restoreAllMocks();
});

function api(user: User, baselines: FimBaseline[], extra: Parameters<typeof mockFetch>[0] = {}) {
  return mockFetch({
    "GET /api/v1/auth/me": jsonResponse(user),
    "GET /api/v1/tools": jsonResponse([
      tool("fim_baseline", "FIM: Create Baseline"),
      tool("fim_check", "File Integrity Check"),
    ]),
    "GET /health": jsonResponse({ status: "ok", version: "1.0.0" }),
    "GET /api/v1/fim/baselines": jsonResponse({ baselines, schedule_choices: [15, 60, 360, 1440] }),
    ...extra,
  });
}

describe("FIM baselines panel", () => {
  it("lists baselines with their location, last check and schedule", async () => {
    api(ME, [MINE, THEIRS]);
    renderApp("/tools/fim_check");

    await screen.findByText("web config");
    const panel = screen.getByRole("region", { name: "FIM baselines" });
    expect(within(panel).getByText("demo:/etc")).toBeInTheDocument();
    expect(within(panel).getByRole("link", { name: /3 change\(s\)/ })).toHaveAttribute(
      "href",
      "/runs/r-9",
    );
    expect(within(panel).getByText("Never")).toBeInTheDocument();
    expect(within(panel).getByText("Every 1 h", { selector: "span" })).toBeInTheDocument(); // read-only for bob's
  });

  it("offers schedule and delete only on the user's own baselines", async () => {
    api(ME, [MINE, THEIRS]);
    renderApp("/tools/fim_check");

    await screen.findByText("web config");
    expect(screen.getByLabelText("Check schedule for web config")).toBeInTheDocument();
    expect(screen.queryByLabelText("Check schedule for someone else's")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete web config" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete someone else's" })).not.toBeInTheDocument();
    // Any analyst may check any baseline.
    expect(screen.getByRole("button", { name: "Check someone else's now" })).toBeInTheDocument();
  });

  it("admins may change every baseline", async () => {
    api(makeUser({ role: "admin" }), [THEIRS]);
    renderApp("/tools/fim_check");

    expect(await screen.findByLabelText("Check schedule for someone else's")).toBeInTheDocument();
  });

  it("starts a check run for the chosen baseline", async () => {
    const fetchMock = api(ME, [MINE], { "POST /api/v1/tools/fim_check/runs": STOP });
    renderApp("/tools/fim_check");

    await userEvent.click(await screen.findByRole("button", { name: "Check web config now" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/api/v1/tools/fim_check/runs"),
        expect.objectContaining({ method: "POST" }),
      ),
    );
    const call = fetchMock.mock.calls.find(([url]) => String(url).includes("/fim_check/runs"));
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ params: { baseline_id: "b-1" } });
    expect(await screen.findByText("Could not start the check")).toBeInTheDocument();
  });

  it("sets a schedule", async () => {
    const fetchMock = api(ME, [MINE], {
      "PATCH /api/v1/fim/baselines/b-1": jsonResponse({ ...MINE, schedule_minutes: 360 }),
    });
    renderApp("/tools/fim_check");

    await userEvent.selectOptions(
      await screen.findByLabelText("Check schedule for web config"),
      "360",
    );

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(([, init]) => init?.method === "PATCH");
      expect(JSON.parse(String(call?.[1]?.body))).toEqual({ schedule_minutes: 360 });
    });
    expect(await screen.findByText("Schedule for 'web config': Every 6 h")).toBeInTheDocument();
  });

  it("deletes only after confirmation", async () => {
    const fetchMock = api(ME, [MINE], {
      "DELETE /api/v1/fim/baselines/b-1": new Response(null, { status: 204 }),
    });
    const confirm = vi
      .spyOn(window, "confirm")
      .mockReturnValueOnce(false)
      .mockReturnValueOnce(true);
    renderApp("/tools/fim_check");
    const button = await screen.findByRole("button", { name: "Delete web config" });

    await userEvent.click(button);
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === "DELETE")).toBe(false);

    await userEvent.click(button);
    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([, init]) => init?.method === "DELETE")).toBe(true),
    );
    expect(confirm).toHaveBeenCalledTimes(2);
  });

  it("viewers see the list without actions", async () => {
    api(makeUser({ role: "viewer" }), [MINE]);
    renderApp("/tools/fim_check");

    await screen.findByText("web config");
    expect(screen.queryByRole("button", { name: /Check .* now/ })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/Check schedule/)).not.toBeInTheDocument();
  });

  it("points to baseline creation when there are none", async () => {
    api(ME, []);
    renderApp("/tools/fim_check");

    expect(await screen.findByRole("link", { name: "Create one" })).toHaveAttribute(
      "href",
      "/tools/fim_baseline",
    );
  });

  it("appears on the baseline tool's page too", async () => {
    api(ME, []);
    renderApp("/tools/fim_baseline");

    expect(
      await screen.findByText("No baselines yet. Create the first one with the form above."),
    ).toBeInTheDocument();
  });
});
