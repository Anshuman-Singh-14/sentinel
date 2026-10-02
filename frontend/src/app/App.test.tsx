/**
 * App-level flows through the real route table, providers and API client,
 * with only `fetch` stubbed.
 */

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { __resetClientStateForTests } from "../lib/api/client";
import {
  ECHO_TOOL,
  errorResponse,
  jsonResponse,
  makeSession,
  makeUser,
  mockFetch,
  renderApp,
} from "../test/utils";
import type { AuditEvent } from "../types/api";

const HEALTH = jsonResponse({ status: "ok", version: "0.3.0" });

afterEach(() => {
  __resetClientStateForTests();
});

function signedIn(user = makeUser(), extra: Parameters<typeof mockFetch>[0] = {}) {
  return mockFetch({
    "GET /api/v1/auth/me": jsonResponse(user),
    "GET /api/v1/tools": jsonResponse([ECHO_TOOL]),
    "GET /health": HEALTH,
    ...extra,
  });
}

function anonymous(extra: Parameters<typeof mockFetch>[0] = {}) {
  return mockFetch({
    "GET /api/v1/auth/me": errorResponse(401, "authentication_required"),
    "POST /api/v1/auth/refresh": errorResponse(401, "authentication_required"),
    ...extra,
  });
}

describe("authentication", () => {
  it("redirects an anonymous user to /login, remembering the page", async () => {
    anonymous();
    const { router } = renderApp("/account");
    expect(await screen.findByRole("button", { name: /sign in/i })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/login");
    expect(router.state.location.search).toBe("?next=%2Faccount");
  });

  it("logs in end to end and lands on the requested page", async () => {
    const user = makeUser();
    let loggedIn = false;
    const fetchMock = anonymous({
      "GET /api/v1/auth/me": () =>
        loggedIn ? jsonResponse(user) : errorResponse(401, "authentication_required"),
      "POST /api/v1/auth/login": () => {
        loggedIn = true;
        return jsonResponse(makeSession(user));
      },
      "GET /api/v1/tools": jsonResponse([ECHO_TOOL]),
      "GET /health": HEALTH,
    });
    const { router } = renderApp("/login?next=%2Ftools%2Fecho");

    await userEvent.type(await screen.findByLabelText("Username"), "analyst01");
    await userEvent.type(screen.getByLabelText("Password"), "correct horse battery");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByRole("heading", { name: "Echo", level: 1 })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/tools/echo");
    const loginCall = fetchMock.mock.calls.find(([url]) => url === "/api/v1/auth/login")!;
    expect(JSON.parse((loginCall[1] as RequestInit).body as string)).toEqual({
      username: "analyst01",
      password: "correct horse battery",
    });
  });

  it("shows the generic error on bad credentials and clears the password", async () => {
    anonymous({
      "POST /api/v1/auth/login": errorResponse(
        401,
        "invalid_credentials",
        "Invalid username or password.",
      ),
    });
    renderApp("/login");
    await userEvent.type(await screen.findByLabelText("Username"), "someone");
    await userEvent.type(screen.getByLabelText("Password"), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid username or password.");
    expect(screen.getByLabelText("Password")).toHaveValue("");
  });

  it("explains rate limiting", async () => {
    anonymous({ "POST /api/v1/auth/login": errorResponse(429, "rate_limited") });
    renderApp("/login");
    await userEvent.type(await screen.findByLabelText("Username"), "someone");
    await userEvent.type(screen.getByLabelText("Password"), "pw");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/too many sign-in attempts/i);
  });

  it("ignores an off-site next parameter (open redirect)", async () => {
    const user = makeUser();
    signedIn(user);
    const { router } = renderApp("/login?next=https%3A%2F%2Fevil.example");
    await screen.findByRole("heading", { name: /welcome back/i });
    expect(router.state.location.pathname).toBe("/");
  });

  it("signs out and returns to the login page", async () => {
    const user = makeUser();
    let loggedIn = true;
    const fetchMock = signedIn(user, {
      "GET /api/v1/auth/me": () =>
        loggedIn ? jsonResponse(user) : errorResponse(401, "authentication_required"),
      "POST /api/v1/auth/refresh": errorResponse(401, "authentication_required"),
      "POST /api/v1/auth/logout": () => {
        loggedIn = false;
        return new Response(null, { status: 204 });
      },
    });
    const { router } = renderApp("/");
    await userEvent.click(await screen.findByRole("button", { name: /sign out/i }));
    expect(await screen.findByRole("button", { name: /sign in/i })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/login");
    expect(fetchMock.mock.calls.some(([url]) => url === "/api/v1/auth/logout")).toBe(true);
  });

  it("sends the user to login when the session expires mid-use", async () => {
    const user = makeUser();
    signedIn(user, {
      "GET /api/v1/auth/me": jsonResponse(user),
      "GET /api/v1/tools": errorResponse(401, "authentication_required"),
      "POST /api/v1/auth/refresh": errorResponse(401, "authentication_required"),
    });
    const { router } = renderApp("/");
    await waitFor(() => expect(router.state.location.pathname).toBe("/login"));
    expect(await screen.findByText(/session ended/i)).toBeInTheDocument();
  });

  it("shows an outage message instead of the login page when the API is down", async () => {
    mockFetch({
      "GET /api/v1/auth/me": errorResponse(503, "service_unavailable", "Service unavailable."),
    });
    const { router } = renderApp("/");
    expect(await screen.findByText(/cannot reach sentinel/i)).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/");
  });
});

describe("shell and navigation", () => {
  it("builds the sidebar from the local manifest and the backend catalogue", async () => {
    signedIn();
    renderApp("/");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(await within(nav).findByRole("link", { name: /echo/i })).toHaveAttribute(
      "href",
      "/tools/echo",
    );
    expect(within(nav).getByText("Diagnostics")).toBeInTheDocument();
    expect(within(nav).getByText(/runs in your browser only/i)).toBeInTheDocument();
    // Local tools are not shipped yet: listed, but not links.
    const password = within(nav).getByText("Password Analyzer").closest("[aria-disabled]");
    expect(password).toHaveAttribute("aria-disabled", "true");
  });

  it("shows API status and version in the status area", async () => {
    signedIn();
    renderApp("/");
    expect(await screen.findByText("API online")).toBeInTheDocument();
    expect(await screen.findByText("v0.3.0")).toBeInTheDocument();
  });

  it("navigates to a tool page with its parameter schema", async () => {
    signedIn();
    renderApp("/");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    await userEvent.click(await within(nav).findByRole("link", { name: /echo/i }));
    expect(await screen.findByRole("heading", { name: "Echo", level: 1 })).toBeInTheDocument();
    expect(screen.getByRole("tree", { name: "Parameter JSON Schema" })).toBeInTheDocument();
  });

  it("tells a viewer they cannot run an analyst tool", async () => {
    signedIn(makeUser({ role: "viewer", username: "viewer01" }));
    renderApp("/tools/echo");
    expect(await screen.findByText(/cannot run it/i)).toBeInTheDocument();
  });

  it("shows not-found for unknown tools and routes", async () => {
    signedIn();
    renderApp("/tools/nope");
    expect(await screen.findByRole("heading", { name: "Not found" })).toBeInTheDocument();
  });
});

describe("RBAC", () => {
  it("hides admin navigation and blocks the audit page for non-admins", async () => {
    signedIn(makeUser({ role: "analyst" }));
    renderApp("/admin/audit");
    expect(await screen.findByRole("heading", { name: "Access denied" })).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).queryByText("Audit log")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /security alert/i })).not.toBeInTheDocument();
  });
});

describe("admin audit viewer", () => {
  const admin = makeUser({ role: "admin", username: "admin" });
  const event: AuditEvent = {
    id: 7,
    event_id: "e7",
    occurred_at: "2026-10-02T09:00:00Z",
    actor_type: "user",
    user_id: admin.id,
    username: "admin",
    role: "admin",
    session_id: "s1",
    source_ip: "172.18.0.1",
    user_agent: "<script>alert(1)</script>",
    service: "api",
    hostname: "api-1",
    process_user: "app",
    action: "auth.login.failure",
    resource_type: null,
    resource_id: null,
    target: null,
    outcome: "FAILURE",
    reason: "bad_password",
    details: {},
    request_id: "req-7",
    is_security_event: true,
    prev_hash: "0".repeat(64),
    row_hash: "a".repeat(64),
  };

  function adminApi(extra: Parameters<typeof mockFetch>[0] = {}) {
    return signedIn(admin, {
      "GET /api/v1/admin/audit": jsonResponse({ events: [event], next_before_id: null }),
      "GET /api/v1/admin/alerts": jsonResponse([
        {
          id: "al1",
          created_at: "2026-10-02T09:01:00Z",
          rule: "failed_login_burst",
          severity: "HIGH",
          message: "5 failed logins for admin",
          details: {},
          audit_event_id: null,
          acknowledged_at: null,
          acknowledged_by: null,
        },
      ]),
      ...extra,
    });
  }

  it("lists events and opens the detail drawer with escaped content", async () => {
    adminApi();
    const { container } = renderApp("/admin/audit");
    const row = await screen.findByRole("row", { name: /event 7/i });
    expect(within(row).getByText("FAILURE")).toBeInTheDocument();
    await userEvent.click(row);
    const dialog = screen.getByRole("dialog", { name: /event #7/i });
    expect(within(dialog).getByText("req-7")).toBeInTheDocument();
    expect(container.ownerDocument.querySelector("script")).toBeNull();
  });

  it("sends filters to the API", async () => {
    const fetchMock = adminApi();
    renderApp("/admin/audit");
    await screen.findByRole("row", { name: /event 7/i });
    await userEvent.type(screen.getByLabelText("Username"), "admin");
    await userEvent.selectOptions(screen.getByLabelText("Outcome"), "DENIED");
    await userEvent.click(screen.getByLabelText(/security events only/i));
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([url]) =>
            String(url) === "/api/v1/admin/audit?username=admin&outcome=DENIED&security_only=true",
        ),
      ).toBe(true),
    );
  });

  it("verifies the chain and reports a break", async () => {
    adminApi({
      "POST /api/v1/admin/audit/verify": jsonResponse({
        ok: false,
        checked: 12,
        head_hash: "f".repeat(64),
        first_broken_id: 5,
        reason: "row_hash_mismatch",
      }),
    });
    renderApp("/admin/audit");
    await userEvent.click(await screen.findByRole("button", { name: /verify chain/i }));
    const alert = await screen.findByText("Chain broken");
    expect(alert.closest("[role=alert]")).toHaveTextContent("#5 (row_hash_mismatch)");
  });

  it("shows open alerts in the top bar and lets an admin acknowledge them", async () => {
    let acked = false;
    const alert = {
      id: "al1",
      created_at: "2026-10-02T09:01:00Z",
      rule: "failed_login_burst",
      severity: "HIGH",
      message: "5 failed logins for admin",
      details: {},
      audit_event_id: null,
      acknowledged_at: null as string | null,
      acknowledged_by: null,
    };
    adminApi({
      "GET /api/v1/admin/alerts": () => jsonResponse(acked ? [] : [alert]),
      "POST /api/v1/admin/alerts/al1/acknowledge": () => {
        acked = true;
        return jsonResponse({ ...alert, acknowledged_at: "2026-10-02T09:05:00Z" });
      },
    });
    renderApp("/admin/audit?tab=alerts");
    const bell = await screen.findByRole("link", { name: "1 open security alert" });
    expect(bell).toHaveAttribute("href", "/admin/audit?tab=alerts");
    expect(await screen.findByText("5 failed logins for admin")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Acknowledge" }));
    expect(await screen.findByText("No open alerts.")).toBeInTheDocument();
    expect(
      await screen.findByRole("link", { name: "No open security alerts" }),
    ).toBeInTheDocument();
  });
});
