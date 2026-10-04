/**
 * Tools that accept uploads (Phase 10 log analyzer, ADR 0014): a file picker
 * appears, the file is sent as the raw request body to the upload route, the
 * size limit is checked before sending, and server-set fields stay hidden.
 */

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { __resetClientStateForTests } from "../../lib/api/client";
import { jsonResponse, makeUser, mockFetch, renderApp } from "../../test/utils";
import type { ToolDescriptor } from "../../types/api";
import { fieldsFromSchema } from "./SchemaForm";
import type { ObjectSchema } from "./SchemaForm";

const USER = makeUser();
const STOP = jsonResponse(
  { error: { code: "conflict", message: "stop here", request_id: "r", details: {} } },
  409,
);

const SCHEMA: ObjectSchema = {
  type: "object",
  properties: {
    path: { type: "string", title: "File on the server", maxLength: 255, default: "" },
    parser: {
      type: "string",
      title: "Log format",
      enum: ["auto", "auth_log", "nginx_access"],
      default: "auto",
    },
    upload_name: { type: "string", readOnly: true, default: "" },
  },
};

const LOG_TOOL: ToolDescriptor = {
  tool_id: "log_analyzer",
  name: "Log File Analyzer",
  description: "Finds signs of attack in logs.",
  version: "1.0.0",
  category: "FORENSIC",
  is_active: false,
  required_role: "analyst",
  params_schema: SCHEMA as Record<string, unknown>,
  available: true,
  accepts_upload: true,
  max_upload_bytes: 1024,
};

afterEach(() => __resetClientStateForTests());

function api(extra: Parameters<typeof mockFetch>[0] = {}) {
  return mockFetch({
    "GET /api/v1/auth/me": jsonResponse(USER),
    "GET /api/v1/tools": jsonResponse([LOG_TOOL]),
    "GET /health": jsonResponse({ status: "ok", version: "1.0.0" }),
    ...extra,
  });
}

describe("schema fields", () => {
  it("skips read-only, server-set properties", () => {
    const fields = fieldsFromSchema(SCHEMA);
    expect(Array.isArray(fields) && fields.map((f) => f.name)).toEqual(["path", "parser"]);
  });
});

describe("a tool that accepts uploads", () => {
  it("sends the chosen file as the raw body to the upload route", async () => {
    const fetchMock = api({ "POST /api/v1/tools/log_analyzer/runs/upload": STOP });
    renderApp("/tools/log_analyzer");
    const picker = await screen.findByLabelText("Upload a file");
    expect(screen.queryByLabelText(/upload name/i)).not.toBeInTheDocument();
    expect(screen.getByText(/up to 1 KB\. .*deleted when the run ends/)).toBeInTheDocument();

    const file = new File(["Oct  4 09:15:00 h sshd[1]: hi\n"], "auth.log", { type: "text/plain" });
    await userEvent.upload(picker, file);
    await userEvent.click(screen.getByRole("button", { name: "Upload and run" }));

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("stop here"));
    const call = fetchMock.mock.calls.find(([url]) =>
      String(url).startsWith("/api/v1/tools/log_analyzer/runs/upload"),
    )!;
    const url = new URL(String(call[0]), "http://localhost");
    expect(url.searchParams.get("filename")).toBe("auth.log");
    expect(JSON.parse(url.searchParams.get("params")!)).toEqual({ parser: "auto" });
    const init = call[1] as RequestInit;
    expect(init.body).toBe(file);
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe(
      "application/octet-stream",
    );
  });

  it("refuses a file over the limit without sending anything", async () => {
    const fetchMock = api();
    renderApp("/tools/log_analyzer");
    const picker = await screen.findByLabelText("Upload a file");
    await userEvent.upload(picker, new File(["x".repeat(2048)], "big.log"));

    expect(screen.getByRole("alert")).toHaveTextContent("larger than the");
    expect(screen.getByRole("button", { name: "Run" })).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes("/runs/upload"))).toBe(false);
  });

  it("without a file, runs on a server path through the JSON route", async () => {
    const fetchMock = api({ "POST /api/v1/tools/log_analyzer/runs": STOP });
    renderApp("/tools/log_analyzer");
    await userEvent.type(await screen.findByLabelText("File on the server (optional)"), "auth.log");
    await userEvent.click(screen.getByRole("button", { name: "Run" }));

    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([url]) => url === "/api/v1/tools/log_analyzer/runs")).toBe(
        true,
      ),
    );
    const call = fetchMock.mock.calls.find(([url]) => url === "/api/v1/tools/log_analyzer/runs")!;
    expect(JSON.parse((call[1] as RequestInit).body as string)).toEqual({
      params: { path: "auth.log", parser: "auto" },
    });
  });
});
