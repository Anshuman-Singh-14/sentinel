import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { errorResponse, jsonResponse, mockFetch } from "../../test/utils";
import { __resetClientStateForTests, api, buildUrl, onSessionExpired } from "./client";
import { ApiError, NetworkError } from "./errors";

function headersOf(call: unknown[]): Record<string, string> {
  return (call[1] as RequestInit).headers as Record<string, string>;
}

// jsdom runs on http://, where browsers refuse __Host- cookies, so these tests
// use the dev-mode name. Prefix precedence is covered in lib.test.ts.
beforeEach(() => {
  document.cookie = "sentinel_csrf=csrf-token-value";
});

afterEach(() => {
  __resetClientStateForTests();
  document.cookie = "sentinel_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
});

describe("buildUrl", () => {
  it.each(["https://evil.example/x", "//evil.example/x", "/\\evil.example", "api/v1/tools"])(
    "refuses non same-origin path %s",
    (path) => {
      expect(() => buildUrl(path)).toThrow(/same-origin/);
    },
  );

  it("encodes query parameters and drops empty values", () => {
    expect(buildUrl("/api/v1/x", { a: "b c", n: 1, skip: undefined, empty: "", f: false })).toBe(
      "/api/v1/x?a=b+c&n=1&f=false",
    );
  });
});

describe("request basics", () => {
  it("sends same-origin credentials and no CSRF header on GET", async () => {
    const fetchMock = mockFetch({ "GET /api/v1/tools": jsonResponse([]) });
    await api.get("/api/v1/tools");
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    expect(init.credentials).toBe("same-origin");
    expect(init.redirect).toBe("error");
    expect(headersOf(fetchMock.mock.calls[0]!)).not.toHaveProperty("X-CSRF-Token");
  });

  it("echoes the CSRF cookie on state-changing requests", async () => {
    const fetchMock = mockFetch({ "POST /api/v1/x": jsonResponse({ ok: true }) });
    await api.post("/api/v1/x", { a: 1 });
    const headers = headersOf(fetchMock.mock.calls[0]!);
    expect(headers["X-CSRF-Token"]).toBe("csrf-token-value");
    expect(headers["Content-Type"]).toBe("application/json");
    expect((fetchMock.mock.calls[0]![1] as RequestInit).body).toBe('{"a":1}');
  });

  it("returns undefined for 204", async () => {
    mockFetch({ "POST /api/v1/auth/logout": new Response(null, { status: 204 }) });
    await expect(api.post("/api/v1/auth/logout")).resolves.toBeUndefined();
  });

  it("parses the backend error envelope", async () => {
    mockFetch({ "GET /api/v1/x": errorResponse(403, "permission_denied", "Not allowed.") });
    const error = await api.get("/api/v1/x").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({
      status: 403,
      code: "permission_denied",
      message: "Not allowed.",
      requestId: "req-1",
    });
  });

  it("never surfaces a non-envelope body", async () => {
    mockFetch({ "GET /api/v1/x": new Response("<html>stack trace</html>", { status: 502 }) });
    const error = (await api.get("/api/v1/x").catch((e: unknown) => e)) as ApiError;
    expect(error.code).toBe("http_502");
    expect(error.message).not.toContain("stack trace");
  });

  it("maps fetch failures to NetworkError", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(api.get("/api/v1/x")).rejects.toBeInstanceOf(NetworkError);
  });

  it("times out", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_url: string, init: RequestInit) =>
          new Promise((_resolve, reject) => {
            init.signal?.addEventListener("abort", () => reject(init.signal?.reason));
          }),
      ),
    );
    const error = (await api
      .get("/api/v1/x", { timeoutMs: 10 })
      .catch((e: unknown) => e)) as ApiError;
    expect(error).toBeInstanceOf(NetworkError);
    expect(error.code).toBe("timeout");
  });

  it("propagates caller aborts unchanged", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_url: string, init: RequestInit) =>
          new Promise((_resolve, reject) => {
            init.signal?.addEventListener("abort", () =>
              reject(new DOMException("x", "AbortError")),
            );
          }),
      ),
    );
    const controller = new AbortController();
    const pending = api.get("/api/v1/x", { signal: controller.signal });
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
  });
});

describe("refresh on 401", () => {
  it("refreshes once and retries the request", async () => {
    let calls = 0;
    const fetchMock = mockFetch({
      "GET /api/v1/x": () =>
        ++calls === 1 ? errorResponse(401, "authentication_required") : jsonResponse({ value: 42 }),
      "POST /api/v1/auth/refresh": jsonResponse({}),
    });
    await expect(api.get("/api/v1/x")).resolves.toEqual({ value: 42 });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("shares one refresh between concurrent 401s (single-flight)", async () => {
    let refreshed = false;
    let resolveRefresh: (() => void) | undefined;
    const fetchMock = mockFetch({
      "GET /api/v1/a": () =>
        refreshed ? jsonResponse("a") : errorResponse(401, "authentication_required"),
      "GET /api/v1/b": () =>
        refreshed ? jsonResponse("b") : errorResponse(401, "authentication_required"),
      "POST /api/v1/auth/refresh": () =>
        new Promise<Response>((resolve) => {
          resolveRefresh = () => {
            refreshed = true;
            resolve(jsonResponse({}));
          };
        }),
    });
    const both = Promise.all([api.get("/api/v1/a"), api.get("/api/v1/b")]);
    await vi.waitFor(() => expect(resolveRefresh).toBeDefined());
    resolveRefresh!();
    await expect(both).resolves.toEqual(["a", "b"]);
    const refreshCalls = fetchMock.mock.calls.filter(([url]) => url === "/api/v1/auth/refresh");
    expect(refreshCalls).toHaveLength(1);
  });

  it("notifies session expiry when the refresh fails", async () => {
    const expired = vi.fn();
    onSessionExpired(expired);
    mockFetch({
      "GET /api/v1/x": errorResponse(401, "authentication_required"),
      "POST /api/v1/auth/refresh": errorResponse(401, "authentication_required"),
    });
    await expect(api.get("/api/v1/x")).rejects.toMatchObject({ status: 401 });
    expect(expired).toHaveBeenCalledOnce();
  });

  it("does not refresh on invalid credentials or when skipRefresh is set", async () => {
    const fetchMock = mockFetch({
      "POST /api/v1/auth/login": errorResponse(401, "invalid_credentials"),
      "GET /api/v1/y": errorResponse(401, "authentication_required"),
    });
    await expect(api.post("/api/v1/auth/login", {})).rejects.toMatchObject({
      code: "invalid_credentials",
    });
    await expect(api.get("/api/v1/y", { skipRefresh: true })).rejects.toMatchObject({
      status: 401,
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("serialises refreshes across tabs with the Web Locks API when available", async () => {
    const request = vi.fn((_name: string, fn: () => Promise<boolean>) => fn());
    vi.stubGlobal("navigator", { ...navigator, locks: { request } });
    let calls = 0;
    mockFetch({
      "GET /api/v1/x": () =>
        ++calls === 1 ? errorResponse(401, "authentication_required") : jsonResponse(1),
      "POST /api/v1/auth/refresh": jsonResponse({}),
    });
    await api.get("/api/v1/x");
    expect(request).toHaveBeenCalledWith("sentinel-session-refresh", expect.any(Function));
  });
});
