import { describe, expect, it } from "vitest";

import { readCookie, readCsrfToken } from "./api/csrf";
import { ApiError, NetworkError } from "./api/errors";
import { shouldRetry } from "./queryClient";
import { safeRedirectPath } from "./safeRedirect";

describe("safeRedirectPath (open-redirect guard)", () => {
  it.each([
    ["/tools/echo", "/tools/echo"],
    ["/admin/audit?tab=alerts", "/admin/audit?tab=alerts"],
    ["/account#security", "/account#security"],
  ])("keeps internal path %s", (input, expected) => {
    expect(safeRedirectPath(input)).toBe(expected);
  });

  it.each([
    null,
    "",
    "https://evil.example",
    "//evil.example",
    "/\\evil.example",
    "/\t/evil.example",
    "/\n/evil.example",
    "javascript:alert(1)",
    "evil.example",
    "/login",
    "/login?next=/x",
    `/${"a".repeat(3000)}`,
  ])("rejects %j", (input) => {
    expect(safeRedirectPath(input)).toBe("/");
  });
});

describe("CSRF cookie lookup", () => {
  it("reads and decodes a named cookie", () => {
    expect(readCookie("b", "a=1; b=hello%20world; c=3")).toBe("hello world");
    expect(readCookie("missing", "a=1")).toBeNull();
  });

  it("does not match on a name suffix", () => {
    expect(readCookie("csrf", "xcsrf=1")).toBeNull();
  });

  it("prefers the __Host- prefixed cookie over the dev fallback", () => {
    expect(readCsrfToken("sentinel_csrf=dev; __Host-sentinel_csrf=prod")).toBe("prod");
    expect(readCsrfToken("sentinel_csrf=dev")).toBe("dev");
    expect(readCsrfToken("")).toBeNull();
  });
});

describe("query retry policy", () => {
  it("retries network errors and 5xx a limited number of times", () => {
    expect(shouldRetry(0, new NetworkError())).toBe(true);
    expect(shouldRetry(1, new ApiError("x", { status: 503 }))).toBe(true);
    expect(shouldRetry(2, new NetworkError())).toBe(false);
  });

  it("never retries client errors or rate limits", () => {
    for (const status of [400, 401, 403, 404, 422, 429]) {
      expect(shouldRetry(0, new ApiError("x", { status }))).toBe(false);
    }
    expect(shouldRetry(0, new Error("render bug"))).toBe(false);
  });
});
