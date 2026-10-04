/**
 * The one place the frontend talks HTTP to the backend.
 *
 * Security properties (ADR 0003 client contract, ADR 0004):
 *
 * - **Same-origin only.** Paths must be absolute paths on this origin. A full
 *   URL is refused, so a bug can never send session cookies to another host.
 *   `credentials: "same-origin"` is the stricter equivalent of the ADR's
 *   `"include"` for our relative URLs.
 * - **CSRF.** Every state-changing request echoes the CSRF cookie in
 *   `X-CSRF-Token`.
 * - **Timeouts.** Every request has one (CLAUDE.md rule 7).
 * - **Single-flight refresh.** On a 401 `authentication_required` the client
 *   refreshes once and retries the request once. Concurrent 401s share one
 *   refresh, and the Web Locks API serialises refreshes across tabs: two
 *   parallel refreshes with the same token look like token theft to the server
 *   and revoke the session (ADR 0003, section 2).
 */

import { CSRF_HEADER, readCsrfToken } from "./csrf";
import { ApiError, NetworkError, errorFromResponse } from "./errors";

export const DEFAULT_TIMEOUT_MS = 10_000;
const REFRESH_PATH = "/api/v1/auth/refresh";
const REFRESH_LOCK = "sentinel-session-refresh";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
export type QueryValue = string | number | boolean | null | undefined;

export interface RequestOptions {
  body?: unknown;
  query?: Record<string, QueryValue>;
  signal?: AbortSignal;
  timeoutMs?: number;
  /** Skip the refresh-and-retry dance (used by the auth endpoints themselves). */
  skipRefresh?: boolean;
}

// --- session-expiry notifications -------------------------------------------

type Listener = () => void;
const sessionExpiredListeners = new Set<Listener>();

/** Called when a refresh fails, i.e. the user must log in again. */
export function onSessionExpired(listener: Listener): () => void {
  sessionExpiredListeners.add(listener);
  return () => sessionExpiredListeners.delete(listener);
}

function notifySessionExpired(): void {
  for (const listener of sessionExpiredListeners) listener();
}

// --- URL handling -------------------------------------------------------------

/** Reject anything that is not a same-origin absolute path. */
export function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  // "//host" is protocol-relative and "/\host" is treated like it by browsers.
  if (!path.startsWith("/") || path.startsWith("//") || path.startsWith("/\\")) {
    throw new Error(`API paths must be same-origin absolute paths, got ${JSON.stringify(path)}`);
  }
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    params.append(key, String(value));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

// --- core request ---------------------------------------------------------------

async function send(method: HttpMethod, url: string, options: RequestOptions): Promise<Response> {
  const timeout = AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout;

  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (!SAFE_METHODS.has(method)) {
    const csrf = readCsrfToken();
    if (csrf) headers[CSRF_HEADER] = csrf;
  }

  try {
    return await fetch(url, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal,
    });
  } catch (error) {
    // A caller-initiated abort (component unmounted, query cancelled) is not a
    // failure; let it propagate unchanged so TanStack Query can ignore it.
    if (options.signal?.aborted) throw error;
    if (timeout.aborted) throw new NetworkError("The request timed out.", "timeout");
    throw new NetworkError();
  }
}

async function parse<T>(response: Response): Promise<T> {
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  if (!text) return undefined as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError("The server returned a malformed response.", {
      status: response.status,
      code: "malformed_response",
    });
  }
}

// --- refresh ----------------------------------------------------------------------

let refreshInFlight: Promise<boolean> | null = null;

async function doRefresh(): Promise<boolean> {
  try {
    const response = await send("POST", REFRESH_PATH, {});
    return response.ok;
  } catch {
    return false;
  }
}

function withCrossTabLock(fn: () => Promise<boolean>): Promise<boolean> {
  const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
  if (!locks) return fn();
  return locks.request(REFRESH_LOCK, fn);
}

/**
 * Refresh the session. Concurrent callers share one network request.
 * Resolves to whether the session is usable afterwards.
 */
export function refreshSession(): Promise<boolean> {
  if (!refreshInFlight) {
    refreshInFlight = withCrossTabLock(doRefresh).finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

// --- public API ---------------------------------------------------------------------

/** Send with the refresh-and-retry dance; throws ApiError for any non-2xx response. */
async function sendWithRefresh(
  method: HttpMethod,
  path: string,
  options: RequestOptions,
): Promise<Response> {
  const url = buildUrl(path, options.query);
  let response = await send(method, url, options);

  if (response.status === 401 && !options.skipRefresh) {
    const error = await errorFromResponse(response.clone());
    // invalid_credentials is a wrong password, not an expired session.
    if (error.code === "authentication_required") {
      if (await refreshSession()) {
        response = await send(method, url, options);
      } else {
        notifySessionExpired();
        throw error;
      }
      if (response.status === 401) notifySessionExpired();
    }
  }

  if (!response.ok) throw await errorFromResponse(response);
  return response;
}

export async function request<T>(
  method: HttpMethod,
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  return parse<T>(await sendWithRefresh(method, path, options));
}

export interface DownloadedFile {
  blob: Blob;
  headers: Headers;
}

/**
 * Fetch a file (report, audit export) through the same client: same-origin,
 * session refresh, timeout. A plain `<a href>` would bypass the refresh, so an
 * expired access token would save a JSON error as the "report".
 */
export async function download(
  path: string,
  options: Omit<RequestOptions, "body"> = {},
): Promise<DownloadedFile> {
  const response = await sendWithRefresh("GET", path, { timeoutMs: 60_000, ...options });
  return { blob: await response.blob(), headers: response.headers };
}

/** Hand a blob to the browser as a download, then release it. */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.append(link);
  link.click();
  link.remove();
  // Revoke on the next tick: some browsers start the download asynchronously.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export const api = {
  get: <T>(path: string, options?: Omit<RequestOptions, "body">) =>
    request<T>("GET", path, options),
  post: <T>(path: string, body?: unknown, options?: RequestOptions) =>
    request<T>("POST", path, { ...options, body }),
  patch: <T>(path: string, body?: unknown, options?: RequestOptions) =>
    request<T>("PATCH", path, { ...options, body }),
  delete: <T>(path: string, options?: RequestOptions) => request<T>("DELETE", path, options),
};

/** Test hook: forget any in-flight refresh between tests. */
export function __resetClientStateForTests(): void {
  refreshInFlight = null;
  sessionExpiredListeners.clear();
}
