/**
 * Typed API errors.
 *
 * The backend always answers failures with one envelope (backend/app/core/errors.py):
 *
 *     {"error": {"code": "...", "message": "...", "request_id": "...", "details": {}}}
 *
 * `code` is stable and drives client behaviour (for example, refresh on
 * `authentication_required`). `message` is written to be safe to show a user.
 * `requestId` is shown with errors so a user can quote it and an admin can find
 * the matching server-side log lines.
 */

export class ApiError extends Error {
  readonly status: number | undefined;
  readonly code: string;
  readonly requestId: string | undefined;
  readonly details: Record<string, unknown>;

  constructor(
    message: string,
    options: {
      status?: number;
      code?: string;
      requestId?: string;
      details?: Record<string, unknown>;
    } = {},
  ) {
    super(message);
    this.name = "ApiError";
    this.status = options.status;
    this.code = options.code ?? "unknown_error";
    this.requestId = options.requestId;
    this.details = options.details ?? {};
  }
}

/** Raised when the request never got an HTTP response (offline, DNS, timeout). */
export class NetworkError extends ApiError {
  constructor(message = "The server could not be reached.", code = "network_error") {
    super(message, { code });
    this.name = "NetworkError";
  }
}

interface ErrorEnvelope {
  error: { code: string; message: string; request_id?: string | null; details?: unknown };
}

function isErrorEnvelope(value: unknown): value is ErrorEnvelope {
  if (typeof value !== "object" || value === null || !("error" in value)) return false;
  const err = (value as { error: unknown }).error;
  return (
    typeof err === "object" &&
    err !== null &&
    typeof (err as { code?: unknown }).code === "string" &&
    typeof (err as { message?: unknown }).message === "string"
  );
}

/**
 * Build an ApiError from a failed response. Anything that is not our envelope
 * (a proxy's HTML 502 page, for instance) becomes a generic message: we never
 * show raw upstream bodies to the user.
 */
export async function errorFromResponse(response: Response): Promise<ApiError> {
  const headerRequestId = response.headers.get("X-Request-ID") ?? undefined;
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  if (isErrorEnvelope(body)) {
    const details = body.error.details;
    return new ApiError(body.error.message, {
      status: response.status,
      code: body.error.code,
      requestId: body.error.request_id ?? headerRequestId,
      details:
        typeof details === "object" && details !== null ? (details as Record<string, unknown>) : {},
    });
  }
  return new ApiError(`The server returned an unexpected response (HTTP ${response.status}).`, {
    status: response.status,
    code: `http_${response.status}`,
    requestId: headerRequestId,
  });
}

/** A user-facing message for any thrown value. */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return "Something went wrong.";
}
