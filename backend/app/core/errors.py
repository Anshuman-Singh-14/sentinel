"""Exception hierarchy and the handlers that turn exceptions into structured JSON.

Every error response has the same shape::

    {"error": {"code": "scope_denied", "message": "...", "request_id": "...", "details": {}}}

``code`` is stable and machine-readable. ``message`` is safe to show a user.
Internal detail (stack traces, driver errors, file paths) never leaves the
server. It goes to the log under the same ``request_id`` (CLAUDE.md rule 8).
"""

import json
from collections.abc import Mapping
from http import HTTPStatus
from typing import Any, ClassVar, cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger
from app.core.logging.context import current_request_id

logger = get_logger("sentinel.errors")


class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: ErrorDetail


class SentinelError(Exception):
    """Base class for expected, user-facing failures."""

    code: ClassVar[str] = "internal_error"
    status_code: ClassVar[int] = 500
    default_message: ClassVar[str] = "An internal error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ):
        self.message = message or self.default_message
        self.details = details or {}
        # Extra response headers, e.g. Retry-After on 429 or WWW-Authenticate on 401.
        self.headers = dict(headers or {})
        super().__init__(self.message)


class ValidationFailed(SentinelError):
    code = "validation_failed"
    status_code = 422
    default_message = "The request is invalid."


class AuthenticationRequired(SentinelError):
    code = "authentication_required"
    status_code = 401
    default_message = "Authentication is required."


class InvalidCredentials(AuthenticationRequired):
    # One message for every login failure (unknown user, wrong password,
    # locked, disabled), so the response cannot be used to enumerate accounts.
    # The real reason is recorded in the audit log only.
    code = "invalid_credentials"
    default_message = "Invalid username or password."


class PermissionDenied(SentinelError):
    code = "permission_denied"
    status_code = 403
    default_message = "You do not have permission to perform this action."


class CsrfFailed(PermissionDenied):
    code = "csrf_failed"
    default_message = "The request failed cross-site request forgery validation."


class ScopeDenied(PermissionDenied):
    code = "scope_denied"
    default_message = "The target is outside the permitted scope."


class AuthorizationRequired(PermissionDenied):
    # The user has not yet accepted the authorised-use statement required
    # before running active tools (04-security.md section 2).
    code = "authorization_required"
    default_message = "Accept the authorised-use statement before running active tools."


class PathDenied(PermissionDenied):
    code = "path_denied"
    default_message = "The requested path is not permitted."


class NotFound(SentinelError):
    code = "not_found"
    status_code = 404
    default_message = "The requested resource was not found."


class ToolNotFound(NotFound):
    code = "tool_not_found"
    default_message = "No tool with that ID is registered."


class Conflict(SentinelError):
    code = "conflict"
    status_code = 409
    default_message = "The request conflicts with the current state."


class PasswordPolicyViolation(ValidationFailed):
    code = "password_policy"
    default_message = "The password does not meet the password policy."


class RateLimited(SentinelError):
    code = "rate_limited"
    status_code = 429
    default_message = "Too many requests. Try again later."


class ProviderError(SentinelError):
    code = "provider_error"
    status_code = 502
    default_message = "An external service failed to respond correctly."


class ServiceUnavailable(SentinelError):
    code = "service_unavailable"
    status_code = 503
    default_message = "A required service is temporarily unavailable."


class AuditUnavailable(ServiceUnavailable):
    # Raised when a security-relevant audit write fails. The action fails
    # closed rather than going unrecorded (03-logging-audit.md section 5).
    code = "audit_unavailable"
    default_message = "The action could not be recorded, so it was not performed."


class IntegrityCheckFailed(SentinelError):
    # Stored content no longer matches the hash recorded when it was written
    # (Phase 13 report downloads). Served as an error, never as the file.
    code = "integrity_failed"
    status_code = 500
    default_message = "The stored file failed its integrity check and was not served."


class ToolTimeout(SentinelError):
    code = "tool_timeout"
    status_code = 504
    default_message = "The tool did not finish within its time limit."


def _error_response(
    status_code: int,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    body = ErrorResponse(
        error=ErrorDetail(
            code=code, message=message, request_id=current_request_id(), details=details or {}
        )
    )
    return JSONResponse(status_code=status_code, content=body.model_dump(), headers=headers)


def internal_error_body(request_id: str | None) -> bytes:
    """Generic 500 body, used by the outermost middleware."""
    body = ErrorResponse(
        error=ErrorDetail(
            code=SentinelError.code, message=SentinelError.default_message, request_id=request_id
        )
    )
    return json.dumps(body.model_dump()).encode()


async def _handle_sentinel_error(request: Request, exc: Exception) -> JSONResponse:
    # Each handler is registered for exactly one exception type (see below).
    error = cast(SentinelError, exc)
    log = logger.error if error.status_code >= 500 else logger.warning
    log(
        "request.failed",
        error_code=error.code,
        status=error.status_code,
        error_message=error.message,
    )
    return _error_response(
        error.status_code, error.code, error.message, error.details, headers=error.headers
    )


async def _handle_validation_error(request: Request, exc: Exception) -> JSONResponse:
    # Pydantic includes the rejected *input* (and sometimes a ctx/url) in each
    # error. The input could be a password or token, so only the location,
    # message and type are returned.
    errors = [
        {"loc": list(err.get("loc", ())), "msg": err.get("msg", ""), "type": err.get("type", "")}
        for err in cast(RequestValidationError, exc).errors()
    ]
    logger.info("request.validation_failed", error_count=len(errors))
    return _error_response(
        422, ValidationFailed.code, ValidationFailed.default_message, {"errors": errors}
    )


_HTTP_STATUS_CODES = {
    401: "authentication_required",
    403: "permission_denied",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    429: "rate_limited",
}


async def _handle_http_exception(request: Request, exc: Exception) -> JSONResponse:
    http_exc = cast(StarletteHTTPException, exc)
    code = _HTTP_STATUS_CODES.get(http_exc.status_code, f"http_{http_exc.status_code}")
    try:
        default_message = HTTPStatus(http_exc.status_code).phrase
    except ValueError:
        default_message = "Request failed."
    message = http_exc.detail if isinstance(http_exc.detail, str) else default_message
    return _error_response(http_exc.status_code, code, message, headers=http_exc.headers)


def install_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(SentinelError, _handle_sentinel_error)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(StarletteHTTPException, _handle_http_exception)
