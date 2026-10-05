"""``GET /metrics`` for Prometheus (optional observability profile, ADR 0016).

* **Off by default:** without ``METRICS_TOKEN`` the route answers 404, like
  any unknown path.
* **Bearer token, compared in constant time.** It is not a user session:
  Prometheus has no cookies or CSRF token, and metrics are not per-user data.
* **Not proxied by the production nginx** (only /api, /health, /ready, /ws),
  so only containers on the Docker networks can reach it.
"""

import hmac

from fastapi import APIRouter, Request, Response

from app.core import metrics
from app.core.auth.dependencies import SessionDep, SettingsDep
from app.core.errors import AuthenticationRequired, NotFound
from app.core.logging import get_logger
from app.core.runs.events import get_redis

logger = get_logger("sentinel.metrics")

router = APIRouter(tags=["metrics"])


@router.get(metrics.METRICS_ROUTE, include_in_schema=False)
async def prometheus_metrics(request: Request, db: SessionDep, settings: SettingsDep) -> Response:
    token = settings.metrics_token
    if token is None or not metrics.enabled():
        raise NotFound()
    scheme, _, supplied = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(
        supplied.encode(), token.get_secret_value().encode()
    ):
        logger.warning("metrics.auth_failed")
        raise AuthenticationRequired("A valid metrics token is required.")
    body, content_type = metrics.render(await metrics.business_metrics(db, get_redis()))
    return Response(body, media_type=content_type)
