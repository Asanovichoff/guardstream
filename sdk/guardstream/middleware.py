import logging
import time
import uuid
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# How many fast-path latency samples to keep in Redis for percentile calculation.
_LATENCY_WINDOW = 1000


class GuardStreamMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, guard) -> None:
        super().__init__(app)
        self._guard = guard

    async def dispatch(self, request: Request, call_next):
        ip = self._get_ip(request)
        endpoint = request.url.path

        t0 = time.perf_counter()
        try:
            allowed, reason = self._guard.enforcer.check(ip, endpoint)
        except Exception as exc:
            # Redis is unreachable — fail open: allow the request, log the outage.
            # Rationale: a temporary lapse in rate limiting is less harmful than
            # returning 500 to every user while Redis recovers.
            logger.error("GuardStream enforcer unavailable — failing open: %s", exc)
            return await call_next(request)

        latency_ms = (time.perf_counter() - t0) * 1000
        self._record_latency(latency_ms)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "reason": reason,
                    "retry_after": self._guard.config.block_ttl_seconds,
                },
                headers={"Retry-After": str(self._guard.config.block_ttl_seconds)},
            )

        response = await call_next(request)

        self._guard.publisher.publish({
            "ip": ip,
            "endpoint": endpoint,
            "method": request.method,
            "user_agent": request.headers.get("user-agent", ""),
            "status_code": response.status_code,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        return response

    def _record_latency(self, latency_ms: float) -> None:
        try:
            r = self._guard.enforcer._redis
            member = uuid.uuid4().hex
            pipe = r.pipeline()
            pipe.zadd("gs:metrics:fastpath_ms", {member: latency_ms})
            pipe.zremrangebyrank("gs:metrics:fastpath_ms", 0, -(_LATENCY_WINDOW + 1))
            pipe.incr("gs:metrics:request_count")
            pipe.execute()
        except Exception:
            pass  # never let metrics recording affect the request path

    @staticmethod
    def _get_ip(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
