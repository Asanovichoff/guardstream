from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class GuardStreamMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, guard) -> None:
        super().__init__(app)
        self._guard = guard

    async def dispatch(self, request: Request, call_next):
        ip = self._get_ip(request)
        endpoint = request.url.path

        allowed, reason = self._guard.enforcer.check(ip, endpoint)

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

    @staticmethod
    def _get_ip(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
