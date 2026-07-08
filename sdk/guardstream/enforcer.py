import os
import time

import redis as redis_lib

from .config import GuardStreamConfig

_LUA_PATH = os.path.join(os.path.dirname(__file__), "lua", "fast_path.lua")


class Enforcer:
    def __init__(self, redis_client: redis_lib.Redis, config: GuardStreamConfig) -> None:
        self._redis = redis_client
        self._config = config
        with open(_LUA_PATH) as f:
            self._sha = self._redis.script_load(f.read())

    def check(self, ip: str, endpoint: str) -> tuple[bool, str]:
        """
        Returns (allowed, message).
        allowed=False means the request should be blocked; message is the reason.
        """
        now_ms = int(time.time() * 1000)
        result = self._redis.evalsha(
            self._sha,
            3,
            f"gs:blocked:{ip}",
            f"gs:window:{ip}:{endpoint}",
            f"gs:blocked:{ip}:reason",
            now_ms,
            self._config.window_seconds * 1000,
            self._config.default_limit,
        )
        status, message = result
        if isinstance(message, bytes):
            message = message.decode()
        return bool(status), message
