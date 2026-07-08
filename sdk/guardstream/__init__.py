import redis as redis_lib

from .config import GuardStreamConfig
from .enforcer import Enforcer
from .middleware import GuardStreamMiddleware
from .publisher import KafkaPublisher

__all__ = ["GuardStream", "GuardStreamMiddleware"]


class GuardStream:
    """
    GuardStream client. Pass to GuardStreamMiddleware.

    Usage::

        guard = GuardStream(redis_url="redis://localhost:6379", kafka_url="localhost:9092")
        app.add_middleware(GuardStreamMiddleware, guard=guard)
    """

    def __init__(
        self,
        redis_url: str,
        kafka_url: str,
        default_limit: int = 60,
        window_seconds: int = 60,
        block_ttl_seconds: int = 3600,
    ) -> None:
        self.config = GuardStreamConfig(
            redis_url=redis_url,
            kafka_url=kafka_url,
            default_limit=default_limit,
            window_seconds=window_seconds,
            block_ttl_seconds=block_ttl_seconds,
        )
        _redis = redis_lib.from_url(redis_url)
        self.enforcer = Enforcer(_redis, self.config)
        self.publisher = KafkaPublisher(kafka_url)
