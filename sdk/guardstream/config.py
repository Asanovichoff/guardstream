from dataclasses import dataclass


@dataclass
class GuardStreamConfig:
    redis_url: str
    kafka_url: str
    default_limit: int = 60
    window_seconds: int = 60
    block_ttl_seconds: int = 3600
