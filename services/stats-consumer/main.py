"""
stats-consumer: reads api-events from Kafka and maintains real-time statistics
in Redis sorted sets. Independent from the ai-consumer — uses its own consumer group.
"""
import json
import logging
import os

import redis
from confluent_kafka import Consumer, KafkaError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [stats-consumer] %(message)s",
)
logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

redis_client = redis.from_url(REDIS_URL, decode_responses=True)


def process(event: dict) -> None:
    ip = event.get("ip", "unknown")
    endpoint = event.get("endpoint", "unknown")
    status_code = event.get("status_code", 200)

    redis_client.zincrby("gs:stats:top_ips", 1, ip)
    redis_client.zincrby("gs:stats:top_endpoints", 1, endpoint)

    if status_code == 429:
        redis_client.incr("gs:stats:blocked_count")


def main() -> None:
    consumer = Consumer({
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": "stats",
        "auto.offset.reset": "latest",
        "enable.auto.commit": False,
    })
    consumer.subscribe(["api-events"])
    logger.info("Started. Listening on consumer group 'stats'...")

    while True:
        msg = consumer.poll(timeout=1.0)
        if msg is None:
            continue
        if msg.error():
            if msg.error().code() != KafkaError._PARTITION_EOF:
                logger.error("Kafka error: %s", msg.error())
            continue

        try:
            event = json.loads(msg.value().decode())
            process(event)
        except Exception as exc:
            logger.warning("Failed to process event: %s", exc)

        consumer.commit(asynchronous=False)


if __name__ == "__main__":
    main()
