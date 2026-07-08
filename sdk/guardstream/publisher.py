import json
import logging
import threading
import time

logger = logging.getLogger(__name__)

TOPIC = "api-events"


class KafkaPublisher:
    """
    Non-blocking Kafka producer that runs in a background daemon thread.
    Events are best-effort: if Kafka is unavailable they are silently dropped.
    This is intentional — Kafka failure must never affect API response latency.
    """

    def __init__(self, kafka_url: str) -> None:
        self._producer = None
        self._kafka_url = kafka_url
        self._init_producer()
        threading.Thread(target=self._poll_loop, daemon=True, name="gs-kafka-poll").start()

    def _init_producer(self) -> None:
        try:
            from confluent_kafka import Producer
            self._producer = Producer({"bootstrap.servers": self._kafka_url})
            logger.info("GuardStream: Kafka producer connected to %s", self._kafka_url)
        except Exception as exc:
            logger.warning("GuardStream: Kafka unavailable (%s) — events will be dropped", exc)

    def _poll_loop(self) -> None:
        while True:
            if self._producer:
                self._producer.poll(0)
            time.sleep(0.1)

    def publish(self, event: dict) -> None:
        if not self._producer:
            return
        try:
            self._producer.produce(
                TOPIC,
                value=json.dumps(event).encode(),
                callback=self._on_delivery,
            )
        except Exception as exc:
            logger.debug("GuardStream: failed to produce event: %s", exc)

    @staticmethod
    def _on_delivery(err, _msg) -> None:
        if err:
            logger.debug("GuardStream: Kafka delivery error: %s", err)
