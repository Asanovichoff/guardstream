"""
ai-consumer: reads api-events from Kafka, batches them, calls an LLM to detect
attack patterns, and writes block rules + plain-English alerts to Redis.
"""
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone

import redis
from confluent_kafka import Consumer, KafkaError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [ai-consumer] %(message)s",
)
logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
AI_BATCH_SIZE = int(os.getenv("AI_BATCH_SIZE", "50"))
AI_BATCH_INTERVAL = int(os.getenv("AI_BATCH_INTERVAL", "30"))
BLOCK_TTL = int(os.getenv("BLOCK_TTL_SECONDS", "3600"))
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")

redis_client = redis.from_url(REDIS_URL, decode_responses=True)

SYSTEM_PROMPT = (
    "You are a security analyst reviewing API traffic logs. "
    "Identify the single most significant attack pattern. "
    "Respond ONLY with valid JSON — no prose, no markdown fences."
)

RESPONSE_SCHEMA = """{
  "pattern_type": "credential_stuffing | scraping | ddos | enumeration | suspicious | none",
  "affected_ips": ["ip1", "ip2"],
  "confidence": 0.0,
  "explanation": "one plain-English paragraph describing what you observed",
  "recommended_action": "block | rate_limit | watch | none",
  "block_ttl_seconds": 3600
}"""


def build_prompt(events: list) -> str:
    return (
        f"Here are {len(events)} API events from the last {AI_BATCH_INTERVAL} seconds:\n"
        f"{json.dumps(events, indent=2)}\n\n"
        "Analyze for: credential stuffing (many logins, few IPs), scraping (rapid "
        "sequential reads), DDoS (high volume from many IPs), enumeration (sequential "
        "IDs or endpoints), suspicious timing (bots have very low inter-request variance).\n\n"
        f"Respond with exactly this JSON shape:\n{RESPONSE_SCHEMA}"
    )


def call_llm(events: list) -> dict | None:
    prompt = build_prompt(events)

    for attempt in range(2):
        try:
            text = _call_provider(prompt if attempt == 0 else (
                "Your previous response was not valid JSON. "
                "Respond with only the JSON object, no other text."
            ))
            return json.loads(text.strip())
        except json.JSONDecodeError:
            logger.warning("LLM returned invalid JSON (attempt %d/2)", attempt + 1)
        except Exception as exc:
            logger.error("LLM call failed: %s", exc)
            return None

    logger.error("LLM retry exhausted — skipping batch")
    return None


def _call_provider(prompt: str) -> str:
    if LLM_PROVIDER == "anthropic":
        import anthropic
        client = anthropic.Anthropic()
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=512,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text

    if LLM_PROVIDER == "openai":
        from openai import OpenAI
        client = OpenAI()
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            max_tokens=512,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        return resp.choices[0].message.content

    raise ValueError(f"Unknown LLM_PROVIDER: {LLM_PROVIDER!r}. Set to 'anthropic' or 'openai'.")


def write_results(result: dict) -> None:
    if result.get("pattern_type") == "none":
        return
    if result.get("confidence", 0) < 0.6:
        logger.info(
            "Pattern '%s' detected but confidence %.0f%% < 60%% — skipping",
            result.get("pattern_type"),
            result.get("confidence", 0) * 100,
        )
        return

    action = result.get("recommended_action", "none")
    if action not in ("block", "rate_limit"):
        return

    explanation = result.get("explanation", "Suspicious traffic detected by GuardStream AI.")
    ttl = result.get("block_ttl_seconds", BLOCK_TTL)
    alert_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    affected_ips = result.get("affected_ips", [])

    for ip in affected_ips:
        redis_client.setex(f"gs:blocked:{ip}", ttl, "1")
        redis_client.setex(f"gs:blocked:{ip}:reason", ttl, explanation)
        logger.info("Blocked %s for %ds — %s", ip, ttl, explanation[:100])

    redis_client.hset(f"gs:alert:{alert_id}", mapping={
        "pattern_type": result.get("pattern_type", ""),
        "ips": json.dumps(affected_ips),
        "explanation": explanation,
        "action": action,
        "confidence": str(result.get("confidence", 0)),
        "ts": now,
    })
    redis_client.expire(f"gs:alert:{alert_id}", 86400)
    redis_client.lpush("gs:alerts", alert_id)
    redis_client.ltrim("gs:alerts", 0, 99)

    logger.info(
        "Alert %s: %s (%.0f%% confidence, %d IPs affected)",
        alert_id,
        result.get("pattern_type"),
        result.get("confidence", 0) * 100,
        len(affected_ips),
    )


def main() -> None:
    consumer = Consumer({
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": "ai-guard",
        "auto.offset.reset": "latest",
        "enable.auto.commit": False,
    })
    consumer.subscribe(["api-events"])
    logger.info("Started. Waiting for events (batch_size=%d, interval=%ds)...", AI_BATCH_SIZE, AI_BATCH_INTERVAL)

    batch: list[dict] = []
    last_flush = time.time()

    while True:
        msg = consumer.poll(timeout=1.0)

        if msg is None:
            pass
        elif msg.error():
            if msg.error().code() != KafkaError._PARTITION_EOF:
                logger.error("Kafka error: %s", msg.error())
        else:
            try:
                batch.append(json.loads(msg.value().decode()))
            except Exception as exc:
                logger.warning("Failed to parse event: %s", exc)
            consumer.commit(asynchronous=False)

        now = time.time()
        should_flush = len(batch) >= AI_BATCH_SIZE or (batch and now - last_flush >= AI_BATCH_INTERVAL)

        if should_flush:
            logger.info("Analyzing batch of %d events...", len(batch))
            result = call_llm(batch)
            if result:
                write_results(result)
            batch = []
            last_flush = now


if __name__ == "__main__":
    main()
