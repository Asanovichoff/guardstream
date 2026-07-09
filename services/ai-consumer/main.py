"""
ai-consumer: reads api-events from Kafka, batches them, runs rule-based
behavioral analysis to detect attack patterns, then writes block rules
and plain-English alerts to Redis.

AWS integrations (all optional — skip gracefully if env vars not set):
  S3       → archive every alert as JSON for permanent storage
  SNS      → push attack notifications to email / Slack / PagerDuty
  CloudWatch → emit custom metrics per batch (events processed, IPs blocked)
"""
import json
import logging
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from statistics import mean, stdev

import boto3
import redis
from botocore.exceptions import BotoCoreError, ClientError
from confluent_kafka import Consumer, KafkaError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [ai-consumer] %(message)s",
)
logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────

KAFKA_BOOTSTRAP   = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
REDIS_URL         = os.getenv("REDIS_URL", "redis://localhost:6379")
AI_BATCH_SIZE     = int(os.getenv("AI_BATCH_SIZE", "50"))
AI_BATCH_INTERVAL = int(os.getenv("AI_BATCH_INTERVAL", "30"))
BLOCK_TTL         = int(os.getenv("BLOCK_TTL_SECONDS", "3600"))

# AWS — all optional; set AWS_ENDPOINT_URL=http://localstack:4566 for local dev
AWS_REGION       = os.getenv("AWS_REGION", "us-east-1")
AWS_ENDPOINT_URL = os.getenv("AWS_ENDPOINT_URL")          # LocalStack endpoint
S3_BUCKET        = os.getenv("S3_BUCKET", "")             # e.g. guardstream-alerts
SNS_TOPIC_ARN    = os.getenv("SNS_TOPIC_ARN", "")         # e.g. arn:aws:sns:...
CW_NAMESPACE     = os.getenv("CW_NAMESPACE", "GuardStream")

redis_client = redis.from_url(REDIS_URL, decode_responses=True)


# ── AWS helpers ────────────────────────────────────────────────────────────────

def _aws(service: str):
    kwargs = {"region_name": AWS_REGION}
    if AWS_ENDPOINT_URL:
        kwargs["endpoint_url"] = AWS_ENDPOINT_URL
    return boto3.client(service, **kwargs)


def archive_to_s3(alert_id: str, result: dict) -> None:
    """Write the full alert JSON to S3 for permanent storage."""
    if not S3_BUCKET:
        return
    try:
        key = f"alerts/{datetime.now(timezone.utc).strftime('%Y/%m/%d')}/{alert_id}.json"
        _aws("s3").put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=json.dumps(result, default=str),
            ContentType="application/json",
        )
        logger.info("Archived to s3://%s/%s", S3_BUCKET, key)
    except (BotoCoreError, ClientError) as exc:
        logger.warning("S3 archive failed: %s", exc)


def notify_sns(result: dict) -> None:
    """Publish an attack notification to SNS (email, Slack, PagerDuty, etc.)."""
    if not SNS_TOPIC_ARN:
        return
    try:
        pattern = result.get("pattern_type", "unknown").replace("_", " ").title()
        ips = ", ".join(result.get("affected_ips", []))
        conf = int(result.get("confidence", 0) * 100)
        _aws("sns").publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[GuardStream] {pattern} detected ({conf}% confidence)",
            Message=(
                f"Attack pattern: {pattern}\n"
                f"Confidence: {conf}%\n"
                f"Affected IPs: {ips}\n\n"
                f"{result.get('explanation', '')}\n\n"
                f"Action taken: {result.get('recommended_action', 'none')}"
            ),
            MessageAttributes={
                "pattern_type": {
                    "DataType": "String",
                    "StringValue": result.get("pattern_type", "unknown"),
                }
            },
        )
        logger.info("SNS notification sent for %s", result.get("pattern_type"))
    except (BotoCoreError, ClientError) as exc:
        logger.warning("SNS notification failed: %s", exc)


def push_cloudwatch_metrics(batch_size: int, results: list[dict]) -> None:
    """Push batch processing metrics to CloudWatch."""
    try:
        ips_blocked = sum(len(r.get("affected_ips", [])) for r in results)
        patterns = len(results)
        _aws("cloudwatch").put_metric_data(
            Namespace=CW_NAMESPACE,
            MetricData=[
                {
                    "MetricName": "EventsProcessed",
                    "Value": batch_size,
                    "Unit": "Count",
                },
                {
                    "MetricName": "PatternsDetected",
                    "Value": patterns,
                    "Unit": "Count",
                },
                {
                    "MetricName": "IPsBlocked",
                    "Value": ips_blocked,
                    "Unit": "Count",
                },
            ],
        )
        logger.info("CloudWatch metrics pushed (events=%d, patterns=%d, ips=%d)",
                    batch_size, patterns, ips_blocked)
    except (BotoCoreError, ClientError) as exc:
        logger.warning("CloudWatch push failed: %s", exc)


# ── Detection rules ────────────────────────────────────────────────────────────

def _parse_ts(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts).timestamp()
    except Exception:
        return 0.0


def detect_credential_stuffing(events: list[dict]) -> dict | None:
    login_events = [
        e for e in events
        if e.get("method") == "POST" and "login" in e.get("endpoint", "")
    ]
    if len(login_events) < 10:
        return None

    by_ip: dict[str, list] = defaultdict(list)
    for e in login_events:
        by_ip[e["ip"]].append(e)

    unique_ips = len(by_ip)
    unique_uas = len({e.get("user_agent", "") for e in login_events})

    if unique_ips <= 5 and unique_uas <= 2:
        top_ips = sorted(by_ip, key=lambda ip: len(by_ip[ip]), reverse=True)
        confidence = min(0.95, 0.6 + len(login_events) * 0.01)
        return {
            "pattern_type": "credential_stuffing",
            "affected_ips": top_ips[:5],
            "confidence": round(confidence, 2),
            "explanation": (
                f"Detected credential stuffing: {len(login_events)} login attempts "
                f"from {unique_ips} IP(s) sharing {unique_uas} User-Agent string(s). "
                f"High-frequency automated login attempts with shared tooling signatures "
                f"indicate a coordinated credential stuffing attack."
            ),
            "recommended_action": "block",
            "block_ttl_seconds": BLOCK_TTL,
        }
    return None


def detect_scraping(events: list[dict]) -> dict | None:
    by_ip: dict[str, list] = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    for ip, ip_events in by_ip.items():
        get_events = [e for e in ip_events if e.get("method") == "GET"]
        if len(get_events) < 10:
            continue

        endpoints = {e.get("endpoint", "") for e in get_events}
        timestamps = sorted(
            _parse_ts(e["timestamp"]) for e in get_events if e.get("timestamp")
        )

        if len(timestamps) < 3 or len(endpoints) < 2:
            continue

        gaps = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        avg_gap = mean(gaps)
        gap_stdev = stdev(gaps) if len(gaps) > 1 else 0.0

        if avg_gap < 2.0 and gap_stdev < 0.5:
            confidence = min(0.95, 0.65 + (1.0 - min(avg_gap, 1.0)) * 0.3)
            return {
                "pattern_type": "scraping",
                "affected_ips": [ip],
                "confidence": round(confidence, 2),
                "explanation": (
                    f"Detected scraping from {ip}: {len(get_events)} GET requests "
                    f"across {len(endpoints)} endpoint(s) with avg inter-request delay "
                    f"of {avg_gap:.2f}s (stdev {gap_stdev:.3f}s). "
                    f"Low timing variance is a strong bot indicator."
                ),
                "recommended_action": "block",
                "block_ttl_seconds": BLOCK_TTL,
            }
    return None


def detect_ddos(events: list[dict]) -> dict | None:
    if len(events) < 40:
        return None

    by_ip: dict[str, list] = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    unique_ips = len(by_ip)
    if unique_ips < 8:
        return None

    top_ips = sorted(by_ip, key=lambda ip: len(by_ip[ip]), reverse=True)[:10]
    confidence = min(0.90, 0.60 + unique_ips * 0.02)
    return {
        "pattern_type": "ddos",
        "affected_ips": top_ips,
        "confidence": round(confidence, 2),
        "explanation": (
            f"Detected potential DDoS: {len(events)} requests from {unique_ips} "
            f"distinct IPs in a {AI_BATCH_INTERVAL}s window. "
            f"High-volume distributed traffic may indicate a volumetric attack."
        ),
        "recommended_action": "block",
        "block_ttl_seconds": BLOCK_TTL,
    }


def detect_enumeration(events: list[dict]) -> dict | None:
    import re
    by_ip: dict[str, list] = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    for ip, ip_events in by_ip.items():
        if len(ip_events) < 8:
            continue
        nums = []
        for e in ip_events:
            m = re.search(r"/(\d+)", e.get("endpoint", ""))
            if m:
                nums.append(int(m.group(1)))
        if len(nums) < 5:
            continue
        nums_sorted = sorted(nums)
        diffs = [nums_sorted[i + 1] - nums_sorted[i] for i in range(len(nums_sorted) - 1)]
        if all(d == 1 for d in diffs):
            return {
                "pattern_type": "enumeration",
                "affected_ips": [ip],
                "confidence": 0.88,
                "explanation": (
                    f"Detected enumeration from {ip}: sequentially accessed "
                    f"IDs {nums_sorted[0]}–{nums_sorted[-1]} across "
                    f"{len(nums)} endpoints in order. "
                    f"Sequential ID scanning indicates automated data harvesting."
                ),
                "recommended_action": "block",
                "block_ttl_seconds": BLOCK_TTL,
            }
    return None


DETECTORS = [
    detect_credential_stuffing,
    detect_scraping,
    detect_ddos,
    detect_enumeration,
]


def analyze_batch(events: list[dict]) -> list[dict]:
    """Run all detectors and return every match, highest confidence first."""
    results = []
    for detector in DETECTORS:
        result = detector(events)
        if result:
            results.append(result)
    return sorted(results, key=lambda r: r["confidence"], reverse=True)


# ── Writers ────────────────────────────────────────────────────────────────────

def write_results(result: dict) -> None:
    if result.get("pattern_type") == "none":
        return
    if result.get("confidence", 0) < 0.6:
        return

    action = result.get("recommended_action", "none")
    if action not in ("block", "rate_limit"):
        return

    explanation = result.get("explanation", "Suspicious traffic detected by GuardStream.")
    ttl = result.get("block_ttl_seconds", BLOCK_TTL)
    alert_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    affected_ips = result.get("affected_ips", [])

    # Redis — fast-path enforcement and dashboard
    for ip in affected_ips:
        redis_client.setex(f"gs:blocked:{ip}", ttl, "1")
        redis_client.setex(f"gs:blocked:{ip}:reason", ttl, explanation)
        logger.info("Blocked %s for %ds — %s", ip, ttl, explanation[:100])

    alert_payload = {
        "pattern_type": result.get("pattern_type", ""),
        "ips": json.dumps(affected_ips),
        "explanation": explanation,
        "action": action,
        "confidence": str(result.get("confidence", 0)),
        "ts": now,
    }
    redis_client.hset(f"gs:alert:{alert_id}", mapping=alert_payload)
    redis_client.expire(f"gs:alert:{alert_id}", 86400)
    redis_client.lpush("gs:alerts", alert_id)
    redis_client.ltrim("gs:alerts", 0, 99)

    logger.info(
        "Alert %s: %s (%.0f%% confidence, %d IPs affected)",
        alert_id, result.get("pattern_type"),
        result.get("confidence", 0) * 100, len(affected_ips),
    )

    # AWS — archive to S3 and notify via SNS
    full_result = {**result, "alert_id": alert_id, "ts": now}
    archive_to_s3(alert_id, full_result)
    notify_sns(result)


# ── Kafka consumer loop ────────────────────────────────────────────────────────

def main() -> None:
    consumer = Consumer({
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": "ai-guard",
        "auto.offset.reset": "latest",
        "enable.auto.commit": False,
    })
    consumer.subscribe(["api-events"])
    logger.info(
        "Started (rule-based mode). Waiting for events (batch_size=%d, interval=%ds)...",
        AI_BATCH_SIZE, AI_BATCH_INTERVAL,
    )

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
        should_flush = (
            len(batch) >= AI_BATCH_SIZE
            or (batch and now - last_flush >= AI_BATCH_INTERVAL)
        )

        if should_flush:
            logger.info("Analyzing batch of %d events...", len(batch))
            results = analyze_batch(batch)
            if results:
                for result in results:
                    write_results(result)
            else:
                logger.info("No attack pattern detected in this batch.")

            # Push CloudWatch metrics regardless of whether an attack was found
            push_cloudwatch_metrics(len(batch), results)

            batch = []
            last_flush = now


if __name__ == "__main__":
    main()
