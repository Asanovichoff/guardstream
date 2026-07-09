import json
import os

import redis
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

app = FastAPI(title="GuardStream Dashboard")
templates = Jinja2Templates(directory="templates")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/")
async def root():
    return {"redirect": "/dashboard"}


@app.get("/api/stats")
async def stats():
    top_ips = redis_client.zrevrange("gs:stats:top_ips", 0, 9, withscores=True)
    top_endpoints = redis_client.zrevrange("gs:stats:top_endpoints", 0, 9, withscores=True)
    blocked_count = redis_client.get("gs:stats:blocked_count") or "0"

    return {
        "top_ips": [{"ip": ip, "count": int(count)} for ip, count in top_ips],
        "top_endpoints": [{"endpoint": ep, "count": int(count)} for ep, count in top_endpoints],
        "blocked_count": int(blocked_count),
    }


@app.get("/api/alerts")
async def alerts():
    alert_ids = redis_client.lrange("gs:alerts", 0, 19)
    result = []
    for alert_id in alert_ids:
        data = redis_client.hgetall(f"gs:alert:{alert_id}")
        if not data:
            continue
        result.append({
            "id": alert_id,
            "pattern_type": data.get("pattern_type", ""),
            "confidence": float(data.get("confidence", 0)),
            "explanation": data.get("explanation", ""),
            "action": data.get("action", ""),
            "ts": data.get("ts", ""),
            "ips": json.loads(data.get("ips", "[]")),
        })
    return result


@app.get("/api/metrics")
async def metrics():
    latencies = redis_client.zrange("gs:metrics:fastpath_ms", 0, -1, withscores=True)
    request_count = int(redis_client.get("gs:metrics:request_count") or 0)
    blocked_count = int(redis_client.get("gs:stats:blocked_count") or 0)

    info = redis_client.info("memory")
    redis_memory_mb = round(info.get("used_memory", 0) / 1024 / 1024, 2)

    if latencies:
        vals = sorted(v for _, v in latencies)
        n = len(vals)
        p50 = round(vals[int(n * 0.50)], 3)
        p99 = round(vals[int(n * 0.99)], 3)
        avg = round(sum(vals) / n, 3)
    else:
        p50 = p99 = avg = 0.0

    block_rate = round(blocked_count / request_count * 100, 1) if request_count else 0.0

    return {
        "fast_path_latency_ms": {"avg": avg, "p50": p50, "p99": p99},
        "request_count": request_count,
        "blocked_count": blocked_count,
        "block_rate_pct": block_rate,
        "redis_memory_mb": redis_memory_mb,
        "latency_sample_size": len(latencies),
    }


@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str):
    data = redis_client.hgetall(f"gs:alert:{alert_id}")
    if not data:
        raise HTTPException(status_code=404, detail="alert_expired")
    return {
        "id": alert_id,
        "pattern_type": data.get("pattern_type", ""),
        "confidence": float(data.get("confidence", 0)),
        "explanation": data.get("explanation", ""),
        "action": data.get("action", ""),
        "ts": data.get("ts", ""),
        "ips": json.loads(data.get("ips", "[]")),
    }
