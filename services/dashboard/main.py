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
