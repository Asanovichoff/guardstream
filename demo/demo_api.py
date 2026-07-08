"""
Demo API — protected by GuardStream.
This shows the 3-line integration: import, configure, add_middleware.
"""
import os

from fastapi import FastAPI
from guardstream import GuardStream, GuardStreamMiddleware

app = FastAPI(title="Demo API — Protected by GuardStream")

guard = GuardStream(
    redis_url=os.getenv("REDIS_URL", "redis://localhost:6379"),
    kafka_url=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
    default_limit=10,    # 10 requests per minute — low for easy demo triggering
    window_seconds=60,
)
app.add_middleware(GuardStreamMiddleware, guard=guard)


@app.get("/")
async def root():
    return {"status": "ok", "protected_by": "GuardStream"}


@app.post("/api/login")
async def login(body: dict = None):
    return {"status": "authenticated", "token": "demo-token-abc123"}


@app.get("/api/users")
async def users():
    return {"users": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]}


@app.get("/api/data")
async def data():
    return {"records": list(range(50))}


@app.get("/health")
async def health():
    return {"status": "ok"}
