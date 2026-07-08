# GuardStream

**API rate limiting and abuse detection using Kafka and Redis.**

Most rate limiters count requests and block after N hits. GuardStream does something different: it separates the enforcement path from the analysis path, so behavioral detection never adds latency to your API.

```
Every API Request
      │
      ├── Fast Path (< 1ms): Redis Lua script
      │   Check blocklist → check sliding window → ALLOW or 429
      │   Always instant. Never waits for analysis.
      │
      └── Analysis Path (async): Kafka → Detection Consumer
          Runs behavioral rules on batches of 50 events
          Detected attacks → block rules written to Redis
          Fast path enforces them on the next request
```

## Why both tools?

| Tool | Role | What breaks if you remove it |
|------|------|-------------------------------|
| **Redis** | Enforcement — atomic sliding window + blocklist, < 1ms per request | Every request now needs a database query. Latency goes from 1ms to 20ms+. |
| **Kafka** | Event log — two independent consumer groups read the same stream | Replace with Redis Pub/Sub and the stats consumer loses events when it disconnects. No replay. No durability. |
| **Rule engine** | Intelligence — detects behavioral patterns Redis can't count | Without it, you only know a threshold was hit. Not whether it's a bot, a flash sale, or a credential stuffing attack. |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Your FastAPI App                        │
│  guard = GuardStream(redis_url=..., kafka_url=...)           │
│  app.add_middleware(GuardStreamMiddleware, guard=guard)       │
└──────────────────────┬──────────────────────────────────────┘
                       │ Every Request
                       ▼
            ┌──────────────────────┐
            │  GuardStreamMiddleware│
            │  Fast Path: Lua      │◄── Redis (< 1ms enforcement)
            │  Async: Kafka produce│──► Kafka (event log)
            └──────────────────────┘
                       │
              Kafka topic: api-events
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
  ┌──────────────┐         ┌──────────────────┐
  │ detection-   │         │  stats-consumer  │
  │ consumer     │         │  Group: stats    │
  │ Group:       │         │                  │
  │ ai-guard     │         │  ZINCRBY top_ips │
  │              │         │  ZINCRBY top_eps │
  │  Batch 50    │         │  INCR blocked    │
  │  events →    │         └──────────────────┘
  │  rule engine │
  │  → block IPs │
  │  → write     │
  │    alerts    │
  └──────┬───────┘
         │ writes to Redis
         ▼
  gs:blocked:<ip>  ← Fast path checks this on every request
  gs:alert:<uuid>  ← Dashboard reads this for explanations
```

## Quick Start

**1. Clone and start**

```bash
git clone https://github.com/Asanovichoff/guardstream.git
cd guardstream
docker compose up --build
```

Wait ~30 seconds for Kafka to be ready. All services start automatically. No API keys required.

| Service | URL |
|---------|-----|
| Demo API | http://localhost:8001 |
| Dashboard | http://localhost:8080/dashboard |
| Kafka UI | http://localhost:8090 |
| Redis Insight | http://localhost:5540 |

**2. Run the attack simulator**

```bash
pip install httpx
python demo/attack_simulator.py
```

Watch the dashboard. Within 30 seconds, the detection consumer will identify the attack pattern and post a plain-English alert explaining what it found and why it blocked the IPs.

## 60-Second Demo

```bash
# Terminal 1 — start the stack
docker compose up --build

# Terminal 2 — run the attack
pip install httpx
python demo/attack_simulator.py

# Open in browser
open http://localhost:8080/dashboard
```

You will see:
1. Request counts climb in the "Top IPs" chart
2. Blocked count increase as the rate limit kicks in
3. An alert appear with a plain-English explanation of the detected attack pattern

## Detection Rules

The detection consumer runs four behavioral rules against each batch of 50 events. All four run on every batch — multiple alerts can fire simultaneously.

| Rule | Signal | Threshold |
|------|--------|-----------|
| **Credential stuffing** | Many POST /login from ≤5 IPs sharing ≤2 User-Agents | ≥10 login events |
| **Scraping** | Rapid GETs from one IP across multiple endpoints | avg gap < 2s, stdev < 0.5s |
| **DDoS** | High volume from many distinct IPs in one window | ≥40 events from ≥8 IPs |
| **Enumeration** | One IP accessing sequential numeric endpoint IDs | ≥5 consecutive IDs |

Confidence scores are computed from signal strength (e.g. login count, timing variance). Results below 60% confidence are silently discarded.

## SDK Integration

Add GuardStream to any FastAPI app in 3 lines:

```python
from guardstream import GuardStream, GuardStreamMiddleware

guard = GuardStream(
    redis_url="redis://localhost:6379",
    kafka_url="localhost:9092",
    default_limit=60,    # requests per window per IP per endpoint
    window_seconds=60,
)
app.add_middleware(GuardStreamMiddleware, guard=guard)
```

When a request is blocked, the API returns:

```json
{
  "error": "rate_limit_exceeded",
  "reason": "Detected credential stuffing: 23 login attempts from 3 IP(s) sharing 1 User-Agent string(s). High-frequency automated login attempts with shared tooling signatures indicate a coordinated credential stuffing attack.",
  "retry_after": 3600
}
```

## Project Structure

```
guardstream/
├── docker-compose.yml          # Full stack: Kafka, Redis, all services
├── sdk/                        # Python SDK — install in any FastAPI app
│   └── guardstream/
│       ├── __init__.py         # GuardStream + GuardStreamMiddleware
│       ├── enforcer.py         # Redis fast path (Lua script)
│       ├── publisher.py        # Kafka async background producer
│       ├── middleware.py       # Starlette BaseHTTPMiddleware
│       └── lua/fast_path.lua   # Atomic blocklist + sliding window check
├── services/
│   ├── ai-consumer/            # Consumer group: ai-guard → rule engine → Redis
│   ├── stats-consumer/         # Consumer group: stats → Redis ZSETs
│   └── dashboard/              # FastAPI + live-updating HTML dashboard
├── demo/
│   ├── demo_api.py             # Example protected API (3-line integration)
│   └── attack_simulator.py     # Sends credential stuffing + scraping patterns
├── tests/
│   └── test_detectors.py       # Unit tests for all four detection rules
└── scripts/
    └── load_test.sh            # 50 concurrent requests — proves atomicity
```

## Key Technical Decisions

**Why a Lua script for the fast path?**
The blocklist check and sliding window are a single atomic Redis operation. No two requests can race — one will always win and the other will see the updated counter. Without the Lua script, two concurrent requests could both pass the check and both decrement past the limit.

**Why Kafka instead of Redis Pub/Sub for the event stream?**
Two consumer groups (`ai-guard` and `stats`) read from the same topic independently. If the stats consumer disconnects and reconnects, it replays from its last committed offset — no events lost. Redis Pub/Sub has no persistence: a disconnected subscriber loses all messages published while it was gone.

**Why does detection run asynchronously?**
Behavioral analysis batches 50 events and runs four rule passes. If the enforcement path waited for this on every request, p99 latency would spike. By decoupling enforcement (Redis, synchronous) from analysis (Kafka, async), both paths do exactly what they're good at.

**Why batch 50 events before analyzing?**
Individual events have no pattern signal. Batching lets the detector see timing distributions, IP clusters, and endpoint sequences that are invisible in a single request. A single login attempt is normal. 30 login attempts from 3 IPs in 18 seconds with identical User-Agents is a credential stuffing attack.

**Why run all four detectors on every batch?**
A real attack often triggers multiple rules simultaneously — a scraping session that also fits a DDoS profile should produce two alerts, not one. Each detector is independent so they compose without interference.

## Tech Stack

- **Apache Kafka** (KRaft mode, no Zookeeper) — durable event log with consumer group replay
- **Redis** — sub-millisecond enforcement via Lua, blocklist, sorted set stats, alert storage
- **Python / FastAPI** — services and SDK
- **Docker Compose** — one-command local deployment, no external dependencies

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_BATCH_SIZE` | `50` | Events per detection run |
| `AI_BATCH_INTERVAL` | `30` | Max seconds between detection runs |
| `BLOCK_TTL_SECONDS` | `3600` | How long a blocked IP stays blocked |

---

Built with Kafka and Redis. Designed as a portfolio project demonstrating distributed systems, event streaming, and real-time behavioral analysis.
