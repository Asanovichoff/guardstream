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

## How the Detectors Work

Each detector answers the question: "does this batch of 50 events look like a known attack pattern?" All four run on every batch — multiple can fire simultaneously.

### Credential Stuffing

**What it is:** Attackers buy leaked username/password lists from data breaches (billions exist) and automatically try each pair against your login endpoint, hoping some users reused passwords. One attacker can test thousands of credentials per minute.

**The signal:** Human login traffic is sparse and varied — different users, different browsers, different timing. An automated credential stuffing tool reveals itself through uniformity: many attempts from a small cluster of IPs, all using the same HTTP client (same User-Agent string).

**The rule:**
```
≥10 POST /login events
AND ≤5 distinct source IPs
AND ≤2 distinct User-Agent strings
→ credential_stuffing
```

**Why this works without false positives:** Legitimate users log in from their own IP with their own browser. Even a shared office network (many users, one IP) would have many different User-Agents. The combination of IP clustering *and* User-Agent uniformity is the fingerprint of automation.

---

### Scraping

**What it is:** Bots systematically read your API to harvest data — product catalogs, pricing, user profiles. The attacker wants all your data, not a specific record.

**The signal:** Humans browse at irregular speeds (read an article, click, wait, click again). Bots run at machine speed: constant, low-variance intervals because they're just executing a loop with `time.sleep(0.05)`.

**The rule:**
```
≥10 GET requests from one IP
AND ≥2 distinct endpoints
AND avg inter-request gap < 2s
AND stdev of gaps < 0.5s
→ scraping
```

**The math:** Standard deviation measures how much the gaps vary. Human traffic: gaps of 0.5s, 3s, 12s, 0.8s — high stdev. Bot traffic: 47ms, 52ms, 49ms, 51ms — near-zero stdev. The stdev threshold distinguishes a fast human from a slow bot.

---

### DDoS

**What it is:** Overwhelming your server with traffic from many sources simultaneously, making it unavailable to legitimate users.

**The signal:** A legitimate traffic spike (flash sale, viral post) comes from many IPs but with organic timing. A volumetric attack has extremely high request rates from a large number of coordinated sources simultaneously.

**The rule:**
```
≥40 events in the batch window
AND ≥8 distinct source IPs
→ ddos
```

---

### Enumeration

**What it is:** Systematically probing sequential IDs to discover resources — scanning `/api/users/1`, `/api/users/2`, `/api/users/3`... to find all user records, or `/api/orders/1000`... to discover order volumes.

**The signal:** Real user traffic accesses specific IDs based on actual links or searches. Sequential integer access is a machine behavior.

**The rule:**
```
≥8 requests from one IP
AND ≥5 endpoint IDs match /\d+/
AND those IDs are consecutive integers
→ enumeration
```

---

## Failure Modes

A distributed system's failure behavior is as important as its happy path.

| Component fails | Fast path | Detection | Recovery |
|----------------|-----------|-----------|----------|
| **Kafka down** | Unaffected — Redis-only | Pauses. Existing blocks stay in Redis. | Consumer resumes from last committed offset when Kafka comes back. Missed events are not replayed (`auto.offset.reset=latest`). |
| **Redis down** | **Fails open** — requests are allowed through with an error logged. See below. | Pauses — cannot write new blocks. | When Redis recovers, all in-memory state (blocks, counters) is gone. Blocks are not persisted by default. |
| **Detection consumer crashes** | Unaffected | Pauses. Existing blocks stay active until TTL. | Docker restarts the container automatically (`restart: unless-stopped`). Consumer replays from its committed offset. |
| **Stats consumer crashes** | Unaffected | Unaffected | Dashboard counters go stale. Auto-restart replays from offset. |

**Redis failure — fail open vs fail closed:**

GuardStream chooses **fail open**: when Redis is unreachable, the middleware logs an error and allows the request through rather than returning 500.

```
Fail closed: Redis down → every API request gets 500 → your API is down
Fail open:   Redis down → rate limiting pauses → your API keeps serving
```

For a rate limiter, fail open is the right default. The risk (temporary loss of rate limiting) is less severe than the consequence (full API outage for all users). For stricter security requirements, change the `except` block in `middleware.py` to return a 503.

**Redis persistence:** By default, Redis is configured without persistence (`appendonly no`). A Redis restart clears all blocks and counters. For production, add `--appendonly yes` to the Redis command or mount a volume with an `redis.conf`.

---

## Measured Performance

Benchmarked on a MacBook with the full Docker Compose stack running locally.

**Fast path latency** (Redis Lua script — the enforcer.check() call only):

| Metric | Value |
|--------|-------|
| Average | 0.9 ms |
| p50 | 0.7 ms |
| p99 | 2.6 ms |

**Load test** (`scripts/load_test.sh` — 50 concurrent requests):
- 10 allowed, 40 blocked (limit=10 per window)
- 0 errors — atomicity held under full concurrency

**Resource usage** (full stack — Kafka + Redis + 4 services):
- Redis memory: ~1.7 MB
- No CPU overhead on the fast path between requests

Live metrics available at `/api/metrics` while the stack is running.

---

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
