# GuardStream

**AI-powered API rate limiting and abuse detection using Kafka, Redis, and LLMs.**

Most rate limiters count requests and block after N hits. GuardStream does something different: it separates the enforcement path from the intelligence path, so AI-driven behavioral analysis never adds latency to your API.

```
Every API Request
      │
      ├── Fast Path (< 1ms): Redis Lua script
      │   Check blocklist → check sliding window → ALLOW or 429
      │   Never waits for AI. Always instant.
      │
      └── Smart Path (async): Kafka → LLM Consumer
          Detects attack patterns → writes block rules to Redis
          Fast path enforces them on the next request
```

## Why both tools?

| Tool | Role | What breaks if you remove it |
|------|------|-------------------------------|
| **Redis** | Enforcement — sliding window counter + blocklist, < 1ms per request | Every request now needs a database query. Latency goes from 1ms to 20ms+. |
| **Kafka** | Event log — two independent consumer groups (AI + stats) read the same stream | Replace with Redis Pub/Sub and the stats consumer loses events when it disconnects. No replay. No durability. |
| **LLM** | Intelligence — detects behavioral patterns Redis can't count | Without AI, you only know a threshold was hit. Not whether it's a bot, a flash sale, or a credential stuffing attack. |

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
              Kafka topic: api-events (3 partitions)
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
  ┌──────────────┐         ┌──────────────────┐
  │  ai-consumer │         │  stats-consumer  │
  │  Group:      │         │  Group: stats    │
  │  ai-guard    │         │                  │
  │              │         │  ZINCRBY top_ips │
  │  Batch 50    │         │  ZINCRBY top_eps │
  │  events →    │         │  INCR blocked    │
  │  LLM API     │         └──────────────────┘
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

**1. Clone and configure**

```bash
git clone https://github.com/Asanovichoff/guardstream.git
cd guardstream
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

**2. Start everything**

```bash
docker compose up --build
```

Wait ~30 seconds for Kafka to be ready. All services start automatically.

| Service | URL |
|---------|-----|
| Demo API | http://localhost:8001 |
| Dashboard | http://localhost:8080/dashboard |
| Kafka UI | http://localhost:8090 |
| Redis Insight | http://localhost:5540 |

**3. Run the attack simulator**

```bash
pip install httpx
python demo/attack_simulator.py
```

Watch the dashboard. Within 30 seconds, the AI will detect the attack pattern and post a plain-English alert explaining what it found and why it blocked the IPs.

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
3. An AI-generated alert appear with a plain-English explanation of the detected attack pattern

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
  "reason": "Your IP was blocked after detecting a credential stuffing pattern. 23 login attempts in 45 seconds from 3 IPs sharing the same User-Agent string.",
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
│   ├── ai-consumer/            # Consumer group: ai-guard → LLM → Redis
│   ├── stats-consumer/         # Consumer group: stats → Redis ZSETs
│   └── dashboard/              # FastAPI + live-updating HTML dashboard
├── demo/
│   ├── demo_api.py             # Example protected API (3-line integration)
│   └── attack_simulator.py     # Sends credential stuffing + scraping patterns
└── scripts/
    └── load_test.sh            # 50 concurrent requests — proves atomicity
```

## Key Technical Decisions

**Why a Lua script for the fast path?**
The blocklist check and sliding window decrement are a single atomic Redis operation. No two requests can race — one will always win and the other will see the updated counter. Without the Lua script, two concurrent requests could both pass the check and both decrement past the limit.

**Why Kafka instead of Redis Pub/Sub for the event stream?**
Two consumer groups (`ai-guard` and `stats`) read from the same topic independently. If the stats consumer disconnects and reconnects, it replays from its last committed offset — no events lost. Redis Pub/Sub has no persistence: a disconnected subscriber loses all messages published while it was gone.

**Why does the AI run asynchronously?**
LLM inference takes 500ms–2s. If the enforcement path waited for AI on every request, your API's p99 latency would be 2000ms instead of < 1ms. By decoupling enforcement (Redis, synchronous) from intelligence (Kafka + LLM, async), both paths do exactly what they're good at.

**Why batch events before calling the LLM?**
Individual events don't have enough signal. Sending 50 events at once lets the model see timing patterns, IP clusters, and endpoint sequences that are invisible in a single request. It also reduces API costs by ~50x compared to per-event calls.

## Tech Stack

- **Apache Kafka** (KRaft mode, no Zookeeper) — distributed event log
- **Redis** — sub-millisecond enforcement, blocklist, stats, alert storage
- **Python / FastAPI** — services and SDK
- **Claude Haiku / Gemini Flash / GPT-4o-mini** — pluggable LLM backend for attack pattern detection
- **Docker Compose** — one-command local deployment

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_PROVIDER` | `anthropic` | `anthropic`, `gemini`, or `openai` |
| `ANTHROPIC_API_KEY` | — | Required when `LLM_PROVIDER=anthropic` |
| `GEMINI_API_KEY` | — | Required when `LLM_PROVIDER=gemini` |
| `OPENAI_API_KEY` | — | Required when `LLM_PROVIDER=openai` |
| `AI_BATCH_SIZE` | `50` | Events per LLM call |
| `AI_BATCH_INTERVAL` | `30` | Seconds between LLM calls |
| `BLOCK_TTL_SECONDS` | `3600` | How long to block a flagged IP |

---

Built with Kafka, Redis, and Claude. Designed as a portfolio project demonstrating distributed systems, event streaming, and applied AI.
