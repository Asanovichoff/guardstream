"""
GuardStream Attack Simulator

Simulates realistic attack patterns against the demo API to trigger
AI-powered detection. Run this from your host machine while the
Docker Compose stack is running.

Usage:
    pip install httpx
    python demo/attack_simulator.py
"""
import asyncio
import random
import sys
import time

import httpx

BASE_URL = "http://localhost:8001"
DASHBOARD_URL = "http://localhost:8080/dashboard"


async def send(client: httpx.AsyncClient, method: str, path: str, ip: str, ua: str, body: dict | None = None) -> int:
    headers = {"X-Forwarded-For": ip, "User-Agent": ua}
    try:
        if method == "POST":
            resp = await client.post(f"{BASE_URL}{path}", json=body or {}, headers=headers)
        else:
            resp = await client.get(f"{BASE_URL}{path}", headers=headers)
        return resp.status_code
    except Exception:
        return 0


async def credential_stuffing() -> None:
    print("\n" + "=" * 60)
    print("SCENARIO 1: Credential Stuffing")
    print("60 login attempts from 3 IPs sharing an identical User-Agent")
    print("=" * 60)

    ips = ["10.10.1.1", "10.10.1.2", "10.10.1.3"]
    ua = "python-requests/2.28.0"
    allowed = blocked = 0

    async with httpx.AsyncClient(timeout=5.0) as client:
        for i in range(60):
            ip = random.choice(ips)
            code = await send(client, "POST", "/api/login", ip, ua,
                              {"username": f"user{i}@example.com", "password": "Password123!"})
            if code == 429:
                blocked += 1
                if blocked == 1:
                    print(f"  First block at request {i + 1} from {ip}")
            elif code == 200:
                allowed += 1
            await asyncio.sleep(0.3)

    print(f"\n  Result: {allowed} allowed / {blocked} blocked out of 60")


async def scraping() -> None:
    print("\n" + "=" * 60)
    print("SCENARIO 2: Scraping")
    print("100 rapid GET requests from 1 IP cycling through endpoints")
    print("=" * 60)

    ip = "10.20.0.1"
    ua = "Scrapy/2.11.0 (+https://scrapy.org)"
    endpoints = ["/api/users", "/api/data"]
    allowed = blocked = 0

    async with httpx.AsyncClient(timeout=5.0) as client:
        for i in range(100):
            endpoint = endpoints[i % len(endpoints)]
            code = await send(client, "GET", endpoint, ip, ua)
            if code == 429:
                blocked += 1
                if blocked == 1:
                    print(f"  First block at request {i + 1}")
            elif code == 200:
                allowed += 1
            await asyncio.sleep(0.05)

    print(f"\n  Result: {allowed} allowed / {blocked} blocked out of 100")


async def main() -> None:
    print("╔══════════════════════════════════════════════════════════╗")
    print("║         GuardStream Attack Simulator                     ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"\nTarget API  : {BASE_URL}")
    print(f"Dashboard   : {DASHBOARD_URL}")
    print("\nMake sure `docker compose up` is running before continuing.")
    print("\nStarting in 3 seconds...")
    await asyncio.sleep(3)

    # Verify the API is up
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{BASE_URL}/health")
            if r.status_code != 200:
                raise Exception(f"unexpected status {r.status_code}")
        print("  API is up.")
    except Exception as exc:
        print(f"\nERROR: Cannot reach {BASE_URL} — {exc}")
        print("Make sure `docker compose up` is running and the demo service started.")
        sys.exit(1)

    await credential_stuffing()
    print("\nWaiting 10s before next scenario...")
    await asyncio.sleep(10)
    await scraping()

    print("\n" + "=" * 60)
    print("Simulation complete.")
    print(f"Open {DASHBOARD_URL} to see the AI-generated alerts.")
    print("Alerts appear within ~30 seconds after traffic is analyzed.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
