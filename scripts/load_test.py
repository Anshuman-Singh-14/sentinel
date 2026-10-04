r"""Load test: many users starting runs at once, through the real API and workers.

Runs inside the api container (httpx is already there; nothing to install):

    LOADTEST_ADMIN=admin LOADTEST_PASSWORD=... \
    docker compose exec -T -e LOADTEST_ADMIN -e LOADTEST_PASSWORD api \
        python - < scripts/load_test.py

Optional: LOADTEST_USERS (default 6), LOADTEST_RUNS (runs per user, default 15),
LOADTEST_BASE (default http://127.0.0.1:8000).

What it does:
1. Logs in as the admin and creates LOADTEST_USERS temporary analysts.
2. Every user, concurrently, starts LOADTEST_RUNS echo runs as fast as the API
   allows. A 429 (per-user quota) is expected: the user waits for Retry-After
   and tries again. That is the quota working, not an error.
3. Waits for every run to finish, then has each user export one report.
4. Verifies the audit hash chain, disables the temporary users, and prints
   latency percentiles, status-code counts and throughput.

Exit status is non-zero if any request returned 5xx, any run did not
complete, a report failed, or the audit chain does not verify. Keep
LOADTEST_USERS modest: logins are rate-limited per client IP
(AUTH_RATE_LIMIT_PER_MINUTE) and every user logs in from this container, so
larger runs spend their first minute waiting for login slots.
"""

import asyncio
import os
import secrets
import statistics
import sys
import time
from collections import Counter, defaultdict
from typing import Any

import httpx

BASE = os.environ.get("LOADTEST_BASE", "http://127.0.0.1:8000") + "/api/v1"
ORIGIN = os.environ.get("LOADTEST_ORIGIN", "http://localhost:5173")
USERS = int(os.environ.get("LOADTEST_USERS", "6"))
RUNS = int(os.environ.get("LOADTEST_RUNS", "15"))
TERMINAL = {"COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"}

latencies: dict[str, list[float]] = defaultdict(list)
codes: Counter[str] = Counter()


class Session:
    """A cookie session. Cookies are Secure (__Host-), so they are kept by hand:
    httpx would not send Secure cookies over plain HTTP inside the container."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self.jar: dict[str, str] = {}

    async def call(self, method: str, path: str, label: str, **kwargs: Any) -> httpx.Response:
        headers = {
            "Origin": ORIGIN,
            "X-CSRF-Token": self.jar.get("__Host-sentinel_csrf", ""),
            "Cookie": "; ".join(f"{k}={v}" for k, v in self.jar.items()),
        }
        started = time.perf_counter()
        response = await self.client.request(method, BASE + path, headers=headers, **kwargs)
        latencies[label].append((time.perf_counter() - started) * 1000)
        codes[f"{label} {response.status_code}"] += 1
        for raw in response.headers.get_list("set-cookie"):
            name, _, rest = raw.partition("=")
            self.jar[name] = rest.split(";", 1)[0]
        return response

    async def login(self, username: str, password: str) -> None:
        # Logins are rate-limited per client IP, and every user logs in from
        # this container: wait out a 429 rather than fail the whole test.
        for _ in range(10):
            response = await self.call(
                "POST", "/auth/login", "login", json={"username": username, "password": password}
            )
            if response.status_code != 429:
                break
            await asyncio.sleep(float(response.headers.get("Retry-After", "10")))
        response.raise_for_status()


async def user_workload(client: httpx.AsyncClient, username: str, password: str) -> list[str]:
    session = Session(client)
    await session.login(username, password)
    run_ids: list[str] = []
    while len(run_ids) < RUNS:
        response = await session.call(
            "POST",
            "/tools/echo/runs",
            "create run",
            json={"params": {"message": f"load {username} {len(run_ids)}", "repeat": 3}},
        )
        if response.status_code == 202:
            run_ids.append(response.json()["run_id"])
        elif response.status_code == 429:
            await asyncio.sleep(min(float(response.headers.get("Retry-After", "2")), 5))
        else:
            print(f"! {username}: unexpected {response.status_code} {response.text[:200]}")
            return run_ids

    pending = set(run_ids)
    deadline = time.monotonic() + 300
    while pending and time.monotonic() < deadline:
        for run_id in list(pending):
            body = (await session.call("GET", f"/runs/{run_id}", "get run")).json()
            if body["status"] in TERMINAL:
                pending.discard(run_id)
        await asyncio.sleep(0.5)

    report = await session.call(
        "POST",
        "/reports",
        "create report",
        json={"source_type": "tool_run", "source_id": run_ids[-1], "format": "txt"},
    )
    if report.status_code == 202:
        report_id = report.json()["report_id"]
        for _ in range(120):
            state = (await session.call("GET", f"/reports/{report_id}", "get report")).json()
            if state["status"] in ("COMPLETED", "FAILED"):
                codes[f"report {state['status']}"] += 1
                break
            await asyncio.sleep(0.5)
    return run_ids


def pct(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * p))]


async def main() -> int:
    admin_user = os.environ["LOADTEST_ADMIN"]
    admin_password = os.environ["LOADTEST_PASSWORD"]
    limits = httpx.Limits(max_connections=100)
    async with httpx.AsyncClient(timeout=30, limits=limits) as client:
        admin = Session(client)
        await admin.login(admin_user, admin_password)
        tag = secrets.token_hex(3)
        users: list[tuple[str, str, str]] = []
        for i in range(USERS):
            username, password = f"load{tag}u{i}", secrets.token_urlsafe(18)
            created = await admin.call(
                "POST",
                "/admin/users",
                "admin",
                json={"username": username, "password": password, "role": "analyst"},
            )
            created.raise_for_status()
            users.append((username, password, created.json()["id"]))
        print(f"created {USERS} analysts (load{tag}u*), {RUNS} echo runs each")

        started = time.perf_counter()
        try:
            results = await asyncio.gather(*(user_workload(client, u, p) for u, p, _ in users))
        finally:
            for _, _, user_id in users:
                await admin.call(
                    "PATCH", f"/admin/users/{user_id}", "admin", json={"is_active": False}
                )
        elapsed = time.perf_counter() - started

        statuses: Counter[str] = Counter()
        durations: list[float] = []
        for run_ids in results:
            for run_id in run_ids:
                body = (await admin.call("GET", f"/runs/{run_id}", "get run")).json()
                statuses[body["status"]] += 1
                if body["duration_ms"] is not None:
                    durations.append(body["duration_ms"])
        verify = (await admin.call("POST", "/admin/audit/verify", "admin")).json()

    total = sum(len(r) for r in results)
    print(f"\n{total} runs by {USERS} users in {elapsed:.1f} s ({total / elapsed:.1f} runs/s)")
    print("run outcomes:", dict(statuses))
    if durations:
        median = statistics.median(durations)
        print(f"tool execution ms: median {median:.0f}, max {max(durations):.0f}")
    print("\nendpoint           n     p50 ms   p95 ms   max ms")
    for label, values in sorted(latencies.items()):
        print(
            f"{label:<16} {len(values):>5} {pct(values, 0.5):>9.0f} {pct(values, 0.95):>8.0f}"
            f" {max(values):>8.0f}"
        )
    print("\nstatus codes:", dict(sorted(codes.items())))
    print(f"audit chain: ok={verify['ok']} checked={verify['checked']}")

    server_errors = sum(n for key, n in codes.items() if key.split()[-1].startswith("5"))
    failed = (
        server_errors
        or statuses.get("COMPLETED", 0) != total
        or total != USERS * RUNS
        or codes.get("report COMPLETED", 0) != USERS
        or not verify["ok"]
    )
    print("\nRESULT:", "FAIL" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
