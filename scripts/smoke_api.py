#!/usr/bin/env python3
"""Exercise a running AVS instance end to end.

    # terminal 1
    python -m avs.cli serve --certs demo/certs --port 8077

    # terminal 2
    python scripts/smoke_api.py

Why this exists rather than a list of curl commands: PowerShell aliases `curl`
to `Invoke-WebRequest`, which does not accept `-X` or `-F`. Bash-shaped curl
lines silently do the wrong thing on Windows. This script uses httpx and behaves
identically everywhere.

Run `python scripts/make_demo_document.py` first — it builds the fixtures this
reads.

⛔ Points at 127.0.0.1 by default. Never run it against a service holding real
   Aadhaar data; it prints verdicts and messages to the terminal.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

try:
    import httpx
except ImportError:
    sys.exit('httpx is not installed.  pip install -e ".[service]"')

GREEN, RED, YELLOW, DIM, BOLD, OFF = (
    "\033[32m",
    "\033[31m",
    "\033[33m",
    "\033[2m",
    "\033[1m",
    "\033[0m",
)

failures: list[str] = []


def check(label: str, actual: object, expected: object) -> None:
    ok = actual == expected
    mark = f"{GREEN}PASS{OFF}" if ok else f"{RED}FAIL{OFF}"
    detail = f"{actual}" if ok else f"{RED}{actual}{OFF}  (expected {expected})"
    print(f"  {mark}  {label:<44} {detail}")
    if not ok:
        failures.append(label)


def heading(text: str) -> None:
    print(f"\n{BOLD}{text}{OFF}\n" + "─" * 72)


def poll(client: httpx.Client, job_id: str, timeout: float = 40.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        body = client.get(f"/v1/verify/{job_id}").json()
        if body["status"] in {"DONE", "FAILED"}:
            return body
        time.sleep(0.25)
    raise SystemExit(f"job {job_id} did not finish within {timeout}s")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8077")
    parser.add_argument("--demo", type=Path, default=Path("demo"))
    args = parser.parse_args()

    demo = args.demo
    required = ["front.jpg", "back.jpg", "back_tampered.jpg", "back_other_card.jpg"]
    absent = [name for name in required if not (demo / name).is_file()]
    if absent:
        print(f"{RED}Missing fixtures in {demo.resolve()}: {', '.join(absent)}{OFF}")
        print("Run:  python scripts/make_demo_document.py")
        return 1

    def images(front: str, back: str) -> dict:
        return {
            "front": (front, (demo / front).read_bytes(), "image/jpeg"),
            "back": (back, (demo / back).read_bytes(), "image/jpeg"),
        }

    print(f"{BOLD}AVS API smoke test{OFF}  →  {args.url}")

    # trust_env=False ignores HTTP_PROXY / HTTPS_PROXY / ALL_PROXY. A corporate
    # or sandbox proxy must not sit between us and 127.0.0.1 — it either fails
    # outright or, worse, answers instead of the service.
    with httpx.Client(base_url=args.url, timeout=60.0, trust_env=False) as client:
        try:
            client.get("/health")
        except httpx.ConnectError:
            print(f"\n{RED}Cannot reach {args.url}{OFF}")
            print("Start the service in another terminal:")
            print(f"  python -m avs.cli serve --certs {demo}/certs --port 8077")
            return 1

        # ── Probes ───────────────────────────────────────────────────────
        heading("Probes")
        check("GET /health", client.get("/health").status_code, 200)

        ready = client.get("/ready")
        body = ready.json()
        check("GET /ready", ready.status_code, 200)
        print(
            f"       {DIM}certificates {body['certificates']} · "
            f"expires in {body['days_to_certificate_expiry']} days · "
            f"decoders {', '.join(body['decoders'])}{OFF}"
        )
        if not body["ready"]:
            print(f"  {YELLOW}Not ready: {body['reason']}{OFF}")
            print(
                f"  {DIM}Every document will return ERROR. This is correct "
                f"behaviour with an empty trust store.{OFF}"
            )

        # ── Verification ─────────────────────────────────────────────────
        heading("Verification  (each takes ~7s)")

        accepted = client.post(
            "/v1/verify/upload", files=images("front.jpg", "back.jpg"), data={"job_id": "smoke-1"}
        )
        check("POST /v1/verify/upload", accepted.status_code, 202)
        check("  already_queued on first submit", accepted.json()["already_queued"], False)

        retry = client.post(
            "/v1/verify/upload", files=images("front.jpg", "back.jpg"), data={"job_id": "smoke-1"}
        )
        check("  already_queued on retry", retry.json()["already_queued"], True)

        done = poll(client, "smoke-1")
        result = done["result"]
        check("  genuine document", result["verdict"], "VERIFIED")
        print(f"       {DIM}{result['processing_ms']} ms · {result['user_message'][:60]}{OFF}")

        for label, front, back, expected in [
            ("QR on the FRONT instead", "back.jpg", "front.jpg", "VERIFIED"),
            ("name edited on the back", "front.jpg", "back_tampered.jpg", "TAMPERED"),
            ("two different people's cards", "back.jpg", "back_other_card.jpg", "TEXT_MISMATCH"),
        ]:
            response = client.post("/v1/verify/sync", files=images(front, back))
            check(f"  {label}", response.json()["verdict"], expected)

        check("GET /v1/verify/<unknown>", client.get("/v1/verify/nope").status_code, 404)

        # ── SSRF ─────────────────────────────────────────────────────────
        heading("SSRF guard  (must be refused BEFORE a job is created)")
        for url, expected in [
            ("http://169.254.169.254/latest/meta-data/", 400),  # cloud credentials
            ("http://127.0.0.1:6379/", 400),  # local Redis
            ("http://10.0.0.5/internal", 400),  # inside the VPC
            ("http://192.168.1.1/admin", 400),  # the router
            ("file:///etc/passwd", 422),  # local disk
        ]:
            response = client.post("/v1/verify", json={"front_url": url, "back_url": url})
            check(f"  {url[:38]:<38}", response.status_code, expected)

        client.post(
            "/v1/verify",
            json={
                "front_url": "http://169.254.169.254/a.jpg",
                "back_url": "http://169.254.169.254/b.jpg",
                "job_id": "ssrf-probe",
            },
        )
        check("  refused URL created no job", client.get("/v1/verify/ssrf-probe").status_code, 404)

        # ── Privacy ──────────────────────────────────────────────────────
        heading("Privacy")
        import json as _json
        import re as _re

        leaked = _re.search(r"\b\d{12}\b", _json.dumps(done))
        check("  no 12-digit number in any response", leaked, None)

        # ── Metrics ──────────────────────────────────────────────────────
        heading("Metrics")
        for line in client.get("/metrics").text.splitlines():
            if line and not line.startswith("#"):
                print(f"  {DIM}{line}{OFF}")

    print()
    if failures:
        print(f"{RED}{BOLD}{len(failures)} check(s) failed:{OFF} " + ", ".join(failures))
        return 1
    print(f"{GREEN}{BOLD}All checks passed.{OFF}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
