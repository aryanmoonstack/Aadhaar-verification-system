#!/usr/bin/env python3
"""Stand-in for the Spring backend, so the frontend can be tested today.

    python scripts/mock_hrm.py

Then point the Next.js app at it:

    HRM_API_URL=http://127.0.0.1:8080

⛔⛔ DEVELOPMENT ONLY. NEVER DEPLOY THIS.

   It has NO session authentication, NO database, NO employee model, and it
   accepts any `employeeId` anybody sends. It exists so a frontend developer is
   not blocked while the real backend is being finished, and for nothing else.

   The banner it prints on startup says the same thing, deliberately loudly.

WHAT IT DOES AND DOES NOT REPLACE
---------------------------------
It speaks exactly the two endpoints the Next.js route calls::

    POST /api/kyc/aadhaar/submit        multipart: front, back, employeeId
    GET  /api/kyc/aadhaar/status/{id}   jobId, status, verdict, approved, message

and forwards to a REAL AVS, so the verdicts are real — a genuine card returns a
genuine VERIFIED, backed by a real UIDAI signature check.

What it does NOT replicate, and what therefore still needs testing against the
real Spring service later:

  - HMAC signing of the AVS request (this runs AVS with auth off)
  - the callback endpoint, the security-critical one
  - the database CHECK constraint that makes `VERIFIED` impossible without a
    valid signature
  - session authentication and the employee model

⚠ `approved` is computed here EXACTLY as the Spring entity does —
  `verdict == VERIFIED && signatureValid` — so the frontend sees the same shape
  it will see in production. Getting that wrong would have the UI built against
  a field that behaves differently once the real backend arrives.
"""

# ⛔ NO `from __future__ import annotations` HERE, DELIBERATELY.
#
#    It turns every annotation into a string, and FastAPI resolves those at
#    runtime through pydantic. With `UploadFile` imported inside main(), the
#    name is not in the module namespace and every upload failed with a 500:
#
#        PydanticUserError: `TypeAdapter[Annotated[ForwardRef('UploadFile')...]]`
#        is not fully defined
#
#    The FastAPI symbols are therefore imported at MODULE level below.

import argparse
import sys
import threading
import time
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

AVS_PORT = 8477
HRM_PORT = 8080


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=HRM_PORT, help="Port for the mock HRM")
    parser.add_argument("--certs", type=Path, default=REPO_ROOT / "certs")
    parser.add_argument(
        "--origin",
        default="http://localhost:3000",
        help="Where the Next.js app runs, for CORS.",
    )
    arguments = parser.parse_args()

    import httpx
    import uvicorn

    from avs.api import create_app

    # ── The real AVS, on its own port ─────────────────────────────────────
    avs = create_app(
        cert_dir=str(arguments.certs),
        require_auth=False,
        audit_path=str(REPO_ROOT / "mock_hrm_audit.jsonl"),
        time_budget_seconds=5.0,
    )
    avs_server = uvicorn.Server(
        uvicorn.Config(avs, host="127.0.0.1", port=AVS_PORT, log_level="critical")
    )
    threading.Thread(target=avs_server.run, daemon=True).start()

    avs_client = httpx.Client(
        base_url=f"http://127.0.0.1:{AVS_PORT}", timeout=60.0, trust_env=False
    )
    for _ in range(40):
        try:
            if avs_client.get("/health").status_code == 200:
                break
        except Exception:  # noqa: S110 — still booting
            pass
        time.sleep(0.5)
    else:
        print("⛔ AVS did not start")
        return 1

    ready = avs_client.get("/ready").json()
    certificates = ready.get("certificates", 0)

    # ── The stand-in HRM ──────────────────────────────────────────────────
    hrm = FastAPI(title="MOCK HRM — development only")

    # ⚠ CORS is required because the browser calls this from a DIFFERENT origin
    #   (:3000 -> :8080). Without it every request fails with an opaque CORS
    #   error that looks like the server is down.
    hrm.add_middleware(
        CORSMiddleware,
        allow_origins=[arguments.origin, "http://127.0.0.1:3000"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    #: jobId -> the AVS job. In-memory; the real backend uses PostgreSQL.
    jobs: dict[str, str] = {}

    # ⚠ B008 is the FastAPI idiom, not a mistake: `File(...)` and `Form(...)`
    #   in the defaults are how the framework declares multipart fields.
    @hrm.post("/api/kyc/aadhaar/submit")
    async def submit(  # type: ignore[no-untyped-def]
        front: UploadFile = File(...),  # noqa: B008
        back: UploadFile = File(...),  # noqa: B008
        employeeId: str = Form("0"),  # noqa: N803 — the name Spring uses
    ):
        """⚠ Mirrors `AadhaarSubmitController.submit` — 202 with a jobId."""
        response = avs_client.post(
            "/v1/verify/upload",
            files={
                "front": (front.filename or "front.jpg", await front.read(), "image/jpeg"),
                "back": (back.filename or "back.jpg", await back.read(), "image/jpeg"),
            },
        )
        if response.status_code >= 300:
            return JSONResponse(
                status_code=500,
                content={"message": "We could not read the photos. Please try again."},
            )

        job_id = response.json()["job_id"]
        jobs[job_id] = job_id
        return JSONResponse(
            status_code=202,
            content={"jobId": job_id, "status": "PENDING", "message": ""},
        )

    @hrm.get("/api/kyc/aadhaar/status/{job_id}")
    def status(job_id: str):  # type: ignore[no-untyped-def]
        """⚠ Mirrors `AadhaarSubmitController.status`."""
        if job_id not in jobs:
            return JSONResponse(status_code=404, content={})

        body = avs_client.get(f"/v1/verify/{job_id}").json()
        result = body.get("result") or {}
        verdict = result.get("verdict")
        signature_valid = (result.get("proof") or {}).get("valid") is True
        settled = body.get("status") in ("DONE", "SUCCEEDED", "FAILED", "ERROR")

        return {
            "jobId": job_id,
            "status": "DONE" if settled else "PENDING",
            "verdict": verdict or "PENDING",
            # ⛔ Exactly the Spring rule: `verdict == VERIFIED && signatureValid`.
            #    Also what the database CHECK constraint enforces. A UI built
            #    against a different rule would break when the real backend lands.
            "approved": verdict == "VERIFIED" and signature_valid,
            "awaitsReview": verdict in ("PROFILE_MISMATCH", "TEXT_MISMATCH", "DUPLICATE"),
            # ⛔ The service's own wording. Never rewrite it in the UI — it is
            #    phrased to never accuse anyone of forgery. CONTRACTS.md §1.
            "message": result.get("user_message") or "",
        }

    @hrm.get("/api/kyc/aadhaar/review-queue")
    def review_queue():  # type: ignore[no-untyped-def]
        """Empty here. The real queue needs the database."""
        return []

    print("\n" + "=" * 72)
    print("  ⛔  MOCK HRM — DEVELOPMENT ONLY. NEVER DEPLOY THIS.")
    print("      No session auth. No database. Any employeeId is accepted.")
    print("=" * 72)
    print(f"\n  mock HRM     http://127.0.0.1:{arguments.port}")
    print(f"  real AVS     http://127.0.0.1:{AVS_PORT}  ({certificates} certificate(s))")
    print(f"  CORS allows  {arguments.origin}")

    if not certificates:
        print("\n  ⚠ NO CERTIFICATES — every card will return ERROR.")
        print(f"    Put UIDAI public certificates in {arguments.certs}")

    print("\n  Tell the frontend developer to set:")
    print(f"      HRM_API_URL=http://127.0.0.1:{arguments.port}")
    print("      HRM_SERVICE_TOKEN=anything-this-mock-ignores-it")
    print("\n  Endpoints served (same shape as Spring):")
    print("      POST /api/kyc/aadhaar/submit")
    print("      GET  /api/kyc/aadhaar/status/{jobId}")
    print("      GET  /api/kyc/aadhaar/review-queue")
    print("\n  Ctrl+C to stop.\n")

    uvicorn.run(hrm, host="127.0.0.1", port=arguments.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
