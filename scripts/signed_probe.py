#!/usr/bin/env python3
"""Send ONE correctly-signed request. Proves whether AVS or the client is at fault.

    python scripts/signed_probe.py --url http://127.0.0.1:8477 ^
        --secret <the AVS_SECRET the frontend uses> ^
        --file C:\\aadhaar-corpus\\pdfs\\yours.pdf

★ WHY THIS EXISTS

  A 401 has three completely different causes and they look identical from the
  outside — the caller gets one word, deliberately, so an attacker cannot use
  the response to probe the scheme.

  The AVS log does distinguish them, and the wording is the diagnosis:

      "missing authentication headers"  the four X-AVS-* headers were absent.
                                        The request never went through code that
                                        signs. Almost always a browser calling
                                        AVS directly, or curl/Postman.

      "signature mismatch"              headers present, signature wrong. Either
                                        the secrets differ, or the body was
                                        regenerated after signing.

      "unknown tenant"                  X-AVS-Tenant does not match tenants.json.

  This script sends a request that is correct by construction. If it succeeds,
  AVS and the secret are fine and the fault is entirely in the caller.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


def build_multipart(field: str, filename: str, content_type: str, data: bytes) -> tuple[bytes, str]:
    """By hand, because the signature covers the exact bytes on the wire.

    ⛔ This is the same discipline the Java and TypeScript clients follow. Letting
       a library build the body means signing one byte sequence and sending
       another, which produces a 401 while every secret is correct.
    """
    boundary = "----avsprobe" + secrets.token_hex(16)
    body = b"".join(
        [
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'.encode(),
            f"Content-Type: {content_type}\r\n\r\n".encode(),
            data,
            b"\r\n",
            f"--{boundary}--\r\n".encode(),
        ]
    )
    return body, f"multipart/form-data; boundary={boundary}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8477")
    parser.add_argument("--secret", required=True, help="Must equal the frontend's AVS_SECRET")
    parser.add_argument("--tenant", default="m-one-prod")
    parser.add_argument("--file", type=Path, required=True, help="Any Aadhaar image or PDF")
    parser.add_argument("--password", default=None, help="For an encrypted PDF")
    arguments = parser.parse_args()

    if not arguments.file.is_file():
        print(f"⛔ No such file: {arguments.file}")
        return 2

    import httpx

    data = arguments.file.read_bytes()
    is_pdf = data[:5] == b"%PDF-"
    body, content_type = build_multipart(
        "front",
        arguments.file.name,
        "application/pdf" if is_pdf else "image/jpeg",
        data,
    )

    if arguments.password:
        # Rebuild with the extra field, still by hand.
        boundary = content_type.split("boundary=")[1]
        extra = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="password"\r\n\r\n'
            f"{arguments.password}\r\n"
        ).encode()
        body = extra + body

    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)

    # The canonical string: timestamp + "." + nonce + "." + body
    # ⛔ The dots are load-bearing — without them ("12","3") and ("1","23")
    #    hash identically.
    message = f"{timestamp}.{nonce}.".encode("ascii") + body
    signature = hmac.new(arguments.secret.encode(), message, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": content_type,
        "X-AVS-Tenant": arguments.tenant,
        "X-AVS-Timestamp": timestamp,
        "X-AVS-Nonce": nonce,
        "X-AVS-Signature": signature,
    }

    print(f"POST {arguments.url}/v1/verify/upload")
    print(f"  tenant   {arguments.tenant}")
    print(f"  body     {len(body):,} bytes ({'PDF' if is_pdf else 'image'})")
    print(f"  secret   {len(arguments.secret)} chars\n")

    client = httpx.Client(timeout=90.0, trust_env=False)
    response = client.post(f"{arguments.url}/v1/verify/upload", content=body, headers=headers)

    if response.status_code == 401:
        print("⛔ 401 with a CORRECTLY signed request.")
        print("   AVS and this secret disagree. Check the AVS log line:")
        print("     'signature mismatch' -> the two secrets differ")
        print("     'unknown tenant'     -> tenant id does not match tenants.json")
        print(f"\n   The secret used here ends in ...{arguments.secret[-6:]}")
        print("   Compare it with AVS_TENANT_M_ONE_PROD_SECRET on the server.")
        return 1

    if response.status_code >= 300:
        print(f"⛔ HTTP {response.status_code}: {response.text[:300]}")
        return 1

    job_id = response.json()["job_id"]
    print(f"✓ 202 Accepted — job {job_id}")
    print("  ★ AVS AND THE SECRET ARE CORRECT. A 401 from the app is the app's bug.\n")

    for _ in range(200):
        status = client.get(
            f"{arguments.url}/v1/verify/{job_id}", headers=_sign_get(arguments)
        ).json()
        if status.get("status") in ("DONE", "SUCCEEDED", "FAILED", "ERROR"):
            break
        time.sleep(0.3)

    decision = status.get("decision") or {}
    result = status.get("result") or {}
    print(f"  status_code  {decision.get('status_code')}")
    print(f"  status       {decision.get('status')}")
    print(f"  verdict      {decision.get('verdict')}")
    print(f"  signature    {decision.get('signature_valid')}")
    print(f"  message      {decision.get('message')}")
    errors = [s.get("error") for s in (result.get("sides") or []) if s.get("error")]
    if errors:
        print(f"  side errors  {', '.join(sorted(set(errors)))}")
    return 0


def _sign_get(arguments) -> dict[str, str]:  # type: ignore[no-untyped-def]
    """⚠ A GET has no body, so the canonical string ends at the final dot."""
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    message = f"{timestamp}.{nonce}.".encode("ascii")
    return {
        "X-AVS-Tenant": arguments.tenant,
        "X-AVS-Timestamp": timestamp,
        "X-AVS-Nonce": nonce,
        "X-AVS-Signature": hmac.new(
            arguments.secret.encode(), message, hashlib.sha256
        ).hexdigest(),
    }


if __name__ == "__main__":
    raise SystemExit(main())
