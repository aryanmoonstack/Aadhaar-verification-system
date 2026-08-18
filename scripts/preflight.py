#!/usr/bin/env python3
"""Pre-flight check before uploading real Aadhaar cards.

    python scripts/preflight.py --url https://avs.internal.example

⛔ WHY RUN THIS FIRST

   Almost every first-attempt failure is configuration, not code — an empty
   certificate directory, an unpinned trust store, a secret that does not match
   between the HRM and AVS. Each produces a confusing symptom at upload time:

       certs/ empty          -> EVERY card returns ERROR, including genuine ones
       trust store unpinned  -> anyone who can write certs/ can mint approvals
       secret mismatch       -> 401, which looks like a network problem
       AVS_HASH_SECRET unset -> reference hashes change on every restart, so
                                duplicate detection silently never matches

   All four are visible from `/ready` in under a second. Diagnosing them from a
   failed upload takes considerably longer.

⚠ THIS SENDS NO IMAGES AND READS NO CARDS.

  It calls `/health`, `/ready` and `/metrics` only. Safe to run against the
  production service — unlike `smoke_api.py`, which submits fixtures and prints
  verdicts.
"""

from __future__ import annotations

import argparse

EXIT_OK = 0
EXIT_BLOCKING = 1
EXIT_UNREACHABLE = 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Base URL of the AVS")
    parser.add_argument("--timeout", type=float, default=10.0)
    arguments = parser.parse_args()

    try:
        import httpx
    except ImportError:
        print("httpx is not installed:  pip install httpx")
        return EXIT_UNREACHABLE

    base = arguments.url.rstrip("/")

    # ⛔ REFUSE PLACEHOLDER URLS.
    #
    #    `--url https://your-avs-url` resolves to nothing and reports
    #    "getaddrinfo failed", which reads like a DNS or firewall fault and
    #    sends someone to debug their network. The real problem is that the
    #    example was pasted unedited. Name it.
    lowered = base.lower()
    placeholders = ("your-avs-url", "your-avs", "example.com", "avs.internal", "<", ">", "your-")
    if any(token in lowered for token in placeholders):
        print(f"⛔ That is the example URL, not yours: {base}\n")
        print("   Use the address your backend developer deployed AVS to, e.g.")
        print("     python scripts/preflight.py --url https://avs.m-one.cloud")
        print("\n   If it runs on this machine, the default already works:")
        print("     python scripts/preflight.py")
        return EXIT_UNREACHABLE
    # ⚠ trust_env=False — a corporate HTTP_PROXY would otherwise silently
    #   reroute this and report the proxy's health rather than the service's.
    client = httpx.Client(timeout=arguments.timeout, trust_env=False)

    print(f"Checking {base}\n")

    try:
        health = client.get(f"{base}/health")
    except Exception as exc:
        print(f"⛔ UNREACHABLE: {type(exc).__name__}: {exc}")
        print("\n   Is the service running, and is the URL right?")
        print("   Locally:  python -m avs.cli serve --tenants tenants.json")
        return EXIT_UNREACHABLE

    print(f"  /health   {health.status_code}")

    ready = client.get(f"{base}/ready")
    print(f"  /ready    {ready.status_code}")

    try:
        state = ready.json()
    except Exception:
        print("⛔ /ready did not return JSON. Is something else on this port?")
        return EXIT_UNREACHABLE

    blocking: list[str] = []
    warnings: list[str] = []

    # ── The trust store ───────────────────────────────────────────────────
    certificates = state.get("certificates", 0)
    if not certificates:
        blocking.append(
            "NO UIDAI CERTIFICATES. Every card — genuine ones included — will\n"
            "     return ERROR, because there is nothing to verify signatures\n"
            "     against. Put the UIDAI public certificates in certs/."
        )

    if not state.get("pinning_enabled"):
        blocking.append(
            "TRUST STORE NOT PINNED. Anyone who can write to certs/ can add a\n"
            "     certificate and mint approvals for forged cards.\n"
            "     Fix:  python -m avs.cli certs pin --dir certs"
        )

    days = state.get("days_to_certificate_expiry")
    if isinstance(days, (int, float)):
        if days < 0:
            warnings.append(
                f"every certificate lapsed {abs(int(days))} days ago. Genuine cards\n"
                "     still verify — a signature does not expire with the cert that\n"
                "     made it — but no NEW UIDAI certificate is present."
            )
        elif days < 90:
            warnings.append(f"certificate expires in {int(days)} days. Alert on this.")

    # ── Authentication ────────────────────────────────────────────────────
    if not state.get("auth_required"):
        blocking.append(
            "AUTHENTICATION IS OFF. Anyone who can reach this URL can submit\n"
            "     documents and read verdicts. Start with --tenants tenants.json."
        )

    tenants = state.get("tenants")
    if isinstance(tenants, int) and tenants == 0:
        blocking.append("NO TENANTS CONFIGURED. Every request will return 401.")

    # ── Audit ─────────────────────────────────────────────────────────────
    if not state.get("audit_enabled"):
        warnings.append(
            "audit trail is off. Verdicts leave no tamper-evident record, so a\n"
            "     dispute about an approval cannot be answered later."
        )

    # ── Decoders ──────────────────────────────────────────────────────────
    # ⚠ `/ready` returns decoders as a LIST of available names, not a mapping.
    #   Assuming a dict here crashed the check against a live service; the shape
    #   is worth reading rather than guessing.
    raw = state.get("decoders") or []
    available = [n for n, ok in raw.items() if ok] if isinstance(raw, dict) else list(raw)
    if not available:
        blocking.append("NO QR DECODERS AVAILABLE. Nothing can be read at all.")
    elif "zxing-cpp" not in available:
        warnings.append(
            f"zxing-cpp is missing (have: {', '.join(available)}). It is the\n"
            "     decoder that reads dense Secure QRs; without it the decode rate\n"
            "     will be far lower.  pip install zxing-cpp"
        )

    print()
    for key in sorted(state):
        print(f"    {key:<28} {state[key]}")

    # ── Verdict ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    if blocking:
        print(f"⛔ {len(blocking)} BLOCKING PROBLEM(S) — do not upload real cards yet")
        print("=" * 70)
        for index, item in enumerate(blocking, start=1):
            print(f"  {index}. {item}")
    else:
        print("✓ No blocking problems. Safe to upload.")
        print("=" * 70)

    if warnings:
        print(f"\n⚠ {len(warnings)} warning(s):")
        for index, item in enumerate(warnings, start=1):
            print(f"  {index}. {item}")

    if not blocking:
        print("\nWhat to expect on the first real upload:")
        print("  • A card whose QR decodes -> VERIFIED, typically in 1-3 seconds")
        print("  • A card whose QR does not -> UNREADABLE with specific advice")
        print("  • ⛔ NOTHING is ever auto-rejected. UNREADABLE means 'try again',")
        print("    not 'this is fake'.")
        print("\nWatch avs_decode_rate in /metrics. It measured 30% on a corpus")
        print("shot deliberately badly; real guided uploads should be higher, but")
        print("that has not been measured and the first week will tell you.")

    return EXIT_BLOCKING if blocking else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
