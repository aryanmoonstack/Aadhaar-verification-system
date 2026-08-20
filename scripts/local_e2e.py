#!/usr/bin/env python3
"""Run the WHOLE service locally and push real cards through the HTTP API.

    python scripts/local_e2e.py C:\\aadhaar-corpus\\phone-a-good-light

⛔ WHY THIS IS WORTH RUNNING BEFORE THE DEPLOYMENT IS READY

   Every previous measurement called the pipeline as a Python function. That
   skips the parts most likely to be misconfigured in production:

       ingest limits      a 12MP file may exceed a size cap
       the worker queue   jobs run on a background thread, not inline
       the time budget    12s per DOCUMENT, shared across both sides
       job polling        the HRM polls; a job that never completes hangs it
       certificate load   `/ready` may be green while a cert fails to parse
       audit writing      verdicts must reach the trail

   This starts a real uvicorn server with a real trust store, submits real
   images over real HTTP, polls like the HRM will, and reports what came back.
   If it works here, the only remaining unknowns are the Java client and the
   browser — not AVS itself.

⚠ WHAT LEAVES YOUR MACHINE

  Nothing. The server binds to 127.0.0.1 on a port nothing else uses, and the
  output is verdicts, timings and error codes. No payload, no name, no number.
  Aadhaar content is never printed — see `_summarise`.
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

PORT = 8477  # unlikely to collide

_SIGNATURES: tuple[bytes, ...] = (
    b"\xff\xd8\xff",
    b"\x89PNG\r\n\x1a\n",
    b"BM",
    b"II*\x00",
    b"MM\x00*",
)


def looks_like_an_image(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            header = handle.read(16)
    except OSError:
        return False
    if any(header.startswith(s) for s in _SIGNATURES):
        return True
    return len(header) >= 12 and header[4:8] == b"ftyp"


def looks_like_a_pdf(path: Path) -> bool:
    """Magic bytes, not the extension — same rule the service applies.

    ⚠ Matters here because a PDF saved from a browser is sometimes named
      `.pdf.jpg` or has no extension at all, and an extension check would drop
      exactly the files this harness now exists to measure.
    """
    try:
        with path.open("rb") as handle:
            return handle.read(5) == b"%PDF-"
    except OSError:
        return False


def content_type_for(path: Path) -> str:
    return "application/pdf" if looks_like_a_pdf(path) else "image/jpeg"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path, help="Folder of card images (stays local)")
    parser.add_argument("--certs", type=Path, default=REPO_ROOT / "certs")
    parser.add_argument("--pairs", type=int, default=6, help="How many submissions to try")
    parser.add_argument(
        "--password",
        default=None,
        help="Password for encrypted PDFs. ⛔ Applied to every PDF in the folder, "
        "so use a folder belonging to ONE person. Never written anywhere.",
    )
    arguments = parser.parse_args()

    text = str(arguments.folder)
    if any(token in text for token in ("path\\to", "path/to", "<", ">", "your-")):
        print(f"⛔ That is the example path, not a real one: {text}")
        print("   e.g.  python scripts/local_e2e.py C:\\aadhaar-corpus\\phone-a-good-light")
        return 2

    # ⛔ The same placeholder trap, one argument along. Documentation writes
    #    `--password YOUR_PASSWORD` and it gets pasted verbatim; the run then
    #    reports PDF_PASSWORD_INCORRECT, which reads as "your PDFs are broken"
    #    rather than "you did not substitute the example".
    if arguments.password and arguments.password.upper() in {
        "YOUR_ACTUAL_PASSWORD",
        "YOUR_PASSWORD",
        "YOURPASSWORD",
        "PASSWORD",
        "<PASSWORD>",
    }:
        print(f"⛔ That is the example password, not a real one: {arguments.password}")
        print("   Use the real e-Aadhaar password — first 4 letters of the name in")
        print("   CAPITALS plus the birth year, e.g.  --password RAME1990")
        print("   If the PDFs are not password-protected, omit --password entirely.")
        return 2

    # ⚠ Report a missing renderer HERE, not as a per-document failure. Without
    #   pypdfium2 every PDF fails at ingest with the generic "could not open
    #   your photos" message, which looks like a problem with the documents.
    from avs.ingest.pdf import PDFIUM_AVAILABLE

    if not PDFIUM_AVAILABLE:
        print("\n⛔ pypdfium2 is NOT INSTALLED — every PDF will fail at ingest.")
        print("   This is a new dependency. Install it with:")
        print("       pip install pypdfium2")
        print("   or:  pip install -e .[ingest]")
        return 2
    if not arguments.folder.is_dir():
        print(f"⛔ No such folder: {arguments.folder}")
        return 2

    files = sorted(p for p in arguments.folder.rglob("*") if p.is_file())
    pdfs = [p for p in files if looks_like_a_pdf(p)]
    images = [p for p in files if looks_like_an_image(p)]

    if not pdfs and not images:
        print(f"⛔ No images or PDFs under {arguments.folder}")
        # ⚠ Say what WAS there. An earlier version of this harness silently
        #   filtered PDFs out and reported "no images", which reads as an empty
        #   folder rather than a harness that cannot see the files in it.
        if files:
            from collections import Counter

            seen = Counter(p.suffix.lower() or "(no extension)" for p in files)
            print(f"   {len(files)} file(s) found, none recognised:")
            for suffix, count in seen.most_common(8):
                print(f"     {suffix:<18} {count}")
        return 1

    import httpx
    import uvicorn

    from avs.api import create_app

    print(f"Starting AVS on 127.0.0.1:{PORT}")
    print(f"  certificates from: {arguments.certs}")

    # ⚠ auth OFF deliberately. This exercises the VERIFICATION path; HMAC is
    #   already proven by tests/unit/test_security.py, and signing multipart by
    #   hand here would test the harness rather than the service.
    # ⛔ `cert_dir` must be PASSED. An earlier version accepted --certs and
    #    never used it, so the server silently loaded the default `certs/`
    #    directory — the run looked fine and was testing the wrong trust store.
    app = create_app(
        cert_dir=str(arguments.certs),
        require_auth=False,
        audit_path=str(REPO_ROOT / "local_e2e_audit.jsonl"),
    )
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="critical"))
    threading.Thread(target=server.run, daemon=True).start()

    client = httpx.Client(base_url=f"http://127.0.0.1:{PORT}", timeout=90.0, trust_env=False)
    for _ in range(40):
        try:
            if client.get("/health").status_code == 200:
                break
        except Exception:  # noqa: S110 — still booting
            pass
        time.sleep(0.5)
    else:
        print("⛔ server did not start")
        return 1

    ready = client.get("/ready").json()
    print(
        f"  certificates loaded: {ready.get('certificates')}   "
        f"status: {ready.get('certificate_status')}   "
        f"decoders: {ready.get('decoders')}"
    )
    if not ready.get("certificates"):
        print("\n⛔ NO CERTIFICATES. Every card will return ERROR.")
        print(f"   Put the UIDAI public certificates in {arguments.certs}")
        return 1

    # ⛔ A PDF is submitted ALONE — its pages already carry both faces
    #    (CONTRACTS.md §11). Pairing two PDFs would test something no employee
    #    will ever do, and would double the rendering for no extra evidence.
    #    Images are still paired front/back, the way an employee submits them.
    submissions: list[tuple[Path, Path | None]] = [(p, None) for p in pdfs]
    submissions += [(images[i], images[i + 1]) for i in range(0, len(images) - 1, 2)]
    if not submissions and images:
        submissions = [(images[0], images[0])]
    submissions = submissions[: arguments.pairs]

    if pdfs:
        print(f"\n  {len(pdfs)} PDF(s) — each submitted alone, pages searched for the QR")
    if len(images) > 1:
        print(f"  {len(images)} image(s) — paired front/back")
    if pdfs and not arguments.password:
        print("  ⚠ No --password given. An encrypted e-Aadhaar will report")
        print("    PDF_PASSWORD_REQUIRED rather than failing to decode.")

    print(f"\nSubmitting {len(submissions)} document(s) over HTTP, polling like the HRM will.\n")
    print(f"{'#':<4}{'kind':<7}{'verdict':<12}{'sig':<7}{'approve':<9}{'ms':>7}  message")
    print("-" * 90)

    outcomes: dict[str, int] = {}
    for index, (front, back) in enumerate(submissions, start=1):
        started = time.perf_counter()

        payload = {"front": (front.name, front.read_bytes(), content_type_for(front))}
        if back is not None:
            payload["back"] = (back.name, back.read_bytes(), content_type_for(back))

        data = {}
        if arguments.password and looks_like_a_pdf(front):
            data["password"] = arguments.password

        response = client.post("/v1/verify/upload", files=payload, data=data)
        if response.status_code >= 300:
            print(f"{index:<6}HTTP {response.status_code}  {response.text[:60]}")
            outcomes["HTTP_ERROR"] = outcomes.get("HTTP_ERROR", 0) + 1
            continue

        job = response.json().get("job_id")
        body: dict = {}
        for _ in range(120):
            poll = client.get(f"/v1/verify/{job}")
            body = poll.json()
            if body.get("status") in ("DONE", "SUCCEEDED", "FAILED", "ERROR"):
                break
            time.sleep(0.5)

        elapsed = int((time.perf_counter() - started) * 1000)
        _summarise(
            index, "PDF" if looks_like_a_pdf(front) else "images", body, elapsed, outcomes
        )

    print("\n" + "=" * 60)
    total = sum(outcomes.values())
    for verdict, count in sorted(outcomes.items(), key=lambda kv: -kv[1]):
        print(f"  {verdict:<16} {count:>3}   {count / total:>4.0%}")
    print("=" * 60)

    verified = outcomes.get("VERIFIED", 0)
    if verified:
        print(f"\n✓ {verified} card(s) verified END TO END over HTTP.")
        print("  Ingest, queue, decode, signature, rules, privacy and audit all work.")
    else:
        print("\n⚠ Nothing verified. If these are cards that failed before, that is")
        print("  expected — try a folder whose images decoded in quality.csv.")

    from avs.audit import FileAuditTrail, verify_chain

    trail = REPO_ROOT / "local_e2e_audit.jsonl"
    if trail.is_file():
        entries = len(FileAuditTrail(str(trail)).entries())
        print(f"\nAudit: {entries} entr(ies), chain intact: {verify_chain(str(trail)) == []}")

    server.should_exit = True
    return 0


def _summarise(
    index: int, kind: str, body: dict, elapsed_ms: int, outcomes: dict[str, int]
) -> None:
    """Print one result.

    ⛔ PRIVACY-CRITICAL. `result` also carries `identity` and `address` — a real
       person's name, date of birth and home address. Only the verdict, the
       signature boolean and the (deliberately generic) user message are read.
    """
    result = body.get("result") or {}
    verdict = result.get("verdict") or body.get("status") or "NO_RESULT"
    proof = result.get("proof") or {}
    outcomes[str(verdict)] = outcomes.get(str(verdict), 0) + 1

    # ⛔ `is_auto_approve` is a PYTHON PROPERTY, not a serialised field, so it
    #    is absent from the JSON. Reading it with a False default made a
    #    genuinely VERIFIED card display as not-approved.
    #
    #    Computed here exactly as the Spring entity does
    #    (`verdict == VERIFIED && signatureValid`), which is also the rule the
    #    database CHECK constraint enforces. Two places, one rule.
    approve = verdict == "VERIFIED" and proof.get("valid") is True

    # ★ Cross-check the `decision` block the front end actually reads against
    #   the rule computed independently above. They are derived by different
    #   code in different places; if they ever disagree, the front end is being
    #   told something the database would refuse to store.
    decision = body.get("decision") or {}
    if decision:
        if (decision.get("status") == "APPROVED") != approve:
            print(
                f"    ⛔ decision.status={decision.get('status')} but "
                f"verdict/signature says approve={approve} — THESE MUST AGREE"
            )
            outcomes["DECISION_DISAGREEMENT"] = outcomes.get("DECISION_DISAGREEMENT", 0) + 1

    print(
        f"{index:<4}{kind:<7}{verdict!s:<12}{proof.get('valid')!s:<7}"
        f"{approve!s:<9}{elapsed_ms:>7}  "
        f"{(result.get('user_message') or '')[:34]}"
    )

    # ⛔ THE ERROR CODE, whenever something failed.
    #
    #    Without it every ingest failure prints the same sentence — "we could
    #    not open your photos" — whether the cause was a missing PDF renderer,
    #    a wrong password, or a corrupt file. Those need completely different
    #    fixes, and the generic message reads as "your documents are broken",
    #    which sends someone hunting for a problem with the wrong thing.
    #
    # ⚠ Codes only. No filenames, no payloads, no identity fields — this line
    #   is meant to be safe to paste into a chat.
    errors = [s.get("error") for s in (result.get("sides") or []) if s.get("error")]
    if errors:
        print(f"       error: {', '.join(sorted(set(errors)))}")
    elif verdict not in ("VERIFIED", "PENDING"):
        failed_checks = [
            f"{c.get('name')}={c.get('result')}"
            for c in (result.get("checks") or [])
            if c.get("result") == "FAIL"
        ]
        if failed_checks:
            print(f"       failed: {', '.join(failed_checks)}")


if __name__ == "__main__":
    raise SystemExit(main())
