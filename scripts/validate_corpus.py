#!/usr/bin/env python3
"""Validate the Step 1 core against REAL Aadhaar QR payloads — run locally only.

⛔ THIS SCRIPT NEVER PRINTS PERSONAL DATA.
   It reports counts, field-presence booleans, and error codes. Names, dates of
   birth, addresses and payload strings are never written to stdout or to any
   file. You can safely paste its output into a chat or a ticket.

WHY THIS EXISTS
---------------
Step 1's unit tests use synthetic payloads signed with a throwaway key. That
proves the parsing logic and the signature mathematics are correct, but it cannot
prove that the FIELD ORDER in ``avs.parser.fields.FIELD_MAPS`` matches what UIDAI
actually emits. Only a real card can confirm that.

So: run this against your own corpus, then send the summary — not the data.

USAGE
-----
1. Put UIDAI's public certificates in ``certs/`` (see certs/README.md).

2. Decode your Aadhaar QR codes to payload strings. Any QR reader works; UIDAI's
   own Aadhaar QR Scanner app is the reference. Save each decoded string to its
   own ``.txt`` file:

       ~/aadhaar-corpus/payloads/card01.txt
       ~/aadhaar-corpus/payloads/card02.txt

   Keep this directory OUTSIDE the repository. ``.gitignore`` blocks the usual
   paths, but the safest place is somewhere the repo cannot reach.

3. Run:

       python scripts/validate_corpus.py ~/aadhaar-corpus/payloads

4. For the tampered case, edit a card in an image editor, re-print it,
   re-photograph it, decode that QR, and put it in a ``tampered/`` subfolder:

       python scripts/validate_corpus.py ~/aadhaar-corpus/payloads \\
              --tampered ~/aadhaar-corpus/tampered

EXIT CRITERION FOR STEP 1
-------------------------
    100% of genuine payloads  -> VALID
    100% of tampered payloads -> INVALID
    All expected fields present
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from avs.crypto import SecureQrVerifier
from avs.parser import ParseError, SecureQrParser
from avs.truststore import UidaiCertificate, load_certificate_file

#: Fields we expect a real Secure QR to populate. Presence is reported as a
#: boolean per file — never the value itself.
EXPECTED_FIELDS = (
    "name",
    "dob",
    "gender",
    "aadhaar_last4",
    "district",
    "state",
    "pincode",
    "vtc",
)


def load_certificates(cert_dir: Path) -> list[UidaiCertificate]:
    certificates: list[UidaiCertificate] = []
    if not cert_dir.exists():
        return certificates
    for path in sorted(cert_dir.iterdir()):
        if path.suffix.lower() in {".cer", ".crt", ".pem", ".der"}:
            try:
                certificates.append(load_certificate_file(path))
            except ValueError as exc:
                print(f"  ! skipped {path.name}: {exc}")
    return certificates


def field_presence(payload: object) -> dict[str, bool]:
    """Which expected fields are non-empty. Booleans only — never values."""
    identity = payload.identity  # type: ignore[attr-defined]
    address = payload.address  # type: ignore[attr-defined]
    present: dict[str, bool] = {}
    for name in EXPECTED_FIELDS:
        value = getattr(identity, name, None)
        if value is None:
            value = getattr(address, name, None)
        present[name] = bool(value and str(value).strip())
    return present


def run_group(
    label: str,
    directory: Path,
    parser: SecureQrParser,
    verifier: SecureQrVerifier,
    expect_valid: bool,
) -> tuple[int, int, Counter[str], Counter[str]]:
    files = sorted(p for p in directory.glob("*.txt"))
    if not files:
        print(f"\n{label}: no .txt files found in {directory}")
        return 0, 0, Counter(), Counter()

    print(f"\n{label}  ({len(files)} payloads, expecting {'VALID' if expect_valid else 'INVALID'})")
    print("-" * 62)

    as_expected = 0
    errors: Counter[str] = Counter()
    missing: Counter[str] = Counter()
    versions: Counter[str] = Counter()

    for index, path in enumerate(files, start=1):
        raw = path.read_text(encoding="utf-8").strip()
        tag = f"  [{index:>3}] {path.name:<24}"

        try:
            payload = parser.parse(raw)
        except ParseError as exc:
            errors[exc.code.value] += 1
            # A tampered payload that fails to parse is still correctly rejected.
            ok = not expect_valid
            as_expected += int(ok)
            print(f"{tag} PARSE FAIL  {exc.code.value}  {'OK' if ok else 'UNEXPECTED'}")
            continue

        versions[payload.version] += 1
        proof = verifier.verify(payload)
        ok = proof.valid is expect_valid
        as_expected += int(ok)

        present = field_presence(payload)
        absent = [name for name, found in present.items() if not found]
        for name in absent:
            missing[name] += 1

        status = "VALID  " if proof.valid else "INVALID"
        flag = "OK" if ok else "** UNEXPECTED **"
        extra = f"  missing={','.join(absent)}" if absent else ""
        print(f"{tag} {status}  {payload.version}  {flag}{extra}")

    print(f"\n  as expected: {as_expected}/{len(files)}")
    if versions:
        print(f"  QR versions: {dict(versions)}")
    return as_expected, len(files), errors, missing


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("genuine", type=Path, help="directory of genuine payload .txt files")
    ap.add_argument("--tampered", type=Path, default=None, help="directory of tampered payloads")
    ap.add_argument("--certs", type=Path, default=Path("certs"), help="UIDAI certificate directory")
    args = ap.parse_args()

    print("=" * 62)
    print("AVS Step 1 — corpus validation")
    print("=" * 62)
    print("No personal data is printed. Counts and error codes only.")

    certificates = load_certificates(args.certs)
    print(f"\nCertificates loaded: {len(certificates)}")
    if not certificates:
        print("  ! Trust store is empty — nothing can verify. Populate certs/ first.")
        print("  ! See certs/README.md")
        return 2
    for cert in certificates:
        print(f"  - {cert.source}  serial={cert.serial[:16]}  expires in {cert.days_to_expiry}d")

    parser = SecureQrParser()
    verifier = SecureQrVerifier(certificates)

    g_ok, g_total, g_errors, g_missing = run_group(
        "GENUINE", args.genuine, parser, verifier, expect_valid=True
    )

    t_ok = t_total = 0
    t_errors: Counter[str] = Counter()
    if args.tampered:
        t_ok, t_total, t_errors, _ = run_group(
            "TAMPERED", args.tampered, parser, verifier, expect_valid=False
        )

    print("\n" + "=" * 62)
    print("SUMMARY  (safe to share)")
    print("=" * 62)
    print(f"  genuine  verified : {g_ok}/{g_total}")
    if t_total:
        print(f"  tampered rejected : {t_ok}/{t_total}")
    if g_missing:
        print(f"  missing fields    : {dict(g_missing)}")
        print("    -> a field missing across ALL cards means FIELD_MAPS ordering")
        print("       is wrong. Fix src/avs/parser/fields.py and re-run.")
    if g_errors:
        print(f"  genuine errors    : {dict(g_errors)}")
    if t_errors:
        print(f"  tampered errors   : {dict(t_errors)}")

    passed = g_total > 0 and g_ok == g_total and (t_total == 0 or t_ok == t_total)
    print()
    if passed:
        print("  RESULT: PASS — Step 1 exit criterion met.")
    else:
        print("  RESULT: FAIL — see above. Send this summary, not the payloads.")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
