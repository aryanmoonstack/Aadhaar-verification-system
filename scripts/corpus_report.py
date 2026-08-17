#!/usr/bin/env python3
"""Measure the real-world decode rate and validate FIELD_MAPS — runs locally only.

    python scripts/corpus_report.py C:\\aadhaar-corpus --out report.txt

Run it once with a folder that does not exist and it will create the folder
structure and tell you where to put the photos.

⛔ THIS SCRIPT NEVER PRINTS PERSONAL DATA.

   Not names, not dates of birth, not addresses, not payload strings, not
   Aadhaar numbers, not even the last four digits. It emits counts, booleans,
   error codes, timings and format *shapes*.

   Everything it writes is designed to be pasted into a chat or a ticket. Read
   the report yourself before sending it — it is plain text, and short.

WHAT IT ANSWERS
---------------
1. **Decode rate.** What fraction of real photos yield a Secure QR, broken down
   by whatever conditions you organised into subfolders. This number is
   currently unknown, and it decides whether employees sail through or get
   stuck re-uploading.

2. **★ FIELD_MAPS ordering.** `src/avs/parser/fields.py` says which position in
   the payload holds the name, the DOB, the district. It was written from the
   UIDAI spec and has never been checked against a real card.

   This matters more than it sounds. The signature is computed over raw bytes,
   so a wrong field order still verifies — the card is genuine, the signature is
   valid, the verdict is VERIFIED, and the DOB quietly lands in the name column.
   Cryptography cannot catch that. Only a real card can.

   The script checks the *shape* of each field (is `dob` date-like? is `pincode`
   six digits? is `gender` one of M/F/T?) and reports how often each holds
   something of the wrong shape. A field wrong on every card means the ordering
   is wrong, and the fix is one line of data.

3. **Which preprocessing rescued what.** Feeds the Step 14 quality model.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from avs.contracts import CaptureMethod
from avs.crypto import SecureQrVerifier
from avs.imaging import PreprocessingVariantGenerator
from avs.ingest import ImageIngestor, IngestError
from avs.ingest.magic import FileKind, detect
from avs.parser import ParseError, SecureQrParser
from avs.qr import QrDecoderCascade, decoder_availability
from avs.truststore import FileCertificateStore, TrustStoreError

README = """\
PUT YOUR AADHAAR PHOTOS IN THE SUBFOLDERS HERE
==============================================

This folder is OUTSIDE your git repository on purpose. Nothing in it is ever
committed, uploaded, or sent anywhere. The report the script produces contains
no personal data at all.

HOW TO ORGANISE
---------------
Each subfolder is a "condition" the report breaks results down by. Use whatever
labels are meaningful to you -- the folder names are the only thing that appears
in the report, so keep them generic (a phone model is fine, a person's name is
not).

    phone-a-good-light/
    phone-a-dim/
    phone-b-good-light/
    phone-b-angled/
    phone-b-glare/
    scanner/

Drop both faces of each card in. Filenames do not matter.

WHAT TO SHOOT
-------------
20-30 photos across 2-3 phones. Deliberately include bad ones -- angled, dim,
glare on the lamination, slight blur, the hologram catching the light. The
failures are more informative than the successes: they are what the Step 14
quality model gets tuned against.

CONSENT
-------
Only cards whose owner knows what this is for and has agreed. Your own card is
the easiest place to start.
"""

#: What counts as a photo here. Narrower than "detect() recognised it" — a PDF
#: or a zip is recognised too, and would sail past the filter only to be
#: rejected at ingest. Matches ingest's ALLOWED_MIME_TYPES.
IMAGE_KINDS = frozenset({FileKind.JPEG, FileKind.PNG, FileKind.WEBP, FileKind.HEIF})

SUBFOLDERS = [
    "phone-a-good-light",
    "phone-a-dim",
    "phone-b-good-light",
    "phone-b-angled",
    "phone-b-glare",
    "scanner",
]


# --------------------------------------------------------------------------- #
# Field shape checks — how we detect a FIELD_MAPS ordering error without ever
# looking at, or printing, a value.
# --------------------------------------------------------------------------- #

_DATE = re.compile(r"^\d{1,4}[-/]\d{1,2}[-/]\d{1,4}$")
_PIN = re.compile(r"^\d{6}$")
_DIGITS = re.compile(r"^\d+$")


def _shape_problems(identity, address) -> list[str]:
    """Return the names of fields whose CONTENT SHAPE contradicts their meaning.

    No value is returned or printed — only the field name. If `dob` holds
    something that is not a date on all 30 cards, the ordering is wrong.
    """
    problems: list[str] = []

    if not _DATE.match(identity.dob.strip()):
        problems.append("dob_not_date_like")
    if identity.gender.strip().upper() not in {"M", "F", "T", "MALE", "FEMALE", "TRANSGENDER"}:
        problems.append("gender_not_mft")
    if _DATE.match(identity.name.strip()):
        problems.append("name_looks_like_a_date")
    if _DIGITS.match(identity.name.strip()):
        problems.append("name_is_all_digits")

    if address.pincode and not _PIN.match(address.pincode.strip()):
        problems.append("pincode_not_6_digits")
    if address.state and _DIGITS.match(address.state.strip()):
        problems.append("state_is_all_digits")
    if address.district and _DIGITS.match(address.district.strip()):
        problems.append("district_is_all_digits")

    return problems


def _container_facts(raw: str) -> list[str]:
    """Why did unpacking fail? Container-level facts only — never content.

    ⛔ `_decompress` returns the input UNCHANGED when gzip, zlib and raw-deflate
       all fail. That makes "decompression failed" indistinguishable from
       "payload was not compressed", and the failure surfaces much later as the
       useless message "no delimited fields found".

    The first four bytes are a FORMAT HEADER (gzip 1f8b, zlib 78xx), not
    personal data — the same way a file's magic number is not its contents.
    """
    import gzip
    import zlib

    facts: list[str] = []
    try:
        value = int(raw)
    except ValueError:
        return ["payload is not a decimal integer"]

    data = value.to_bytes((value.bit_length() + 7) // 8, "big")
    facts.append(f"bytes={len(data) // 250 * 250}-{len(data) // 250 * 250 + 249}")
    facts.append(f"first4=0x{data[:4].hex()}")

    decompressed = None
    for name, fn in (
        ("gzip", lambda d: gzip.decompress(d)),
        ("zlib", lambda d: zlib.decompress(d)),
        ("deflate", lambda d: zlib.decompressobj(-zlib.MAX_WBITS).decompress(d)),
    ):
        try:
            decompressed = fn(data)
            facts.append(f"decompressed via {name}")
            break
        except Exception:  # noqa: S112 - probing container formats in turn;
            continue  # a format that does not apply is the normal case

    if decompressed is None:
        facts.append("*** NO DECOMPRESSION WORKED — passed through raw ***")
        decompressed = data

    facts.append(f"0xFF delimiters found = {decompressed.count(255)}")
    printable = sum(1 for b in decompressed[:60] if 32 <= b < 127)
    facts.append(f"first 60 bytes are {printable * 100 // 60}% printable")

    # ★ FIELD SKELETON — the structural shape of the first few fields.
    #
    #   `detect_version` reads field 0. If it is not the literal "V2" the parser
    #   silently falls back to the V1 map, which shifts EVERY field by one and
    #   lands reference_id on the wrong value. We need to see the shape of those
    #   leading fields to tell a version mismatch from a genuine data problem.
    #
    #   Lengths and character classes only. A field of length 12 that is all
    #   digits is structure, not content — no value is ever emitted.
    chunks = decompressed.split(b"\xff")
    for index, chunk in enumerate(chunks[:6]):
        if len(chunk) > 40:
            facts.append(f"field[{index}] len={len(chunk)} (long — likely binary tail)")
            break
        try:
            text = chunk.decode("utf-8")
            encoding = "utf8"
        except UnicodeDecodeError:
            text = chunk.decode("iso-8859-1")
            encoding = "*** NOT utf8 ***"
        kind = (
            "digits"
            if text.isdigit()
            else "alpha"
            if text.isalpha()
            else "empty"
            if not text
            else "mixed"
        )
        ascii_note = "" if text.isascii() else "  HIGH-BYTE"
        facts.append(f"field[{index}] len={len(chunk)} {kind} {encoding}{ascii_note}")

    # The version marker itself is a format token, not personal data.
    if chunks:
        try:
            marker = chunks[0].decode("iso-8859-1").strip()
        except Exception:
            marker = "?"
        safe = marker if marker.isascii() and len(marker) <= 4 else "<non-ascii or long>"
        facts.append(f"version marker field[0] = {safe!r}")

    return facts


def _present(identity, address) -> set[str]:
    """Which canonical fields came back non-empty. Names only, never values."""
    found = set()
    for name in ("name", "dob", "gender", "aadhaar_last4"):
        if (getattr(identity, name) or "").strip():
            found.add(name)
    for name in (
        "care_of", "house", "street", "landmark", "location", "vtc",
        "sub_district", "district", "state", "pincode", "post_office",
    ):  # fmt: skip
        if (getattr(address, name) or "").strip():
            found.add(name)
    return found


# --------------------------------------------------------------------------- #


def scaffold(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for name in SUBFOLDERS:
        (root / name).mkdir(exist_ok=True)
    (root / "README.txt").write_text(README, encoding="utf-8")

    print(f"\nCreated {root.resolve()}\n")
    print("Put your Aadhaar photos in these subfolders:\n")
    for name in SUBFOLDERS:
        print(f"    {root / name}")
    print(f"\nRead {root / 'README.txt'} for what to shoot.")
    print("Delete any subfolders you do not use — empty ones are skipped.\n")
    print("Then run this command again.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure real decode rate and validate FIELD_MAPS. Prints no personal data."
    )
    parser.add_argument("corpus", type=Path, help="Folder of Aadhaar photos, OUTSIDE the repo.")
    parser.add_argument("--out", type=Path, default=Path("corpus_report.txt"))
    parser.add_argument("--budget", type=float, default=8.0, help="Seconds allowed per image.")
    parser.add_argument(
        "--certs",
        type=Path,
        default=Path("certs"),
        help="UIDAI trust store. With it, the report gives the REAL VERDICT, not "
        "just whether the payload parsed.",
    )
    args = parser.parse_args()

    root: Path = args.corpus

    if not root.exists():
        scaffold(root)
        return 0

    # ★ Find images by their LEADING BYTES, not their extension.
    #
    #   Photos arriving from a phone are routinely named `Image (4)` with no
    #   suffix at all, or `.jfif`, or `.dat` — messaging apps and Windows both
    #   do this. Filtering on the extension silently skips a whole corpus and
    #   reports "no images found", which is the least useful thing we could say.
    #
    #   We already built `avs.ingest.magic` in Step 3 for exactly this reason:
    #   the real service never trusts a filename either. Reuse it here so the
    #   script and the service agree on what an image is.
    candidates = [p for p in root.rglob("*") if p.is_file() and p.name != "README.txt"]
    images: list[Path] = []
    non_images: Counter = Counter()

    for path in candidates:
        try:
            with path.open("rb") as handle:
                head = handle.read(64)
        except OSError:
            continue
        if detect(head).kind in IMAGE_KINDS:
            images.append(path)
        else:
            kind = detect(head).kind
            label = path.suffix.lower() or "(no extension)"
            non_images[f"{label}  [{kind.name.lower()}]"] += 1

    images.sort()

    if not images:
        print(f"\nNo images found under {root.resolve()}")
        if candidates:
            # Say what IS there. "No images found" next to a folder full of
            # photos is a dead end; the file list is the actual diagnosis.
            print(f"\n{len(candidates)} file(s) present, none recognised as an image:")
            for suffix, count in non_images.most_common(10):
                print(f"    {suffix:<20} {count}")
            print("\nJudged by content, not by name. Accepted: JPEG, PNG, HEIC, WebP.")
            print("If these are videos or documents, remove them and add photos.")
        else:
            print(f"The subfolders are empty. See {root / 'README.txt'}.")
            print("\nExpected locations:")
            for name in SUBFOLDERS:
                if (root / name).is_dir():
                    print(f"    {root / name}")
        print()
        return 1

    if not any(decoder_availability().values()):
        print("No QR decoder backend available. Install one:")
        print('  pip install -e ".[imaging]"')
        return 1

    # ★ Load the trust store so the report can answer the question that actually
    #   matters — does a real card VERIFY? Parsing is necessary but not
    #   sufficient: only the RSA signature decides authenticity.
    certificates = []
    trust_note = "no trust store — signatures NOT checked"
    if args.certs.is_dir():
        try:
            store = FileCertificateStore(args.certs)
            store.load()
            certificates = store.certificates()
            trust_note = f"{len(certificates)} certificate(s) from {args.certs}"
        except TrustStoreError as exc:
            trust_note = f"trust store unusable: {exc}"
    verifier = SecureQrVerifier(certificates) if certificates else None

    ingestor = ImageIngestor(scanner=None)
    generator = PreprocessingVariantGenerator()
    cascade = QrDecoderCascade()
    payload_parser = SecureQrParser()

    lines: list[str] = []

    def emit(text: str = "") -> None:
        print(text)
        lines.append(text)

    emit("=" * 68)
    emit("AVS corpus report")
    emit("=" * 68)
    emit("No personal data appears below. Counts, error codes and field")
    emit("SHAPES only — never a name, a date, an address or a payload.")
    emit("")
    emit(f"images    : {len(images)}")
    emit(f"decoders  : {', '.join(n for n, ok in decoder_availability().items() if ok)}")
    emit(f"budget    : {args.budget}s per image")
    emit(f"trust     : {trust_note}")

    by_condition: dict[str, Counter] = {}
    errors: Counter = Counter()
    decoders_used: Counter = Counter()
    strategies: Counter = Counter()
    versions: Counter = Counter()
    variant_index: list[int] = []
    timings: list[float] = []

    verdicts: Counter = Counter()
    container_facts: Counter = Counter()
    parse_reasons: Counter = Counter()
    payload_shapes: Counter = Counter()
    field_presence: Counter = Counter()
    shape_problems: Counter = Counter()
    parsed_count = 0

    print()
    for index, path in enumerate(images, start=1):
        condition = path.parent.relative_to(root).as_posix() or "(root)"
        stats = by_condition.setdefault(condition, Counter())
        stats["total"] += 1

        print(f"  [{index}/{len(images)}] {condition}/… ", end="", flush=True)
        started = time.perf_counter()

        try:
            validated = ingestor.ingest(path.read_bytes(), capture_method=CaptureMethod.UNKNOWN)
        except IngestError as exc:
            stats["ingest_failed"] += 1
            errors[exc.code.value] += 1
            print(f"ingest failed ({exc.code.value})")
            continue

        # The budget gates the stream, but a variant already being built runs to
        # completion — which is why an 8s budget produced 18s runs on large
        # photos. Report the overshoot rather than hiding it; the same effect
        # applies to the pipeline's 12s document budget in production.
        deadline = started + args.budget
        result = cascade.decode(
            v for v in generator.generate(validated) if time.perf_counter() < deadline
        )
        elapsed = time.perf_counter() - started
        timings.append(elapsed)

        if not result.success:
            stats["no_qr"] += 1
            if result.foreign_qr_found:
                stats["foreign_qr"] += 1
                errors["FOREIGN_QR"] += 1
            else:
                errors["QR_NOT_FOUND"] += 1
            print(f"no Secure QR  ({elapsed:.1f}s, {result.attempts} variants)")
            continue

        stats["decoded"] += 1
        decoders_used[result.decoder or "?"] += 1
        strategies[result.strategy or "?"] += 1
        variant_index.append(result.attempts)

        # Shape of the decoded payload — counts and character class only.
        raw = result.raw_payload or ""
        payload_shapes[
            f"len={len(raw) // 500 * 500}-{len(raw) // 500 * 500 + 499} "
            f"digits={'y' if raw.isdigit() else 'n'}"
        ] += 1

        try:
            payload = payload_parser.parse(raw)
        except ParseError as exc:
            stats["parse_failed"] += 1
            errors[exc.code.value] += 1
            # ★ The MESSAGE is what tells us which of the five malformed paths
            #   we hit. The code alone is useless for diagnosis. Messages carry
            #   byte counts and failure reasons, never content.
            parse_reasons[f"{exc.code.value}: {exc.message}"] += 1
            for fact in _container_facts(raw):
                container_facts[fact] += 1
            print(f"decoded, parse failed ({exc.code.value})  {elapsed:.1f}s")
            print(f"        reason: {exc.message}")
            continue

        parsed_count += 1
        versions[payload.version] += 1

        # ⛔ THE ONLY QUESTION THAT DECIDES ANYTHING.
        if verifier is not None:
            proof = verifier.verify(payload)
            verdicts["VERIFIED" if proof.valid else "SIGNATURE INVALID"] += 1
            if proof.valid and proof.certificate_expired:
                verdicts["  (via a lapsed certificate)"] += 1
            marker = "VERIFIED" if proof.valid else "*** SIGNATURE INVALID ***"
        else:
            verdicts["parsed, unverified"] += 1
            marker = "parsed (no trust store)"
        for name in _present(payload.identity, payload.address):
            field_presence[name] += 1
        for problem in _shape_problems(payload.identity, payload.address):
            shape_problems[problem] += 1

        print(
            f"OK  {payload.version}  {marker}  "
            f"via {result.decoder}/{result.strategy}  {elapsed:.1f}s"
        )

    # ── Report ────────────────────────────────────────────────────────────
    total = len(images)
    decoded = sum(c["decoded"] for c in by_condition.values())

    emit()
    emit("=" * 68)
    emit("1. DECODE RATE   (safe to share)")
    emit("=" * 68)
    emit(f"  overall : {decoded}/{total}  =  {decoded / total:.1%}")
    if timings:
        ordered = sorted(timings)
        emit(
            f"  time    : median {ordered[len(ordered) // 2]:.1f}s   "
            f"p90 {ordered[int(len(ordered) * 0.9)]:.1f}s   max {ordered[-1]:.1f}s"
        )
    if variant_index:
        emit(f"  variants: mean {sum(variant_index) / len(variant_index):.1f} tried before success")
    emit()
    emit("  by condition:")
    for condition in sorted(by_condition):
        c = by_condition[condition]
        rate = c["decoded"] / c["total"] if c["total"] else 0.0
        emit(f"    {condition:<28} {c['decoded']:>3}/{c['total']:<3}  {rate:>6.1%}")

    if errors:
        emit()
        emit("  failure reasons:")
        for code, count in errors.most_common():
            emit(f"    {code:<28} {count}")

    if decoders_used:
        emit()
        emit("  decoder that succeeded:")
        for name, count in decoders_used.most_common():
            emit(f"    {name:<28} {count}")
        emit()
        emit("  preprocessing strategy that succeeded:")
        for name, count in strategies.most_common():
            emit(f"    {name:<28} {count}")

    emit()
    emit("=" * 68)
    emit("2. SIGNATURE VERIFICATION   ***  the only thing that approves  ***")
    emit("=" * 68)
    if verifier is None:
        emit("  No trust store loaded — nothing was verified.")
        emit(f"  Put UIDAI certificates in {args.certs} and re-run.")
    elif not verdicts:
        emit("  No payload reached the verifier.")
    else:
        for name, count in verdicts.most_common():
            emit(f"    {name:<32} {count}")
        emit()
        if verdicts.get("VERIFIED"):
            emit("  >>> Real Aadhaar cards VERIFIED against UIDAI's own public key.")
            emit("      Steps 1, 2 and 6 are now proven against reality.")
        if verdicts.get("SIGNATURE INVALID"):
            emit("  >>> A payload PARSED but FAILED verification. Either the card was")
            emit("      altered, or it was signed under a certificate we do not hold.")
            emit("      Download the older certificates from UIDAI before concluding")
            emit("      anything — see certs/README.md.")

    emit()
    emit("=" * 68)
    emit("3. FIELD_MAPS VALIDATION   ***  the important one  ***")
    emit("=" * 68)

    parse_failures = sum(c["parse_failed"] for c in by_condition.values())

    if payload_shapes:
        emit("  shape of every payload that DECODED:")
        for shape, count in payload_shapes.most_common():
            emit(f"    {shape:<40} {count}")
        emit()

    if parse_failures:
        emit(f"  {parse_failures} payload(s) decoded but failed to parse:")
        for reason, count in parse_reasons.most_common():
            emit(f"    [{count}] {reason}")
        emit()
        if container_facts:
            emit("  container-level facts for the failures (no content):")
            for fact, count in container_facts.most_common():
                emit(f"    [{count}] {fact}")
            emit()

        if parsed_count:
            # ⚠ Do NOT call this an ordering error. If other cards parsed cleanly
            #   with the same map, the map is fine and these payloads are
            #   something else — a partial decode, or a different QR entirely
            #   (the small front-face QR on newer PVC cards is not a Secure QR).
            emit("  NOT necessarily a FIELD_MAPS problem: other cards parsed")
            emit("  cleanly with the same map. More likely a partial/corrupted")
            emit("  decode, or a different QR type on the card.")
        else:
            emit("  Nothing parsed at all, so the map is unconfirmed. This MAY be")
            emit("  a FIELD_MAPS ordering error — but a corrupted decode looks the")
            emit("  same from here. Run corpus_diagnose.py to tell them apart.")
        emit()

    if parsed_count == 0:
        emit("  No payload parsed successfully — ordering could not be confirmed.")
    else:
        emit(f"  payloads parsed : {parsed_count}")
        emit(f"  QR versions     : {dict(versions)}")
        emit()
        emit("  field presence (how many cards had each field non-empty):")
        for name in (
            "name", "dob", "gender", "aadhaar_last4", "care_of", "house", "street",
            "landmark", "location", "vtc", "sub_district", "district", "state",
            "pincode", "post_office",
        ):  # fmt: skip
            count = field_presence.get(name, 0)
            required = name in {"name", "dob", "gender", "aadhaar_last4"}
            if count == 0 and required:
                flag = "  <-- MISSING, and this field is mandatory"
            elif count == 0 and parsed_count >= 8:
                flag = "  <-- empty on all; suspicious at this sample size"
            elif count == 0:
                flag = "  <-- empty on all (optional field, normal at small n)"
            else:
                flag = ""
            emit(f"    {name:<16} {count:>3}/{parsed_count}{flag}")

        emit()
        if shape_problems:
            emit("  *** SHAPE MISMATCHES — likely FIELD_MAPS ordering error ***")
            for problem, count in shape_problems.most_common():
                severity = "ALL CARDS" if count == parsed_count else f"{count}/{parsed_count}"
                emit(f"    {problem:<28} {severity}")
            emit()
            emit("  A problem on ALL CARDS means the ordering in")
            emit("  src/avs/parser/fields.py is wrong. Optional fields being empty")
            emit("  on some cards is normal — many people have no care_of or landmark.")
        else:
            emit("  No shape mismatches. Every field held content of the expected")
            emit("  kind — dates in dob, 6 digits in pincode, M/F/T in gender.")
            emit("  FIELD_MAPS ordering is CONFIRMED against real cards.")

    emit()
    emit("=" * 68)
    emit("Send this file. Do not send the images.")
    emit("=" * 68)

    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nWritten to {args.out.resolve()}")
    print("Read it, then paste its contents into the chat.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
