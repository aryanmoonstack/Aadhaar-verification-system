#!/usr/bin/env python3
"""Pair capture-quality metrics with REAL decode outcomes — Step 14.

    python scripts/measure_decode_quality.py C:\\aadhaar-corpus --out quality.csv

⛔ WHY THIS EXISTS, AND WHY IT RUNS BEFORE ANY THRESHOLD IS CHOSEN

   Step 13 set its thresholds from generated images. The code and the fixtures
   were built from the same understanding, so they agreed perfectly — and were
   wrong about reality. Measured against 19 real wrong-uploads, that classifier
   caught 0. Tuning could not have saved it, because the features could not
   express the difference.

   The quality model is the highest-value AI component in the plan, so it does
   not get to repeat that. This script runs **the actual decoder cascade** over
   real images and records, for each one:

       quality metrics  ->  did it ACTUALLY decode?

   Thresholds are then derived from that table. Not proposed and checked —
   derived. A threshold that has never been compared against a real decode
   outcome is a guess wearing a number.

⚠ WHAT LEAVES YOUR MACHINE

   Numbers and folder names. This script decodes QR codes in order to know
   whether decoding SUCCEEDS, but it never records, prints or writes the payload
   — only the boolean, which decoder won, which preprocessing strategy won, and
   how many variants were consumed.

   Read `_row_for` below if you want to confirm that; it is fifteen lines.

WHAT THE OUTPUT TELLS YOU
-------------------------
The report ends with the separation for each metric: how cleanly decoders and
non-decoders divide on it. A metric with clean separation is a usable threshold.
A metric that overlaps is Step 13's edge density all over again, and is reported
as unusable rather than quietly used anyway.
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

#: Magic bytes, not extensions — phone downloads are often named "Image (4)"
#: with no extension at all. Step 7.5 lost an afternoon to that.
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
    if any(header.startswith(signature) for signature in _SIGNATURES):
        return True
    return len(header) >= 12 and header[4:8] == b"ftyp"  # HEIC/AVIF


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path, help="Directory of images (stays local)")
    parser.add_argument("--out", type=Path, default=Path("quality.csv"))
    parser.add_argument(
        "--budget",
        type=float,
        default=6.0,
        help="Seconds per image. The real pipeline gives ~6s per side.",
    )
    parser.add_argument(
        "--from-csv",
        type=Path,
        default=None,
        help="Re-analyse an existing CSV instead of decoding again (instant).",
    )
    arguments = parser.parse_args()

    # ⛔ Re-analysis must not cost another full decode pass. The first run took
    #    251 seconds; fixing a bug in the REPORT should not charge that again.
    if arguments.from_csv is not None:
        return _reanalyse(arguments.from_csv)

    if not arguments.corpus.is_dir():
        print(f"Not a directory: {arguments.corpus}")
        return 2

    import cv2
    import numpy as np

    from avs.ai.quality.metrics import measure_quality
    from avs.imaging import PreprocessingVariantGenerator
    from avs.ingest import ImageIngestor
    from avs.qr import QrDecoderCascade

    files = [
        p for p in sorted(arguments.corpus.rglob("*")) if p.is_file() and looks_like_an_image(p)
    ]
    if not files:
        print(f"No images found under {arguments.corpus}.")
        print("Checked file CONTENT, not extensions, so unnamed downloads count too.")
        return 1

    print(f"Measuring and DECODING {len(files)} images (~{arguments.budget}s each worst case).")
    print("This runs the real cascade, so it is not fast. Progress below.\n")

    ingestor = ImageIngestor()
    generator = PreprocessingVariantGenerator()

    rows: list[dict] = []
    started = time.perf_counter()

    for index, path in enumerate(files, start=1):
        label = path.parent.name if path.parent != arguments.corpus else "unlabelled"
        try:
            image = cv2.imdecode(np.fromfile(path, dtype=np.uint8), cv2.IMREAD_COLOR)
        except BaseException:
            image = None
        if image is None:
            continue

        row = _row_for(
            image=image,
            raw=path.read_bytes(),
            label=label,
            ingestor=ingestor,
            generator=generator,
            cascade=QrDecoderCascade(time_budget_seconds=arguments.budget),
            measure_quality=measure_quality,
        )
        rows.append(row)

        flag = "OK " if row["decoded"] else "   "
        print(
            f"  [{index:>3}/{len(files)}] {flag} {label:<20} "
            f"px/module={row['px_per_module']:.2f}  sharpness={row['sharpness']:.0f}",
            flush=True,
        )

    if not rows:
        print("No images could be decoded as image files.")
        return 1

    with arguments.out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nDone in {time.perf_counter() - started:.0f}s.")
    _report(rows)
    print(f"\nWrote {len(rows)} rows to {arguments.out}")
    print("⚠ Open it. Every column is a number or a folder name.")
    print("  No payload, no filename, no decoded content — see `_row_for`.")
    return 0


def _reanalyse(path: Path) -> int:
    """Redo the report from a saved CSV. No decoding, no images touched."""
    if not path.is_file():
        print(f"No such file: {path}")
        return 2

    numeric = (
        "px_per_module", "sharpness", "megapixels", "mean_brightness",
        "glare_over_qr", "shadow_range", "qr_located", "qr_area_fraction",
        "qr_fully_inside", "glare_fraction", "skew_degrees", "decoded",
        "is_secure_qr", "attempts", "decode_ms",
    )  # fmt: skip

    rows: list[dict] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for raw in csv.DictReader(handle):
            row = dict(raw)
            for key in numeric:
                if key in row:
                    try:
                        row[key] = float(row[key])
                    except (TypeError, ValueError):
                        row[key] = 0.0
            rows.append(row)

    if not rows:
        print(f"{path} has no rows.")
        return 1

    print(f"Re-analysing {len(rows)} rows from {path} — no images read, no decoding.")
    _report(rows)
    return 0


def _row_for(*, image, raw, label, ingestor, generator, cascade, measure_quality) -> dict:
    """One image: its metrics, and whether it ACTUALLY decoded.

    ⛔ THE PRIVACY-CRITICAL FUNCTION. `result.raw_payload` holds the signed
       demographic record of a real person. It is used here ONLY to ask "is this
       a Secure QR?" and is never stored, printed or returned. Everything below
       is a number, a boolean, or a strategy name.
    """
    from avs.qr import classify_payload

    metrics = measure_quality(image)
    row: dict = {"label": label}
    row.update(metrics.as_row())

    decoded = False
    decoder = ""
    strategy = ""
    attempts = 0
    elapsed_ms = 0
    is_secure_qr = False

    # ⛔ Declared up front, ALWAYS. Adding this key only on failure meant the
    #    first row defined the CSV fieldnames without it, and csv.DictWriter
    #    then raised "dict contains fields not in fieldnames" the moment any
    #    later image failed ingest — losing the whole run at the write step,
    #    after every expensive decode had already been paid for.
    row["ingest_error"] = ""

    try:
        validated = ingestor.ingest(raw)
        started = time.perf_counter()
        result = cascade.decode(generator.generate(validated))
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        decoded = bool(result.success)
        decoder = result.decoder or ""
        strategy = result.strategy or ""
        attempts = int(result.attempts)
        if result.raw_payload:
            # ⛔ Boolean out. The payload itself goes no further than this line.
            is_secure_qr = classify_payload(result.raw_payload).value == "secure_qr"
    except BaseException as exc:
        row["ingest_error"] = type(exc).__name__

    row["decoded"] = int(decoded)
    row["is_secure_qr"] = int(is_secure_qr)
    row["decoder"] = decoder
    row["winning_strategy"] = strategy
    row["attempts"] = attempts
    row["decode_ms"] = elapsed_ms
    return row


#: Folder names meaning "deliberately NOT an Aadhaar document".
_NEGATIVE_HINTS = (
    "not-document", "not_document", "notdocument", "non-document",
    "negative", "selfie", "wall", "random", "junk",
)  # fmt: skip


def _is_negative(label: str) -> bool:
    lowered = label.lower()
    return any(hint in lowered for hint in _NEGATIVE_HINTS)


def _report(rows: list[dict]) -> None:
    """Score the metrics against real decode outcomes.

    ⛔⛔ THE BUG THIS REPLACES INVERTED ITS OWN CONCLUSION.

       The first version computed separation over EVERY image, including the
       non-documents. Those have no Aadhaar QR at all — they were never going to
       decode — so lumping them into "failed" buried the real signal and every
       metric came back OVERLAP.

       Worse, `find_qr_region` false-positives on screenshots and UI (D136), so
       16 of 19 negatives reported a plausible-looking px_per_module, up to
       27.62. The contamination was invisible in the summary.

       Non-documents are now EXCLUDED from the threshold analysis and reported
       separately, where they measure something genuinely useful: how often the
       QR localiser hallucinates.
    """
    documents = [r for r in rows if not _is_negative(r["label"])]
    negatives = [r for r in rows if _is_negative(r["label"])]

    decoded = [r for r in documents if r["decoded"]]
    failed = [r for r in documents if not r["decoded"]]

    print("\n" + "=" * 78)
    print(
        f"DECODE RATE (documents only): {len(decoded)}/{len(documents)}"
        f"  ({len(decoded) / max(1, len(documents)):.0%})"
    )
    if negatives:
        print(f"  {len(negatives)} non-document(s) excluded — they have no QR to decode.")
    print("=" * 78)

    by_label: dict[str, list[dict]] = {}
    for row in documents:
        by_label.setdefault(row["label"], []).append(row)

    print(f"\n{'label':<22} {'n':>3} {'decoded':>9} {'px/module med':>14} {'sharpness med':>14}")
    print("-" * 66)
    for label in sorted(by_label):
        subset = by_label[label]
        ok = sum(r["decoded"] for r in subset)
        pxm = statistics.median([r["px_per_module"] for r in subset])
        shp = statistics.median([r["sharpness"] for r in subset])
        print(f"{label:<22} {len(subset):>3} {ok:>5}/{len(subset):<3} {pxm:>14.2f} {shp:>14.0f}")

    _warn_about_duplicates(documents)

    if not decoded or not failed:
        print("\n⚠ Cannot derive thresholds — every document is on the same side.")
        return

    # ------------------------------------------------------------------ #
    # ★ NECESSARY-CONDITION ANALYSIS — the actionable form.
    #
    #   Not "where do the classes separate" (they overlap; real data usually
    #   does). Instead: how far can a floor be pushed before it would have
    #   rejected an image that ACTUALLY decoded?
    #
    #   That floor is safe by construction — zero false alarms on this corpus —
    #   and the fraction of failures it catches is exactly the value it adds.
    # ------------------------------------------------------------------ #
    print("\n" + "=" * 78)
    print("NECESSARY CONDITIONS — floors that no successful decode fell below")
    print("=" * 78)
    print(f"{'metric':<18} {'floor':>10} {'catches':>10} {'of failures':>13} {'false alarms':>14}")
    print("-" * 78)

    findings: list[tuple[str, float, float]] = []
    for metric in ("sharpness", "px_per_module", "megapixels", "mean_brightness"):
        successes = [r[metric] for r in decoded]
        floor = min(successes)
        caught = [r for r in failed if r[metric] < floor]
        share = len(caught) / len(failed)
        findings.append((metric, floor, share))
        print(f"{metric:<18} {floor:>10.2f} {len(caught):>10} {share:>12.0%} {0:>14}")

    findings.sort(key=lambda item: -item[2])
    best, best_floor, best_share = findings[0]
    print(
        f"\n★ STRONGEST: {best} — a floor at {best_floor:.1f} would flag "
        f"{best_share:.0%} of failures\n  without ever having rejected an image that worked."
    )

    # ------------------------------------------------------------------ #
    # ★ DO THE RULES STACK, OR DO THEY CATCH THE SAME IMAGES?
    #
    #   Two rules each catching 70% mean very different things depending on
    #   whether they overlap. If they flag the same photos, the second adds
    #   nothing but code to maintain. If they are independent, together they
    #   cover far more than either alone.
    #
    #   Every floor here is safe by construction — no successful decode falls
    #   below it — so their UNION is safe too. That is what makes stacking them
    #   legitimate rather than a compounding of risk.
    # ------------------------------------------------------------------ #
    print("\n" + "-" * 78)
    print("COMBINED COVERAGE — does adding a second rule help?")
    print("-" * 78)

    caught_by = {
        metric: {index for index, row in enumerate(failed) if row[metric] < floor}
        for metric, floor, _ in findings
    }

    union: set[int] = set()
    for metric, _, _ in findings:
        added = caught_by[metric] - union
        union |= caught_by[metric]
        if caught_by[metric]:
            print(
                f"  + {metric:<16} adds {len(added):>2} new  "
                f"-> running total {len(union):>2}/{len(failed)} "
                f"= {len(union) / len(failed):.0%}"
            )

    missed = [row for index, row in enumerate(failed) if index not in union]
    print(f"\n  {len(missed)} failure(s) caught by NO rule.")
    if missed:
        print("  Captures that look fine on every metric and still fail — the")
        print("  population a TRAINED model would have to earn its place on.")
        for row in missed[:5]:
            print(
                f"    {row['label']:<20} sharpness={row['sharpness']:>7.0f} "
                f"px/module={row['px_per_module']:>6.2f} "
                f"brightness={row['mean_brightness']:>6.1f}"
            )

    # ⚠ Sample-size honesty. Five successes cannot support a tight threshold,
    #   and a floor placed exactly at the weakest one is fitted to that image.
    print(f"\n⚠ Based on {len(decoded)} successful decodes. A floor set exactly at the")
    print("  weakest success is overfitted to it — ship it with margin BELOW the")
    print("  floor, so a slightly worse-but-workable capture is not turned away.")

    # ------------------------------------------------------------------ #
    # What the negatives measure: localiser hallucination (D136)
    # ------------------------------------------------------------------ #
    if negatives:
        hallucinated = [r for r in negatives if r["px_per_module"] > 0]
        print("\n" + "=" * 78)
        print("QR LOCALISER ON NON-DOCUMENTS (D136)")
        print("=" * 78)
        print(f"Reported a QR in {len(hallucinated)}/{len(negatives)} images that have none.")
        if hallucinated:
            worst = max(r["px_per_module"] for r in hallucinated)
            print(f"Largest phantom QR: {worst:.2f} px/module — indistinguishable from a real one.")
            print("⛔ So QR-presence is NOT evidence a document is an Aadhaar, and")
            print("   px_per_module is only meaningful once something else has")
            print("   established that a card is present. Step 15 must be scored on")
            print("   negatives, not only on cards.")

    located_failures = [r for r in failed if r["qr_located"]]
    print(f"\n{len(located_failures)} document(s) had a QR LOCATED but not decoded.")
    print("  That is the population Steps 15 and 19 exist to convert.")

    winners: dict[str, int] = {}
    for row in decoded:
        winners[row["winning_strategy"] or "(none)"] = (
            winners.get(row["winning_strategy"] or "(none)", 0) + 1
        )
    if winners:
        print("\nWinning preprocessing strategy (drives variant ordering):")
        for name, count in sorted(winners.items(), key=lambda kv: -kv[1]):
            print(f"  {count:>3}x  {name}")


def _warn_about_duplicates(documents: list[dict]) -> None:
    """⚠ Duplicates inflate confidence without adding evidence.

    Found in the first real run: the `scanner` folder held two images identical
    to `phone-a-good-light` ones. Counting them twice makes a corpus look 10%
    larger than the information it actually contains.
    """
    from collections import Counter

    signature = Counter(
        (round(r["px_per_module"], 2), round(r["sharpness"], 2), round(r["megapixels"], 3))
        for r in documents
    )
    repeated = {key: count for key, count in signature.items() if count > 1}
    if repeated:
        print(f"\n⚠ {len(repeated)} image(s) appear more than once (identical metrics):")
        for (pxm, shp, mp), count in repeated.items():
            print(f"    px/module={pxm} sharpness={shp} mp={mp}  -> {count} copies")
        print("  Likely the same photo in two folders. They add no new evidence.")


if __name__ == "__main__":
    raise SystemExit(main())
