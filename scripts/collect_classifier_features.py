#!/usr/bin/env python3
"""Measure classifier features across a local image corpus — Step 13.

    python scripts/collect_classifier_features.py C:\\aadhaar-corpus --out features.csv

⛔ WHAT THIS DELIBERATELY DOES NOT DO

   It does not copy an image. It does not decode a QR. It does not read text,
   extract a name, or record a filename. It reads pixels, computes ten shape
   statistics, and writes those numbers.

   That is the whole design constraint. The corpus lives on one machine and
   stays there; what leaves is a table of numbers with no path back to a person.
   Run this yourself, look at the CSV, and send the SUMMARY — or the CSV, once
   you have satisfied yourself it contains nothing but numbers.

WHY IT IS NEEDED
----------------
``EDGE_DENSITY_FLOOR`` in ``ai/classify/heuristic.py`` was set from GENERATED
images, because generated images are all this code has ever been allowed to see.
Generated non-documents measured exactly 0.0000 edge density — a figure no real
photograph will ever produce, since real frames carry sensor noise and clutter.

So the threshold is currently parked an order of magnitude below the weakest
generated document, which is safe but leaves capability on the table. This
script produces the numbers needed to move it to where measurement says it
belongs.

⚠ THE LESSON THIS ENCODES

  Step 7.5 spent three wrong hypotheses on a decode-rate problem before
  measuring. Every breakthrough in this project has come from an INDEPENDENT
  source of truth — UIDAI's published spec, UIDAI's certificate page, real
  images — rather than from reasoning about what the code should do. Thresholds
  chosen from generated data are exactly the kind of self-consistency that
  looked fine for 540 tests while real cards failed.

USAGE
-----
Label subfolders by content so the output can be grouped::

    C:\\aadhaar-corpus\\
        aadhaar\\        genuine cards, any angle or lighting
        other-id\\       PAN, driving licence, voter ID, passport
        not-document\\   selfies, walls, screenshots, accidents

Folders may be named anything; the folder name becomes the label. Images at the
top level are labelled ``unlabelled``.
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

#: Magic bytes, not extensions.
#:
#: ⚠ Step 7.5 lost an afternoon here: the corpus reporter filtered on file
#:   extension and found zero images, because phone downloads were named
#:   "Image (4)" with no extension at all. Sniff the content.
_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"BM", "bmp"),
    (b"II*\x00", "tiff"),
    (b"MM\x00*", "tiff"),
)


def looks_like_an_image(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            header = handle.read(16)
    except OSError:
        return False

    if any(header.startswith(signature) for signature, _ in _SIGNATURES):
        return True
    # HEIC/AVIF: 'ftyp' at offset 4.
    return len(header) >= 12 and header[4:8] == b"ftyp"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path, help="Directory of images (stays local)")
    parser.add_argument("--out", type=Path, default=Path("features.csv"))
    arguments = parser.parse_args()

    if not arguments.corpus.is_dir():
        print(f"Not a directory: {arguments.corpus}")
        return 2

    import cv2
    import numpy as np

    from avs.ai.classify.features import extract_features
    from avs.ai.classify.heuristic import (
        EDGE_DENSITY_FLOOR,
        MIN_MEAN_BRIGHTNESS,
        HeuristicClassifier,
    )

    classifier = HeuristicClassifier()
    files = [
        p for p in sorted(arguments.corpus.rglob("*")) if p.is_file() and looks_like_an_image(p)
    ]

    if not files:
        print(f"No images found under {arguments.corpus}.")
        print("Checked file CONTENT, not extensions, so unnamed downloads count too.")
        return 1

    print(f"Measuring {len(files)} images...\n")

    rows: list[dict] = []
    for path in files:
        label = path.parent.name if path.parent != arguments.corpus else "unlabelled"
        try:
            data = np.fromfile(path, dtype=np.uint8)
            image = cv2.imdecode(data, cv2.IMREAD_COLOR)
        except BaseException:
            image = None

        if image is None:
            continue

        features = extract_features(image)
        row = {"label": label}
        row.update(features.as_row())
        # ⛔ What the SHIPPED heuristic says, so its accuracy can be scored
        #    against the labels without shipping anything new.
        row["predicted"] = classifier.classify_features(features).doc_type.value
        rows.append(row)

    if not rows:
        print("No images could be decoded.")
        return 1

    with arguments.out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    _report(rows, EDGE_DENSITY_FLOOR, MIN_MEAN_BRIGHTNESS)
    print(f"\nWrote {len(rows)} rows to {arguments.out}")
    print("⚠ Open it. Every column is a number or a folder name — no image data,")
    print("  no filenames, no decoded content. Safe to share once you agree.")
    return 0


#: Folder names that mean "this is deliberately NOT a document".
#:
#: ⚠ Everything else counts as a document. That default is the safe one: an
#:   unrecognised label being treated as a document means the misfire check runs
#:   against it, which is exactly the check we want to be over-eager.
_NEGATIVE_LABEL_HINTS = (
    "not-document",
    "not_document",
    "notdocument",
    "non-document",
    "negative",
    "selfie",
    "wall",
    "random",
    "junk",
)


def _is_negative_label(label: str) -> bool:
    lowered = label.lower()
    return any(hint in lowered for hint in _NEGATIVE_LABEL_HINTS)


def _report(rows: list[dict], floor: float, brightness_floor: float) -> None:
    """Score the SHIPPED heuristic against the labels and give a verdict.

    ⛔ Two numbers decide whether this classifier earns its place, and they are
       not symmetric:

       FALSE POSITIVES — a real document called "not a document". Tells someone
                         their genuine Aadhaar is not a document. Unacceptable
                         at any rate above zero.
       RECALL          — non-documents correctly caught. If this is zero the
                         heuristic never fires, and code that never fires is
                         code that should be deleted rather than maintained.

       A run with no negatives can measure the first and not the second, so it
       says so instead of implying success.
    """
    labels = sorted({row["label"] for row in rows})

    print(f"{'label':<20} {'n':>3}   {'edge (min/med/max)':>26}   {'brightness (min/max)':>21}")
    print("-" * 78)
    for label in labels:
        subset = [r for r in rows if r["label"] == label]
        edges = sorted(r["edge_density"] for r in subset)
        brights = sorted(r.get("mean_brightness", 0.0) for r in subset)
        marker = "  (negative)" if _is_negative_label(label) else ""
        print(
            f"{label:<20} {len(subset):>3}   "
            f"{edges[0]:>7.4f} {statistics.median(edges):>8.4f} {edges[-1]:>8.4f}   "
            f"{brights[0]:>9.1f} {brights[-1]:>10.1f}{marker}"
        )

    print(f"\nThresholds: EDGE_DENSITY_FLOOR={floor}  MIN_MEAN_BRIGHTNESS={brightness_floor}")

    # ⛔ THE BUG THIS REPLACES SAID "PASS" BY MATCHING NOTHING.
    #
    #    The old filter was `"aadhaar" in label or "id" in label`. Run against a
    #    real corpus labelled `phone-a-dim`, `phone-b-angled`, `scanner`, it
    #    matched ZERO rows — so "weakest real document" never printed and the
    #    misfire check compared against an empty set and reported success.
    #    Meanwhile three genuine cards sat below the threshold.
    #
    #    A safety check that passes because it found nothing is worse than no
    #    check: it produces a green tick that a human then trusts. So the
    #    default is inverted — EVERYTHING is a document unless a folder name
    #    explicitly says otherwise — and the assumption is printed.
    document_rows = [r for r in rows if not _is_negative_label(r["label"])]
    negative_rows = [r for r in rows if _is_negative_label(r["label"])]

    print(
        f"\nTreating {len(document_rows)} image(s) as DOCUMENTS and "
        f"{len(negative_rows)} as non-documents, from folder names."
    )

    # ------------------------------------------------------------------ #
    # 1. False positives — the error that costs something
    # ------------------------------------------------------------------ #
    print("\n" + "=" * 78)
    print("1. FALSE POSITIVES — real documents wrongly called 'not a document'")
    print("=" * 78)

    misfires = [r for r in document_rows if r["predicted"] == "not_a_document"]
    if not document_rows:
        print("⛔ Nothing was treated as a document. This check proved NOTHING.")
    elif misfires:
        print(f"⛔ {len(misfires)} of {len(document_rows)} REAL DOCUMENTS misclassified.")
        for row in misfires[:8]:
            print(
                f"   {row['label']:<20} edge={row['edge_density']:.4f} "
                f"brightness={row.get('mean_brightness', 0):.1f}"
            )
        print("   FIX: raise MIN_MEAN_BRIGHTNESS, or lower EDGE_DENSITY_FLOOR.")
    else:
        print(f"✓ 0 of {len(document_rows)} real documents misclassified.")

    # ⚠ WHICH GUARD is protecting each document. A document protected only by
    #   the QR check is one failed localisation away from being misclassified —
    #   exactly the situation the phone-a-dim images were in before the exposure
    #   gate was added.
    if document_rows:
        qr_only = [
            r
            for r in document_rows
            if r["edge_density"] < floor
            and r.get("mean_brightness", 255) >= brightness_floor
            and (r.get("has_qr") or r.get("has_document_quad"))
        ]
        if qr_only:
            print(f"\n⚠ {len(qr_only)} document(s) are WELL-LIT and below the edge floor.")
            print("  Only QR/quad detection protects them. That is luck, not margin.")

    # ------------------------------------------------------------------ #
    # 2. Recall — does the thing ever actually fire?
    # ------------------------------------------------------------------ #
    print("\n" + "=" * 78)
    print("2. RECALL — non-documents the classifier actually caught")
    print("=" * 78)

    if not negative_rows:
        print("⚠ UNMEASURED. No non-document folder in this corpus.")
        print("  Create one — e.g. C:\\aadhaar-corpus\\not-document\\ — with ~10")
        print("  selfies, walls, screenshots and random objects, then re-run.")
        print("  Without it, whether this classifier EVER helps is unknown.")
    else:
        caught = [r for r in negative_rows if r["predicted"] == "not_a_document"]
        missed = [r for r in negative_rows if r["predicted"] != "not_a_document"]
        recall = len(caught) / len(negative_rows)
        print(f"Caught {len(caught)} of {len(negative_rows)}  ({recall:.0%})")

        for row in missed[:8]:
            # ⛔ Say WHY it was missed. "It didn't fire" is not actionable; the
            #    guard that swallowed it is.
            reason = "edge density above floor"
            if row.get("has_qr") or row.get("has_document_quad"):
                reason = "a QR or document quad was detected in it"
            elif row.get("mean_brightness", 255) < brightness_floor:
                reason = "too dark — the exposure gate declined to judge"
            print(
                f"   missed: {row['label']:<16} edge={row['edge_density']:.4f} "
                f"brightness={row.get('mean_brightness', 0):.1f}  -> {reason}"
            )

    # ------------------------------------------------------------------ #
    # 3. Verdict
    # ------------------------------------------------------------------ #
    print("\n" + "=" * 78)
    print("3. VERDICT")
    print("=" * 78)

    if misfires:
        print("⛔ BROKEN — it misclassifies real documents. Fix before shipping.")
    elif not negative_rows:
        print("◐ SAFE BUT UNPROVEN. It harms nothing; whether it helps is unmeasured.")
    else:
        caught = [r for r in negative_rows if r["predicted"] == "not_a_document"]
        recall = len(caught) / len(negative_rows)
        if recall == 0:
            print("◐ NEVER FIRES. It is safe but useless on this sample — it would")
            print("  add no message anyone would ever see. Consider deleting it and")
            print("  waiting for the trained model, rather than maintaining dead code.")
        elif recall < 0.5:
            print(f"✓ USEFUL BUT NARROW — catches {recall:.0%}, harms nothing.")
            print("  Worth keeping: every catch replaces a misleading message.")
        else:
            print(f"✓ EARNS ITS PLACE — catches {recall:.0%} with zero false positives.")


if __name__ == "__main__":
    raise SystemExit(main())
