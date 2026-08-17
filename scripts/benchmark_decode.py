#!/usr/bin/env python3
"""Decode-rate benchmark — the project's primary metric.

⛔ PRINTS NO PERSONAL DATA. Counts, strategy names, decoder names and timings
   only. Output is safe to paste into a chat or a ticket.

TWO MODES
---------

**Synthetic** (works today, no corpus needed)

    python scripts/benchmark_decode.py --synthetic

Renders a real Secure-QR-sized payload onto a card image, degrades it in the ways
phone photos are degraded — blur, noise, low contrast, glare, perspective,
distance, JPEG compression — and measures decode rate per failure mode.

This is a *controlled* baseline. It cannot tell you how the pipeline behaves on
real captures, but it tells you precisely which failure mode each later
improvement fixes, because the same sweep re-runs identically.

**Real corpus** (the number that matters)

    $env:AVS_CORPUS_DIR = "C:\\Users\\Moonstack\\aadhaar-corpus"
    python scripts/benchmark_decode.py

Runs the full pipeline over your own photographs. Real captures carry sensor
noise, print texture and lighting no simulation reproduces, so this is the figure
every later AI investment is measured against. Record it.

WHAT TO WATCH
-------------
* **decode rate** — the headline number
* **mean variant index** — the latency driver. Decoding on variant 1 costs ~100 ms;
  variant 19 costs several seconds. Step 4's tier ordering exists to keep this low.
* **time to failure** — an image that cannot decode still burns the whole matrix.
  This is what the cascade's time budget, and later the Step 14 quality model,
  are for.
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from avs.imaging import PreprocessingVariantGenerator
from avs.ingest import ImageIngestor, IngestError
from avs.qr import QrDecoderCascade, decoder_availability


class Outcome:
    """One benchmark row. Deliberately holds no image data."""

    __slots__ = ("decoder", "label", "ms", "note", "strategy", "success", "variants")

    def __init__(
        self,
        label: str,
        success: bool,
        decoder: str | None,
        strategy: str | None,
        variants: int,
        ms: float,
        note: str = "",
    ) -> None:
        self.label = label
        self.success = success
        self.decoder = decoder
        self.strategy = strategy
        self.variants = variants
        self.ms = ms
        self.note = note


def run_pipeline(
    image_bytes: bytes,
    label: str,
    *,
    ingestor: ImageIngestor,
    generator: PreprocessingVariantGenerator,
    cascade: QrDecoderCascade,
    expected_payload: str | None = None,
) -> Outcome:
    started = time.perf_counter()
    try:
        image = ingestor.ingest(image_bytes)
    except IngestError as exc:
        return Outcome(label, False, None, None, 0, 0.0, f"ingest:{exc.code.value}")

    result = cascade.decode(generator.generate(image))
    elapsed_ms = (time.perf_counter() - started) * 1000

    note = ""
    if result.success and expected_payload and result.raw_payload != expected_payload:
        note = "PAYLOAD MISMATCH"
    elif not result.success and result.foreign_qr_found:
        note = "foreign QR only"

    return Outcome(
        label,
        result.success,
        result.decoder,
        result.strategy,
        result.attempts,
        elapsed_ms,
        note,
    )


# --------------------------------------------------------------------------- #


def benchmark_synthetic(qr_scale: int, verbose: bool) -> list[Outcome]:
    from tests.fixtures.qr_images import DEGRADATIONS, encode_jpeg, render_card
    from tests.fixtures.synthetic import SyntheticQrBuilder, make_test_keypair

    key, _ = make_test_keypair()
    payload = SyntheticQrBuilder(private_key=key).build()
    card = render_card(payload, qr_scale=qr_scale)

    print(f"Synthetic card: {card.shape[1]}x{card.shape[0]}, payload {len(payload)} digits")
    print("(a real Secure QR is 1,500-4,000 digits — same density class)\n")

    ingestor = ImageIngestor()
    generator = PreprocessingVariantGenerator()
    cascade = QrDecoderCascade()

    outcomes: list[Outcome] = []
    for family, cases in DEGRADATIONS.items():
        for name, transform in cases:
            degraded = transform(card)  # type: ignore[operator]
            outcome = run_pipeline(
                encode_jpeg(degraded),
                f"{family}/{name}",
                ingestor=ingestor,
                generator=generator,
                cascade=cascade,
                expected_payload=payload,
            )
            outcomes.append(outcome)
            if verbose:
                mark = "OK " if outcome.success else "-- "
                print(
                    f"  {mark} {outcome.label:26} v{outcome.variants:<3} "
                    f"{outcome.ms:7.0f}ms  {outcome.strategy or ''} {outcome.note}"
                )
    return outcomes


def benchmark_corpus(corpus_dir: Path, verbose: bool) -> list[Outcome]:
    images = sorted(
        p
        for p in corpus_dir.rglob("*")
        if p.suffix.lower() in {".jpg", ".jpeg", ".png", ".webp", ".heic", ".heif"}
    )
    if not images:
        print(f"No images found in {corpus_dir}")
        return []

    print(f"Corpus: {len(images)} images from {corpus_dir}\n")

    ingestor = ImageIngestor()
    generator = PreprocessingVariantGenerator()
    cascade = QrDecoderCascade()

    outcomes: list[Outcome] = []
    for index, path in enumerate(images, start=1):
        outcome = run_pipeline(
            path.read_bytes(),
            path.name,  # filename only — no directory structure, no content
            ingestor=ingestor,
            generator=generator,
            cascade=cascade,
        )
        outcomes.append(outcome)
        if verbose:
            mark = "OK " if outcome.success else "-- "
            print(
                f"  [{index:>3}] {mark} {outcome.label:34} v{outcome.variants:<3} "
                f"{outcome.ms:7.0f}ms  {outcome.strategy or ''} {outcome.note}"
            )
    return outcomes


# --------------------------------------------------------------------------- #


def report(outcomes: list[Outcome]) -> int:
    if not outcomes:
        return 1

    successes = [o for o in outcomes if o.success]
    failures = [o for o in outcomes if not o.success]
    rate = len(successes) / len(outcomes)

    print("\n" + "=" * 66)
    print("BENCHMARK SUMMARY  (safe to share — no personal data)")
    print("=" * 66)
    print(f"  decode rate        : {rate:.1%}   ({len(successes)}/{len(outcomes)})")

    if successes:
        variants = [o.variants for o in successes]
        print(
            f"  mean variant index : {statistics.mean(variants):.1f}   "
            f"(median {statistics.median(variants):.0f}, max {max(variants)})"
        )
        print(f"  mean time (success): {statistics.mean([o.ms for o in successes]):.0f} ms")
        print(f"  decoded on v1      : {sum(1 for v in variants if v == 1)}/{len(successes)}")
    if failures:
        print(f"  mean time (failure): {statistics.mean([o.ms for o in failures]):.0f} ms")

    if successes:
        print("\n  decoder:")
        for name, count in Counter(o.decoder for o in successes).most_common():
            print(f"    {name:<16} {count:>4}")
        print("\n  winning strategy:")
        for name, count in Counter(o.strategy for o in successes).most_common(8):
            print(f"    {name:<34} {count:>4}")

    families = sorted({o.label.split("/")[0] for o in outcomes})
    if len(families) > 1:
        print("\n  by family:")
        for family in families:
            group = [o for o in outcomes if o.label.startswith(family)]
            ok = sum(1 for o in group if o.success)
            print(f"    {family:<16} {ok}/{len(group)}   {ok / len(group):.0%}")

    if failures:
        print("\n  failed:")
        for outcome in failures:
            note = f"  [{outcome.note}]" if outcome.note else ""
            print(f"    {outcome.label}{note}")

    mismatches = [o for o in outcomes if o.note == "PAYLOAD MISMATCH"]
    if mismatches:
        print(f"\n  ⚠ {len(mismatches)} PAYLOAD MISMATCHES — decoder returned wrong data")
        return 2

    print()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("corpus", type=Path, nargs="?", help="directory of real card photos")
    parser.add_argument("--synthetic", action="store_true", help="run the degradation sweep")
    parser.add_argument("--qr-scale", type=int, default=5, help="synthetic pixels per module")
    parser.add_argument("-q", "--quiet", action="store_true", help="summary only")
    args = parser.parse_args()

    print("=" * 66)
    print("AVS decode-rate benchmark")
    print("=" * 66)
    availability = decoder_availability()
    print(
        "decoders: "
        + ", ".join(f"{name}={'yes' if ok else 'NO'}" for name, ok in availability.items())
    )
    if not any(availability.values()):
        print("\n  ! No decoder backend is available. Nothing can decode.")
        return 2
    print()

    if args.synthetic:
        outcomes = benchmark_synthetic(args.qr_scale, verbose=not args.quiet)
    else:
        corpus = args.corpus or (
            Path(os.environ["AVS_CORPUS_DIR"]) if os.environ.get("AVS_CORPUS_DIR") else None
        )
        if corpus is None:
            print("No corpus given. Set AVS_CORPUS_DIR, pass a directory, or use --synthetic.")
            return 1
        if not corpus.exists():
            print(f"Corpus directory not found: {corpus}")
            return 1
        outcomes = benchmark_corpus(corpus, verbose=not args.quiet)

    return report(outcomes)


if __name__ == "__main__":
    raise SystemExit(main())
