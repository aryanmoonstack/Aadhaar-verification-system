"""QR decoder cascade — Step 5.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 5
Provides : QrDecoderCascade (implements avs.contracts.QrDecoder),
           PayloadKind, classify_payload()
Consumes : avs.contracts, avs.qr.decoders, OpenCV
Used by  : avs.parser (Step 1) via the Step 6 pipeline

THE LOOP ORDER IS THE DESIGN
----------------------------
For each variant, try every decoder. Then — and only then — ask for the next
variant.

    for variant in variants:          # lazy, cheapest-first (Step 4)
        for decoder in decoders:      # cheap relative to another variant
            ...

The reverse order — for each decoder, try every variant — would force the whole
variant stream to be materialised, which is exactly what contract 1.1.0 was
widened to avoid. Running four decoders over one image costs a few milliseconds;
generating another preprocessing variant of a 12 MP photo costs a hundred times
that.

Combined with Step 4's tier ordering, a well-lit capture decodes on variant 1 and
the pipeline stops there.

NOT EVERY QR IS THE ONE WE WANT
-------------------------------
A photograph can contain more than one code — a URL sticker, an app's UI, a
courier label. Accepting the first QR found would let a stray code short-circuit
the cascade and hand the parser something that was never an Aadhaar payload.

So candidates are classified before acceptance. Only a Secure QR payload (a long
digit string) or a pre-2018 legacy XML QR is accepted. Anything else is recorded
as ``foreign_qr_found`` and scanning continues — which also lets the employee be
told "that isn't an Aadhaar QR" rather than the far less useful "no QR found".
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from enum import Enum

import cv2
import numpy as np

from avs.contracts import DecodeResult, ImageVariant
from avs.qr.decoders import Decoder, available_decoders

__all__ = ["MIN_SECURE_QR_DIGITS", "PayloadKind", "QrDecoderCascade", "classify_payload"]


#: A real Secure QR decodes to roughly 1,500–4,000 digits. The signature block
#: alone is 256 bytes, so nothing genuine comes close to this floor — but it sits
#: far enough below the real range to tolerate formats we have not seen.
MIN_SECURE_QR_DIGITS = 500


class PayloadKind(str, Enum):
    """What a decoded QR string turned out to be."""

    SECURE_QR = "secure_qr"
    """A signed Aadhaar Secure QR. The payload we want."""

    LEGACY_XML = "legacy_xml"
    """A pre-2018 unsigned Aadhaar QR.

    Accepted deliberately. It cannot be verified, but passing it to the parser
    produces ``LEGACY_FORMAT`` — telling the employee to download a fresh
    e-Aadhaar — instead of the misleading ``UNREADABLE``. A genuine old card is
    not an unreadable one.
    """

    FOREIGN = "foreign"
    """Some other QR. Not an Aadhaar payload."""


def classify_payload(text: str) -> PayloadKind:
    """Identify a decoded QR string. Cheap, and never raises."""
    stripped = text.strip()

    if len(stripped) >= MIN_SECURE_QR_DIGITS and stripped.isdigit():
        return PayloadKind.SECURE_QR

    head = stripped[:200].lstrip().lower()
    if head.startswith("<?xml") or "printletterbarcodedata" in head or "uid=" in head:
        return PayloadKind.LEGACY_XML

    return PayloadKind.FOREIGN


class QrDecoderCascade:
    """Decodes an Aadhaar Secure QR from a stream of preprocessed variants."""

    def __init__(
        self,
        decoders: list[Decoder] | None = None,
        *,
        max_variants: int | None = None,
        time_budget_seconds: float | None = None,
    ) -> None:
        """
        Args:
            decoders: backends to try, in order. Defaults to everything usable
                on this host.
            max_variants: stop after this many variants even without success.
            time_budget_seconds: stop once this much wall time has elapsed.
                A hard bound matters in production: one pathological image must
                not hold a worker while other employees queue behind it.
        """
        self.decoders = decoders if decoders is not None else available_decoders()
        self.max_variants = max_variants
        self.time_budget_seconds = time_budget_seconds

    # ------------------------------------------------------------------ #

    def decode(self, variants: Iterable[ImageVariant]) -> DecodeResult:
        """Try each variant against each decoder. Stop at the first Aadhaar QR."""
        started = time.perf_counter()
        attempts = 0
        foreign_found = False

        if not self.decoders:
            # No usable backend at all. Report failure rather than pretending —
            # a silent zero decode rate is far worse than a loud one.
            return DecodeResult(success=False, attempts=0, foreign_qr_found=False)

        for variant in variants:
            attempts += 1

            image = self._to_array(variant)
            if image is None:
                continue

            for decoder in self.decoders:
                for text in decoder.decode(image):
                    kind = classify_payload(text)

                    if kind is PayloadKind.FOREIGN:
                        foreign_found = True
                        continue

                    return DecodeResult(
                        success=True,
                        raw_payload=text,
                        decoder=decoder.name,
                        strategy=variant.strategy,
                        attempts=attempts,
                        foreign_qr_found=foreign_found,
                    )

            if self.max_variants is not None and attempts >= self.max_variants:
                break
            if (
                self.time_budget_seconds is not None
                and (time.perf_counter() - started) >= self.time_budget_seconds
            ):
                break

        return DecodeResult(
            success=False,
            attempts=attempts,
            foreign_qr_found=foreign_found,
        )

    # ------------------------------------------------------------------ #

    @staticmethod
    def _to_array(variant: ImageVariant) -> np.ndarray | None:
        """Decode variant PNG bytes. Returns None rather than raising.

        A variant that will not decode is a skipped variant, not a failed run —
        the next one may well work.
        """
        try:
            buffer = np.frombuffer(variant.data, dtype=np.uint8)
            return cv2.imdecode(buffer, cv2.IMREAD_GRAYSCALE)
        except Exception:
            return None

    @property
    def decoder_names(self) -> list[str]:
        return [d.name for d in self.decoders]
