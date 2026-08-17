"""Variant generation — Step 4.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 4
Provides : PreprocessingVariantGenerator (implements avs.contracts.VariantGenerator)
Consumes : avs.contracts, avs.imaging.ops, avs.imaging.strategy, OpenCV
Used by  : avs.qr (Step 5)

LAZINESS IS THE POINT
---------------------
Generation yields one variant at a time, cheapest tier first, and the Step 5
cascade stops at the first successful decode. A well-lit photo therefore costs
one or two variants; only a genuinely difficult capture pays for the full matrix.

Doing it eagerly would mean encoding ~22 variants of a 12 MP photo — several
hundred megabytes and a second or more of CPU — to use the first one. Contract
1.1.0 widened the return type to ``Iterable`` specifically to allow this.

TWO SEAMS ARE ALREADY WIRED
---------------------------
* ``quality`` (Step 14) narrows the strategy set to those addressing the
  problems the model actually detected.
* ``region`` (Step 15) crops to the located QR before any processing, which both
  speeds everything up and makes thresholding far more accurate — a threshold
  computed over a whole desk is worse than one computed over the code itself.

Neither is required. With both ``None`` the generator runs the full
deterministic matrix over the whole image, which is the Step 4 behaviour.
"""

from __future__ import annotations

from collections.abc import Iterator

import cv2
import numpy as np

from avs.contracts import ImageVariant, QrRegion, QualityScores, ValidatedImage
from avs.imaging import ops
from avs.imaging.errors import ImagingError
from avs.imaging.strategy import Strategy, select_strategies

__all__ = ["PreprocessingVariantGenerator"]


class PreprocessingVariantGenerator:
    """Yields preprocessed variants of an image, cheapest first."""

    def __init__(
        self,
        *,
        max_tier: int = 4,
        limit: int | None = None,
        enable_warp: bool = True,
        rotations: tuple[int, ...] = (),
        working_max_edge: int = 1_500,
        target_qr_edge: int = 520,
        min_working_edge: int = 900,
        scout_edge: int = 1_400,
        qr_context: float = 0.60,
        region_padding: float = 0.15,
    ) -> None:
        """
        Args:
            max_tier: skip strategies above this cost tier.
            limit: hard cap on variants yielded.
            enable_warp: attempt document boundary detection and perspective
                correction. Disable to skip tier 3 entirely.
            rotations: extra 90° rotations to try after all strategies.
                **Empty by default, deliberately** — QR finder patterns are
                rotation-invariant, so every decoder in the Step 5 cascade already
                handles a sideways code. EXIF orientation is applied in Step 3.
                This exists only as an escape hatch if a decoder is found that
                needs it; enabling it multiplies the work for close to no gain.
            working_max_edge: fallback cap used ONLY when no QR can be located.
                Aggressive on purpose. ``ops.find_qr_region`` is measurably MORE
                sensitive than the decoder — it finds codes at 57px that zxing
                cannot read, and across the degradation matrix it never missed
                one zxing could read. So "nothing located" means there is almost
                certainly nothing to decode, and the right response is to fail
                FAST rather than spend 50s proving a negative at 12MP.
            target_qr_edge: when the QR IS located, scale so its short side lands
                here. 520px over a ~97-module symbol is ~5.4 px/module, comfortably
                above the ~3 px floor, and makes every downstream op ~5x cheaper.
            min_working_edge: floor for the whole-frame fallback path.
            scout_edge: resolution at which the QR is LOCATED. Searching a 12MP
                frame costs ~1s; searching a 1400px copy costs ~0.1s and finds
                the same finder patterns, which are large features.
            qr_context: how much surrounding card to keep around the located QR,
                as a fraction of its size. Not zero — the decoder needs a quiet
                zone and the warp strategies need a document outline.
            region_padding: fraction of the region size to add as margin when a
                QR region is supplied. Decoders need the quiet zone around a code.
        """
        self.max_tier = max_tier
        self.limit = limit
        self.enable_warp = enable_warp
        self.rotations = rotations
        self.working_max_edge = working_max_edge
        self.target_qr_edge = target_qr_edge
        self.min_working_edge = min_working_edge
        self.scout_edge = scout_edge
        self.qr_context = qr_context
        self.region_padding = region_padding

    # ------------------------------------------------------------------ #

    def generate(
        self,
        image: ValidatedImage,
        region: QrRegion | None = None,
        quality: QualityScores | None = None,
    ) -> Iterator[ImageVariant]:
        """Yield preprocessed variants, cheapest tier first.

        Raises:
            ImagingError: only if the input cannot be decoded at all. Individual
                strategies that fail are skipped, not fatal — one broken recipe
                must not deny the decoder the other twenty.
        """
        full = self._decode(image)

        if region is not None:
            full = self._crop_to_region(full, region)

        source = self._fit_working_size(full)

        # ⛔ SAFETY NET — cropping must never LOSE a decode.
        #
        #   `_fit_working_size` crops to a located QR, and localisation can be
        #   wrong. On the real corpus one image that decoded fine from the
        #   untouched frame stopped decoding once we cropped: the box was in the
        #   wrong place, so the QR was thrown away before any decoder saw it.
        #
        #   Speed is not worth a regression. If the working image differs from
        #   the original, the untouched frame is offered as well. It goes SECOND
        #   because the cropped version is both cheaper and more likely to
        #   succeed — but it is always offered, so the new path can only ever
        #   add decodes, never remove them.
        cropped = source.shape[:2] != full.shape[:2]

        warped: np.ndarray | None = None
        if self.enable_warp:
            quad = ops.find_document_quad(source)
            if quad is not None:
                warped = ops.warp_to_quad(source, quad)

        strategies = select_strategies(quality, max_tier=self.max_tier, limit=self.limit)

        yielded = 0
        for index, strategy in enumerate(strategies):
            if strategy.needs_warp and warped is None:
                # No quadrilateral found — the card probably already fills the
                # frame. Nothing to correct, so skip rather than warp garbage.
                continue

            base = warped if strategy.needs_warp else source
            variant = self._build(strategy, base, rotation=0)
            if variant is not None:
                yielded += 1
                yield variant
                if self.limit and yielded >= self.limit:
                    return

            # Immediately after the first (cheapest) strategy, offer the same
            # recipe on the UNCROPPED frame. One extra decode buys immunity to
            # a mislocated QR.
            if index == 0 and cropped:
                fallback = self._build(strategy, full, rotation=0)
                if fallback is not None:
                    yielded += 1
                    yield fallback
                    if self.limit and yielded >= self.limit:
                        return

        for degrees in self.rotations:
            if degrees == 0:
                continue
            rotated = ops.rotate(source, degrees)
            for strategy in (s for s in strategies if s.tier == 0 and not s.needs_warp):
                variant = self._build(strategy, rotated, rotation=degrees)
                if variant is not None:
                    yielded += 1
                    yield variant
                    if self.limit and yielded >= self.limit:
                        return

    # ------------------------------------------------------------------ #

    @staticmethod
    def _decode(image: ValidatedImage) -> np.ndarray:
        buffer = np.frombuffer(image.data, dtype=np.uint8)
        decoded = cv2.imdecode(buffer, cv2.IMREAD_COLOR)
        if decoded is None:
            raise ImagingError(
                f"could not decode {image.mime_type} image "
                f"({image.width}x{image.height}, {len(image.data)} bytes)"
            )
        return decoded

    def _crop_to_region(self, image: np.ndarray, region: QrRegion) -> np.ndarray:
        """Crop to a located QR, with padding for the quiet zone.

        QR decoding requires a clear margin around the symbol. Cropping exactly
        to a detected bounding box removes it and can make an otherwise readable
        code fail, so we deliberately over-crop.
        """
        height, width = image.shape[:2]
        pad_x = int(region.width * self.region_padding)
        pad_y = int(region.height * self.region_padding)

        left = max(0, region.x - pad_x)
        top = max(0, region.y - pad_y)
        right = min(width, region.x + region.width + pad_x)
        bottom = min(height, region.y + region.height + pad_y)

        if right - left < 20 or bottom - top < 20:
            return image  # implausible region — fall back to the whole image
        return image[top:bottom, left:right]

    def _fit_working_size(self, image: np.ndarray) -> np.ndarray:
        """Size the working image to the QR, not to an arbitrary pixel cap.

        ⛔ THIS IS THE STEP-4 BUG THAT COST US THE REAL DECODE RATE.

           The old rule was "downscale only above 4000px", justified by the fear
           that shrinking a dense QR drops it below the ~3 px-per-module floor.
           The fear was right; the remedy was not. Phone photos are 4032px, so
           in practice **nothing was ever downscaled**, and every strategy ran on
           12 megapixels.

           Measured cost per variant on a 12MP frame with no readable QR:

               generate 0.82s + zxing decode 1.81s  =  2.63s

           zxing is slow precisely when it FAILS, because it searches the whole
           frame before giving up. At 2.63s a variant, a 12s budget buys 4-6 of
           the 23 strategies. Seventeen never ran. That is why the corpus showed
           every success coming from `original` at index 1: nothing else was
           ever reached.

           At 1800px the same work costs 0.48s a variant — all 23 strategies fit
           in under 9s.

        So: locate the QR first, then scale so the QR lands at
        ``target_qr_edge`` pixels. That keeps roughly 8 px per module — well
        above the floor — while making everything downstream 5x cheaper. When
        the QR cannot be found we fall back to a conservative cap, because an
        image with no locatable QR is exactly the one we must not shrink into
        oblivion.
        """
        height, width = image.shape[:2]
        longest = max(height, width)

        # Scout on a cheap copy. Locating costs ~1s at 12MP and ~0.1s at 1400px,
        # and finder patterns are large features that survive the downscale
        # intact — so there is no reason to pay full price for the search.
        scout_scale = min(1.0, self.scout_edge / longest)
        scout = (
            image
            if scout_scale >= 0.999
            else cv2.resize(
                image,
                (max(1, int(width * scout_scale)), max(1, int(height * scout_scale))),
                interpolation=cv2.INTER_AREA,
            )
        )

        box = ops.find_qr_region(scout)
        if box is not None:
            x, y, w, h = (int(v / scout_scale) for v in box)

            # Crop generously rather than tightly. The decoder needs the quiet
            # zone, and the warp strategies need enough surrounding card to find
            # a document outline — cropping to the bare symbol would silently
            # disable tier 3.
            pad_x, pad_y = int(w * self.qr_context), int(h * self.qr_context)
            left, top = max(0, x - pad_x), max(0, y - pad_y)
            right, bottom = min(width, x + w + pad_x), min(height, y + h + pad_y)
            cropped = image[top:bottom, left:right]

            if cropped.size and min(cropped.shape[:2]) >= 40:
                qr_edge = min(w, h)
                if qr_edge > self.target_qr_edge:
                    scale = self.target_qr_edge / qr_edge
                    return cv2.resize(
                        cropped,
                        (
                            max(1, int(cropped.shape[1] * scale)),
                            max(1, int(cropped.shape[0] * scale)),
                        ),
                        interpolation=cv2.INTER_AREA,
                    )
                return cropped

        # Nothing located. The localiser is more sensitive than the decoder, so
        # this frame almost certainly holds no readable QR — cap it hard and let
        # the attempt fail in seconds instead of a minute.
        if longest <= self.working_max_edge:
            return image
        scale = self.working_max_edge / longest
        return cv2.resize(
            image,
            (int(width * scale), int(height * scale)),
            interpolation=cv2.INTER_AREA,
        )

    @staticmethod
    def _build(strategy: Strategy, image: np.ndarray, rotation: int) -> ImageVariant | None:
        """Apply one strategy and encode. Returns None if the recipe fails.

        A strategy failing is not exceptional — ``adaptive_threshold`` on a
        degenerate image, ``inpaint`` on an all-white frame, and similar edge
        cases legitimately raise. Skipping that recipe and continuing is right;
        aborting the whole pipeline over it is not.
        """
        try:
            processed = strategy.apply(image)
            return ImageVariant(
                data=ops.encode_png(processed),
                strategy=strategy.name,
                rotation=rotation,
            )
        except (cv2.error, ValueError, ZeroDivisionError):
            return None
