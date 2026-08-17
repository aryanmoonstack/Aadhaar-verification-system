"""QR decoder backends — Step 5.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 5
Provides : Decoder protocol, ZxingDecoder, WeChatDecoder, ZbarDecoder,
           OpenCvDecoder, available_decoders()
Consumes : OpenCV, zxing-cpp, pyzbar (all optional at runtime)
Used by  : avs.qr.cascade

WHY FOUR DECODERS AND NOT ONE
-----------------------------
The Aadhaar Secure QR is a version-20-plus symbol: roughly 100x100 modules
carrying a 1,500–4,000 digit payload. That density is where QR libraries diverge
sharply. A code one library reads instantly, another cannot find at all —
particularly when the capture is blurred, tilted, or unevenly lit.

Running several decoders over the same image is cheap relative to generating
another preprocessing variant, so the cascade exhausts every available decoder on
a variant before asking for the next one.

Order matters. ``zxing-cpp`` is first because it handles dense symbols and
imperfect captures best in practice; OpenCV's built-in detector is last because
it is the weakest on exactly the input we care about, though it is always present.

EVERY DECODER IS OPTIONAL
-------------------------
``pyzbar`` needs a system ``libzbar`` that many hosts lack. The WeChat detector
needs model files shipped with opencv-contrib. Neither is guaranteed, so each
backend reports its own availability and an unavailable one is silently skipped.

Same rule as the AI layer: a missing component degrades the pipeline, it never
breaks it. A deployment with only ``zxing-cpp`` and OpenCV still works.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import cv2
import numpy as np

__all__ = [
    "Decoder",
    "OpenCvDecoder",
    "WeChatDecoder",
    "ZbarDecoder",
    "ZxingDecoder",
    "available_decoders",
    "decoder_availability",
]


@runtime_checkable
class Decoder(Protocol):
    """One QR decoding backend."""

    name: str

    @property
    def available(self) -> bool:
        """False when the backend's dependency is missing on this host."""
        ...

    def decode(self, image: np.ndarray) -> list[str]:
        """Return every QR payload found. Empty list when none. Never raises."""
        ...


# --------------------------------------------------------------------------- #


class ZxingDecoder:
    """zxing-cpp. First in the cascade — strongest on dense, imperfect symbols."""

    name = "zxing-cpp"

    def __init__(self) -> None:
        try:
            import zxingcpp

            self._zxing = zxingcpp
        except ImportError:
            self._zxing = None

    @property
    def available(self) -> bool:
        return self._zxing is not None

    def decode(self, image: np.ndarray) -> list[str]:
        if self._zxing is None:
            return []
        try:
            results = self._zxing.read_barcodes(image)
        except Exception:
            return []
        return [r.text for r in results if r.text]


class WeChatDecoder:
    """OpenCV's WeChat detector. Strong on damaged and partially occluded codes.

    Needs opencv-contrib plus four downloaded model files, so it is frequently
    unavailable. When present it recovers captures the others miss.
    """

    name = "opencv-wechat"

    def __init__(self, model_dir: str | None = None) -> None:
        self._detector = None
        factory = getattr(cv2, "wechat_qrcode_WeChatQRCode", None)
        if factory is None:
            return
        try:
            if model_dir:
                self._detector = factory(
                    f"{model_dir}/detect.prototxt",
                    f"{model_dir}/detect.caffemodel",
                    f"{model_dir}/sr.prototxt",
                    f"{model_dir}/sr.caffemodel",
                )
            else:
                self._detector = factory()
        except Exception:
            self._detector = None

    @property
    def available(self) -> bool:
        return self._detector is not None

    def decode(self, image: np.ndarray) -> list[str]:
        if self._detector is None:
            return []
        try:
            texts, _ = self._detector.detectAndDecode(image)
        except Exception:
            return []
        return [t for t in texts if t]


class ZbarDecoder:
    """pyzbar / libzbar. Fast, but weaker on very dense symbols.

    Requires a system ``libzbar`` shared library that many hosts — including
    default Windows installs — do not have.
    """

    name = "pyzbar"

    def __init__(self) -> None:
        try:
            from pyzbar import pyzbar

            self._pyzbar = pyzbar
        except Exception:
            self._pyzbar = None

    @property
    def available(self) -> bool:
        return self._pyzbar is not None

    def decode(self, image: np.ndarray) -> list[str]:
        if self._pyzbar is None:
            return []
        try:
            results = self._pyzbar.decode(image)
        except Exception:
            return []
        payloads = []
        for result in results:
            try:
                payloads.append(result.data.decode("utf-8"))
            except UnicodeDecodeError:
                continue
        return payloads


class OpenCvDecoder:
    """OpenCV's built-in detector. Always available; weakest on dense symbols.

    Last in the cascade. Kept because it costs nothing to try and occasionally
    succeeds where the others have already failed.
    """

    name = "opencv"

    def __init__(self) -> None:
        self._detector = cv2.QRCodeDetector()

    @property
    def available(self) -> bool:
        return True

    def decode(self, image: np.ndarray) -> list[str]:
        try:
            ok, texts, _, _ = self._detector.detectAndDecodeMulti(image)
            if ok and texts:
                return [t for t in texts if t]
        except Exception:  # noqa: S110 - multi-decode is a best-effort first try;
            pass  # the single-code path below is the real attempt
        try:
            text, _, _ = self._detector.detectAndDecode(image)
            return [text] if text else []
        except Exception:
            return []


# --------------------------------------------------------------------------- #

#: Cascade order — most capable on dense, imperfect symbols first.
_DECODER_ORDER: tuple[type, ...] = (
    ZxingDecoder,
    WeChatDecoder,
    ZbarDecoder,
    OpenCvDecoder,
)


def available_decoders() -> list[Decoder]:
    """Instantiate every backend and return those usable on this host.

    Constructed once and reused — creating a detector is not free, and the
    cascade calls them repeatedly.
    """
    return [d for d in (cls() for cls in _DECODER_ORDER) if d.available]


def decoder_availability() -> dict[str, bool]:
    """Which backends are usable here. For ``avs doctor`` and the readiness probe."""
    return {d.name: d.available for d in (cls() for cls in _DECODER_ORDER)}
