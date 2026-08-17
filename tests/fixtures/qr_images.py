"""Synthetic Aadhaar-like card images with real Secure QR codes — fixtures only.

⛔ NOT PRODUCTION CODE. No real Aadhaar is ever used.

WHY THIS EXISTS
---------------
Step 5's decode rate is the project's primary metric, and it cannot be measured
without images that contain a genuinely dense QR under realistic degradation.

These fixtures render an *actual* Secure-QR-sized payload (1,500–4,000 digits,
producing a ~100x100 module symbol — the same density as a real card) onto a
card-shaped image, then degrade it in the ways real phone photos are degraded.

That gives a measurable, repeatable baseline today, and a controlled way to
attribute later improvements: when Step 15's localiser lands, the same sweep
re-run tells us exactly how much it moved which failure mode.

It is not a substitute for the real-card corpus. Real captures have sensor
characteristics, printing artefacts and lighting that no simulation reproduces.
It *is* a substitute for having nothing to measure.
"""

from __future__ import annotations

import io

import cv2
import numpy as np
import segno

__all__ = [
    "DEGRADATIONS",
    "add_glare",
    "add_noise",
    "apply_perspective",
    "blur",
    "downscale",
    "encode_jpeg",
    "jpeg_artifacts",
    "reduce_contrast",
    "render_card",
    "render_qr",
]


def render_qr(payload: str, scale: int = 6, border: int = 4) -> np.ndarray:
    """Render a payload as a QR image.

    A Secure-QR-sized payload produces roughly a 100x100 module symbol, so
    ``scale`` is directly pixels-per-module — the quantity that actually
    determines whether a decoder succeeds.
    """
    qr = segno.make(payload, error="m")
    buffer = io.BytesIO()
    qr.save(buffer, kind="png", scale=scale, border=border)
    image = cv2.imdecode(np.frombuffer(buffer.getvalue(), np.uint8), cv2.IMREAD_GRAYSCALE)
    return cv2.cvtColor(image, cv2.COLOR_GRAY2BGR)


def render_card(
    payload: str,
    *,
    width: int = 1600,
    height: int = 1000,
    qr_scale: int = 5,
    qr_fraction: float = 0.42,
) -> np.ndarray:
    """Place a QR on a card-shaped image with text-like blocks beside it.

    Mirrors the back of an Aadhaar card: address text on the left, Secure QR on
    the right. ``qr_fraction`` controls how much of the card height the code
    occupies — the single biggest driver of decode success in real photos, since
    it determines pixels per module.
    """
    card = np.full((height, width, 3), 246, dtype=np.uint8)

    # Text-like blocks, so the frame is not a QR floating in white. Detectors
    # behave differently when there is competing structure in the image.
    rng = np.random.default_rng(7)
    y = int(height * 0.18)
    while y < int(height * 0.82):
        line_width = int(width * 0.42 * rng.uniform(0.5, 1.0))
        cv2.rectangle(
            card,
            (int(width * 0.06), y),
            (int(width * 0.06) + line_width, y + 14),
            (90, 90, 90),
            thickness=-1,
        )
        y += 42

    qr = render_qr(payload, scale=qr_scale)
    target = int(height * qr_fraction)
    qr = cv2.resize(qr, (target, target), interpolation=cv2.INTER_NEAREST)

    x0 = int(width * 0.62)
    y0 = (height - target) // 2
    card[y0 : y0 + target, x0 : x0 + target] = qr

    cv2.rectangle(card, (0, 0), (width - 1, height - 1), (150, 150, 150), 3)
    return card


# --------------------------------------------------------------------------- #
# Degradations — each mirrors a specific real-world failure mode
# --------------------------------------------------------------------------- #


def blur(image: np.ndarray, sigma: float = 2.0) -> np.ndarray:
    """Defocus or motion blur — smears module edges together."""
    if sigma <= 0:
        return image
    kernel = int(sigma * 6) | 1
    return cv2.GaussianBlur(image, (kernel, kernel), sigma)


def add_noise(image: np.ndarray, sigma: float = 15.0) -> np.ndarray:
    """Sensor noise, as produced by a dim room without flash."""
    if sigma <= 0:
        return image
    rng = np.random.default_rng(11)
    noisy = image.astype(np.float32) + rng.normal(0, sigma, image.shape)
    return np.clip(noisy, 0, 255).astype(np.uint8)


def reduce_contrast(image: np.ndarray, factor: float = 0.4) -> np.ndarray:
    """Grey-on-grey capture — modules barely separate from the background."""
    mean = image.mean()
    return np.clip((image.astype(np.float32) - mean) * factor + mean, 0, 255).astype(np.uint8)


def add_glare(image: np.ndarray, intensity: float = 0.8, radius: float = 0.28) -> np.ndarray:
    """A specular highlight over part of the code — a lamp or window reflection."""
    height, width = image.shape[:2]
    centre = (int(width * 0.72), int(height * 0.45))  # lands on the QR
    yy, xx = np.mgrid[0:height, 0:width]
    distance = np.sqrt((xx - centre[0]) ** 2 + (yy - centre[1]) ** 2)
    falloff = np.exp(-((distance / (min(height, width) * radius)) ** 2))
    hotspot = (falloff * intensity * 255).astype(np.float32)
    if image.ndim == 3:
        hotspot = np.dstack([hotspot] * 3)
    return np.clip(image.astype(np.float32) + hotspot, 0, 255).astype(np.uint8)


def apply_perspective(image: np.ndarray, strength: float = 0.15) -> np.ndarray:
    """Card photographed at an angle — the QR becomes a trapezoid."""
    height, width = image.shape[:2]
    shift = int(min(height, width) * strength)
    source = np.float32([[0, 0], [width, 0], [width, height], [0, height]])
    destination = np.float32(
        [[shift, shift // 2], [width - shift // 2, 0], [width, height], [0, height - shift // 2]]
    )
    matrix = cv2.getPerspectiveTransform(source, destination)
    return cv2.warpPerspective(image, matrix, (width, height), borderValue=(210, 210, 210))


def downscale(image: np.ndarray, factor: float = 0.5) -> np.ndarray:
    """Photographed from too far away — too few pixels per module."""
    if factor >= 1.0:
        return image
    height, width = image.shape[:2]
    small = cv2.resize(
        image, (int(width * factor), int(height * factor)), interpolation=cv2.INTER_AREA
    )
    return small


def jpeg_artifacts(image: np.ndarray, quality: int = 35) -> np.ndarray:
    """Heavy JPEG compression — block ringing lands right on module edges."""
    ok, buffer = cv2.imencode(".jpg", image, [cv2.IMWRITE_JPEG_QUALITY, quality])
    if not ok:
        return image
    return cv2.imdecode(buffer, cv2.IMREAD_COLOR)


def encode_jpeg(image: np.ndarray, quality: int = 92) -> bytes:
    """Encode as JPEG bytes, ready to hand to ``ImageIngestor``."""
    ok, buffer = cv2.imencode(".jpg", image, [cv2.IMWRITE_JPEG_QUALITY, quality])
    if not ok:  # pragma: no cover
        raise ValueError("JPEG encoding failed")
    return bytes(buffer)


#: Named degradation levels for the benchmark sweep. Each is (label, transform).
DEGRADATIONS: dict[str, list[tuple[str, object]]] = {
    "clean": [("none", lambda im: im)],
    "blur": [
        ("blur_1.0", lambda im: blur(im, 1.0)),
        ("blur_2.0", lambda im: blur(im, 2.0)),
        ("blur_3.5", lambda im: blur(im, 3.5)),
    ],
    "noise": [
        ("noise_10", lambda im: add_noise(im, 10.0)),
        ("noise_25", lambda im: add_noise(im, 25.0)),
        ("noise_40", lambda im: add_noise(im, 40.0)),
    ],
    "contrast": [
        ("contrast_0.5", lambda im: reduce_contrast(im, 0.5)),
        ("contrast_0.3", lambda im: reduce_contrast(im, 0.3)),
        ("contrast_0.15", lambda im: reduce_contrast(im, 0.15)),
    ],
    "glare": [
        ("glare_0.5", lambda im: add_glare(im, 0.5)),
        ("glare_0.8", lambda im: add_glare(im, 0.8)),
        ("glare_1.1", lambda im: add_glare(im, 1.1)),
    ],
    "perspective": [
        ("persp_0.10", lambda im: apply_perspective(im, 0.10)),
        ("persp_0.20", lambda im: apply_perspective(im, 0.20)),
        ("persp_0.30", lambda im: apply_perspective(im, 0.30)),
    ],
    "resolution": [
        ("scale_0.60", lambda im: downscale(im, 0.60)),
        ("scale_0.45", lambda im: downscale(im, 0.45)),
        ("scale_0.35", lambda im: downscale(im, 0.35)),
    ],
    "compression": [
        ("jpeg_50", lambda im: jpeg_artifacts(im, 50)),
        ("jpeg_30", lambda im: jpeg_artifacts(im, 30)),
        ("jpeg_15", lambda im: jpeg_artifacts(im, 15)),
    ],
    "combined": [
        ("blur+noise", lambda im: add_noise(blur(im, 1.5), 20.0)),
        ("persp+contrast", lambda im: reduce_contrast(apply_perspective(im, 0.18), 0.45)),
        ("glare+blur", lambda im: blur(add_glare(im, 0.7), 1.5)),
        ("far+blur+noise", lambda im: add_noise(blur(downscale(im, 0.55), 1.2), 15.0)),
    ],
}
