"""Image operations — Step 4. Pure functions on numpy arrays.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 4
Provides : the individual preprocessing operations
Consumes : OpenCV, numpy
Used by  : avs.imaging.strategy, avs.imaging.generator

Every function here takes an array and returns an array. No I/O, no state, no
exceptions for ordinary input — an operation that cannot improve an image
returns it unchanged rather than failing.

WHAT THESE OPERATIONS ARE FOR
-----------------------------
The Aadhaar Secure QR is a very dense symbol. Decoding it from a phone photo
fails for four reasons, and each operation below targets one:

* **Perspective** — the card was photographed at an angle, so the QR is a
  trapezoid rather than a square.
* **Illumination** — a lamp or window creates a bright patch that saturates part
  of the code, or the card is lit unevenly across its face.
* **Contrast** — a grey-on-grey capture where the modules barely separate from
  the background.
* **Resolution and blur** — too few pixels per QR module, or motion blur
  smearing the module edges together.

⚠ NOTHING HERE MAY BE LOSSY IN A WAY THAT DAMAGES MODULE EDGES.
  A QR module edge is a single-pixel transition. Aggressive denoising, JPEG
  re-encoding, or bilinear downscaling all blur that transition and can turn a
  decodable code into an undecodable one. Variants are therefore encoded as PNG,
  and any smoothing is edge-preserving.
"""

from __future__ import annotations

import cv2
import numpy as np

__all__ = [
    "adaptive_threshold",
    "clahe",
    "denoise",
    "encode_png",
    "estimate_blur",
    "estimate_glare_fraction",
    "find_document_quad",
    "normalise_illumination",
    "otsu_threshold",
    "rotate",
    "suppress_glare",
    "to_grayscale",
    "unsharp_mask",
    "upscale",
    "warp_to_quad",
]


# --------------------------------------------------------------------------- #
# Basics
# --------------------------------------------------------------------------- #


def to_grayscale(image: np.ndarray) -> np.ndarray:
    """Collapse to a single channel. QR decoding is a luminance problem."""
    if image.ndim == 2:
        return image
    if image.shape[2] == 4:
        return cv2.cvtColor(image, cv2.COLOR_BGRA2GRAY)
    return cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)


def encode_png(image: np.ndarray) -> bytes:
    """Encode losslessly.

    PNG, never JPEG. JPEG's 8x8 block transform introduces ringing exactly at the
    high-contrast edges that define QR modules — re-encoding a variant as JPEG can
    make a decodable code undecodable.
    """
    ok, buffer = cv2.imencode(".png", image, [cv2.IMWRITE_PNG_COMPRESSION, 1])
    if not ok:  # pragma: no cover - OpenCV failing to encode a valid array
        raise ValueError("PNG encoding failed")
    return bytes(buffer)


# --------------------------------------------------------------------------- #
# Contrast and illumination
# --------------------------------------------------------------------------- #


def clahe(image: np.ndarray, clip_limit: float = 2.5, tile: int = 8) -> np.ndarray:
    """Contrast Limited Adaptive Histogram Equalisation.

    Plain histogram equalisation works on the whole frame, so a bright window in
    one corner drags the entire image. CLAHE equalises within tiles, which is
    what a photograph of a card on a desk actually needs. The clip limit stops it
    amplifying sensor noise into false modules.
    """
    gray = to_grayscale(image)
    return cv2.createCLAHE(clipLimit=clip_limit, tileGridSize=(tile, tile)).apply(gray)


def normalise_illumination(image: np.ndarray, kernel: int = 51) -> np.ndarray:
    """Flat-field correction: divide by a heavily blurred copy of itself.

    The blurred copy approximates the lighting across the frame. Dividing it out
    leaves the card's own reflectance, which is what we want to threshold. This
    is the single most effective operation for the common case of a card lit from
    one side, or photographed under a ceiling light that brightens the middle.
    """
    gray = to_grayscale(image).astype(np.float32)
    background = cv2.GaussianBlur(gray, (kernel | 1, kernel | 1), 0)
    background[background < 1.0] = 1.0
    corrected = (gray / background) * 128.0
    return np.clip(corrected, 0, 255).astype(np.uint8)


def suppress_glare(
    image: np.ndarray,
    threshold: int = 240,
    min_blob_fraction: float = 0.005,
) -> np.ndarray:
    """Inpaint blown-out highlights.

    A specular reflection saturates pixels to pure white, destroying the modules
    underneath. Inpainting cannot recover them, but it stops the white patch
    dominating a subsequent threshold and lets the surrounding modules resolve —
    and QR error correction can often cope with the lost area.

    ⚠ Glare means a *contiguous* blown-out region, not merely bright pixels.
      A photo of a white card legitimately contains many pixels above 240, and a
      noisy sensor scatters them everywhere. Inpainting those is pure damage.

      So the mask is morphologically opened first, which erases isolated bright
      pixels and leaves only real blobs. If what survives is negligible, the
      image is returned untouched.
    """
    gray = to_grayscale(image)
    mask = (gray >= threshold).astype(np.uint8)

    # Opening removes scattered bright pixels; only cohesive blobs survive.
    mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, np.ones((7, 7), np.uint8))

    if mask.sum() < gray.size * min_blob_fraction:
        return gray

    mask = cv2.dilate(mask, np.ones((5, 5), np.uint8), iterations=1)
    return cv2.inpaint(gray, mask, inpaintRadius=3, flags=cv2.INPAINT_TELEA)


# --------------------------------------------------------------------------- #
# Resolution and sharpness
# --------------------------------------------------------------------------- #


def upscale(image: np.ndarray, factor: float = 2.0) -> np.ndarray:
    """Enlarge with cubic interpolation.

    Below roughly 3 pixels per QR module, decoders fail regardless of contrast.
    Upscaling adds no information but gives the decoder's sub-pixel sampling more
    room to work, which in practice recovers a meaningful share of marginal
    captures. Cubic preserves edges better than linear.
    """
    if factor <= 1.0:
        return image
    height, width = image.shape[:2]
    return cv2.resize(
        image,
        (int(width * factor), int(height * factor)),
        interpolation=cv2.INTER_CUBIC,
    )


def unsharp_mask(image: np.ndarray, amount: float = 1.5, radius: int = 3) -> np.ndarray:
    """Sharpen by subtracting a blurred copy.

    Counteracts mild defocus and the softening introduced by upscaling. Too much
    amount creates ringing that reads as spurious modules, so the default is
    deliberately modest.
    """
    gray = to_grayscale(image)
    blurred = cv2.GaussianBlur(gray, (radius | 1, radius | 1), 0)
    return cv2.addWeighted(gray, 1.0 + amount, blurred, -amount, 0)


def denoise(image: np.ndarray, diameter: int = 5) -> np.ndarray:
    """Bilateral filter — smooths flat areas while preserving edges.

    Deliberately *not* ``fastNlMeansDenoising``: it is an order of magnitude
    slower and smooths across module boundaries, which is precisely the
    information we need to keep.
    """
    gray = to_grayscale(image)
    return cv2.bilateralFilter(gray, diameter, sigmaColor=50, sigmaSpace=50)


# --------------------------------------------------------------------------- #
# Binarisation
# --------------------------------------------------------------------------- #


def otsu_threshold(image: np.ndarray) -> np.ndarray:
    """Global threshold at the automatically chosen optimum.

    Works well on evenly lit scans; fails on photographs with a lighting
    gradient, which is why ``adaptive_threshold`` exists alongside it.
    """
    gray = to_grayscale(image)
    _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    return binary


def adaptive_threshold(image: np.ndarray, block: int = 31, constant: int = 5) -> np.ndarray:
    """Per-neighbourhood threshold. The right tool for uneven lighting.

    ``block`` must be odd and should comfortably exceed one QR module, or the
    threshold tracks the modules themselves and erases the pattern.
    """
    gray = to_grayscale(image)
    return cv2.adaptiveThreshold(
        gray,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        block | 1,
        constant,
    )


# --------------------------------------------------------------------------- #
# Geometry
# --------------------------------------------------------------------------- #


def rotate(image: np.ndarray, degrees: int) -> np.ndarray:
    """Rotate by a multiple of 90° with no resampling."""
    normalised = degrees % 360
    if normalised == 0:
        return image
    if normalised == 90:
        return cv2.rotate(image, cv2.ROTATE_90_CLOCKWISE)
    if normalised == 180:
        return cv2.rotate(image, cv2.ROTATE_180)
    if normalised == 270:
        return cv2.rotate(image, cv2.ROTATE_90_COUNTERCLOCKWISE)
    raise ValueError(f"only multiples of 90 are supported, got {degrees}")


#: Distance between adjacent finder-pattern centres, in marker widths.
#:
#: ⛔ Derived from QR geometry, not tuned: for an N-module code the leg is
#:    (N - 7) modules and a finder pattern is 7, so the ratio is (N - 7) / 7.
#:    These bounds span roughly versions 7 to 30. Aadhaar's Secure QR is
#:    version 21-22, landing at 12.9-13.4.
MIN_LEG_TO_MARKER = 5.0
MAX_LEG_TO_MARKER = 20.0


def find_qr_region(image: np.ndarray, min_marker: int = 6) -> tuple[int, int, int, int] | None:
    """Locate a QR by its three finder patterns. Returns (x, y, w, h) or None.

    ⛔ WHY THIS IS NOT ``cv2.QRCodeDetector``
       That detector cannot locate a dense Secure QR — it fails even on a
       pristine synthetic one. Measured, not assumed; see
       ``tests/unit/test_imaging.py::test_find_qr_region_*``.

    Every QR carries three finder patterns: concentric squares in a 1:1:3:1:1
    ratio at three of its corners. Under ``RETR_TREE`` each appears as a contour
    nested at least two deep and roughly square. Three of those whose centres
    form a **right isoceles triangle** is a QR — that geometric constraint is
    what separates a real code from three unrelated boxes on a card, and without
    it the detector happily merges card features into a region covering most of
    the frame.

    Crucially this works on codes too small or too degraded to DECODE, which is
    what lets the caller size its working image to the QR instead of guessing.
    """
    best: tuple[int, int, int, int] | None = None
    best_marker = 0.0

    for block in (31, 61, 101):
        try:
            binary = cv2.adaptiveThreshold(
                to_grayscale(image),
                255,
                cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY,
                block,
                5,
            )
            contours, hierarchy = cv2.findContours(binary, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
        except cv2.error:
            continue
        if hierarchy is None:
            continue

        hierarchy = hierarchy[0]
        markers: list[tuple[int, int, int, int]] = []
        for index, contour in enumerate(contours):
            depth, parent = 0, hierarchy[index][3]
            while parent != -1 and depth < 6:
                depth += 1
                parent = hierarchy[parent][3]
            if depth < 2:
                continue
            x, y, w, h = cv2.boundingRect(contour)
            if w < min_marker or h < min_marker or not (0.6 < w / h < 1.6):
                continue
            if cv2.contourArea(contour) < 0.4 * w * h:
                continue
            markers.append((x, y, w, h))

        if len(markers) < 3:
            continue

        markers.sort(key=lambda m: m[2] * m[3])
        for i in range(len(markers) - 2):
            trio = markers[i : i + 3]
            sizes = [m[2] for m in trio]
            if max(sizes) > 2.2 * min(sizes) or not _is_finder_triangle(trio):
                continue
            xs = [m[0] for m in trio] + [m[0] + m[2] for m in trio]
            ys = [m[1] for m in trio] + [m[1] + m[3] for m in trio]
            box = (min(xs), min(ys), max(xs) - min(xs), max(ys) - min(ys))

            if box[2] <= min_marker * 3 or box[3] <= min_marker * 3:
                continue

            # ⛔ A QR IS SQUARE. Measured on a real corpus, this check was absent
            #    and the function returned a 2788x5417 region — aspect 0.51 —
            #    as a "QR". Five of six such regions were non-square, and none
            #    of the six decoded even when cropped and upscaled 4x.
            #
            #    The tolerance allows for perspective: a card photographed at an
            #    angle skews the finder-pattern bounding box, but never to 2:1.
            aspect = box[2] / box[3] if box[3] else 0.0
            if not (0.72 <= aspect <= 1.39):
                continue

            # ⛔ SELECT BY MARKER SIZE, NOT BOX SIZE. Both alternatives were
            #    tried against real images and both failed:
            #
            #      largest box  -> a phantom spanning the whole card always
            #                      beats the real QR (the original bug; every
            #                      corpus px_per_module inflated ~3x)
            #      smallest box -> tiny noise contours always beat the real QR
            #                      (measured: an 86x86 region returned for a
            #                      700px code)
            #
            #    Box size is simply not the discriminator. FINDER PATTERN size
            #    is: a real QR's markers are substantial, while the contours
            #    that coincidentally line up are specks. Among candidates that
            #    already satisfy the geometry and squareness constraints, the
            #    one with the biggest markers is the real code.
            marker_size = min(m[2] for m in trio)
            if marker_size > best_marker:
                best_marker = marker_size
                best = box

    return best


def _is_finder_triangle(trio: list[tuple[int, int, int, int]], tolerance: float = 0.30) -> bool:
    """Do three markers sit at three corners of a square?

    Two equal legs and a hypotenuse of leg x sqrt(2). This single check is what
    stops the detector inventing regions out of ordinary card furniture.
    """
    centres = [(x + w / 2, y + h / 2) for x, y, w, h in trio]
    sides = sorted(
        ((centres[i][0] - centres[j][0]) ** 2 + (centres[i][1] - centres[j][1]) ** 2) ** 0.5
        for i, j in ((0, 1), (1, 2), (0, 2))
    )
    if sides[0] <= 0:
        return False
    if abs(sides[1] - sides[0]) / sides[0] > tolerance:
        return False
    expected = sides[0] * 2**0.5
    if abs(sides[2] - expected) / expected > tolerance:
        return False

    # ⛔ THE CHECK THAT WAS ~9x TOO LOOSE.
    #
    #    This used to be `sides[0] > trio[0][2] * 1.5` — "the markers are more
    #    than 1.5 marker-widths apart". Almost any three small marks on a card
    #    satisfy that, which is why the detector reported a QR in 16 of 19
    #    images that contain none (D136).
    #
    #    QR geometry pins the real value. Finder patterns are 7 modules wide and
    #    their centres sit 3.5 modules in from each edge, so for an N-module code
    #    the leg between adjacent centres is (N - 7) modules::
    #
    #        version 10  ( 57 modules)  leg / marker =  7.1
    #        version 21  ( 97 modules)  leg / marker = 12.9   <- Aadhaar
    #        version 22  (101 modules)  leg / marker = 13.4   <- Aadhaar
    #        version 25  (117 modules)  leg / marker = 15.7
    #
    #    The window below spans roughly QR versions 7 to 30 — permissive enough
    #    for any plausible document code, and still an order of magnitude
    #    tighter than 1.5.
    marker_width = trio[0][2]
    if marker_width <= 0:
        return False
    leg_ratio = sides[0] / marker_width
    return MIN_LEG_TO_MARKER <= leg_ratio <= MAX_LEG_TO_MARKER


def find_document_quad(
    image: np.ndarray,
    min_area_ratio: float = 0.15,
    max_area_ratio: float = 0.95,
) -> np.ndarray | None:
    """Locate the card as a four-cornered shape.

    Returns four corner points, or ``None`` when no plausible quadrilateral is
    found — which is the common case for a tightly cropped photo where the card
    already fills the frame.

    Returning ``None`` rather than guessing matters: a wrong quad produces a
    badly warped image, and warping is one variant among many. Better to skip it
    than to corrupt the input.

    ⚠ ``max_area_ratio`` rejects a quad that covers almost the entire frame.
      Edge detection on a busy or noisy image readily traces the image border
      itself and reports it as a perfect rectangle. Warping to that is a no-op
      at best, and it consumes the tier-3 slot that a genuine correction needed.
      "The document is the whole picture" is not a useful detection.
    """
    gray = to_grayscale(image)
    height, width = gray.shape[:2]
    frame_area = height * width

    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    edges = cv2.Canny(blurred, 50, 150)
    edges = cv2.dilate(edges, np.ones((3, 3), np.uint8), iterations=1)

    contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return None

    for contour in sorted(contours, key=cv2.contourArea, reverse=True)[:5]:
        area = cv2.contourArea(contour)
        if area < frame_area * min_area_ratio:
            break  # sorted by area — everything after this is smaller still
        if area > frame_area * max_area_ratio:
            continue  # this is the image border, not a document
        approximation = cv2.approxPolyDP(contour, 0.02 * cv2.arcLength(contour, True), True)
        if len(approximation) == 4 and cv2.isContourConvex(approximation):
            return approximation.reshape(4, 2).astype(np.float32)
    return None


def _order_corners(points: np.ndarray) -> np.ndarray:
    """Order corners as top-left, top-right, bottom-right, bottom-left."""
    ordered = np.zeros((4, 2), dtype=np.float32)
    coordinate_sum = points.sum(axis=1)
    ordered[0] = points[np.argmin(coordinate_sum)]  # smallest x+y
    ordered[2] = points[np.argmax(coordinate_sum)]  # largest  x+y
    diff = np.diff(points, axis=1)
    ordered[1] = points[np.argmin(diff)]  # smallest y-x
    ordered[3] = points[np.argmax(diff)]  # largest  y-x
    return ordered


def warp_to_quad(image: np.ndarray, quad: np.ndarray) -> np.ndarray:
    """Flatten a four-cornered region into a rectangle.

    This is what turns a photo taken at an angle — where the QR is a trapezoid
    with modules compressed along one edge — into a square-on view the decoder
    can read.
    """
    corners = _order_corners(quad)
    top_left, top_right, bottom_right, bottom_left = corners

    width = int(
        max(np.linalg.norm(bottom_right - bottom_left), np.linalg.norm(top_right - top_left))
    )
    height = int(
        max(np.linalg.norm(top_right - bottom_right), np.linalg.norm(top_left - bottom_left))
    )
    if width < 10 or height < 10:
        return image

    destination = np.array(
        [[0, 0], [width - 1, 0], [width - 1, height - 1], [0, height - 1]],
        dtype=np.float32,
    )
    matrix = cv2.getPerspectiveTransform(corners, destination)
    return cv2.warpPerspective(image, matrix, (width, height), flags=cv2.INTER_CUBIC)


# --------------------------------------------------------------------------- #
# Measurement — deterministic estimates, NOT the Step 14 model
# --------------------------------------------------------------------------- #


def estimate_blur(image: np.ndarray) -> float:
    """Variance of the Laplacian. Higher is sharper.

    A crude proxy, used only to order strategies sensibly when no quality model
    is available. Step 14 replaces this with a model trained on actual decode
    outcomes, which is a far better predictor than any hand-tuned statistic.
    """
    return float(cv2.Laplacian(to_grayscale(image), cv2.CV_64F).var())


def estimate_glare_fraction(image: np.ndarray, threshold: int = 240) -> float:
    """Proportion of near-saturated pixels."""
    gray = to_grayscale(image)
    return float((gray >= threshold).sum()) / float(gray.size)
