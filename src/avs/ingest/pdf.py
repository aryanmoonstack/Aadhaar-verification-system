"""PDF rendering — pages to images, so the rest of the pipeline never sees a PDF.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 3.5 (CONTRACTS.md 2.0.0 — PDF admitted)
Provides : render_pdf(bytes) -> list[RenderedPage], PdfRenderError
Consumes : pypdfium2 (optional dependency)
Used by  : avs.ingest.validator — and nothing else

WHY THIS MODULE EXISTS AT ALL
-----------------------------
Everything downstream of ingest — preprocessing, decoding, OCR — is written
against pixels. Teaching each of those stages about PDFs would spread a
container format through the whole pipeline.

Instead this module is a *converter at the boundary*: a PDF comes in, images go
out, and `validator.py` feeds those images back through the ordinary image path.
Every guard that protects an uploaded JPEG — bomb limits, dimension checks,
metadata stripping — therefore protects a PDF page too, without being rewritten.

⛔ WHY PDF IS A DIFFERENT KIND OF RISK FROM AN IMAGE
---------------------------------------------------
`magic.py` opens with a promise: it must not itself be a parser, because it runs
before anything has been validated. That promise held while input was JPEG and
PNG — formats that describe a grid of pixels and nothing else.

A PDF is not a picture. It is a container that can hold JavaScript, embedded
files, external references, and its own font programs. Rendering one means
running a large C++ parser (PDFium) over bytes a stranger uploaded. PDFium is
the engine inside Chrome and is heavily fuzzed, but "heavily fuzzed" is not
"safe" — it is "fewer bugs than the alternatives".

What this module does about that, concretely:

  * **Forms are never drawn.** `may_draw_forms=False`, and the form environment
    is never initialised, so AcroForm and XFA logic does not execute.
  * **JavaScript never runs.** It requires the form environment this module
    deliberately never creates.
  * **Page count is capped.** A PDF declaring 50,000 pages is a denial of
    service, not a document.
  * **Output pixels are capped per page**, before the bitmap is allocated —
    a page can declare an arbitrary MediaBox, and scale multiplies it.
  * **Nothing is resolved off the machine.** PDFium is not given a network or
    file callback, so external references cannot be fetched.

⚠ These narrow the surface. They do not remove it. The honest mitigation is
  process isolation — running the render in a separate, resource-limited
  process — and that belongs in the deployment, not in this file. It is written
  down in docs/GO_LIVE.md rather than silently assumed.

★ WHY A PDF SHOULD DECODE FAR BETTER THAN A PHOTOGRAPH
------------------------------------------------------
In an e-Aadhaar PDF the Secure QR is stored as vector or lossless raster data.
Rendering it produces exact module edges: no motion blur, no glare, no
perspective, no JPEG ringing. The measured corpus of phone photographs decoded
at roughly 30%. A rendered PDF page has none of the defects that caused the
other 70%.

That is the argument for accepting PDF at all, and it is why the render is
PNG rather than JPEG — see `render_pdf`.
"""

from __future__ import annotations

import io
from dataclasses import dataclass

from avs.contracts import ErrorCode
from avs.ingest.errors import IngestError

__all__ = [
    "PDFIUM_AVAILABLE",
    "DEFAULT_RENDER_DPI",
    "MAX_PDF_PAGES",
    "RenderedPage",
    "render_pdf",
]


# PDF support is optional, exactly as HEIF is. A deployment without pypdfium2
# must give a clear message rather than crash on import.
try:  # pragma: no cover - depends on the deployment image
    import pypdfium2 as pdfium
    import pypdfium2.raw as pdfium_raw

    PDFIUM_AVAILABLE = True
except Exception:  # noqa: BLE001 - any import failure means the codec is absent
    PDFIUM_AVAILABLE = False


#: 300 DPI, chosen by arithmetic rather than habit.
#:
#: The Aadhaar Secure QR is roughly 97 modules across (see
#: ``avs.ai.quality.metrics.MODULES_ACROSS``) and occupies about 1.4 inches on a
#: printed e-Aadhaar. Decoding needs at least 2.0 pixels per module — the floor
#: measured in Step 14.
#:
#:     300 DPI x 1.4 in = 420 px  ->  420 / 97 = 4.3 px per module
#:     150 DPI x 1.4 in = 210 px  ->  210 / 97 = 2.2 px per module
#:
#: 150 clears the floor by a hair; 300 clears it with room for a smaller QR than
#: expected. 600 would double the memory for no decoding benefit.
DEFAULT_RENDER_DPI = 300

#: PDFium expresses scale relative to 72 DPI, the PostScript point.
_POINTS_PER_INCH = 72.0

#: An e-Aadhaar is one or two pages. Four is generous and still bounded.
#: Without a cap, a PDF declaring 50,000 pages is a denial of service.
MAX_PDF_PAGES = 4

#: Per-page ceiling, applied BEFORE the bitmap is allocated. A page may declare
#: any MediaBox it likes and scale multiplies it, so this is checked from the
#: page's own dimensions rather than discovered by running out of memory.
_MAX_RENDER_PIXELS = 40_000_000

#: PDFium error codes. Numeric, so behaviour does not depend on the wording of
#: an error string that a library upgrade may reword.
_ERR_PASSWORD = 4
_ERR_FORMAT = 3


@dataclass(frozen=True, slots=True)
class RenderedPage:
    """One page of a PDF, rendered to PNG bytes.

    PNG, not JPEG, and the reason is the whole point of accepting PDF:
    JPEG is lossy, and its artefacts land hardest on exactly the high-contrast
    edges a dense QR code is made of. Rendering a pristine vector QR and then
    JPEG-compressing it would reintroduce the damage that photographs suffer
    from — having just gone to the trouble of avoiding it.
    """

    page_number: int
    data: bytes
    width: int
    height: int


def render_pdf(
    data: bytes,
    *,
    password: str | None = None,
    dpi: int = DEFAULT_RENDER_DPI,
    max_pages: int = MAX_PDF_PAGES,
) -> list[RenderedPage]:
    """Render each page of a PDF to PNG bytes.

    Args:
        data: the raw PDF. Already size-checked and magic-byte-checked by the
            caller — this function does not re-validate what it is given.
        password: for an encrypted PDF. e-Aadhaar files downloaded from UIDAI
            are password-protected, so this is the common case, not the edge
            case. Never logged; see the IngestError messages below.
        dpi: render resolution. See DEFAULT_RENDER_DPI for why 300.
        max_pages: pages beyond this are ignored rather than rejected — a
            legitimate document with a trailing page should still verify.

    Returns:
        One RenderedPage per page, in document order.

    Raises:
        IngestError: with a code the caller can turn into an employee-facing
            message. Password problems are reported distinctly from corruption,
            because the two need completely different things from the employee.
    """
    if not PDFIUM_AVAILABLE:
        raise IngestError(
            ErrorCode.UNSUPPORTED_MIME_TYPE,
            "pypdfium2 is not installed — PDF rendering unavailable",
            "PDF files cannot be processed on this server right now. Please "
            "upload a photo of your Aadhaar card instead.",
        )

    document = _open(data, password)

    try:
        page_count = len(document)
        if page_count == 0:
            raise IngestError(
                ErrorCode.CORRUPT_IMAGE,
                "PDF contains zero pages",
                "This PDF appears to be empty. Please upload the original "
                "Aadhaar PDF, or a photo of your card.",
            )

        scale = dpi / _POINTS_PER_INCH
        pages: list[RenderedPage] = []

        for index in range(min(page_count, max_pages)):
            rendered = _render_one(document, index, scale)
            if rendered is not None:
                pages.append(rendered)

        if not pages:
            # Every page failed. The document opened, so this is not a password
            # or format problem — the content itself is unrenderable.
            raise IngestError(
                ErrorCode.CORRUPT_IMAGE,
                f"none of the {page_count} page(s) could be rendered",
                "This PDF could not be read. Please upload a photo of your "
                "Aadhaar card instead.",
            )

        return pages

    finally:
        # PDFium holds native memory. Without this, a service under load leaks
        # steadily and is diagnosed weeks later as "the container restarts".
        document.close()


# --------------------------------------------------------------------------- #
# Opening — where the password case is separated from the corruption case
# --------------------------------------------------------------------------- #


def _open(data: bytes, password: str | None):  # type: ignore[no-untyped-def]
    """Open the document, translating PDFium's failure modes into ours.

    ⚠ The distinction between "needs a password" and "wrong password" cannot be
      made from the error code — PDFium reports code 4 for both. It is made from
      whether the caller supplied one, which is information we already have.
      Guessing instead would tell an employee who typed the wrong password that
      their file needs a password, which is useless advice.
    """
    try:
        return pdfium.PdfDocument(data, password=password)

    except pdfium.PdfiumError as exc:
        code = _last_error_code()

        if code == _ERR_PASSWORD:
            if password:
                raise IngestError(
                    ErrorCode.PDF_PASSWORD_INCORRECT,
                    "PDF password rejected by the renderer",
                    "That password did not open the PDF. For an e-Aadhaar the "
                    "password is the first 4 letters of your name in CAPITALS "
                    "followed by your year of birth — for example, RAME1990.",
                ) from exc

            raise IngestError(
                ErrorCode.PDF_PASSWORD_REQUIRED,
                "PDF is encrypted and no password was supplied",
                "This PDF is password-protected. Please enter the password — "
                "for an e-Aadhaar it is the first 4 letters of your name in "
                "CAPITALS followed by your year of birth, for example RAME1990.",
            ) from exc

        if code == _ERR_FORMAT:
            raise IngestError(
                ErrorCode.CORRUPT_IMAGE,
                f"PDF format error from renderer: {exc}",
                "This PDF appears to be damaged. Please download it again, or "
                "upload a photo of your Aadhaar card.",
            ) from exc

        raise IngestError(
            ErrorCode.CORRUPT_IMAGE,
            f"PDF could not be opened (renderer code {code}): {exc}",
            "This PDF could not be read. Please upload a photo of your "
            "Aadhaar card instead.",
        ) from exc

    except IngestError:
        raise

    except Exception as exc:  # noqa: BLE001
        # A native renderer can fail in ways its own exception type does not
        # cover. Anything escaping here would otherwise surface as a 500.
        raise IngestError(
            ErrorCode.CORRUPT_IMAGE,
            f"unexpected failure opening PDF: {type(exc).__name__}: {exc}",
            "This PDF could not be read. Please upload a photo of your "
            "Aadhaar card instead.",
        ) from exc


def _last_error_code() -> int:
    """PDFium's numeric error code, or -1 if it cannot be read.

    Preferred over matching the exception message, which is prose and free to
    change between library versions.
    """
    try:
        return int(pdfium_raw.FPDF_GetLastError())
    except Exception:  # noqa: BLE001
        return -1


# --------------------------------------------------------------------------- #
# Rendering one page
# --------------------------------------------------------------------------- #


def _render_one(document, index: int, scale: float) -> RenderedPage | None:  # type: ignore[no-untyped-def]
    """Render a single page, or return None if that one page is unusable.

    One bad page does not condemn the document. An e-Aadhaar with a damaged
    second page should still verify from the first, which is where the QR is.
    """
    page = None
    try:
        page = document[index]

        # Bounds are checked from the page's declared size BEFORE any bitmap is
        # allocated. Discovering the problem by exhausting memory would take the
        # whole service down, not just this request.
        width_pt, height_pt = page.get_size()
        pixels = (width_pt * scale) * (height_pt * scale)
        if pixels > _MAX_RENDER_PIXELS:
            return None

        bitmap = page.render(
            scale=scale,
            # ⛔ Form rendering executes AcroForm and XFA logic. Never enable it:
            #    an Aadhaar card has no form fields, so this only ever adds
            #    attack surface for zero benefit.
            may_draw_forms=False,
        )
        image = bitmap.to_pil()

        try:
            buffer = io.BytesIO()
            # Lossless. See RenderedPage — JPEG artefacts damage QR module edges,
            # and avoiding that damage is the entire reason PDF is worth having.
            image.save(buffer, format="PNG", optimize=False)
            return RenderedPage(
                page_number=index + 1,
                data=buffer.getvalue(),
                width=image.width,
                height=image.height,
            )
        finally:
            image.close()

    except Exception:  # noqa: BLE001
        # Deliberately broad: this is a native renderer, and a page that fails
        # must be skipped rather than propagated. The caller raises if *every*
        # page fails, so a genuinely broken document is still reported.
        return None

    finally:
        if page is not None:
            try:
                page.close()
            except Exception:  # noqa: BLE001, S110 - best-effort cleanup
                pass
