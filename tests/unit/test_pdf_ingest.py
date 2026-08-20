"""PDF ingest — Step 3.5. CONTRACTS.md 2.0.0.

WHAT THESE TESTS ARE FOR
------------------------
Two claims justify accepting PDF at all, and both are measured here rather than
asserted in a docstring:

  1. A QR rendered from a PDF actually decodes — that is the whole point, since
     photographs decoded at roughly 30% on the real corpus.
  2. The photograph-tuned bomb guard would have rejected valid pages. If that
     is not true, the PDF-specific limit in ``_pdf_page_ingestor`` is dead
     weight and should be deleted rather than carried.

⛔ No real Aadhaar data appears here. Every PDF is generated in-process from a
   synthetic payload.
"""

from __future__ import annotations

import io

import pytest

from avs.contracts import ErrorCode
from avs.ingest import IngestError, ImageIngestor
from avs.ingest.magic import FileKind, detect
from avs.ingest.pdf import PDFIUM_AVAILABLE, render_pdf

pytestmark = pytest.mark.skipif(not PDFIUM_AVAILABLE, reason="pypdfium2 not installed")

reportlab = pytest.importorskip("reportlab", reason="reportlab needed to build test PDFs")
qrcode = pytest.importorskip("qrcode", reason="qrcode needed to build test PDFs")


# --------------------------------------------------------------------------- #
# Fixtures — synthetic documents, never a real card
# --------------------------------------------------------------------------- #

#: Long numeric string, the shape of a Secure QR payload. Not a real one.
SYNTHETIC_PAYLOAD = "7" * 1800


def _qr_png(payload: str) -> bytes:
    import qrcode as qr_lib

    qr = qr_lib.QRCode(error_correction=qr_lib.constants.ERROR_CORRECT_M, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    buffer = io.BytesIO()
    qr.make_image(fill_color="black", back_color="white").save(buffer, format="PNG")
    return buffer.getvalue()


def _build_pdf(
    *,
    pages: int = 1,
    qr_on_page: int | None = None,
    qr_size_pt: float = 140.0,
    password: str | None = None,
    sparse: bool = False,
) -> bytes:
    """A synthetic e-Aadhaar-shaped PDF.

    Args:
        qr_on_page: 1-based page to place the QR on, or None for no QR.
        qr_size_pt: QR width in points. 140pt at 300 DPI is ~583px.
        sparse: draw almost nothing — the shape of a trailing page. This is the
            case that exposes the compression-ratio problem; see
            ``TestBombGuardLimits``.
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    qr_path = None
    if qr_on_page is not None:
        import tempfile

        handle = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        handle.write(_qr_png(SYNTHETIC_PAYLOAD))
        handle.close()
        qr_path = handle.name

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    if password is not None:
        pdf.setEncrypt(password)

    for number in range(1, pages + 1):
        pdf.setFont("Helvetica", 11)
        if sparse:
            pdf.drawString(60, 780, ".")
        else:
            pdf.drawString(60, 780, "Government of India")
            pdf.drawString(60, 762, f"Synthetic test document - page {number}")
        if qr_path and number == qr_on_page:
            pdf.drawImage(qr_path, 60, 480, width=qr_size_pt, height=qr_size_pt)
        pdf.showPage()

    pdf.save()
    return buffer.getvalue()


@pytest.fixture
def ingestor() -> ImageIngestor:
    return ImageIngestor()


# --------------------------------------------------------------------------- #
# The claim that justifies the whole feature
# --------------------------------------------------------------------------- #


class TestRenderedQrDecodes:
    def test_a_qr_rendered_from_pdf_decodes(self, ingestor: ImageIngestor) -> None:
        """★ The reason PDF is worth supporting.

        A phone photograph of a card decoded at roughly 30% on the measured
        corpus — motion blur, glare and JPEG ringing destroy the fine module
        edges. A PDF holds the QR as vector or lossless raster data, so the
        render has none of those defects.

        If this test ever fails, the argument for accepting PDF has collapsed
        and the feature should be reconsidered, not patched.
        """
        zxing = pytest.importorskip("zxingcpp", reason="zxing-cpp needed to decode")
        from PIL import Image

        pages = ingestor.ingest_all(_build_pdf(qr_on_page=1))
        assert len(pages) == 1

        with Image.open(io.BytesIO(pages[0].data)) as image:
            results = zxing.read_barcodes(image)

        assert results, "the rendered QR did not decode at all"
        assert results[0].text == SYNTHETIC_PAYLOAD

    def test_qr_on_the_second_page_is_still_found(self, ingestor: ImageIngestor) -> None:
        """⛔ Why ``ingest_all`` exists and ``ingest`` is not enough.

        ``ingest`` returns page one. An e-Aadhaar routinely carries the Secure
        QR on a later page, so a caller that searches only the first page would
        report a perfectly good document as unreadable.
        """
        zxing = pytest.importorskip("zxingcpp", reason="zxing-cpp needed to decode")
        from PIL import Image

        pages = ingestor.ingest_all(_build_pdf(pages=2, qr_on_page=2))
        assert len(pages) == 2

        decoded = []
        for page in pages:
            with Image.open(io.BytesIO(page.data)) as image:
                decoded.extend(r.text for r in zxing.read_barcodes(image))

        assert SYNTHETIC_PAYLOAD in decoded

        # And the single-page convenience wrapper would have missed it.
        with Image.open(io.BytesIO(ingestor.ingest(_build_pdf(pages=2, qr_on_page=2)).data)) as one:
            assert not [r for r in zxing.read_barcodes(one) if r.text == SYNTHETIC_PAYLOAD]


# --------------------------------------------------------------------------- #
# The bomb guard — measured, not assumed
# --------------------------------------------------------------------------- #


class TestBombGuardLimits:
    def test_photograph_limit_would_reject_a_valid_sparse_page(self) -> None:
        """⛔ The measurement that justifies ``pdf_max_pixels_per_byte``.

        A rendered page is mostly flat white and compresses far better than any
        camera photograph. Measured at A4/300 DPI (2481x3508, 8.7 MP):

            near-blank page      33,160 B    262.5 px/byte   <- over the limit
            two lines of text    59,727 B    145.7 px/byte   <- just under
            text + Secure QR    141,014 B     61.7 px/byte

        The photograph limit is 150, and valid pages sit *astride* it. That is
        worse than being clearly over: the guard would fire on some real
        documents and not others, which reads as an intermittent fault rather
        than a misapplied constant.

        A sparse page is the realistic trigger — a trailing page of an otherwise
        valid e-Aadhaar, rejected as a decompression bomb.
        """
        sparse = _build_pdf(pages=1, sparse=True)

        strict = ImageIngestor(min_bytes=1, pdf_max_pixels_per_byte=150.0)
        with pytest.raises(IngestError) as exc:
            strict.ingest_all(sparse)

        # Reported as a bomb — which is exactly the misdiagnosis being guarded
        # against. The page is an ordinary document that happens to compress
        # well, not an attack.
        assert exc.value.code is ErrorCode.DECOMPRESSION_BOMB
        assert "262 px/byte" in exc.value.message

        # The shipped default accepts the same document.
        assert ImageIngestor().ingest_all(sparse)

    def test_the_absolute_pixel_ceiling_still_applies(self) -> None:
        """⚠ Raising the ratio must not disarm the real protection.

        ``max_pixels`` is what actually bounds memory. If a raised ratio also
        let pixel count run free, the PDF path would be a genuine bomb vector.
        """
        tiny = ImageIngestor(min_bytes=1, max_pixels=1_000_000)
        with pytest.raises(IngestError) as exc:
            tiny.ingest_all(_build_pdf(qr_on_page=1))
        assert exc.value.code is ErrorCode.DECOMPRESSION_BOMB

    def test_page_cap_bounds_a_document_declaring_many_pages(
        self, ingestor: ImageIngestor
    ) -> None:
        """A PDF declaring thousands of pages is a denial of service, not a card."""
        pages = ingestor.ingest_all(_build_pdf(pages=12))
        assert len(pages) == 4  # MAX_PDF_PAGES


# --------------------------------------------------------------------------- #
# Encryption — the common case for e-Aadhaar, not an edge case
# --------------------------------------------------------------------------- #


class TestPasswordProtection:
    def test_encrypted_pdf_without_a_password_asks_for_one(
        self, ingestor: ImageIngestor
    ) -> None:
        with pytest.raises(IngestError) as exc:
            ingestor.ingest_all(_build_pdf(qr_on_page=1, password="SECRET99"))
        assert exc.value.code is ErrorCode.PDF_PASSWORD_REQUIRED
        assert "password" in exc.value.user_message.lower()

    def test_wrong_password_says_so_rather_than_asking_again(
        self, ingestor: ImageIngestor
    ) -> None:
        """⚠ PDFium reports the same code for both, so the distinction comes
        from whether a password was supplied — information we already hold.

        Telling someone who mistyped their password that the file "needs a
        password" is advice they cannot act on.
        """
        with pytest.raises(IngestError) as exc:
            ingestor.ingest_all(_build_pdf(qr_on_page=1, password="SECRET99"), password="WRONG")
        assert exc.value.code is ErrorCode.PDF_PASSWORD_INCORRECT

    def test_correct_password_opens_the_document(self, ingestor: ImageIngestor) -> None:
        pages = ingestor.ingest_all(
            _build_pdf(qr_on_page=1, password="SECRET99"), password="SECRET99"
        )
        assert len(pages) == 1

    def test_password_never_appears_in_any_message(self, ingestor: ImageIngestor) -> None:
        """⛔ A password typed by an employee must not reach a log or a screen."""
        secret = "ZZTOP1971"
        with pytest.raises(IngestError) as exc:
            ingestor.ingest_all(_build_pdf(password="OTHER123"), password=secret)
        assert secret not in exc.value.message
        assert secret not in exc.value.user_message
        assert secret not in str(exc.value)


# --------------------------------------------------------------------------- #
# Routing and identity
# --------------------------------------------------------------------------- #


class TestRoutingAndIdentity:
    def test_pdf_is_accepted_but_is_not_an_image(self) -> None:
        detected = detect(_build_pdf())
        assert detected.kind is FileKind.PDF
        assert detected.is_accepted is True
        assert detected.kind.is_image is False

    def test_every_page_carries_the_hash_of_the_source_document(
        self, ingestor: ImageIngestor
    ) -> None:
        """⚠ Pages share the digest of the uploaded PDF, not of their render.

        A render hash would change with the pypdfium2 version. Duplicate
        detection compares hashes, so that would silently stop matching after a
        routine dependency bump — with nothing in the logs to explain it.
        """
        import hashlib

        source = _build_pdf(pages=2, qr_on_page=1)
        pages = ingestor.ingest_all(source)
        expected = hashlib.sha256(source).hexdigest()

        assert len(pages) == 2
        assert {page.sha256 for page in pages} == {expected}

    def test_rendered_pages_are_normalised_like_any_image(
        self, ingestor: ImageIngestor
    ) -> None:
        """The rejoin: a PDF page leaves ingest in the same shape as a JPEG."""
        page = ingestor.ingest_all(_build_pdf(qr_on_page=1))[0]
        assert page.mime_type in {"image/jpeg", "image/png"}
        assert page.width > 0 and page.height > 0

    def test_size_bytes_reports_the_uploaded_file_not_the_render(
        self, ingestor: ImageIngestor
    ) -> None:
        """The audit trail should describe what the employee actually sent."""
        source = _build_pdf(qr_on_page=1)
        assert ingestor.ingest_all(source)[0].size_bytes == len(source)


class TestDamagedInput:
    def test_pdf_header_with_no_document_behind_it(self, ingestor: ImageIngestor) -> None:
        with pytest.raises(IngestError) as exc:
            ingestor.ingest_all(b"%PDF-1.7\n" + b"0" * 80_000)
        assert exc.value.code is ErrorCode.CORRUPT_IMAGE

    def test_truncated_pdf(self, ingestor: ImageIngestor) -> None:
        full = _build_pdf(qr_on_page=1)
        with pytest.raises(IngestError):
            ingestor.ingest_all(full[: len(full) // 3])

    def test_render_errors_are_ingest_errors_not_raw_exceptions(self) -> None:
        """⛔ Nothing from the native renderer may escape as a 500.

        PDFium is a C++ library reached through ctypes; it can fail in ways its
        own exception type does not describe. Every one of those must arrive as
        an IngestError carrying an employee-readable message.
        """
        for payload in (b"%PDF-", b"%PDF-1.7", b"%PDF-1.7\n%%EOF", b"%PDF-" + bytes(range(256))):
            with pytest.raises(IngestError):
                render_pdf(payload)
