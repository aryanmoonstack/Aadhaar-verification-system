"""PDF through the full pipeline — Step 3.5. CONTRACTS.md 2.0.0.

`test_pdf_ingest.py` proves a PDF page renders and its QR decodes. This file
proves the thing that actually matters to an employee: an Aadhaar PDF produces
**VERIFIED**, with a real RSA signature check behind it, through the same
pipeline a photograph uses.

★ The case worth the file is `test_qr_on_page_two_still_verifies`. Reading only
  the first page of a PDF is the exact same class of mistake as assuming
  "QR = back" — it works on the documents you happen to test with and fails
  silently on a large share of real ones.

⛔ No real Aadhaar data. Every PDF is generated in-process and signed with a
   synthetic test key.
"""

from __future__ import annotations

import io

import pytest

from avs.contracts import CardSide, CheckName, CheckResult, ErrorCode, Strictness, Verdict
from avs.crypto import SecureQrVerifier
from avs.ingest.pdf import PDFIUM_AVAILABLE
from avs.pipeline import DocumentVerifier, SideInput
from avs.privacy import DataMinimisingFilter
from tests.fixtures.qr_images import render_card
from tests.fixtures.synthetic import SyntheticQrBuilder, make_test_certificate, make_test_keypair

pytestmark = pytest.mark.skipif(not PDFIUM_AVAILABLE, reason="pypdfium2 not installed")

reportlab = pytest.importorskip("reportlab", reason="reportlab needed to build test PDFs")

SECRET = "pdf-pipeline-test-secret"


@pytest.fixture(scope="module")
def keypair():
    return make_test_keypair()


@pytest.fixture(scope="module")
def payload(keypair) -> str:
    return SyntheticQrBuilder(private_key=keypair[0]).build()


@pytest.fixture(scope="module")
def card_png(payload: str) -> bytes:
    """A rendered card face carrying the Secure QR, as PNG bytes.

    ⚠ PNG, not JPEG. This image is about to be embedded in a PDF and rendered
      back out, and the point of the PDF path is that the QR survives intact.
      Starting from a JPEG would bake in the compression artefacts the feature
      exists to avoid, and the test would be measuring the wrong thing.
    """
    import cv2

    ok, buffer = cv2.imencode(".png", render_card(payload))
    assert ok, "PNG encoding failed"
    return bytes(buffer)


def _pdf(
    card: bytes | None,
    *,
    pages: int = 1,
    card_on_page: int = 1,
    password: str | None = None,
) -> bytes:
    """Wrap a rendered card image into a PDF, e-Aadhaar style.

    The card is drawn large enough that the QR clears the 2.0 px/module decode
    floor once rendered at 300 DPI — the same arithmetic as
    ``avs.ingest.pdf.DEFAULT_RENDER_DPI``.
    """
    import tempfile

    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    path = None
    if card is not None:
        handle = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        handle.write(card)
        handle.close()
        path = handle.name

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    if password is not None:
        pdf.setEncrypt(password)

    for number in range(1, pages + 1):
        pdf.setFont("Helvetica", 11)
        pdf.drawString(50, 800, "Synthetic test document")
        if path and number == card_on_page:
            pdf.drawImage(path, 40, 380, width=515, height=325)
        pdf.showPage()

    pdf.save()
    return buffer.getvalue()


def make_verifier(keypair, *, budget: float = 8.0) -> DocumentVerifier:
    """⚠ A larger budget than the image tests use.

    Rendering four A4 pages at 300 DPI is real work that a JPEG decode is not.
    The budget bounds decoding, so a document with more pages to search
    legitimately needs more of it.
    """
    return DocumentVerifier(
        SecureQrVerifier(keypair[1:2]),
        DataMinimisingFilter(hash_secret=SECRET),
        strictness=Strictness.STANDARD,
        time_budget_seconds=budget,
    )


# --------------------------------------------------------------------------- #
# The claim
# --------------------------------------------------------------------------- #


class TestPdfVerifies:
    def test_a_pdf_aadhaar_verifies(self, keypair, card_png) -> None:
        """★ The end-to-end claim: PDF in, VERIFIED out, signature checked."""
        document = _pdf(card_png)
        result = make_verifier(keypair).verify(
            [SideInput(CardSide.FRONT, document), SideInput(CardSide.BACK, document)]
        )

        assert result.verdict is Verdict.VERIFIED
        assert result.proof is not None
        assert result.proof.valid is True
        assert result.is_auto_approve is True

    def test_qr_on_page_two_still_verifies(self, keypair, card_png) -> None:
        """⛔ The bug this whole step exists to prevent.

        ``ingest()`` returns page one. If the pipeline had kept using it, this
        document — entirely valid, signature intact — would come back
        UNREADABLE, and the employee would re-upload the identical file to the
        identical result, forever.
        """
        document = _pdf(card_png, pages=2, card_on_page=2)
        result = make_verifier(keypair).verify(
            [SideInput(CardSide.FRONT, document), SideInput(CardSide.BACK, document)]
        )

        assert result.verdict is Verdict.VERIFIED
        assert result.proof is not None and result.proof.valid is True

    def test_a_legacy_qr_on_page_one_does_not_end_the_search(
        self, keypair, card_png
    ) -> None:
        """⛔⛔ THE BUG REAL DOCUMENTS FOUND AND NO FIXTURE COULD.

        A real e-Aadhaar PDF carries more than one QR — a small legacy or
        address-slip code as well as the signed Secure QR, frequently on
        different pages. The page loop originally stopped at the first page that
        decoded ANYTHING, so a legacy code on page 1 ended the search and the
        Secure QR on page 2 was never reached.

        The document came back LEGACY_FORMAT: "this is an older Aadhaar card,
        please download a fresh one". For a current card that advice is a dead
        end — downloading again produces the same PDF and the same wrong answer.

        ⚠ Every synthetic fixture had exactly one QR, which is precisely why the
          whole suite passed while the first three real PDFs failed. The test
          below builds the shape that actually occurs.
        """
        import io as _io
        import tempfile

        import qrcode as qr_lib
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        # A pre-2018 unsigned Aadhaar QR — XML, not a long integer.
        legacy = qr_lib.make(
            '<?xml version="1.0"?><PrintLetterBarcodeData uid="" name="TEST"/>'
        )
        legacy_file = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        legacy.save(legacy_file.name)
        legacy_file.close()

        card_file = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        card_file.write(card_png)
        card_file.close()

        buffer = _io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        pdf.setFont("Helvetica", 11)
        pdf.drawString(50, 800, "page 1 - legacy code only")
        pdf.drawImage(legacy_file.name, 60, 560, width=170, height=170)
        pdf.showPage()
        pdf.drawString(50, 800, "page 2 - the Secure QR")
        pdf.drawImage(card_file.name, 40, 380, width=515, height=325)
        pdf.showPage()
        pdf.save()

        result = make_verifier(keypair, budget=12.0).verify(
            [SideInput(CardSide.FRONT, buffer.getvalue())]
        )

        assert result.verdict is Verdict.VERIFIED, (
            f"got {result.verdict.value} — the search stopped at the legacy QR "
            "on page 1 instead of continuing to the Secure QR on page 2"
        )
        assert result.proof is not None and result.proof.valid is True

    def test_a_pdf_paired_with_a_photo_verifies(self, keypair, card_png) -> None:
        """Mixed input. An employee may well have a PDF for one face and a photo
        for the other, and nothing in the pipeline should care."""
        import io as _io

        from PIL import Image

        photo = _io.BytesIO()
        with Image.open(_io.BytesIO(card_png)) as image:
            image.convert("RGB").save(photo, format="JPEG", quality=95, subsampling=0)

        result = make_verifier(keypair).verify(
            [
                SideInput(CardSide.FRONT, photo.getvalue()),
                SideInput(CardSide.BACK, _pdf(card_png)),
            ]
        )
        assert result.verdict is Verdict.VERIFIED

    def test_encrypted_pdf_verifies_with_the_password(self, keypair, card_png) -> None:
        document = _pdf(card_png, password="SECRET99")
        result = make_verifier(keypair).verify(
            [
                SideInput(CardSide.FRONT, document, password="SECRET99"),
                SideInput(CardSide.BACK, document, password="SECRET99"),
            ]
        )
        assert result.verdict is Verdict.VERIFIED


# --------------------------------------------------------------------------- #
# Failure paths — still no auto-rejection
# --------------------------------------------------------------------------- #


class TestPdfFailures:
    def test_encrypted_pdf_without_a_password_is_not_a_rejection(
        self, keypair, card_png
    ) -> None:
        """⛔ CONTRACTS.md §1 Rule 2 holds for PDFs too.

        A locked file is a retry, never a rejection — the employee simply has
        not typed the password yet.
        """
        document = _pdf(card_png, password="SECRET99")
        result = make_verifier(keypair).verify(
            [SideInput(CardSide.FRONT, document), SideInput(CardSide.BACK, document)]
        )

        assert result.verdict is not Verdict.VERIFIED
        assert result.verdict.is_auto_reject is False
        assert result.verdict.allows_retry is True

        front = next(s for s in result.sides if s.side is CardSide.FRONT)
        assert front.error is ErrorCode.PDF_PASSWORD_REQUIRED
        assert front.ingested is False

    def test_the_password_never_reaches_the_result(self, keypair, card_png) -> None:
        """⛔ A password typed by an employee must not survive into anything
        stored, logged or displayed."""
        secret = "ZZTOP1971"
        document = _pdf(card_png, password="OTHER123")
        result = make_verifier(keypair).verify(
            [
                SideInput(CardSide.FRONT, document, password=secret),
                SideInput(CardSide.BACK, document, password=secret),
            ]
        )
        assert secret not in result.model_dump_json()

    def test_a_pdf_with_no_card_in_it_is_unreadable_not_rejected(self, keypair) -> None:
        result = make_verifier(keypair).verify(
            [SideInput(CardSide.FRONT, _pdf(None)), SideInput(CardSide.BACK, _pdf(None))]
        )
        assert result.verdict is Verdict.UNREADABLE
        assert result.verdict.is_auto_reject is False
        assert "fake" not in result.user_message.lower()


# --------------------------------------------------------------------------- #
# One PDF, submitted once — CONTRACTS.md §11 exception
# --------------------------------------------------------------------------- #


class TestSingleDocumentUpload:
    def test_one_pdf_alone_verifies(self, keypair, card_png) -> None:
        """★ An employee with one PDF submits it once.

        Previously they had to put the same bytes in both slots, which added no
        evidence and doubled the rendering work.
        """
        result = make_verifier(keypair).verify(
            [SideInput(CardSide.FRONT, _pdf(card_png))]
        )
        assert result.verdict is Verdict.VERIFIED
        assert result.proof is not None and result.proof.valid is True
        assert len(result.sides) == 1

    def test_side_agreement_stops_claiming_corroboration_it_does_not_have(
        self, keypair, card_png
    ) -> None:
        """⛔ The honesty fix hiding inside the convenience fix.

        Submitting identical bytes twice produced
        ``SIDE_AGREEMENT = PASS, "both sides carry the same payload"``. Two
        copies of one file agreeing with each other is a tautology, and
        recording it as PASS reads like independent corroboration to anyone
        reviewing the checks later.

        One upload reports SKIP — nothing to compare, which is the truth.
        """
        document = _pdf(card_png)
        verifier = make_verifier(keypair)

        duplicated = verifier.verify(
            [SideInput(CardSide.FRONT, document), SideInput(CardSide.BACK, document)]
        )
        single = verifier.verify([SideInput(CardSide.FRONT, document)])

        def agreement(result):
            return next(c for c in result.checks if c.name is CheckName.SIDE_AGREEMENT)

        assert duplicated.verdict is Verdict.VERIFIED
        assert single.verdict is Verdict.VERIFIED

        assert agreement(duplicated).result is CheckResult.PASS
        assert agreement(single).result is CheckResult.SKIP

    def test_a_single_pdf_is_not_told_a_photo_was_unclear(self, keypair, card_png) -> None:
        """⛔ A wording bug the §11 change introduced, caught in a live run.

        ``SIDE_AGREEMENT = SKIP`` used to mean exactly one thing: two faces were
        submitted and only one carried a QR — so "one of the photos was unclear"
        was true and useful. Allowing a single PDF made SKIP ambiguous, and the
        VERIFIED message started telling people who uploaded one file to go find
        a bad photo that does not exist.

        The two situations now carry different `detail`, and the message only
        fires for the one it was written for.
        """
        single = make_verifier(keypair).verify([SideInput(CardSide.FRONT, _pdf(card_png))])
        assert single.verdict is Verdict.VERIFIED
        assert "unclear" not in single.user_message
        assert "photos" not in single.user_message

        # The original wording must survive for the case it was written for:
        # two faces submitted, only one usable.
        pair = make_verifier(keypair).verify(
            [
                SideInput(CardSide.FRONT, _pdf(card_png)),
                SideInput(CardSide.BACK, _pdf(None)),
            ]
        )
        assert pair.verdict is Verdict.VERIFIED
        assert "unclear" in pair.user_message

    def test_one_pdf_renders_half_as_many_pages(self, keypair, card_png) -> None:
        """The point of the change — and note what it is NOT.

        ⛔ This asserts **pages rendered**, not elapsed time, and the distinction
           was found by measurement rather than reasoning. An earlier version of
           this test asserted ``one.processing_ms < both.processing_ms`` and
           passed at a 12-second budget. Measured across budgets:

               budget   one PDF            both slots
               5s       3 pages, 6405ms    6 pages, 6884ms
               8s       3 pages, 9163ms    6 pages, 8663ms   <- one is SLOWER
               12s      3 pages, 12388ms   6 pages, 13170ms

           Rendering halves every time. Wall-clock does not, because the time
           budget governs: freed rendering time is simply spent searching the
           remaining pages harder. A timing assertion here would be a flaky test
           dressed as a performance guarantee.
        """
        from avs.contracts import CaptureMethod
        from avs.ingest import ImageIngestor

        rendered: list[int] = []

        class Counting(ImageIngestor):
            def ingest_all(  # type: ignore[override]
                self, data, filename=None, capture_method=CaptureMethod.UNKNOWN, password=None
            ):
                pages = super().ingest_all(data, filename, capture_method, password)
                rendered.append(len(pages))
                return pages

        document = _pdf(card_png, pages=3, card_on_page=3)

        def run(inputs: list[SideInput]) -> int:
            rendered.clear()
            verifier = DocumentVerifier(
                SecureQrVerifier(keypair[1:2]),
                DataMinimisingFilter(hash_secret=SECRET),
                ingestor=Counting(),
                time_budget_seconds=12.0,
            )
            assert verifier.verify(inputs).verdict is Verdict.VERIFIED
            return sum(rendered)

        one = run([SideInput(CardSide.FRONT, document)])
        both = run([SideInput(CardSide.FRONT, document), SideInput(CardSide.BACK, document)])

        assert one == 3
        assert both == 6


# --------------------------------------------------------------------------- #
# Cost accounting
# --------------------------------------------------------------------------- #


class TestBudgetAndAccounting:
    def test_a_multi_page_pdf_shares_one_document_budget(self, keypair) -> None:
        """⚠ Pages must not each be granted a fresh budget.

        Four pages at a 3-second budget is a 3-second document, not a
        12-second one. The recomputation in ``_process_page`` is what enforces
        that, and it is easy to break by hoisting the deadline out of the loop.
        """
        import time as _time

        blank = _pdf(None, pages=4)
        started = _time.perf_counter()
        make_verifier(keypair, budget=3.0).verify(
            [SideInput(CardSide.FRONT, blank), SideInput(CardSide.BACK, blank)]
        )
        elapsed = _time.perf_counter() - started

        # Generous ceiling: rendering is outside the budget, decoding is inside.
        # A per-page budget would blow well past this.
        assert elapsed < 20.0, f"took {elapsed:.1f}s against a 3s document budget"

    def test_early_pages_cannot_starve_the_page_holding_the_qr(
        self, keypair, card_png
    ) -> None:
        """⛔ The failure mode this step could plausibly have introduced.

        Pages are searched in order against one shared deadline. If pages 1-3
        burn the whole budget, page 4 — the one actually holding the QR — could
        be left with nothing and the document would come back UNREADABLE. Worse,
        it would do so *intermittently*, depending on machine load.

        Measured: a 4-page PDF verifies at a 2-second budget. The floor in
        ``_process_page`` (``max(0.05, ...)``) is what saves it, and 0.05s is
        enough because a rendered QR decodes on the FIRST preprocessing variant
        — the Step 14 measurement that also justified `--budget 5`.

        If this ever fails, the fix is to reserve budget per page, not to raise
        the global budget.
        """
        document = _pdf(card_png, pages=4, card_on_page=4)
        result = make_verifier(keypair, budget=2.0).verify(
            [SideInput(CardSide.FRONT, document), SideInput(CardSide.BACK, document)]
        )
        assert result.verdict is Verdict.VERIFIED
        assert result.proof is not None and result.proof.valid is True

    def test_variants_tried_counts_every_page(self, keypair, card_png) -> None:
        """The metric must describe the work done, not just the winning page.

        Decode-cost figures are read to decide whether the time budget is set
        correctly. A count that ignored the pages searched first would argue
        for a budget that cannot hold in production.
        """
        one_page = _pdf(card_png, pages=1, card_on_page=1)
        three_pages = _pdf(card_png, pages=3, card_on_page=3)

        verifier = make_verifier(keypair, budget=12.0)
        shallow = verifier.verify(
            [SideInput(CardSide.FRONT, one_page), SideInput(CardSide.BACK, one_page)]
        )
        deep = verifier.verify(
            [SideInput(CardSide.FRONT, three_pages), SideInput(CardSide.BACK, three_pages)]
        )

        assert shallow.verdict is Verdict.VERIFIED
        assert deep.verdict is Verdict.VERIFIED

        shallow_front = next(s for s in shallow.sides if s.side is CardSide.FRONT)
        deep_front = next(s for s in deep.sides if s.side is CardSide.FRONT)
        assert deep_front.variants_tried > shallow_front.variants_tried
