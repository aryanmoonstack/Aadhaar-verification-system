"""Every ingest failure must say something the employee can act on.

★ THE FAILURE THIS FILE PREVENTS

  Nine distinct ingest errors used to collapse into one sentence — "We could not
  open your file." Someone whose photo was 30 MB, someone who uploaded a GIF and
  someone whose PDF was locked all read identical words, and none of them
  learned what to do differently.

  The generic text also mentioned photos, so a person holding a perfectly good
  e-Aadhaar PDF was told to upload clearer JPEGs: advice they cannot act on,
  about a problem they do not have. That is what the first real HRM integration
  test surfaced.
"""

from __future__ import annotations

import pytest

from avs.contracts import CheckName, CheckOutcome, CheckResult, ErrorCode, Verdict
from avs.rules.messages import INGEST_MESSAGES, message_for

#: Every code `avs.ingest` can raise. Kept explicit rather than derived, so
#: adding a raise site without wording fails here instead of shipping.
INGEST_CODES = [
    ErrorCode.FILE_TOO_LARGE,
    ErrorCode.FILE_TOO_SMALL,
    ErrorCode.UNSUPPORTED_MIME_TYPE,
    ErrorCode.CORRUPT_IMAGE,
    ErrorCode.DIMENSIONS_INVALID,
    ErrorCode.DECOMPRESSION_BOMB,
    ErrorCode.MALWARE_DETECTED,
    ErrorCode.PDF_PASSWORD_REQUIRED,
    ErrorCode.PDF_PASSWORD_INCORRECT,
]


def failed_validation(code: ErrorCode) -> dict[CheckName, CheckOutcome]:
    return {
        CheckName.FILE_VALIDATION: CheckOutcome(
            name=CheckName.FILE_VALIDATION,
            result=CheckResult.FAIL,
            detail="no side passed validation",
            error=code,
        )
    }


class TestEveryIngestErrorIsCovered:
    @pytest.mark.parametrize("code", INGEST_CODES)
    def test_has_its_own_wording(self, code: ErrorCode) -> None:
        assert code in INGEST_MESSAGES, (
            f"{code.value} can be raised by avs.ingest but has no employee-facing "
            "message. It would fall back to the generic 'could not open your file'."
        )

    @pytest.mark.parametrize("code", INGEST_CODES)
    def test_reaches_the_employee(self, code: ErrorCode) -> None:
        assert message_for(Verdict.UNREADABLE, failed_validation(code)) == INGEST_MESSAGES[code]

    @pytest.mark.parametrize("code", INGEST_CODES)
    def test_also_reaches_them_when_the_verdict_is_error(self, code: ErrorCode) -> None:
        """⚠ An ingest failure can surface as ERROR, not only UNREADABLE.

        The lookup used to sit under UNREADABLE alone, so those cases fell back
        to "please try again shortly" — advice that can never work, because
        nothing about the file changes on a retry.
        """
        assert message_for(Verdict.ERROR, failed_validation(code)) == INGEST_MESSAGES[code]

    @pytest.mark.parametrize("code", INGEST_CODES)
    def test_messages_are_distinct(self, code: ErrorCode) -> None:
        """Nine codes, nine different things to do. A shared string means one of
        them is telling somebody to fix the wrong thing."""
        others = [m for c, m in INGEST_MESSAGES.items() if c is not code]
        assert INGEST_MESSAGES[code] not in others


class TestTheLanguageRule:
    @pytest.mark.parametrize("code", INGEST_CODES)
    def test_accuses_nobody(self, code: ErrorCode) -> None:
        """CONTRACTS.md §1. A genuine card is not a forgery, and neither is a
        file a scanner disliked."""
        message = INGEST_MESSAGES[code].lower()
        for word in ("fake", "forged", "fraud", "invalid document", "illegal"):
            assert word not in message, f"{code.value} says {word!r}"

    @pytest.mark.parametrize("code", INGEST_CODES)
    def test_says_what_to_do_next(self, code: ErrorCode) -> None:
        """A diagnosis is not an instruction. "This file is too large" leaves
        someone stuck; "upload a photo under 20 MB" does not."""
        assert "please" in INGEST_MESSAGES[code].lower()

    def test_malware_does_not_imply_the_employee_did_it(self) -> None:
        """⛔ A scanner false positive is far likelier than an employee attaching
        malware to their own Aadhaar. The wording must not suggest otherwise."""
        message = INGEST_MESSAGES[ErrorCode.MALWARE_DETECTED].lower()
        assert "virus" not in message
        assert "malware" not in message
        assert "blocked by a security scan" in message


class TestPasswordWording:
    def test_a_locked_pdf_is_never_told_to_upload_clearer_photos(self) -> None:
        """★ The exact bug the first real integration test found.

        A locked PDF fails file validation, just as an unreadable photo does. It
        used to inherit "upload clear, full-resolution JPEG or PNG images" —
        wrong for someone whose file is pristine and merely encrypted.
        """
        for code in (ErrorCode.PDF_PASSWORD_REQUIRED, ErrorCode.PDF_PASSWORD_INCORRECT):
            message = message_for(Verdict.UNREADABLE, failed_validation(code)).lower()
            assert "password" in message
            assert "jpeg" not in message
            assert "photograph" not in message

    def test_does_not_claim_the_employee_typed_a_wrong_password(self) -> None:
        """⛔ The HRM usually DERIVES the password from the employee's profile,
        so in the common case they typed nothing at all.

        "That password did not open the PDF" blames them for our guess — and the
        guess misses routinely, whenever the profile name differs from the name
        printed on the Aadhaar. It is also an assertion we cannot support: the
        renderer reports the same code for a wrong password and for an
        encryption scheme it does not handle.
        """
        message = INGEST_MESSAGES[ErrorCode.PDF_PASSWORD_INCORRECT].lower()
        assert "your password" not in message
        assert "that password did not" not in message
        assert "incorrect" not in message
        # It should still tell them how to find the right one.
        assert "rame1990" in message

    def test_the_two_password_cases_read_differently(self) -> None:
        """"No password supplied" and "the one we tried did not work" need
        different first sentences, or the second looks like the system ignored
        what was entered."""
        assert (
            INGEST_MESSAGES[ErrorCode.PDF_PASSWORD_REQUIRED]
            != INGEST_MESSAGES[ErrorCode.PDF_PASSWORD_INCORRECT]
        )
