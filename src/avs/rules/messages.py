"""Employee-facing messages — Step 6.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 6
Provides : message_for(verdict, checks) -> str, MESSAGES
Consumes : avs.contracts
Used by  : avs.rules.engine

⛔ THE LANGUAGE RULE (CONTRACTS.md §1)

   The word "fake" must never appear here. Nor "forged", "fraudulent",
   "invalid document", or any phrasing that accuses the person holding the card.

   Use "could not be verified".

   A genuine Aadhaar photographed in bad light is not a forgery. The system
   cannot tell the difference between a forgery and a bad photo from the
   employee's point of view — and getting that wrong turns a retake into an
   accusation. Every message here says what to DO next, not what went wrong.

Step 21 translates these into Hindi, Marathi, Tamil and others. The English
strings are the source, so they are written to be translatable: short sentences,
no idiom, no cultural assumptions.
"""

from __future__ import annotations

from avs.contracts import CheckName, CheckOutcome, CheckResult, ErrorCode, Verdict

__all__ = ["MESSAGES", "message_for"]


MESSAGES: dict[Verdict, str] = {
    Verdict.VERIFIED: "Your Aadhaar has been verified.",
    Verdict.TAMPERED: (
        "We could not verify this Aadhaar card. Please upload clear photos of your original card."
    ),
    Verdict.UNREADABLE: (
        "We could not read the QR code. Please photograph both sides of your "
        "Aadhaar card in good light, holding the card flat and filling the frame."
    ),
    Verdict.LEGACY_FORMAT: (
        "This is an older Aadhaar card that cannot be verified automatically. "
        "Please download a current e-Aadhaar from myaadhaar.uidai.gov.in and "
        "upload photos of that instead."
    ),
    Verdict.WRONG_DOCUMENT: (
        "This does not look like an Aadhaar card. Please upload photos of both "
        "sides of your Aadhaar."
    ),
    Verdict.PROFILE_MISMATCH: (
        "The details on your Aadhaar do not match your profile. Your submission "
        "has been sent to HR to review — no further action is needed from you."
    ),
    Verdict.TEXT_MISMATCH: (
        "We need to check a few details on your Aadhaar. Your submission has "
        "been sent to HR to review — no further action is needed from you."
    ),
    Verdict.DUPLICATE: (
        "This Aadhaar is already registered against another employee record. "
        "Your submission has been sent to HR to resolve."
    ),
    Verdict.ERROR: (
        "We could not process your Aadhaar right now. Please try again shortly. "
        "If this keeps happening, contact HR."
    ),
}


#: What to say when the file never got past the security boundary.
#:
#: ⛔ WHY THIS TABLE EXISTS
#:
#:    Nine distinct ingest failures used to collapse into one sentence:
#:    "We could not open your file." An employee whose photo was 30 MB, one who
#:    uploaded a GIF, and one whose PDF was locked all read the same words and
#:    none of them learned what to do.
#:
#:    Worse, the generic text mentioned photos. Someone holding a perfectly good
#:    e-Aadhaar PDF was told to upload clearer JPEGs — advice they cannot act on,
#:    about a problem they do not have. Observed in the first real HRM
#:    integration test.
#:
#: ⚠ Every entry names an ACTION. "This file is too large" is a diagnosis;
#:   "please upload a smaller photo" is something a person can do next.
INGEST_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.PDF_PASSWORD_REQUIRED: (
        "This PDF is password-protected. Please enter its password — for an "
        "e-Aadhaar it is the first 4 letters of the name in CAPITALS followed by "
        "the year of birth, for example RAME1990."
    ),
    # ⛔ Does NOT say "your password was wrong", and deliberately so.
    #
    #    Two reasons. First, the renderer reports the same code for a wrong
    #    password and for an encryption scheme it cannot handle, so asserting
    #    which one happened would be a guess presented as a fact.
    #
    #    Second, and more important: the HRM usually DERIVES this password from
    #    the employee's profile, so in the common case the employee typed
    #    nothing at all. Telling them their password was wrong blames them for
    #    our guess — and the guess misses routinely, whenever the profile name
    #    differs from the name printed on the Aadhaar.
    ErrorCode.PDF_PASSWORD_INCORRECT: (
        "We could not open this PDF with the password we tried. Please enter the "
        "password for this file — for an e-Aadhaar it is the first 4 letters of "
        "the name in CAPITALS followed by the year of birth, for example RAME1990."
    ),
    ErrorCode.FILE_TOO_LARGE: (
        "This file is too large. Please upload a photo under 20 MB, or the "
        "original Aadhaar PDF."
    ),
    ErrorCode.FILE_TOO_SMALL: (
        "This image is too small to read the code. Please upload the full-size "
        "original rather than a thumbnail, a screenshot, or a copy forwarded "
        "through a messaging app."
    ),
    ErrorCode.UNSUPPORTED_MIME_TYPE: (
        "We cannot read this type of file. Please upload a JPEG, PNG or HEIC "
        "photo, or your Aadhaar PDF."
    ),
    ErrorCode.CORRUPT_IMAGE: (
        "This file appears to be damaged or incomplete. Please download it again, "
        "or take a fresh photo of your Aadhaar card."
    ),
    ErrorCode.DIMENSIONS_INVALID: (
        "This image is not a size we can read. Please upload an ordinary "
        "full-resolution photo taken with a camera."
    ),
    ErrorCode.DECOMPRESSION_BOMB: (
        "We could not process this file. Please upload an ordinary camera photo, "
        "or the original Aadhaar PDF."
    ),
    # ⛔ States what happened, accuses nobody. A scanner false positive is far
    #    more likely than an employee attaching malware to their own Aadhaar, and
    #    the wording must not imply otherwise.
    ErrorCode.MALWARE_DETECTED: (
        "This file was blocked by a security scan. Please upload a photo taken "
        "directly with your camera, or download a fresh e-Aadhaar PDF."
    ),
}


def message_for(verdict: Verdict, checks: dict[CheckName, CheckOutcome]) -> str:
    """The message shown to the employee.

    Where a check gives us something more specific and more useful, we say the
    more specific thing. "One side was too blurry" beats "we could not read the
    QR code", because it tells the person exactly which photo to retake.
    """
    base = MESSAGES[verdict]

    # ⛔ Runs for BOTH verdicts a failed ingest can produce.
    #
    #    A file that never passed validation yields UNREADABLE normally, but
    #    ERROR when the fault is ours (an empty trust store, for instance). The
    #    check was previously nested under UNREADABLE alone, so an ingest failure
    #    arriving as ERROR silently lost its specific message and fell back to
    #    "please try again shortly" — advice that will never work, because
    #    nothing about the file changes on a retry.
    validation = checks.get(CheckName.FILE_VALIDATION)
    if (
        verdict in (Verdict.UNREADABLE, Verdict.ERROR)
        and validation is not None
        and validation.result is CheckResult.FAIL
        and validation.error is not None
        and validation.error in INGEST_MESSAGES
    ):
        return INGEST_MESSAGES[validation.error]

    if verdict is Verdict.UNREADABLE:
        if validation is not None and validation.result is CheckResult.FAIL:
            # Reached only for an ingest failure with no entry in
            # INGEST_MESSAGES — a new ErrorCode that nobody has written wording
            # for yet. We never got as far as looking for a QR, so "we could not
            # read the QR code" would send the employee off to fix their
            # lighting when the file itself was the problem.
            return (
                "We could not open your file. Please upload a clear, "
                "full-resolution photo of both sides of your Aadhaar card, "
                "or your Aadhaar PDF."
            )

        decoded = checks.get(CheckName.QR_DECODED)
        detail = (decoded.detail or "") if decoded else ""
        if "front" in detail and "back" not in detail:
            return (
                "We could not read the QR code on the front of your card. The "
                "back may work better — please retake both photos in good light."
            )
        if "back" in detail and "front" not in detail:
            return (
                "We could not read the QR code on the back of your card. Please "
                "retake that photo in good light, holding the card flat."
            )

    if verdict is Verdict.VERIFIED:
        agreement = checks.get(CheckName.SIDE_AGREEMENT)
        # ⚠ Only when a SECOND face was actually submitted and turned out to be
        #   unusable. A single-document upload (one PDF, §11) also reports SKIP,
        #   and telling that employee "one of the photos was unclear" sends them
        #   looking for a bad photo they never uploaded.
        if (
            agreement is not None
            and agreement.result is CheckResult.SKIP
            and "single document" not in (agreement.detail or "")
        ):
            return (
                "Your Aadhaar has been verified. One of the photos was unclear, "
                "but the QR code confirmed your details."
            )

    return base
