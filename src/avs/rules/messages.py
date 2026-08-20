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

from avs.contracts import CheckName, CheckOutcome, CheckResult, Verdict

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


def message_for(verdict: Verdict, checks: dict[CheckName, CheckOutcome]) -> str:
    """The message shown to the employee.

    Where a check gives us something more specific and more useful, we say the
    more specific thing. "One side was too blurry" beats "we could not read the
    QR code", because it tells the person exactly which photo to retake.
    """
    base = MESSAGES[verdict]

    if verdict is Verdict.UNREADABLE:
        validation = checks.get(CheckName.FILE_VALIDATION)
        if validation is not None and validation.result is CheckResult.FAIL:
            # We never got as far as looking for a QR. Saying "we could not read
            # the QR code" would send the employee off to fix their lighting when
            # the file itself was the problem.
            return (
                "We could not open your photos. Please upload clear, "
                "full-resolution JPEG or PNG images of both sides of your "
                "Aadhaar card."
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
