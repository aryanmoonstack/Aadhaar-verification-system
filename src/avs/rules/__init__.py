"""avs.rules — the deterministic verdict engine.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 6
Provides : DeterministicVerdictEngine.decide(checks, proof) -> VerificationResult,
           MESSAGES, message_for()
Consumes : avs.contracts
Used by  : avs.pipeline
Status   : COMPLETE

⛔ SEES ONLY CheckOutcome + SignatureProof. Never model confidences, never raw
   images, never demographic data. That is how CONTRACTS.md §7 is enforced
   structurally — the decision layer physically cannot consult an AI output.

Rule 1: VERIFIED requires proof.valid is True. Nothing else produces it.
Rule 2: nothing is ever auto-rejected.

And the distinction that matters most: SIGNATURE_INVALID means the document was
altered (TAMPERED); TRUSTSTORE_EMPTY means WE are misconfigured (ERROR). Never
blame the employee for our operational mistake.
"""

from avs.rules.engine import DeterministicVerdictEngine
from avs.rules.messages import MESSAGES, message_for

__all__ = ["MESSAGES", "DeterministicVerdictEngine", "message_for"]
