"""avs.privacy — data minimisation at the service boundary.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 6
Provides : DataMinimisingFilter.apply(result) -> VerificationResult, REDACTED
Consumes : avs.contracts
Used by  : avs.pipeline
Status   : COMPLETE

Runs ONCE, at the boundary, over the finished result. Minimisation scattered
inline fails the first time a new code path forgets it; a single gate does not.

Destroyed: reference_id (replaced by a salted HMAC), the signed photograph, and
the address unless the tenant explicitly asks for it.
Kept: name, DOB, gender, last-4, reference hash, verdict, proof, checks.
"""

from avs.privacy.filter import REDACTED, DataMinimisingFilter

__all__ = ["REDACTED", "DataMinimisingFilter"]
