"""avs.ai — AI layer.

GOVERNING RULE (see CONTRACTS.md section 7):
    No module in this package may produce or influence a Verdict.
    AI operates on the INPUT side and the HUMAN-ASSIST side only.
    The verdict comes solely from avs.crypto.verify().

Every AI module must degrade gracefully: if its model fails to load,
the pipeline continues using the deterministic path.
"""

__all__: list[str] = []
