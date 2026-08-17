"""avs.config — settings.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 0 (extended in Step 8 with per-tenant policy)
Provides : Settings, get_settings()
Consumes : nothing
"""

from avs.config.settings import Settings, get_settings

__all__ = ["Settings", "get_settings"]
