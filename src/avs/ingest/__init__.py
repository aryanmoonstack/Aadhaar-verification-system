"""avs.ingest — file intake and validation. The first security boundary.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 3
Provides : ImageIngestor.ingest(bytes) -> ValidatedImage, IngestError,
           detect(), FileKind, MalwareScanner, ClamAvScanner, NullScanner
Consumes : avs.contracts, Pillow
Used by  : avs.imaging (Step 4)
Status   : COMPLETE

ORDER OF CHECKS (cheapest and safest first — see validator.py)
    size -> magic bytes -> allow-list -> malware scan -> header read ->
    bomb guards -> decode

A malicious file should be rejected by the earliest possible check, never by
the decoder.

PRIVACY: all EXIF metadata is stripped during normalisation, GPS coordinates
included. Orientation is applied first so the image stays upright.
"""

from avs.ingest.errors import IngestError
from avs.ingest.magic import ALLOWED_MIME_TYPES, DetectedType, FileKind, detect
from avs.ingest.scanner import ClamAvScanner, MalwareScanner, NullScanner, ScanResult
from avs.ingest.validator import HEIF_AVAILABLE, ImageIngestor

__all__ = [
    "ALLOWED_MIME_TYPES",
    "HEIF_AVAILABLE",
    "ClamAvScanner",
    "DetectedType",
    "FileKind",
    "ImageIngestor",
    "IngestError",
    "MalwareScanner",
    "NullScanner",
    "ScanResult",
    "detect",
]
