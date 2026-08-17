"""Malware scanning — Step 3. Optional, feature-flagged.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 3
Provides : MalwareScanner (Protocol), ClamAvScanner, NullScanner, ScanResult
Consumes : nothing (ClamAV reached over its own socket)
Used by  : avs.ingest.validator

Scanning runs on the ORIGINAL bytes, before any decoder sees them.

ClamAV is optional by design. Many deployments will not have a daemon available,
and the pipeline's other controls — magic-byte allow-listing, size and bomb
guards, a sandboxed container — do the heavy lifting. When no scanner is
configured the pipeline simply skips this stage rather than failing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

__all__ = ["ClamAvScanner", "MalwareScanner", "NullScanner", "ScanResult"]


@dataclass(frozen=True, slots=True)
class ScanResult:
    clean: bool
    signature: str | None = None
    scanner: str = "none"


@runtime_checkable
class MalwareScanner(Protocol):
    def scan(self, data: bytes) -> ScanResult: ...


class NullScanner:
    """Passes everything. Explicit no-op, so the absence of scanning is visible
    in configuration rather than implied by a None."""

    def scan(self, data: bytes) -> ScanResult:
        return ScanResult(clean=True, scanner="null")


class ClamAvScanner:
    """Scans via a clamd daemon over TCP or a Unix socket.

    ⚠ Fails CLOSED. If the daemon is unreachable, ``scan`` reports *not clean*
      rather than silently waving the file through. A scanner that quietly stops
      scanning is worse than no scanner, because operators believe they are
      protected. Set ``fail_open=True`` only if you accept that trade-off
      knowingly.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 3310,
        *,
        unix_socket: str | None = None,
        timeout: float = 10.0,
        fail_open: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.unix_socket = unix_socket
        self.timeout = timeout
        self.fail_open = fail_open

    def scan(self, data: bytes) -> ScanResult:
        try:
            import pyclamd
        except ImportError:
            return self._unavailable("pyclamd is not installed")

        try:
            daemon = (
                pyclamd.ClamdUnixSocket(filename=self.unix_socket, timeout=self.timeout)
                if self.unix_socket
                else pyclamd.ClamdNetworkSocket(
                    host=self.host, port=self.port, timeout=self.timeout
                )
            )
            result = daemon.scan_stream(data)
        except Exception as exc:
            return self._unavailable(f"clamd unreachable: {exc}")

        if result is None:
            return ScanResult(clean=True, scanner="clamav")

        signature = next(iter(result.values()))[1] if result else "unknown"
        return ScanResult(clean=False, signature=str(signature), scanner="clamav")

    def _unavailable(self, reason: str) -> ScanResult:
        if self.fail_open:
            return ScanResult(clean=True, signature=None, scanner=f"clamav-unavailable({reason})")
        return ScanResult(clean=False, signature=f"scanner unavailable: {reason}", scanner="clamav")
