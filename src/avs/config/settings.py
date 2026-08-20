"""Application settings, loaded from environment / .env.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 0
Provides : Settings, get_settings()
Consumes : nothing
Extended : Step 8 adds per-tenant policy overrides on top of these defaults

Limits declared here mirror CONTRACTS.md §9. Changing them is a contract change.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["Settings", "get_settings"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AVS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Service ──────────────────────────────────────────────────────────────
    environment: str = Field(default="development")
    log_level: str = Field(default="INFO")
    log_json: bool = Field(default=True)

    # ── Trust store (Step 2) ─────────────────────────────────────────────────
    cert_dir: Path = Field(
        default=Path("certs"),
        description="Directory of UIDAI public certificates. Loaded at startup, "
        "never fetched at runtime.",
    )
    cert_expiry_warn_days: int = Field(
        default=90, description="Alert threshold — CONTRACTS.md operational requirement"
    )

    # ── Ingest limits (Step 3) — mirror CONTRACTS.md §9 ──────────────────────
    max_file_bytes: int = Field(default=20 * 1024 * 1024)
    min_file_bytes: int = Field(default=50 * 1024)
    min_width: int = Field(default=640)
    min_height: int = Field(default=480)
    max_dimension: int = Field(default=12_000)
    allowed_mime_types: tuple[str, ...] = Field(
        default=(
            "image/jpeg",
            "image/png",
            "image/heic",
            "image/heif",
            "image/webp",
            "application/pdf",
        )
    )

    # ── PDF (CONTRACTS.md 2.0.0) ─────────────────────────────────────────────
    pdf_render_dpi: int = Field(
        default=300,
        description="⚠ Below ~150 the Secure QR falls under 2.0 pixels per module "
        "and stops decoding. See avs.ingest.pdf.DEFAULT_RENDER_DPI for the arithmetic.",
    )
    pdf_max_pages: int = Field(
        default=4,
        description="Pages beyond this are ignored. Bounds a PDF that declares "
        "thousands of pages, which is a denial of service rather than a document.",
    )
    pdf_max_pixels_per_byte: float = Field(
        default=1000.0,
        description="⛔ Deliberately far above the 150 used for photographs. "
        "Rendered pages are mostly flat white and compress far better — a "
        "near-blank A4 page measures 262 px/byte, so the photograph limit "
        "would reject valid e-Aadhaar pages. max_pixels still bounds memory.",
    )
    enable_malware_scan: bool = Field(default=False, description="Requires ClamAV")

    # ── Crypto (Step 1) ──────────────────────────────────────────────────────
    signature_byte_length: int = Field(
        default=256,
        description="⚠ CONTRACTS.md §5 security invariant. Do not change without "
        "re-running the full genuine + tampered corpus.",
    )

    # ── Privacy (Step 6) ─────────────────────────────────────────────────────
    reference_hash_secret: str = Field(
        default="CHANGE-ME-IN-PRODUCTION",
        description="HMAC key for salting reference IDs. Must come from a vault in prod.",
    )
    purge_after_hours: int = Field(default=24)

    # ── AI (Steps 12-21) — every model is optional ───────────────────────────
    model_dir: Path = Field(default=Path("models"))
    enable_ai_classify: bool = Field(default=False)
    enable_ai_quality: bool = Field(default=False)
    enable_ai_localize: bool = Field(default=False)
    enable_ai_restore: bool = Field(default=False)
    enable_ai_namematch: bool = Field(default=False)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
