"""Tenant registry and per-tenant policy — Step 8.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 8
Provides : TenantConfig, TenantRegistry (Protocol), FileTenantRegistry, InMemoryTenantRegistry
Consumes : avs.contracts
Used by  : avs.api, avs.security.signing
Status   : COMPLETE

WHAT A TENANT IS
----------------
One HRM installation. M-One is multi-tenant, so a single AVS deployment serves
several companies, and each needs its own signing secret and its own policy —
one company may want STRICT verification while another accepts STANDARD.

⛔ SECRETS NEVER LIVE IN THE REPOSITORY.
   The registry file holds tenant ids, policy and the NAME of an environment
   variable. The secret itself is read from the environment at load time. A
   registry file is therefore safe to commit and safe to put in a config map;
   the secrets ride separately, in whatever secret manager the deployment uses.

   `FileTenantRegistry` refuses to load a tenant whose secret is missing,
   short, or one of the well-known placeholder strings. A service that silently
   starts with `changeme` as a signing key is worse than one that refuses to
   start, because nothing looks wrong until it is exploited.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from avs.contracts import Strictness

__all__ = [
    "MIN_SECRET_LENGTH",
    "FileTenantRegistry",
    "InMemoryTenantRegistry",
    "TenantConfig",
    "TenantRegistry",
    "TenantRegistryError",
]

#: A 256-bit key rendered as hex is 64 characters. Anything materially shorter
#: is a human-chosen string, and human-chosen strings are guessable.
MIN_SECRET_LENGTH = 32

#: Strings that mean "nobody has set this yet".
_PLACEHOLDERS = frozenset(
    {
        "changeme",
        "change-me",
        "secret",
        "password",
        "test",
        "todo",
        "xxx",
        "placeholder",
        "your-secret-here",
        "local-development-key",
    }
)


class TenantRegistryError(Exception):
    """The registry could not be loaded, or a tenant is misconfigured."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class TenantConfig:
    """One HRM installation's identity and policy."""

    tenant_id: str
    secret: str = field(repr=False)
    """HMAC signing key. ``repr=False`` so it cannot land in a traceback."""

    name: str = ""
    strictness: Strictness = Strictness.STANDARD
    time_budget_seconds: float = 12.0
    enabled: bool = True

    callback_secret: str = field(default="", repr=False)
    """Key for signing callbacks TO this tenant. Defaults to `secret` when empty
    — separate keys per direction are better practice but not worth forcing on
    an integrator who has not asked for it."""

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise TenantRegistryError("tenant_id must not be empty")
        _reject_weak_secret(self.tenant_id, self.secret)

    @property
    def outbound_secret(self) -> str:
        return self.callback_secret or self.secret


def _reject_weak_secret(tenant_id: str, secret: str) -> None:
    """⛔ Refuse at construction, never at first use.

    A weak signing key that only fails when someone attacks it is not a
    failure mode we can detect. Failing at startup is loud, immediate, and
    happens in front of whoever is doing the deployment.
    """
    if not secret:
        raise TenantRegistryError(f"tenant {tenant_id!r} has no signing secret")
    if secret.strip().lower() in _PLACEHOLDERS:
        raise TenantRegistryError(
            f"tenant {tenant_id!r} is using the placeholder secret {secret!r}"
        )
    if len(secret) < MIN_SECRET_LENGTH:
        raise TenantRegistryError(
            f"tenant {tenant_id!r} has a {len(secret)}-character secret; "
            f"minimum is {MIN_SECRET_LENGTH}. Generate one with "
            f'`python -c "import secrets; print(secrets.token_hex(32))"`'
        )


@runtime_checkable
class TenantRegistry(Protocol):
    """Where tenant configuration comes from.

    A Protocol so a deployment can back this with a database or a secret
    manager without touching anything above it.
    """

    def get(self, tenant_id: str) -> TenantConfig | None:
        """The tenant, or None if unknown or disabled."""
        ...

    def secret_for(self, tenant_id: str) -> str | None:
        """Signing key, or None. Used directly by the signature verifier."""
        ...

    @property
    def tenant_ids(self) -> list[str]:
        """For health reporting. Ids only — never secrets."""
        ...


class InMemoryTenantRegistry:
    """Registry from a list of configs. For tests and single-tenant deployments."""

    def __init__(self, tenants: list[TenantConfig] | None = None) -> None:
        self._tenants = {t.tenant_id: t for t in (tenants or [])}

    def get(self, tenant_id: str) -> TenantConfig | None:
        tenant = self._tenants.get(tenant_id)
        return tenant if tenant and tenant.enabled else None

    def secret_for(self, tenant_id: str) -> str | None:
        tenant = self.get(tenant_id)
        return tenant.secret if tenant else None

    @property
    def tenant_ids(self) -> list[str]:
        return sorted(t for t, c in self._tenants.items() if c.enabled)


class FileTenantRegistry:
    """Registry from a JSON file, with secrets resolved from the environment.

    The file is safe to commit. Example::

        {
          "tenants": [
            {
              "tenant_id": "m-one-prod",
              "name": "M-One HRM production",
              "secret_env": "AVS_TENANT_M_ONE_PROD_SECRET",
              "strictness": "STANDARD",
              "time_budget_seconds": 12.0
            }
          ]
        }

    ``secret_env`` names an environment variable. The secret is never written
    here, so this file can live in git and in a Kubernetes ConfigMap.
    """

    def __init__(self, path: str | Path, *, environ: dict[str, str] | None = None) -> None:
        self.path = Path(path)
        self._environ = environ if environ is not None else dict(os.environ)
        self._tenants: dict[str, TenantConfig] = {}
        self._loaded = False

    def load(self) -> None:
        """Read and validate. Raises TenantRegistryError on any problem."""
        if not self.path.is_file():
            raise TenantRegistryError(f"tenant registry not found: {self.path}")

        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TenantRegistryError(f"could not read {self.path}: {exc}") from exc

        entries = document.get("tenants")
        if not isinstance(entries, list) or not entries:
            raise TenantRegistryError(f"{self.path} declares no tenants")

        tenants: dict[str, TenantConfig] = {}
        for entry in entries:
            tenant = self._build(entry)
            if tenant.tenant_id in tenants:
                raise TenantRegistryError(f"duplicate tenant_id {tenant.tenant_id!r}")
            tenants[tenant.tenant_id] = tenant

        self._tenants = tenants
        self._loaded = True

    def _build(self, entry: dict) -> TenantConfig:
        tenant_id = str(entry.get("tenant_id", "")).strip()
        if not tenant_id:
            raise TenantRegistryError(f"a tenant entry in {self.path} has no tenant_id")

        variable = entry.get("secret_env")
        if not variable:
            raise TenantRegistryError(
                f"tenant {tenant_id!r} has no 'secret_env'. Secrets are read from the "
                f"environment, never stored in {self.path}."
            )

        secret = self._environ.get(str(variable), "")
        if not secret:
            raise TenantRegistryError(
                f"tenant {tenant_id!r} expects its secret in ${variable}, which is not set"
            )

        callback_variable = entry.get("callback_secret_env")
        callback_secret = self._environ.get(str(callback_variable), "") if callback_variable else ""

        strictness_name = str(entry.get("strictness", "STANDARD")).upper()
        try:
            strictness = Strictness(strictness_name)
        except ValueError as exc:
            raise TenantRegistryError(
                f"tenant {tenant_id!r} has unknown strictness {strictness_name!r}"
            ) from exc

        return TenantConfig(
            tenant_id=tenant_id,
            secret=secret,
            name=str(entry.get("name", "")),
            strictness=strictness,
            time_budget_seconds=float(entry.get("time_budget_seconds", 12.0)),
            enabled=bool(entry.get("enabled", True)),
            callback_secret=callback_secret,
        )

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    def get(self, tenant_id: str) -> TenantConfig | None:
        self._ensure_loaded()
        tenant = self._tenants.get(tenant_id)
        return tenant if tenant and tenant.enabled else None

    def secret_for(self, tenant_id: str) -> str | None:
        tenant = self.get(tenant_id)
        return tenant.secret if tenant else None

    @property
    def tenant_ids(self) -> list[str]:
        self._ensure_loaded()
        return sorted(t for t, c in self._tenants.items() if c.enabled)
