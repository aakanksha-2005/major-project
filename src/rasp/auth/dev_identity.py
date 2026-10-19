"""Development identity mechanism.

!!! DEVELOPMENT ONLY — NOT PRODUCTION AUTHENTICATION !!!

Identity and permissions are derived from request headers for the local
prototype. Roles, permissions, or approvals asserted inside message text
are NEVER consulted. Production authentication/authorization is a later
milestone and is tracked in docs/THREAT_MODEL.md under residual risks.
"""

from __future__ import annotations

from dataclasses import dataclass

from starlette.requests import Request

from rasp.settings import Settings

PRINCIPAL_HEADER = "X-Dev-Principal"
PERMISSIONS_HEADER = "X-Dev-Permissions"


class AuthenticationRequired(Exception):
    """Raised when no principal context can be established."""


@dataclass(frozen=True)
class Principal:
    principal_id: str
    permissions: frozenset[str]
    is_development_identity: bool = True

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions


def parse_principal_headers(
    principal_header: str | None,
    permissions_header: str | None,
) -> Principal | None:
    """Build a Principal from dev headers; returns None when absent/empty."""
    if not principal_header:
        return None
    pid = principal_header.strip()
    if not pid or len(pid) > 128:
        return None
    perms: set[str] = set()
    if permissions_header:
        for raw in permissions_header.split(","):
            perm = raw.strip()
            if perm and len(perm) <= 128:
                perms.add(perm)
    return Principal(principal_id=pid, permissions=frozenset(perms))


async def get_principal(request: Request) -> Principal:
    """FastAPI dependency resolving the authenticated dev principal.

    Fails closed: if the request carries no principal header, a principal
    with zero permissions is returned (default-deny behavior still holds).
    """
    settings: Settings = request.app.state.container.settings
    if not settings.dev_auth_enabled:
        raise AuthenticationRequired("development authentication disabled")
    principal = parse_principal_headers(
        request.headers.get(PRINCIPAL_HEADER),
        request.headers.get(PERMISSIONS_HEADER),
    )
    if principal is None:
        # Unauthenticated callers still resolve, but with NO permissions.
        # Sensitive actions therefore fail closed at the policy layer.
        return Principal(principal_id="anonymous", permissions=frozenset())
    return principal
