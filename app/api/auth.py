"""Authentication and RBAC dependency injectors for FastAPI routes."""

from typing import Callable, List, Optional
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.logging import logger
from app.core.security import AuthenticatedUser, TokenValidationError, entra_validator

# Standard bearer scheme
security_bearer = HTTPBearer(auto_error=False)


def get_client_ip(request: Request) -> str:
    """Extract client IP safely from proxy headers or socket address."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Return first hop (client IP)
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> AuthenticatedUser:
    """Validate Microsoft Entra ID JWT Bearer token and return AuthenticatedUser."""
    if not credentials or not credentials.credentials:
        logger.warning("Unauthenticated request: missing Authorization header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide a valid Bearer token in Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user = entra_validator.validate_token(credentials.credentials)
        return user
    except TokenValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )


def require_roles(allowed_roles: List[str]) -> Callable[[AuthenticatedUser], AuthenticatedUser]:
    """Dependency factory enforcing that authenticated user holds at least one allowed role."""

    async def role_checker(
        current_user: AuthenticatedUser = Depends(get_current_user),
    ) -> AuthenticatedUser:
        if not current_user.has_any_role(allowed_roles):
            logger.warning(
                f"Access denied for actor={current_user.actor_id}: Requires one of {allowed_roles}, possessed={current_user.roles}",
                extra={"actor_id": current_user.actor_id, "action_type": "RBAC_ACCESS_DENIED"},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: User lacks required role. Allowed roles: {', '.join(allowed_roles)}",
            )
        return current_user

    return role_checker


# Common RBAC dependencies
require_complaint_analyst = require_roles(["Complaints.Analyst", "Banking.Employee", "Admin"])
require_banking_reader = require_roles(["Banking.Reader", "Banking.Employee", "Admin"])
require_audit_viewer = require_roles(["Audit.Viewer", "Compliance.Officer", "Admin"])
require_token_admin = require_roles(["TokenVault.Admin", "Compliance.Officer", "SecurityAdmin"])
