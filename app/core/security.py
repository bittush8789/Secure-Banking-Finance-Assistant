"""Security, authentication, and token verification primitives for Microsoft Entra ID."""

import time
from typing import Any, Dict, List, Optional
import httpx
import jwt
from jwt import PyJWKClient, PyJWTError
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.logging import logger


class AuthenticatedUser(BaseModel):
    """Represents an authenticated user/service principal extracted from an Entra ID token."""

    actor_id: str = Field(description="Unique actor identifier (oid or sub)")
    tenant_id: str = Field(description="Azure AD Tenant UUID")
    roles: List[str] = Field(default_factory=list, description="Application roles assigned in Entra ID")
    scopes: List[str] = Field(default_factory=list, description="Delegated permissions (scp claim)")
    username: Optional[str] = Field(default=None, description="UPN or preferred username if present")
    client_id: Optional[str] = Field(default=None, description="App/Client ID of calling application (azp/appid)")

    def has_role(self, required_role: str) -> bool:
        """Check if user has a specific role or admin access."""
        return required_role in self.roles or "Admin" in self.roles or "Banking.Admin" in self.roles

    def has_any_role(self, required_roles: List[str]) -> bool:
        """Check if user has at least one of the required roles."""
        return any(self.has_role(r) for r in required_roles)


class EntraIDTokenValidator:
    """Validates JWT bearer tokens against Microsoft Entra ID OpenID Connect / JWKS."""

    def __init__(self):
        self._jwks_client: Optional[PyJWKClient] = None
        self._cached_jwks_url: Optional[str] = None
        self._mock_public_key: Optional[str] = None

    def _get_jwks_url(self) -> str:
        return f"https://login.microsoftonline.com/{settings.ENTRA_TENANT_ID}/discovery/v2.0/keys"

    def _get_jwks_client(self) -> PyJWKClient:
        jwks_url = self._get_jwks_url()
        if self._jwks_client is None or self._cached_jwks_url != jwks_url:
            self._cached_jwks_url = jwks_url
            self._jwks_client = PyJWKClient(
                uri=jwks_url,
                cache_keys=True,
                max_cached_keys=16,
                cache_jwk_set=True,
                lifespan=settings.ENTRA_JWKS_CACHE_TTL_SECONDS,
            )
        return self._jwks_client

    def set_mock_public_key(self, public_key_pem: str) -> None:
        """Set a static public key for testing environments."""
        self._mock_public_key = public_key_pem

    def validate_token(self, token: str) -> AuthenticatedUser:
        """Validate an incoming bearer token strictly against Entra ID requirements.

        Performs:
        1. Unverified header inspection for kid / algorithm
        2. Signature verification using signing key from JWKS
        3. Audience verification (aud == settings.ENTRA_AUDIENCE)
        4. Issuer verification (iss == settings.ENTRA_ISSUER)
        5. Expiration (exp) and Not Before (nbf) verification
        6. Tenant verification (tid == settings.ENTRA_TENANT_ID)
        """
        if not token or not isinstance(token, str):
            raise TokenValidationError("Authorization token is missing or empty")

        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        # Offline / Test Mock Mode Handler
        if settings.AUTH_MOCK_ENABLED and self._mock_public_key:
            return self._validate_with_mock_key(token)

        try:
            # 1. Obtain signing key from Entra ID JWKS endpoint
            jwks_client = self._get_jwks_client()
            signing_key = jwks_client.get_signing_key_from_jwt(token)

            # 2. Decode and verify JWT
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=settings.ENTRA_AUDIENCE,
                issuer=settings.ENTRA_ISSUER,
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "require": ["exp", "iss", "aud", "sub"],
                },
            )
            return self._extract_user_from_payload(payload)

        except jwt.ExpiredSignatureError:
            logger.warning("Token validation failed: Signature has expired")
            raise TokenValidationError("Bearer token has expired")
        except jwt.InvalidAudienceError:
            logger.warning("Token validation failed: Invalid audience")
            raise TokenValidationError("Bearer token audience mismatch")
        except jwt.InvalidIssuerError:
            logger.warning("Token validation failed: Invalid issuer")
            raise TokenValidationError("Bearer token issuer mismatch")
        except PyJWTError as exc:
            logger.warning(f"Token validation failed: {type(exc).__name__}")
            raise TokenValidationError(f"Invalid bearer token: {str(exc)}")
        except Exception as exc:
            logger.error(f"Unexpected error during token validation: {str(exc)}")
            raise TokenValidationError("Token validation service unavailable")

    def _validate_with_mock_key(self, token: str) -> AuthenticatedUser:
        """Internal mock verification for isolated unit tests without network calls."""
        try:
            payload = jwt.decode(
                token,
                self._mock_public_key,
                algorithms=["RS256", "HS256"],
                audience=settings.ENTRA_AUDIENCE,
                issuer=settings.ENTRA_ISSUER,
                options={"verify_signature": True, "verify_aud": True, "verify_iss": True, "verify_exp": True},
            )
            return self._extract_user_from_payload(payload)
        except PyJWTError as exc:
            raise TokenValidationError(f"Mock token validation failed: {str(exc)}")

    def _extract_user_from_payload(self, payload: Dict[str, Any]) -> AuthenticatedUser:
        """Extract and enforce tenant & identity claims from verified payload."""
        # Enforce tenant isolation
        token_tid = payload.get("tid")
        if settings.ENTRA_TENANT_ID != "00000000-0000-0000-0000-000000000000":
            if not token_tid or token_tid.lower() != settings.ENTRA_TENANT_ID.lower():
                logger.warning("Token validation failed: Tenant ID mismatch")
                raise TokenValidationError("Cross-tenant access forbidden: Tenant ID mismatch")

        # Identity extraction: prefer oid (unique user object id in AAD), fallback to sub
        actor_id = payload.get("oid") or payload.get("sub")
        if not actor_id:
            raise TokenValidationError("Token lacks valid subject or object identifier")

        # Roles extraction: Entra ID emits roles in 'roles' array claim
        roles: List[str] = payload.get("roles", [])
        if isinstance(roles, str):
            roles = [roles]

        # Scopes extraction: delegated permissions are in 'scp' space-delimited string
        scopes_raw = payload.get("scp", "")
        scopes: List[str] = scopes_raw.split() if isinstance(scopes_raw, str) and scopes_raw else []

        username = payload.get("preferred_username") or payload.get("upn") or payload.get("email")
        client_id = payload.get("azp") or payload.get("appid")

        return AuthenticatedUser(
            actor_id=str(actor_id),
            tenant_id=str(token_tid or settings.ENTRA_TENANT_ID),
            roles=roles,
            scopes=scopes,
            username=username,
            client_id=client_id,
        )


class TokenValidationError(Exception):
    """Raised when bearer token validation fails."""

    pass


# Global token validator instance
entra_validator = EntraIDTokenValidator()
