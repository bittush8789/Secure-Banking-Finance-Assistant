"""API router for restricted token restoration and de-anonymization."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_client_ip, require_token_admin
from app.core.security import AuthenticatedUser
from app.db.database import get_db_session
from app.schemas.token import TokenRestoreRequest, TokenRestoreResponse
from app.services.token_vault import (
    TokenNotFoundError,
    TokenVaultEncryptionError,
    UnauthorizedTokenRestorationError,
    token_vault_service,
)

router = APIRouter(prefix="/tokens", tags=["Token Vault"])


@router.post(
    "/restore",
    response_model=TokenRestoreResponse,
    summary="Restore De-anonymized Value from Token Vault",
    description=(
        "Decrypts and retrieves the original sensitive PII value corresponding to an opaque token. "
        "Strictly restricted to TokenVault.Admin or Compliance.Officer roles with verified justification. "
        "Audits every restoration access attempt."
    ),
)
async def restore_token(
    request: Request,
    payload: TokenRestoreRequest,
    current_user: AuthenticatedUser = Depends(require_token_admin),
    db: AsyncSession = Depends(get_db_session),
) -> TokenRestoreResponse:
    client_ip = get_client_ip(request)

    try:
        result = await token_vault_service.restore_token(
            token_id=payload.token_id,
            user=current_user,
            justification=payload.justification_reason,
            session=db,
            client_ip=client_ip,
        )
        return TokenRestoreResponse(
            token_id=result["token_id"],
            token_type=result["token_type"],
            restored_value=result["original_value"],
            restored_at=datetime.now(timezone.utc),
        )
    except UnauthorizedTokenRestorationError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except TokenNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except TokenVaultEncryptionError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cryptographic key error: {str(exc)}",
        )
