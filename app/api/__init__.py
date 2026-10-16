"""API routers collection."""

from app.api.auth import get_current_user, require_roles
from app.api.complaints import router as complaints_router
from app.api.chat import router as chat_router
from app.api.audit import router as audit_router
from app.api.tokens import router as tokens_router

__all__ = [
    "get_current_user",
    "require_roles",
    "complaints_router",
    "chat_router",
    "audit_router",
    "tokens_router",
]
