"""FastAPI Application Entrypoint for Secure Banking & Finance Assistant."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.audit import router as audit_router
from app.api.chat import router as chat_router
from app.api.complaints import router as complaints_router
from app.api.tokens import router as tokens_router
from app.core.config import settings
from app.core.logging import logger, setup_logging
from app.db.database import engine, init_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle context manager for startup and graceful shutdown."""
    setup_logging(settings.LOG_LEVEL)
    logger.info(
        f"Starting {settings.APP_NAME} in environment={settings.APP_ENV}",
        extra={"action_type": "SYSTEM_STARTUP"},
    )

    # Initialize DB tables for POC if in local/dev mode
    try:
        await init_db()
    except Exception as exc:
        logger.warning(
            f"Database auto-initialization skipped or encountered an error: {str(exc)}"
        )

    yield

    logger.info("Shutting down application and disposing database connection pool...")
    await engine.dispose()


app = FastAPI(
    title="Secure Banking & Finance Assistant API",
    description=(
        "Production-grade POC for PII-redacted customer complaint summarization, "
        "banking procedure Q&A with Amazon Bedrock, and an append-only PostgreSQL audit trail."
    ),
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan,
)

# Apply restrictive CORS policy
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.DEBUG else [],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Enforce strict defensive HTTP response headers."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';"
    return response


@app.exception_handler(Exception)
async def global_sanitized_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Ensure no unhandled exception details or stack traces leak to callers."""
    logger.error(
        f"Unhandled system error: {str(exc)}",
        exc_info=True,
        extra={"action_type": "UNHANDLED_EXCEPTION"},
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred. The incident has been recorded safely.",
        },
    )


# Health Check Endpoint
@app.get("/health", tags=["Health & Readiness"], summary="Liveness & Readiness Probe")
async def health_check():
    """Service liveness probe confirming core dependencies."""
    db_status = "healthy"
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:
        db_status = f"unhealthy: {type(exc).__name__}"

    return {
        "service": settings.APP_NAME,
        "status": "UP" if db_status == "healthy" else "DEGRADED",
        "database": db_status,
        "environment": settings.APP_ENV,
        "bedrock_model": settings.BEDROCK_MODEL_ID,
        "guardrails_configured": bool(settings.BEDROCK_GUARDRAIL_ID),
    }


# Register API v1 Routers
app.include_router(complaints_router, prefix=settings.API_V1_STR)
app.include_router(chat_router, prefix=settings.API_V1_STR)
app.include_router(audit_router, prefix=settings.API_V1_STR)
app.include_router(tokens_router, prefix=settings.API_V1_STR)
