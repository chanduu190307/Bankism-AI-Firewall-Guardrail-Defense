"""FastAPI application entrypoint for Bankism AI Firewall & Guardrail Defense."""

from collections.abc import Awaitable, Callable
from pathlib import Path

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from bankism.app.api.routes import router
from bankism.app.core.config import get_settings
from bankism.app.core.errors import BankismError
from bankism.app.core.logging import logger

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Production-grade defensive AI security gateway and guardrail layer. "
        "Enforces deterministic security boundaries and prompt-injection defense."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware with controlled origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits local development and frontend dashboard
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# Request Size Limit Middleware (enforces max 64 KB payload boundary)
@app.middleware("http")
async def enforce_request_size_limit(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.max_request_bytes:
                return JSONResponse(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    content={
                        "error": "PAYLOAD_TOO_LARGE",
                        "message": (
                            f"Payload exceeds maximum allowed size of "
                            f"{settings.max_request_bytes} bytes."
                        ),
                    },
                )
        except ValueError:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": "INVALID_HEADER",
                    "message": "Malformed Content-Length header.",
                },
            )

    # Security headers on all outgoing responses
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Global sanitized error handlers (never expose raw stack traces)
@app.exception_handler(RequestValidationError)
async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    logger.warning("Validation error on %s: %s", request.url.path, str(exc))
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={
            "error": "VALIDATION_ERROR",
            "message": "The submitted request failed schema or constraint validation.",
            "details": [
                {"loc": list(err.get("loc", [])), "msg": err.get("msg", "")} for err in exc.errors()
            ],
        },
    )


@app.exception_handler(BankismError)
async def handle_domain_error(request: Request, exc: BankismError) -> JSONResponse:
    logger.error("Domain error on %s: %s", request.url.path, exc.message)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": exc.__class__.__name__, "message": exc.message},
    )


@app.exception_handler(Exception)
async def handle_generic_exception(request: Request, exc: Exception) -> JSONResponse:
    # Log internal error with redaction, but return sanitized message to client
    logger.exception("Unhandled server exception on %s", request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "message": "An internal error occurred while processing the request.",
        },
    )


# Include API routes
app.include_router(router)

# Mount frontend static distribution if built
frontend_dist_path = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if frontend_dist_path.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist_path), html=True), name="frontend")
