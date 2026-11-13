"""Centralized domain exceptions and sanitized FastAPI handlers (OWASP A10:2025)."""

import logging
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger("websec.exceptions")


class WebSecBaseError(Exception):
    """Base application exception with safe public message and HTTP status mapping."""

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_code: str = "INTERNAL_ERROR"

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
        status_code: int | None = None,
        error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}
        if status_code is not None:
            self.status_code = status_code
        if error_code is not None:
            self.error_code = error_code


class TargetValidationError(WebSecBaseError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    error_code = "INVALID_TARGET"


class SSRFBlockedError(WebSecBaseError):
    status_code = status.HTTP_403_FORBIDDEN
    error_code = "SSRF_TARGET_BLOCKED"


class AuthorizationRequiredError(WebSecBaseError):
    status_code = status.HTTP_400_BAD_REQUEST
    error_code = "AUTHORIZATION_REQUIRED"


class DomainNotVerifiedError(WebSecBaseError):
    status_code = status.HTTP_403_FORBIDDEN
    error_code = "DOMAIN_OWNERSHIP_NOT_VERIFIED"


class ResourceNotFoundError(WebSecBaseError):
    status_code = status.HTTP_404_NOT_FOUND
    error_code = "RESOURCE_NOT_FOUND"


class ConflictError(WebSecBaseError):
    status_code = status.HTTP_409_CONFLICT
    error_code = "RESOURCE_CONFLICT"


class ScannerExecutionError(WebSecBaseError):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_code = "SCANNER_EXECUTION_ERROR"


def _error_payload(
    *,
    error_code: str,
    message: str,
    correlation_id: str,
    details: Any = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "error": {
            "code": error_code,
            "message": message,
            "correlation_id": correlation_id,
        }
    }
    if details:
        payload["error"]["details"] = details
    return payload


def register_exception_handlers(app: FastAPI) -> None:
    """Register centralized exception handlers ensuring no stack traces leak to clients."""

    @app.exception_handler(WebSecBaseError)
    async def handle_domain_error(request: Request, exc: WebSecBaseError) -> JSONResponse:
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        logger.warning(
            "Domain error handled",
            extra={
                "correlation_id": correlation_id,
                "error_code": exc.error_code,
                "path": request.url.path,
                "details": exc.details,
            },
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_payload(
                error_code=exc.error_code,
                message=exc.message,
                correlation_id=correlation_id,
                details=exc.details,
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        sanitized_errors = [
            {
                "field": ".".join(str(part) for part in err.get("loc", ())),
                "message": err.get("msg", "Invalid input"),
                "type": err.get("type", "value_error"),
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=_error_payload(
                error_code="VALIDATION_ERROR",
                message="La solicitud contiene parámetros inválidos.",
                correlation_id=correlation_id,
                details={"fields": sanitized_errors},
            ),
        )

    @app.exception_handler(HTTPException)
    async def handle_http_exception(request: Request, exc: HTTPException) -> JSONResponse:
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_payload(
                error_code=f"HTTP_{exc.status_code}",
                message=str(exc.detail),
                correlation_id=correlation_id,
            ),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        logger.exception(
            "Unhandled internal exception captured safely",
            extra={"correlation_id": correlation_id, "path": request.url.path},
            exc_info=exc,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_error_payload(
                error_code="INTERNAL_SERVER_ERROR",
                message=(
                    "Error interno inesperado. Consulta el identificador de correlación en los "
                    "registros de auditoría."
                ),
                correlation_id=correlation_id,
            ),
        )
