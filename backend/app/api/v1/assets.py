"""Assets and Domain Ownership Verification endpoints."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.exceptions import (
    ConflictError,
    ResourceNotFoundError,
    SSRFBlockedError,
    TargetValidationError,
)
from app.core.logging import record_security_event_async
from app.core.security import (
    check_domain_ownership_dns_txt,
    check_domain_ownership_well_known,
    generate_verification_challenge,
    validate_target_ssrf,
)
from app.db.session import get_async_db
from app.models.asset import Asset, DomainVerification
from app.models.enums import TargetType, VerificationMethod, VerificationStatus
from app.schemas.asset import (
    AssetCreate,
    AssetDetailOut,
    AssetOut,
    DomainVerificationOut,
    VerificationChallengeCreate,
    VerificationCheckOut,
)

router = APIRouter(prefix="/assets", tags=["assets"])
settings = get_settings()


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _build_verification_instructions(verif: DomainVerification) -> str:
    if verif.method == VerificationMethod.DNS_TXT:
        return (
            f"Crea un registro DNS TXT en '{verif.expected_location}' con el valor exacto: "
            f"{verif.challenge_token}"
        )
    return (
        f"Publica un archivo de texto plano accesible vía HTTP/HTTPS en '{verif.expected_location}' "
        f"que contenga exactamente la línea: {verif.challenge_token}"
    )


def _to_verification_out(verif: DomainVerification) -> DomainVerificationOut:
    out = DomainVerificationOut.model_validate(verif)
    out.instructions = _build_verification_instructions(verif)
    return out


@router.get("", response_model=list[AssetOut])
async def list_assets(db: AsyncSession = Depends(get_async_db)) -> list[Asset]:
    """List registered auditable assets ordered by newest first."""
    result = await db.scalars(select(Asset).order_by(Asset.created_at.desc()))
    return list(result.all())


@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
async def create_asset(
    payload: AssetCreate,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> Asset:
    """Register and SSRF-validate a new domain, URL, or public IP asset."""
    src_ip = _client_ip(request)
    try:
        validated = validate_target_ssrf(payload.target)
    except SSRFBlockedError as exc:
        await record_security_event_async(
            db,
            event_type="SSRF_BLOCKED",
            severity="warning",
            source_ip=src_ip,
            message=f"Intento de registro de activo bloqueado por anti-SSRF: {payload.target}",
            details={"raw_target": payload.target, **exc.details},
        )
        raise

    existing = await db.scalar(
        select(Asset).where(Asset.normalized_target == validated.normalized_target)
    )
    if existing is not None:
        raise ConflictError(
            f"El activo '{validated.normalized_target}' ya se encuentra registrado."
        )

    asset = Asset(
        name=payload.name.strip(),
        target_type=validated.target_type,
        normalized_target=validated.normalized_target,
        hostname=validated.hostname,
        scheme=validated.scheme,
        port=validated.port,
        resolved_ip=validated.resolved_ip,
        environment=payload.environment.strip(),
        owner_email=payload.owner_email.strip() if payload.owner_email else None,
        notes=payload.notes.strip() if payload.notes else None,
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)

    await record_security_event_async(
        db,
        event_type="ASSET_CREATED",
        severity="info",
        source_ip=src_ip,
        asset_id=asset.id,
        message=f"Activo '{asset.normalized_target}' registrado ({asset.resolved_ip}).",
        details={"target_type": asset.target_type.value, "resolved_ip": asset.resolved_ip},
    )
    return asset


@router.get("/{asset_id}", response_model=AssetDetailOut)
async def get_asset(
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_async_db),
) -> AssetDetailOut:
    """Get asset metadata and domain verification challenges."""
    asset = await db.scalar(
        select(Asset)
        .options(selectinload(Asset.verifications))
        .where(Asset.id == asset_id)
    )
    if asset is None:
        raise ResourceNotFoundError(f"Activo '{asset_id}' no encontrado.")

    out = AssetDetailOut.model_validate(asset)
    out.verifications = [_to_verification_out(v) for v in asset.verifications]
    return out


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> None:
    """Delete a registered asset and its historical scans."""
    asset = await db.get(Asset, asset_id)
    if asset is None:
        raise ResourceNotFoundError(f"Activo '{asset_id}' no encontrado.")

    target_label = asset.normalized_target
    await db.delete(asset)
    await db.commit()

    await record_security_event_async(
        db,
        event_type="ASSET_DELETED",
        severity="info",
        source_ip=_client_ip(request),
        message=f"Activo '{target_label}' eliminado del inventario.",
    )


@router.post(
    "/{asset_id}/verifications",
    response_model=DomainVerificationOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_verification_challenge(
    asset_id: uuid.UUID,
    payload: VerificationChallengeCreate,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> DomainVerificationOut:
    """Create a DNS TXT or .well-known/security-audit.txt ownership verification challenge."""
    asset = await db.get(Asset, asset_id)
    if asset is None:
        raise ResourceNotFoundError(f"Activo '{asset_id}' no encontrado.")

    if asset.target_type == TargetType.IP and payload.method == VerificationMethod.DNS_TXT:
        raise TargetValidationError(
            "La verificación DNS TXT no aplica a IPs literales; utiliza '.well-known/security-audit.txt'."
        )

    token, expected_location = generate_verification_challenge(
        asset.hostname, payload.method, asset.scheme
    )
    verif = DomainVerification(
        asset_id=asset.id,
        method=payload.method,
        challenge_token=token,
        expected_location=expected_location,
        status=VerificationStatus.PENDING,
        expires_at=datetime.now(UTC) + timedelta(hours=settings.DOMAIN_VERIFICATION_TTL_HOURS),
    )
    db.add(verif)
    await db.commit()
    await db.refresh(verif)

    await record_security_event_async(
        db,
        event_type="VERIFICATION_CHALLENGE_CREATED",
        severity="info",
        source_ip=_client_ip(request),
        asset_id=asset.id,
        message=f"Reto de verificación ({payload.method.value}) generado para {asset.hostname}.",
        details={"expected_location": expected_location},
    )
    return _to_verification_out(verif)


@router.post(
    "/{asset_id}/verifications/{verification_id}/check",
    response_model=VerificationCheckOut,
)
async def verify_domain_ownership(
    asset_id: uuid.UUID,
    verification_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> VerificationCheckOut:
    """Verify domain ownership challenge in real time against DNS TXT or .well-known file."""
    asset = await db.get(Asset, asset_id)
    if asset is None:
        raise ResourceNotFoundError(f"Activo '{asset_id}' no encontrado.")

    verif = await db.get(DomainVerification, verification_id)
    if verif is None or verif.asset_id != asset.id:
        raise ResourceNotFoundError("Desafío de verificación no encontrado para este activo.")

    now = datetime.now(UTC)
    if verif.expires_at <= now:
        verif.status = VerificationStatus.EXPIRED
        verif.last_checked_at = now
        verif.failure_reason = "El reto de verificación ha expirado; genera uno nuevo."
        await db.commit()
        await db.refresh(verif)
        return VerificationCheckOut(
            verified=False,
            message=verif.failure_reason,
            verification=_to_verification_out(verif),
        )

    src_ip = _client_ip(request)
    try:
        if verif.method == VerificationMethod.DNS_TXT:
            ok, err = check_domain_ownership_dns_txt(asset.hostname, verif.challenge_token)
        else:
            ok, err = check_domain_ownership_well_known(
                asset.hostname,
                verif.challenge_token,
                preferred_scheme=asset.scheme,
                port=asset.port,
            )
    except SSRFBlockedError as exc:
        await record_security_event_async(
            db,
            event_type="SSRF_BLOCKED",
            severity="critical",
            source_ip=src_ip,
            asset_id=asset.id,
            message=f"SSRF bloqueado durante verificación de propiedad: {exc.message}",
            details=exc.details,
        )
        raise

    verif.last_checked_at = now
    if ok:
        verif.status = VerificationStatus.VERIFIED
        verif.verified_at = now
        verif.failure_reason = None
        asset.is_verified = True
        asset.verified_at = now
        asset.verification_method = verif.method
        msg = f"Propiedad verificada exitosamente mediante {verif.method.value}."
        event_type = "DOMAIN_OWNERSHIP_VERIFIED"
        severity = "info"
    else:
        verif.status = VerificationStatus.FAILED
        verif.failure_reason = err or "No se encontró el token de verificación."
        msg = verif.failure_reason
        event_type = "DOMAIN_OWNERSHIP_FAILED"
        severity = "warning"

    await db.commit()
    await db.refresh(verif)

    await record_security_event_async(
        db,
        event_type=event_type,
        severity=severity,
        source_ip=src_ip,
        asset_id=asset.id,
        message=msg,
        details={"method": verif.method.value, "expected_location": verif.expected_location},
    )

    return VerificationCheckOut(
        verified=ok,
        message=msg,
        verification=_to_verification_out(verif),
    )
