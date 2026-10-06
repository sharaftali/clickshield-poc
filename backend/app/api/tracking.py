from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.client_ip import ClientIPError, resolve_client_ip
from app.core.database import get_db
from app.schemas.tracking import TrackingBatchIn, TrackingResponse
from app.services.tracking_service import TrackingService

router = APIRouter(prefix="/api/v1", tags=["tracking"])


@router.get("/tracking.js")
async def tracking_script() -> Response:
    script_path = Path(__file__).resolve().parents[1] / "static" / "clickshield-tracker.js"
    return Response(content=script_path.read_text(encoding="utf-8"), media_type="application/javascript")


@router.post("/track", response_model=TrackingResponse)
async def track_events(
    payload: TrackingBatchIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TrackingResponse:
    """
    Public endpoint — called by the JS tracking script.
    No auth. Rate-limited by IP (handled in middleware later).
    """
    # Real client IP — X-Forwarded-For is only honoured from trusted proxies
    try:
        client_ip = resolve_client_ip(request)
    except ClientIPError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    service = TrackingService(db)
    try:
        result = await service.ingest_batch(payload, client_ip, request)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    return result