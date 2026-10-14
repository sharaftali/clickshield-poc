from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import rate_limit
from app.core.client_ip import ClientIPError, resolve_client_ip
from app.core.config import settings
from app.core.database import get_db
from app.schemas.tracking import TrackingBatchIn, TrackingResponse
from app.services.tracking_service import TrackingRejected, TrackingService

router = APIRouter(prefix="/api/v1", tags=["tracking"])
# The snippet loads /track.js from the API's public origin (task 024).
public_router = APIRouter(tags=["tracking"])

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "static" / "clickshield-tracker.js"


@lru_cache(maxsize=1)
def _script() -> tuple[bytes, str]:
    content = SCRIPT_PATH.read_bytes()
    return content, '"' + hashlib.sha256(content).hexdigest()[:32] + '"'


def _script_response(request: Request) -> Response:
    content, etag = _script()
    headers = {"Cache-Control": "public, max-age=300", "ETag": etag}
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)
    return Response(content=content, media_type="application/javascript", headers=headers)


@router.get("/tracking.js")
async def tracking_script(request: Request) -> Response:
    return _script_response(request)


@public_router.get("/track.js")
async def track_script(request: Request) -> Response:
    return _script_response(request)


async def _read_body(request: Request) -> bytes:
    """Body capped at TRACKING_MAX_BODY_BYTES, refused before any JSON parsing (task 031)."""
    limit = settings.TRACKING_MAX_BODY_BYTES
    too_large = HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Tracking batch is too large.")
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise too_large
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise too_large
    return bytes(body)


@router.post("/track", response_model=TrackingResponse)
async def track_events(request: Request, db: AsyncSession = Depends(get_db)) -> TrackingResponse:
    """
    Public endpoint — called by the JS tracking script. No auth.
    The body is read by hand: sendBeacon posts JSON as text/plain (task 024).
    """
    # Real client IP — X-Forwarded-For is only honoured from trusted proxies
    try:
        client_ip = resolve_client_ip(request)
    except ClientIPError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    result = await rate_limit.hit(f"track:ip:{client_ip}", settings.TRACKING_RATE_LIMIT_PER_MINUTE, 60)
    if not result.allowed:
        await rate_limit.note_rate_limited(client_ip)  # spec §20: excessive request rate is a bot signal
        raise rate_limit.too_many(result)

    body = await _read_body(request)
    try:
        payload = TrackingBatchIn.model_validate(json.loads(body or b"null"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Body is not valid JSON.") from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.errors(include_url=False, include_context=False)
        ) from exc

    site = await rate_limit.hit(
        f"track:site:{payload.events[0].site_token}", settings.TRACKING_RATE_LIMIT_PER_SITE_PER_MINUTE, 60
    )
    if not site.allowed:
        raise rate_limit.too_many(site)

    service = TrackingService(db)
    try:
        return await service.ingest_batch(payload, client_ip, request)
    except TrackingRejected as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
