"""Visitor data erasure (spec §9, task 029). Owners only; this organization only; audited."""
from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.client_ip import ClientIPError, parse_ip
from app.core.database import get_db
from app.dependencies.permissions import Permission
from app.models import AuditResult, Event, IPReputation, Session, Visitor
from app.services import audit_service
from app.services.audit_service import AuditAction
from app.workers.retention import anonymize_sessions

router = APIRouter(prefix="/api/v1/privacy", tags=["privacy"])
PrivacyOwner = Permission("privacy:erase")


class EraseIn(BaseModel):
    visitor_token: str | None = Field(default=None, min_length=8, max_length=64)
    ip: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def exactly_one(self) -> "EraseIn":
        if bool(self.visitor_token) == bool(self.ip):
            raise ValueError("Give either visitor_token or ip")
        if self.ip:
            try:
                self.ip = str(parse_ip(self.ip))
            except ClientIPError as exc:
                raise ValueError("Invalid IP address") from exc
        return self


class EraseOut(BaseModel):
    sessions_anonymized: int
    events_deleted: int
    visitors_deleted: int
    reputation_rows_deleted: int


@router.post("/erase", response_model=EraseOut)
async def erase(payload: EraseIn, request: Request, current_user: PrivacyOwner, db: AsyncSession = Depends(get_db)) -> EraseOut:
    org_id = current_user.organization_id
    visitor_ids: list = []
    if payload.visitor_token:
        visitor_ids = list((await db.execute(
            select(Visitor.id).where(Visitor.organization_id == org_id, Visitor.visitor_token == payload.visitor_token)
        )).scalars())
        session_query = select(Session.id).where(Session.organization_id == org_id, Session.visitor_id.in_(visitor_ids))
    else:
        session_query = select(Session.id).where(Session.organization_id == org_id, Session.ip_address == payload.ip)
    session_ids = list((await db.execute(session_query)).scalars()) if (payload.ip or visitor_ids) else []
    if not session_ids and not visitor_ids:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No data found for this visitor in your organization.")

    events = await db.execute(delete(Event).where(Event.organization_id == org_id, Event.session_id.in_(session_ids)))
    anonymized = await anonymize_sessions(db, session_ids)
    visitors = await db.execute(delete(Visitor).where(Visitor.id.in_(visitor_ids))) if visitor_ids else None
    reputation = None
    if payload.ip:
        reputation = await db.execute(delete(IPReputation).where(IPReputation.organization_id == org_id, IPReputation.ip == payload.ip))
    result = EraseOut(
        sessions_anonymized=anonymized, events_deleted=events.rowcount or 0,
        visitors_deleted=(visitors.rowcount or 0) if visitors is not None else 0,
        reputation_rows_deleted=(reputation.rowcount or 0) if reputation is not None else 0,
    )
    # The audit row must not re-store the identifier we just erased: keep only its hash.
    identifier = payload.visitor_token or payload.ip
    audit_service.record(
        db, action=AuditAction.PRIVACY_ERASE, result=AuditResult.SUCCESS, organization_id=org_id,
        user_id=current_user.id, resource_type="visitor", request=request,
        details={"by": "visitor_token" if payload.visitor_token else "ip",
                 "identifier_sha256": hashlib.sha256(identifier.encode()).hexdigest(), **result.model_dump()},
    )
    await db.commit()
    return result
