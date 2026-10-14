"""
IP reputation (spec §13, §14) — per organization, from history, with decay.

Reputation is computed at scoring time from the organization's OTHER, earlier
sessions on the same IP, so a session can never raise its own reputation
(task 006). Sessions younger than REPUTATION_MIN_AGE_SECONDS are left out: they
are the current burst, which velocity and repeat rules already score. Recent
sessions weigh more than old ones (exponential decay), client feedback
(final_label) overrides the system verdict, and a minimum sample is required
before reputation counts at all. Shared IPs with mostly legitimate history
therefore stay clean (spec §75 test 6).

Two measures feed two rules (task 020):
- `score` — decayed average risk of past sessions → KNOWN_HIGH_RISK_IP
  ("this IP has looked risky"), over all past sessions.
- `fraud_ratio` — decayed share of FRAUD among labelled (FRAUD / SAFE) sessions
  → HIGH_FRAUD_HISTORY ("this IP's traffic was confirmed fraud").

The ip_reputation table is a per-organization cache of counters and the latest
decayed score, for display; scoring does not depend on it.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import IPReputation, Session, Verdict

HISTORY_LIMIT = 500
# Risk a client label stands for in the average: their word overrides the system score.
LABEL_RISK = {Verdict.FRAUD: 100, Verdict.SAFE: 0}


@dataclass(frozen=True)
class ReputationEvidence:
    fraud_weight: float = 0.0    # decayed FRAUD-labelled sessions
    legit_weight: float = 0.0    # decayed SAFE-labelled sessions
    sessions: int = 0            # labelled sessions considered (FRAUD or SAFE)
    risk_weight: float = 0.0     # Σ decay × risk over all past sessions
    all_weight: float = 0.0      # Σ decay over all past sessions
    all_sessions: int = 0

    @property
    def labelled_weight(self) -> float:
        return self.fraud_weight + self.legit_weight

    @property
    def has_enough_history(self) -> bool:
        return self.all_sessions >= settings.REPUTATION_MIN_SAMPLE and self.all_weight > 0

    @property
    def score(self) -> int:
        """0-100 decayed average risk of past sessions; 0 without enough history."""
        if not self.has_enough_history:
            return 0
        return round(self.risk_weight / self.all_weight)

    @property
    def confidence(self) -> int:
        """0-100: how much recent evidence the score rests on."""
        if not self.has_enough_history:
            return 0
        return round(100 * min(1.0, self.all_weight / settings.REPUTATION_FULL_CONFIDENCE_WEIGHT))

    @property
    def fraud_ratio(self) -> float:
        """0-1 decayed share of FRAUD among labelled sessions (0 without labels)."""
        return self.fraud_weight / self.labelled_weight if self.labelled_weight > 0 else 0.0


def decay_weight(age: timedelta, half_life_days: float) -> float:
    age_days = max(0.0, age.total_seconds() / 86400)
    return 0.5 ** (age_days / half_life_days)


def compute_reputation(
    history: Iterable[tuple],
    *,
    now: datetime,
) -> ReputationEvidence:
    """history rows: (created_at, system verdict, client final_label[, risk_score])."""
    fraud = legit = risk_weight = all_weight = 0.0
    sessions = all_sessions = 0
    for row in history:
        created_at, verdict, final_label = row[0], row[1], row[2]
        risk = int(row[3] or 0) if len(row) > 3 else (100 if verdict == Verdict.FRAUD else 0)
        weight = decay_weight(now - created_at, settings.REPUTATION_HALF_LIFE_DAYS)
        all_sessions += 1
        all_weight += weight
        risk_weight += weight * LABEL_RISK.get(final_label, risk)

        label = final_label or verdict
        if label not in (Verdict.FRAUD, Verdict.SAFE):
            continue  # MONITOR / FLAG are not a fraud / legitimate label
        sessions += 1
        if label == Verdict.FRAUD:
            fraud += weight
        else:
            legit += weight
    return ReputationEvidence(
        fraud_weight=fraud, legit_weight=legit, sessions=sessions,
        risk_weight=risk_weight, all_weight=all_weight, all_sessions=all_sessions,
    )


def build_history_query(session: Session, *, now: datetime):
    since = now - timedelta(days=settings.REPUTATION_WINDOW_DAYS)
    until = now - timedelta(seconds=settings.REPUTATION_MIN_AGE_SECONDS)
    return (
        select(Session.created_at, Session.verdict, Session.final_label, Session.risk_score)
        .where(
            Session.organization_id == session.organization_id,
            Session.ip_address == session.ip_address,
            Session.id != session.id,  # never the session being scored
            Session.created_at >= since,
            Session.created_at < until,  # history, not the current burst
        )
        .order_by(Session.created_at.desc())
        .limit(HISTORY_LIMIT)
    )


async def load_reputation(db: AsyncSession, session: Session) -> ReputationEvidence | None:
    if not session.ip_address:
        return None
    now = datetime.now(timezone.utc)
    rows = (await db.execute(build_history_query(session, now=now))).all()
    return compute_reputation(rows, now=now)


def counter_deltas(
    *, is_new_session: bool, previous_verdict: Verdict | None, current_verdict: Verdict
) -> tuple[int, int, int]:
    """(total, fraud, legitimate) changes for this scoring pass."""
    current_is_fraud = current_verdict == Verdict.FRAUD
    if is_new_session:
        return (1, 1, 0) if current_is_fraud else (1, 0, 1)
    if (previous_verdict == Verdict.FRAUD) == current_is_fraud:
        return 0, 0, 0
    return (0, 1, -1) if current_is_fraud else (0, -1, 1)


def build_reputation_upsert(
    session: Session,
    evidence: ReputationEvidence,
    deltas: tuple[int, int, int],
    *,
    now: datetime,
):
    """Atomic per-organization upsert (safe when two sessions from one IP arrive together)."""
    d_total, d_fraud, d_legit = deltas
    stmt = pg_insert(IPReputation).values(
        organization_id=session.organization_id,
        ip=str(session.ip_address),
        risk_score=evidence.score,
        confidence=evidence.confidence,
        country=session.country,
        asn=session.asn,
        isp=session.isp,
        is_vpn=bool(session.is_vpn),
        is_proxy=bool(session.is_proxy),
        is_tor=bool(session.is_tor),
        is_datacenter=bool(session.is_datacenter),
        total_sessions=max(0, d_total),
        fraud_sessions=max(0, d_fraud),
        legitimate_sessions=max(0, d_legit),
        blocked_count=0,
        first_seen=now,
        last_seen=now,
    )
    table = IPReputation.__table__
    return stmt.on_conflict_do_update(
        index_elements=[table.c.organization_id, table.c.ip],
        set_={
            "risk_score": stmt.excluded.risk_score,
            "confidence": stmt.excluded.confidence,
            "country": stmt.excluded.country,
            "asn": stmt.excluded.asn,
            "isp": stmt.excluded.isp,
            "is_vpn": stmt.excluded.is_vpn,
            "is_proxy": stmt.excluded.is_proxy,
            "is_tor": stmt.excluded.is_tor,
            "is_datacenter": stmt.excluded.is_datacenter,
            "total_sessions": table.c.total_sessions + d_total,
            "fraud_sessions": func.greatest(0, table.c.fraud_sessions + d_fraud),
            "legitimate_sessions": func.greatest(0, table.c.legitimate_sessions + d_legit),
            "last_seen": stmt.excluded.last_seen,
            "updated_at": func.now(),
        },
    )


def counter_label(verdict: Verdict | None, final_label: Verdict | None) -> bool:
    """True = counted as fraud in ip_reputation counters (client label wins)."""
    return (final_label or verdict) == Verdict.FRAUD


def build_feedback_counter_update(session: Session, *, was_fraud: bool, is_fraud: bool):
    """Move a session between the fraud and legitimate counters after client feedback (task 020).
    None when nothing changes."""
    if was_fraud == is_fraud or not session.ip_address:
        return None
    d_fraud, d_legit = (1, -1) if is_fraud else (-1, 1)
    table = IPReputation.__table__
    return (
        update(IPReputation)
        .where(IPReputation.organization_id == session.organization_id, IPReputation.ip == str(session.ip_address))
        .values(
            fraud_sessions=func.greatest(0, table.c.fraud_sessions + d_fraud),
            legitimate_sessions=func.greatest(0, table.c.legitimate_sessions + d_legit),
            updated_at=func.now(),
        )
    )
