"""Spec §75 Test 5 — VPN + high velocity + repeated sessions + bad reputation + abnormal behaviour
→ HIGH-CONFIDENCE FRAUD, excluded in Google Ads automatically (spec §84 end-to-end flow)."""
from __future__ import annotations

from app.models import ActionType, ExclusionStatus, Verdict
from app.services.audit_service import AuditAction


async def test_multiple_signals_are_high_confidence_fraud_and_get_excluded(world):
    ip = "203.0.113.50"
    world.ip_intel[ip] = {"is_vpn": True, "country": "RO"}
    await world.seed_history(ip, Verdict.FRAUD, count=5, hours_ago=6)

    responses = [
        await world.visit(ip, visitor="v_fraud_bot", events=["page_view"], duration=0.5)
        for _ in range(10)
    ]
    final = responses[-1]

    assert final["verdict"] == Verdict.FRAUD.value
    assert final["risk_score"] >= 80
    assert final["confidence_score"] >= 80

    # Automatic protection (task 010): exactly one exclusion + one queued ADD action, job pushed.
    [exclusion] = await world.exclusions(ip)
    assert exclusion.status == ExclusionStatus.PENDING
    assert exclusion.campaign_id == "555" and exclusion.google_customer_id == "1234567890"
    [action] = await world.actions()
    assert action.action_type == ActionType.ADD_IP_EXCLUSION
    assert world.pushed_jobs == [action.id]

    # Worker sends it to Google (mocked) without any UI interaction.
    metrics = await world.run_worker()
    assert metrics["successful"] == 1
    [exclusion] = await world.exclusions(ip)
    assert exclusion.status == ExclusionStatus.ACTIVE
    assert exclusion.google_resource_name.startswith("customers/1234567890/campaignCriteria/555~")
    assert [call[0] for call in world.google_calls] == ["create"]

    # Audit trail (task 011): queued, then added with the Google request id.
    [queued] = await world.audit(AuditAction.EXCLUSION_QUEUED)
    [added] = await world.audit(AuditAction.ADD_IP_EXCLUSION)
    assert queued.details["ip"] == ip and queued.details["confidence"] >= 80
    assert added.result.value == "SUCCESS" and added.google_request_id
