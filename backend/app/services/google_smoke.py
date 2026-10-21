"""
Live smoke test of the Google Ads integration, run by `python -m app.cli google-smoke`.

Uses a stored connection's encrypted refresh token and makes REAL Google Ads calls (it refuses to
run with GOOGLE_ADS_DRY_RUN=true). Steps, each printed as OK / FAIL:

    (a) list accessible customers        (b) list campaigns of the selected customer
    (c) add an IP exclusion              (d) read it back from Google
    (e) remove it again (--cleanup)

Nothing is written to Click Shield's own tables, and no token is ever printed. On failure the
Google error code, message and request id are shown.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable

from app.adapters.google_ads_adapter import GoogleAdsAdapter, GoogleAdsApiResult
from app.core.config import settings
from app.core.crypto import decrypt
from app.core.database import AsyncSessionLocal
from app.models import GoogleCampaign, GoogleConnection
from app.services.google_oauth import (
    fetch_accessible_customer_ids,
    list_google_campaigns,
    refresh_access_token,
    resolve_login_customer_id,
)

EXIT_OK, EXIT_FAILED, EXIT_REFUSED = 0, 1, 2


def _describe(error: Exception | GoogleAdsApiResult) -> str:
    """'<code>: <message> (request-id <id>)' for any Google failure; contains no secrets."""
    if isinstance(error, GoogleAdsApiResult):
        code, message, request_id = error.error_code or error.error_category, error.message, error.api_request_id
    else:
        code = getattr(error, "code", None) or getattr(error, "error_code", None)
        message, request_id = str(error), getattr(error, "request_id", None)
    parts = [f"{code}: " if code else "", message or "unknown error", f" (request-id {request_id})" if request_id else ""]
    return "".join(str(part) for part in parts)


async def run_smoke(
    connection_id: str,
    campaign_id: str,
    *,
    ip: str = "203.0.113.7",
    cleanup: bool = False,
    customer_id: str | None = None,
    session_factory=AsyncSessionLocal,
    out: Callable[[str], None] = print,
) -> int:
    """Returns 0 if every step passed, 1 if a step failed, 2 if refused to run."""
    failed = False

    def ok(label: str, detail: str = "") -> None:
        out(f"[OK]   {label}" + (f" - {detail}" if detail else ""))

    def fail(label: str, detail: str) -> None:
        nonlocal failed
        failed = True
        out(f"[FAIL] {label} - {detail}")

    if settings.GOOGLE_ADS_DRY_RUN:
        out("[REFUSED] GOOGLE_ADS_DRY_RUN=true: the smoke test must really call Google. "
            "Set GOOGLE_ADS_DRY_RUN=false and run it again.")
        return EXIT_REFUSED
    if not (settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET):
        out("[REFUSED] GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are not set; Google would reject the token refresh.")
        return EXIT_REFUSED

    # ---- connection and campaign id ----
    try:
        connection_uuid = uuid.UUID(connection_id)
    except ValueError:
        out(f"[FAIL] load connection - {connection_id!r} is not a connection UUID")
        return EXIT_FAILED
    async with session_factory() as db:
        connection = await db.get(GoogleConnection, connection_uuid)
        google_campaign_id = campaign_id.strip()
        if "-" in google_campaign_id:  # a Click Shield campaign row id: resolve to Google's campaign id
            try:
                row = await db.get(GoogleCampaign, uuid.UUID(google_campaign_id))
            except ValueError:
                row = None
            google_campaign_id = row.campaign_id if row else google_campaign_id
    if connection is None:
        out(f"[FAIL] load connection - no connection {connection_id}")
        return EXIT_FAILED
    if not google_campaign_id.isdigit():
        out(f"[FAIL] load connection - campaign id {campaign_id!r} is neither a Google campaign id nor a known campaign row")
        return EXIT_FAILED

    customer = customer_id or connection.customer_id
    login_customer = connection.login_customer_id if customer == connection.customer_id else None
    if not customer or not customer.isdigit():
        out("[FAIL] load connection - the connection has no selected customer (select one first, or pass --customer-id)")
        return EXIT_FAILED
    ok("load connection", f"customer {customer}, login-customer-id {login_customer or 'none'}")

    # ---- access token ----
    try:
        access_token = (await refresh_access_token(decrypt(connection.refresh_token_encrypted))).get("access_token")
    except ValueError as exc:
        out(f"[FAIL] refresh access token - {_describe(exc)}")
        return EXIT_FAILED
    ok("refresh access token")

    # ---- (a) accessible customers ----
    try:
        accessible = await fetch_accessible_customer_ids(access_token)
        ok("(a) list accessible customers", f"{len(accessible)} found: {', '.join(accessible) or '-'}")
    except ValueError as exc:
        fail("(a) list accessible customers", _describe(exc))
        accessible = []

    if customer_id and customer_id != connection.customer_id:
        try:
            login_customer = await resolve_login_customer_id(access_token, customer)
            ok("resolve manager account", f"login-customer-id {login_customer or 'none (direct access)'}")
        except ValueError as exc:
            fail("resolve manager account", _describe(exc))
    elif not login_customer and customer not in accessible and accessible:
        out(f"[WARN] customer {customer} is not directly accessible and the connection stores no manager id; "
            "Google will likely answer USER_PERMISSION_DENIED. Re-select the customer, or pass --customer-id.")

    # ---- (b) campaigns ----
    campaign = None
    try:
        campaigns = await list_google_campaigns(
            access_token=access_token, customer_id=customer, login_customer_id=login_customer
        )
        campaign = next((c for c in campaigns if c["campaign_id"] == google_campaign_id), None)
        if campaign is None:
            fail("(b) list campaigns", f"{len(campaigns)} campaign(s), but none has id {google_campaign_id}")
        else:
            ok("(b) list campaigns", f"{len(campaigns)} found; {google_campaign_id} = {campaign['name']!r} "
               f"({campaign['campaign_type']}, {campaign['status']})")
    except ValueError as exc:
        fail("(b) list campaigns", _describe(exc))
    if failed:
        out("RESULT: FAILED (stopped before changing anything in Google)")
        return EXIT_FAILED

    # ---- (c) add, (d) read back, (e) remove ----
    adapter = GoogleAdsAdapter(customer_id=customer, access_token=access_token, login_customer_id=login_customer)
    created = await adapter.create_ip_exclusion(campaign_id=google_campaign_id, ip_address=ip, reason="Click Shield smoke test")
    resource_name = created.resource_name
    if created.ok:
        note = " (already existed; adopted)" if created.already_existed else ""
        ok("(c) add IP exclusion", f"{ip} -> {resource_name}{note}")
    else:
        fail("(c) add IP exclusion", _describe(created))

    if created.ok and resource_name:
        verified = await adapter.verify_exclusion(resource_name)
        if verified.ok:
            ok("(d) read back", "Google returns the exclusion")
        else:
            fail("(d) read back", _describe(verified))

    if cleanup and resource_name:
        removed = await adapter.remove_ip_exclusion(campaign_id=google_campaign_id, ip_address=ip, resource_name=resource_name)
        if removed.ok:
            ok("(e) remove IP exclusion (--cleanup)", removed.message or "removed")
        else:
            fail("(e) remove IP exclusion (--cleanup)", _describe(removed))
    elif cleanup:
        out("[SKIP] (e) remove IP exclusion - nothing was created")
    elif resource_name:
        out(f"[NOTE] {ip} stays excluded on campaign {google_campaign_id}; re-run with --cleanup to remove it.")

    out("RESULT: " + ("FAILED" if failed else "all steps passed"))
    return EXIT_FAILED if failed else EXIT_OK
