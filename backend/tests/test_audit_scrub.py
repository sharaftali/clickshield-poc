"""Task 011: secrets never reach audit rows, whatever shape the details take."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.models import AuditResult
from app.services.audit_service import REDACTED, record, scrub


def test_scrub_redacts_secret_keys_at_any_depth():
    details = {
        "ip": "203.0.113.7",
        "password": "hunter2",
        "Refresh_Token": "1//abc",
        "nested": {"access_token": "ya29", "Authorization": "Bearer x", "keep": 1},
        "items": [{"client_secret": "s"}, {"api_key": "k", "campaign_id": "555"}],
        "google_request_id": "req-1",  # not a secret: request ids are kept (spec §44)
    }
    clean = scrub(details)
    assert clean["password"] == clean["Refresh_Token"] == REDACTED
    assert clean["nested"] == {"access_token": REDACTED, "Authorization": REDACTED, "keep": 1}
    assert clean["items"] == [{"client_secret": REDACTED}, {"api_key": REDACTED, "campaign_id": "555"}]
    assert clean["ip"] == "203.0.113.7" and clean["google_request_id"] == "req-1"
    assert details["password"] == "hunter2"  # input is not mutated


def test_scrub_makes_values_json_safe():
    value_id = uuid.uuid4()
    when = datetime(2026, 10, 8, tzinfo=timezone.utc)
    assert scrub({"id": value_id, "at": when, "n": None, "ok": True}) == {
        "id": str(value_id), "at": str(when), "n": None, "ok": True,
    }


class AddOnlyDB:
    def __init__(self):
        self.rows = []

    def add(self, row):
        self.rows.append(row)


def test_record_stages_row_in_callers_transaction_and_truncates_errors():
    db = AddOnlyDB()
    row = record(db, action="X", result=AuditResult.FAILED, details={"token": "t"}, error="e" * 5000)
    assert db.rows == [row]
    assert row.details == {"token": REDACTED}
    assert len(row.error_message) == 2000
