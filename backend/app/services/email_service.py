"""
Outgoing email (alerts, task 028; invitations, task 030).

Backends: `console` (development: the message is logged) and `smtp`. Email is sent
from the worker (arq jobs), so an SMTP outage never blocks an API request or a
protection action; delivery status is recorded on the notification row.
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
from email.message import EmailMessage

from app.core.config import settings

logger = logging.getLogger(__name__)


class EmailError(RuntimeError):
    pass


def _send_smtp(message: EmailMessage) -> None:
    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as client:
        if settings.SMTP_USE_TLS:
            client.starttls()
        if settings.SMTP_USER:
            client.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        client.send_message(message)


async def send_email(to: str, subject: str, body: str) -> None:
    """Deliver one plain-text email. Raises EmailError on failure."""
    message = EmailMessage()
    message["From"] = settings.ALERT_FROM_EMAIL
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    if settings.EMAIL_BACKEND == "console":
        logger.info("EMAIL (console backend) to=%s subject=%s\n%s", to, subject, body)
        return
    if not settings.SMTP_HOST:
        raise EmailError("EMAIL_BACKEND=smtp but SMTP_HOST is not set")
    try:
        await asyncio.to_thread(_send_smtp, message)
    except (OSError, smtplib.SMTPException) as exc:
        raise EmailError(f"SMTP delivery failed: {exc}") from exc
