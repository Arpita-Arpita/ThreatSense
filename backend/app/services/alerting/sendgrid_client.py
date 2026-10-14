"""SendGrid Mail Send wrapper (task 2.3, Section 2.5).

Thin adapter over the official SDK implementing the AlertSender interface. The
API key must be restricted to Mail Send and the from-address must have passed
SendGrid Single Sender Verification, or delivery is rejected with a 403.

Every exception is converted into a failed SendResult rather than propagating,
so one bad send can never take the worker process down — the failure is what
drives the retry schedule and the FAILED status on the alerts row.
"""
from __future__ import annotations

import logging

from ...config import settings
from .sender import SendResult

logger = logging.getLogger("threatsense.alerting.sendgrid")


class SendGridSender:
    """Delivers alert email through the SendGrid v3 Mail Send API."""

    name = "sendgrid"

    def __init__(self) -> None:
        if not settings.sendgrid_api_key:
            raise RuntimeError(
                "SENDGRID_API_KEY is not set. Complete task 2.2 (account, Single "
                "Sender Verification, Mail Send key) or set "
                "ALERT_EMAIL_SENDER=mock for offline testing."
            )
        try:
            from sendgrid import SendGridAPIClient
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise RuntimeError(
                "the 'sendgrid' package is not installed — pip install sendgrid"
            ) from exc
        self._client = SendGridAPIClient(settings.sendgrid_api_key)

    def send(self, to: str, subject: str, html: str) -> SendResult:
        from sendgrid.helpers.mail import Mail

        message = Mail(
            from_email=(settings.alert_from_email, settings.alert_from_name),
            to_emails=to,
            subject=subject,
            html_content=html,
        )
        try:
            response = self._client.send(message)
        except Exception as exc:
            # Type only, never str(exc). The exception text is provider- and
            # SDK-controlled, and the Mail object it was raised from carries
            # the message body — which for a password-reset email contains a
            # live reset link. Logging arbitrary exception text is how that
            # ends up in a log sink. detail still carries the full text for
            # the alerts.error_message column (Table 9), where it is stored
            # rather than logged; callers handling credentials must log the
            # status code instead of the detail.
            logger.warning("SendGrid send raised %s", type(exc).__name__)
            return SendResult(False, f"{type(exc).__name__}: {exc}"[:500])

        code = getattr(response, "status_code", None)
        if code is not None and 200 <= code < 300:
            return SendResult(True, "accepted by SendGrid", code)

        body = getattr(response, "body", b"") or b""
        detail = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
        # 403 here is almost always an unverified sender address.
        return SendResult(False, f"SendGrid returned {code}: {detail}"[:500], code)
