"""Pluggable email sender (task 2.3, Section 2.5).

The worker talks to this interface, never to SendGrid directly. That keeps the
whole alert pipeline — dedup, thresholds, quiet hours, retries, alerts rows —
testable before a SendGrid account exists (task 2.2), and makes failure
injection in tests trivial.

Selection is driven by settings.alert_email_sender:
    auto      SendGrid when an API key is present, otherwise mock (default)
    mock      always the mock sender
    sendgrid  always SendGrid; raises if the key is missing
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

from ...config import settings

logger = logging.getLogger("threatsense.alerting.sender")


@dataclass
class SendResult:
    """Outcome of a single delivery attempt."""

    success: bool
    detail: str = ""
    status_code: int | None = None

    @property
    def error_message(self) -> str | None:
        return None if self.success else (self.detail or "unknown send failure")


class AlertSender(Protocol):
    """Anything that can deliver one alert email."""

    name: str

    def send(self, to: str, subject: str, html: str) -> SendResult: ...


@dataclass
class MockSender:
    """Records messages in memory and logs them. Used until task 2.2 is done.

    fail_times > 0 makes the next N attempts fail, which is how the retry and
    backoff behaviour is exercised in tests.
    """

    name: str = "mock"
    sent: list[dict] = field(default_factory=list)
    fail_times: int = 0
    fail_forever: bool = False

    def send(self, to: str, subject: str, html: str) -> SendResult:
        if self.fail_forever or self.fail_times > 0:
            if not self.fail_forever:
                self.fail_times -= 1
            logger.info("[mock] simulated delivery FAILURE to %s", to)
            return SendResult(False, "simulated delivery failure", 502)
        self.sent.append({"to": to, "subject": subject, "html": html})
        logger.info("[mock] email to %s — %s", to, subject)
        return SendResult(True, "queued by mock sender", 202)

    def reset(self) -> None:
        self.sent.clear()
        self.fail_times = 0
        self.fail_forever = False


def get_sender() -> AlertSender:
    """Resolve the configured sender. Import is lazy so sendgrid stays optional."""
    mode = (settings.alert_email_sender or "auto").strip().lower()
    if mode == "mock":
        return MockSender()
    if mode == "sendgrid" or (mode == "auto" and settings.sendgrid_api_key):
        from .sendgrid_client import SendGridSender

        return SendGridSender()
    logger.warning(
        "no SENDGRID_API_KEY set — using the mock sender. Alerts will be logged "
        "and recorded in the alerts table but no email will actually be sent."
    )
    return MockSender()
