"""
Shared pytest fixtures for the ThreatSense backend suite.

    cd backend && source .venv/bin/activate
    pytest tests/ -q

WHY THIS FILE EXISTS
--------------------
NFR-05 throttles login attempts per IP, and Starlette's TestClient reports the
same client host ("testclient") for every request in the process. Without
isolation, the sixth login ANYWHERE in the suite would 429 — so a test file
that merely logs in to obtain a session would start failing because of
attempts made by an unrelated file that happened to run before it.

That is a test-harness artefact, not a product defect: real administrators
arrive from distinct addresses, and the throttle firing after five attempts is
precisely the behaviour Table 11 asks for. The fix therefore belongs in the
harness. The autouse fixture below clears the window before each test, so
every test starts with a full quota and tests remain order-independent.

tests/test_login_rate_limit.py deliberately fills the window on purpose; it
manages its own state on top of this reset and is unaffected.

EXTERNAL SERVICES ARE FORCED TO MOCK
------------------------------------
Both external integrations resolve their client from settings at CALL time,
and both default to "auto" — meaning: use the real service if a key is
present, otherwise fall back to a mock.

    alert_email_sender = "auto"   ->  SendGrid once SENDGRID_API_KEY is set
    report_llm_client  = "auto"   ->  OpenAI   once OPENAI_API_KEY  is set

That is the right default for the running application and the wrong one for a
test suite. Once the Phase 3 keys were added to backend/.env the suite began
calling the live OpenAI API — spending real credit on every run — and the
alerting tests were free to send real email to the configured recipient.

The failure surfaced as test_api_generate_and_history asserting "mock-llm"
and receiving "gpt-4o-mini-2024-07-18". That assertion was right and the
environment was wrong: a test suite must not depend on network, cost money,
or email anyone.

The autouse fixture below pins both to "mock" for every test. Tests that want
to exercise the real client should set it explicitly and be marked so they
can be deselected.
"""
from __future__ import annotations

import pytest

from app.config import settings
from app.middleware.rate_limit import login_rate_limiter


@pytest.fixture(autouse=True)
def _reset_login_rate_limiter():
    """Give every test a fresh NFR-05 login window (see module docstring)."""
    login_rate_limiter.reset()
    yield
    login_rate_limiter.reset()


@pytest.fixture(autouse=True)
def _force_mock_external_services(monkeypatch):
    """Keep the suite hermetic (see module docstring).

    Applied to every test rather than only the ones that obviously send:
    any test that creates a CRITICAL detection can reach the alert worker,
    and it is not obvious from a test's name whether it will. Failing safe
    is cheaper than auditing every path each time one is added.
    """
    monkeypatch.setattr(settings, "alert_email_sender", "mock")
    monkeypatch.setattr(settings, "report_llm_client", "mock")
    yield
