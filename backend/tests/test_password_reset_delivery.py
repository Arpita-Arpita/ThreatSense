"""Password reset token handling and delivery (Section 2.1).

    cd backend && source .venv/bin/activate
    pytest tests/test_password_reset_delivery.py -v

WHY THIS EXISTS
---------------
Section 2.1, verbatim:

    "Password-reset tokens are cryptographically random 256-bit values, stored
     as SHA-256 hashes in a short-lived server-side token store, and expire
     after 15 minutes"

and:

    "The password reset flow sends a time-limited reset link to the email
     inbox"

Two defects were found in an external audit and confirmed against the code:

  1. The router logged the full reset URL, including the raw token, at
     WARNING level — placed there during Phase 1 "so you can test locally"
     and never removed. The token is a bearer credential for the account for
     fifteen minutes, so anyone able to read an application log could take
     over any account by requesting a reset for it. Log sinks are routinely
     more widely readable than databases.

  2. The email was never sent. A TODO stood where the delivery call belonged,
     so the specified flow did not exist: the only way to obtain a link was
     to read the server log.

The first test below is the important one and is written to fail loudly if
anyone reintroduces logging of the token — including at DEBUG, and including
inside a longer message.
"""
from __future__ import annotations

import logging
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.security import hash_password
from app.database import SessionLocal
from app.main import app
from app.models import AdminRole, Administrator, AuditLog
from app.services.auth import reset as reset_service

PASSWORD = "ResetFlow1!"
NEW_PASSWORD = "ResetFlow2@"


@pytest.fixture()
def admin():
    email = f"reset-{uuid.uuid4().hex[:8]}@threatsense.local"
    with SessionLocal() as db:
        row = Administrator(full_name="Reset Test", email=email,
                            password_hash=hash_password(PASSWORD),
                            role=AdminRole.ADMIN)
        db.add(row)
        db.commit()
        admin_id = row.admin_id
    yield {"admin_id": admin_id, "email": email}
    with SessionLocal() as db:
        db.query(AuditLog).filter(AuditLog.admin_id == admin_id).delete()
        db.query(Administrator).filter(Administrator.admin_id == admin_id).delete()
        db.commit()


@pytest.fixture()
def sent(monkeypatch):
    """Capture outgoing mail instead of sending it."""
    box = []

    class _Result:
        success = True
        detail = "captured"

    class _Sender:
        name = "capture"

        def send(self, to, subject, html):
            box.append({"to": to, "subject": subject, "html": html})
            return _Result()

    monkeypatch.setattr(reset_service, "get_sender", lambda: _Sender())
    return box


def _request_reset(client, email):
    return client.post("/api/auth/password-reset/request", json={"email": email})


# --- the token must never reach a log ----------------------------------------

def test_raw_token_never_appears_in_logs(admin, sent, caplog):
    """The defect this file exists for.

    Captures at DEBUG so that demoting the old WARNING to a "harmless" debug
    line still fails. Checks every record's rendered message, not just the
    formatted output, so a token passed as a lazy %s argument is caught too.
    """
    caplog.set_level(logging.DEBUG)
    with TestClient(app) as c:
        assert _request_reset(c, admin["email"]).status_code == 200

    assert sent, "no reset email was sent"
    token = sent[0]["html"].split("token=")[1].split('"')[0]
    assert len(token) > 20, "sanity: extracted something token-shaped"

    haystack = "\n".join(
        [r.getMessage() for r in caplog.records] + [caplog.text])
    assert token not in haystack, "raw reset token was written to the logs"
    assert "reset-password?token=" not in haystack, "reset link was logged"


def test_token_is_not_returned_in_the_response(admin, sent):
    """The token must travel by email only, never back to the caller."""
    with TestClient(app) as c:
        body = _request_reset(c, admin["email"]).json()
    assert "token" not in str(body).lower()


# --- the email is actually sent ----------------------------------------------

def test_reset_email_is_sent_to_the_requested_address(admin, sent):
    with TestClient(app) as c:
        _request_reset(c, admin["email"])
    assert len(sent) == 1
    assert sent[0]["to"] == admin["email"]
    assert "reset" in sent[0]["subject"].lower()


def test_email_contains_a_usable_link(admin, sent):
    with TestClient(app) as c:
        _request_reset(c, admin["email"])
    html = sent[0]["html"]
    assert "/reset-password?token=" in html
    assert str(reset_service.TOKEN_TTL_MINUTES) in html, \
        "the email should tell the administrator how long the link lasts"


def test_no_email_for_an_unknown_address(sent):
    with TestClient(app) as c:
        r = _request_reset(c, f"nobody-{uuid.uuid4().hex[:8]}@threatsense.local")
    assert r.status_code == 200
    assert sent == []


def test_response_is_identical_for_known_and_unknown_addresses(admin, sent):
    """No enumeration: the reply must not reveal whether the account exists."""
    with TestClient(app) as c:
        known = _request_reset(c, admin["email"])
        unknown = _request_reset(c, f"nobody-{uuid.uuid4().hex[:8]}@x.local")
    assert known.status_code == unknown.status_code
    assert known.json() == unknown.json()


def test_delivery_failure_still_returns_the_generic_response(admin, monkeypatch):
    """A provider outage must not become an account-enumeration oracle."""
    class _Result:
        success = False
        detail = "provider unavailable"

    class _Sender:
        name = "failing"

        def send(self, to, subject, html):
            return _Result()

    monkeypatch.setattr(reset_service, "get_sender", lambda: _Sender())
    with TestClient(app) as c:
        r = _request_reset(c, admin["email"])
    assert r.status_code == 200
    assert "if that account exists" in r.json()["message"].lower()


def test_delivery_failure_does_not_log_the_token(admin, monkeypatch, caplog):
    issued = {}
    real_issue = reset_service.reset_token_store.issue

    def _spy(admin_id):
        raw = real_issue(admin_id)
        issued["raw"] = raw
        return raw

    class _Result:
        success = False
        detail = "provider unavailable"

    class _Sender:
        name = "failing"

        def send(self, to, subject, html):
            return _Result()

    monkeypatch.setattr(reset_service.reset_token_store, "issue", _spy)
    monkeypatch.setattr(reset_service, "get_sender", lambda: _Sender())
    caplog.set_level(logging.DEBUG)
    with TestClient(app) as c:
        _request_reset(c, admin["email"])

    haystack = "\n".join(
        [r.getMessage() for r in caplog.records] + [caplog.text])
    assert issued["raw"] not in haystack


# --- the flow still works end to end -----------------------------------------

def test_emailed_link_completes_the_reset(admin, sent):
    """Regression guard: removing the log line must not break the feature."""
    with TestClient(app) as c:
        _request_reset(c, admin["email"])
        token = sent[0]["html"].split("token=")[1].split('"')[0]

        r = c.post("/api/auth/password-reset/confirm",
                   json={"token": token, "new_password": NEW_PASSWORD})
        assert r.status_code == 200, r.text

        old = c.post("/api/auth/login",
                     json={"email": admin["email"], "password": PASSWORD})
        assert old.status_code == 401
        new = c.post("/api/auth/login",
                     json={"email": admin["email"], "password": NEW_PASSWORD})
        assert new.status_code == 200, new.text


def test_token_is_single_use(admin, sent):
    with TestClient(app) as c:
        _request_reset(c, admin["email"])
        token = sent[0]["html"].split("token=")[1].split('"')[0]
        first = c.post("/api/auth/password-reset/confirm",
                       json={"token": token, "new_password": NEW_PASSWORD})
        second = c.post("/api/auth/password-reset/confirm",
                        json={"token": token, "new_password": "ThirdPass3#"})
    assert first.status_code == 200
    assert second.status_code != 200


def test_store_holds_only_the_hash_not_the_token(admin, sent):
    """Section 2.1: tokens are "stored as SHA-256 hashes"."""
    with TestClient(app) as c:
        _request_reset(c, admin["email"])
    token = sent[0]["html"].split("token=")[1].split('"')[0]
    keys = list(reset_service.reset_token_store._store.keys())
    assert token not in keys
    assert reset_service.hash_token(token) in keys


def test_token_is_256_bits_of_randomness():
    """Section 2.1: "cryptographically random 256-bit values"."""
    raw = reset_service.reset_token_store.issue(uuid.uuid4())
    # token_urlsafe(32) is 32 random bytes, base64url-encoded to 43 chars.
    assert len(raw) >= 43


def test_ttl_matches_the_proposal():
    """Section 2.1: "expire after 15 minutes"."""
    assert reset_service.TOKEN_TTL_MINUTES == 15


# --- adversarial: the provider is not trusted to keep the token out ----------
#
# The tests above monkeypatch get_sender, so they only prove that the reset
# ROUTER and SERVICE do not log the token themselves. They say nothing about
# the real delivery path.
#
# That gap mattered. The failure branch used to log result.detail with a
# comment asserting "it does not contain the token" — an assumption about a
# third party's error strings. SendGridSender builds detail from either
# str(exc) or the raw HTTP response body, and the request that produced
# either one carried the reset link in its body. A provider that echoed the
# payload back in an error would have put a live credential in the log, and
# nothing in the code prevented it.
#
# These tests make the provider hostile on purpose: the exception text and
# the response body both contain the token.

_POISON = "POISONTOKEN_abcdef0123456789"


def test_service_does_not_log_provider_detail_containing_a_token(admin, monkeypatch, caplog):
    """A sender whose failure detail embeds the token must not leak it."""
    class _Result:
        success = False
        detail = f"550 rejected: https://host/reset-password?token={_POISON}"
        status_code = 550

    class _Sender:
        name = "hostile"

        def send(self, to, subject, html):
            return _Result()

    monkeypatch.setattr(reset_service, "get_sender", lambda: _Sender())
    caplog.set_level(logging.DEBUG)
    reset_service.send_reset_link(admin["email"], _POISON)

    haystack = "\n".join([r.getMessage() for r in caplog.records] + [caplog.text])
    assert _POISON not in haystack, "provider-supplied detail leaked the token"
    # The diagnostic value must survive: we still want to know it failed.
    assert "delivery failed" in haystack
    assert "550" in haystack


def test_real_sendgrid_client_does_not_log_exception_text(monkeypatch, caplog):
    """Drive the ACTUAL SendGridSender with a client that raises a poisoned error.

    Not a stand-in: this is the class used in production, so it covers the
    `logger.warning("SendGrid send raised ...")` branch that previously
    formatted str(exc) straight into the log.
    """
    from app.config import settings as app_settings
    from app.services.alerting import sendgrid_client

    monkeypatch.setattr(app_settings, "sendgrid_api_key", "SG.fake-for-test")

    sender = sendgrid_client.SendGridSender()

    class _Raising:
        def send(self, message):
            raise RuntimeError(
                f"upstream rejected payload https://host/reset-password?token={_POISON}")

    monkeypatch.setattr(sender, "_client", _Raising())
    caplog.set_level(logging.DEBUG)
    result = sender.send("someone@example.com", "subject", "<p>body</p>")

    assert result.success is False
    haystack = "\n".join([r.getMessage() for r in caplog.records] + [caplog.text])
    assert _POISON not in haystack, "SendGridSender logged provider exception text"
    assert "RuntimeError" in haystack, "the exception type should still be logged"


def test_real_sendgrid_client_does_not_log_response_body(monkeypatch, caplog):
    """Same for the non-2xx branch, where detail comes from the response body."""
    from app.config import settings as app_settings
    from app.services.alerting import sendgrid_client

    monkeypatch.setattr(app_settings, "sendgrid_api_key", "SG.fake-for-test")
    sender = sendgrid_client.SendGridSender()

    class _Response:
        status_code = 403
        body = f"forbidden: token={_POISON}".encode()

    class _Client:
        def send(self, message):
            return _Response()

    monkeypatch.setattr(sender, "_client", _Client())
    caplog.set_level(logging.DEBUG)
    result = sender.send("someone@example.com", "subject", "<p>body</p>")

    assert result.success is False
    haystack = "\n".join([r.getMessage() for r in caplog.records] + [caplog.text])
    assert _POISON not in haystack


def test_end_to_end_hostile_provider_through_the_route(admin, monkeypatch, caplog):
    """Full request path with a failing sender: still no token anywhere."""
    issued = {}
    real_issue = reset_service.reset_token_store.issue

    def _spy(admin_id):
        raw = real_issue(admin_id)
        issued["raw"] = raw
        return raw

    class _Result:
        success = False
        detail = "rejected"
        status_code = 550

    class _Sender:
        name = "hostile"

        def send(self, to, subject, html):
            # Echo the caller's own body into the failure, worst case.
            _Result.detail = html
            return _Result()

    monkeypatch.setattr(reset_service.reset_token_store, "issue", _spy)
    monkeypatch.setattr(reset_service, "get_sender", lambda: _Sender())
    caplog.set_level(logging.DEBUG)
    with TestClient(app) as c:
        r = _request_reset(c, admin["email"])
    assert r.status_code == 200

    haystack = "\n".join([r_.getMessage() for r_ in caplog.records] + [caplog.text])
    assert issued["raw"] not in haystack
