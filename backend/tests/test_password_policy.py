"""
NFR-11 — strong password policy, server side (task 1.5).

    cd backend && source .venv/bin/activate
    pytest tests/test_password_policy.py -v

Proposal Section 3, Table 11, NFR-11 — Requirement (verbatim):
    "The system must enforce strong password policies: a minimum of 8
    characters, with at least one uppercase letter, one lowercase letter, one
    digit, and one special character. Passwords must be validated on both the
    client side and the server side before acceptance."

Proposal Section 3, Table 11, NFR-11 — Measurement / Metric (verbatim):
    "Implementation: client-side regex validation on the registration form,
    and server-side validation immediately before bcrypt hashing. Testing: an
    automated test suite submitting passwords of varying complexity and
    verifying that non-compliant passwords are rejected with appropriate error
    messages."

This file IS that automated suite for the server side. The client side is
frontend/src/lib/passwordPolicy.js, whose rules are pinned against this
module by test_client_and_server_policies_agree below.

Each of the five checks named in the requirement gets a password that fails
ONLY that check, so a regression can be attributed to a specific clause.
"""
from __future__ import annotations

import re
import string
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core import password_policy
from app.core.password_policy import (
    MIN_LENGTH, PasswordPolicyError, is_compliant, password_policy_errors,
    validate_password,
)
from app.core.security import hash_password, verify_password
from app.database import SessionLocal
from app.main import app
from app.middleware.rate_limit import login_rate_limiter
from app.models import AdminRole, Administrator, AuditLog
from app.services.auth.reset import reset_token_store

COMPLIANT = "TestPassw0rd!"

# One password per clause of NFR-11, each failing exactly one check.
FAILS_ONE_CHECK = [
    ("too short",            "Ab1!efg",              "at least 8 characters"),
    ("no uppercase letter",  "testpassw0rd!",        "uppercase"),
    ("no lowercase letter",  "TESTPASSW0RD!",        "lowercase"),
    ("no digit",             "TestPassword!",        "digit"),
    ("no special character", "TestPassw0rdX",        "special"),
]


# --- the five checks -------------------------------------------------------

def test_a_compliant_password_is_accepted():
    assert password_policy_errors(COMPLIANT) == []
    assert is_compliant(COMPLIANT) is True


@pytest.mark.parametrize("label,password,expected_fragment", FAILS_ONE_CHECK,
                         ids=[c[0] for c in FAILS_ONE_CHECK])
def test_each_clause_is_enforced_independently(label, password, expected_fragment):
    """Every clause of NFR-11 rejects on its own, with a message naming it."""
    errors = password_policy_errors(password)
    assert len(errors) == 1, f"{label}: expected exactly one failure, got {errors}"
    assert expected_fragment in errors[0].lower()


def test_minimum_length_is_eight():
    """Table 11, NFR-11: "a minimum of 8 characters"."""
    assert MIN_LENGTH == 8
    assert password_policy_errors("Abc1!" + "x" * (MIN_LENGTH - 5)) == []
    assert password_policy_errors("Abc1!" + "x" * (MIN_LENGTH - 6)) != []


def test_all_five_failures_are_reported_together():
    """"appropriate error messages" — plural, so don't stop at the first."""
    errors = password_policy_errors("")
    assert len(errors) == 5


def test_special_character_set_matches_the_documented_set():
    """Pins the set NFR-11 leaves unenumerated, so it cannot drift silently."""
    assert password_policy.SPECIAL_CHARACTERS == frozenset(string.punctuation)
    for ch in string.punctuation:
        assert is_compliant(f"TestPassw0rd{ch}"), f"{ch!r} should count as special"


def test_whitespace_is_not_a_special_character():
    assert not is_compliant("TestPassw0rd ")


def test_validate_password_raises_with_the_failure_list():
    with pytest.raises(PasswordPolicyError) as exc:
        validate_password("short")
    assert exc.value.errors
    assert len(exc.value.errors) == len(password_policy_errors("short"))


# --- "immediately before bcrypt hashing" -----------------------------------

def test_hash_password_rejects_a_non_compliant_password():
    """The guard sits at the bcrypt call site, per Table 11's measurement column."""
    with pytest.raises(PasswordPolicyError):
        hash_password("weak")


def test_hash_password_still_works_for_a_compliant_password():
    digest = hash_password(COMPLIANT)
    assert verify_password(COMPLIANT, digest)


def test_seed_script_has_its_own_guard():
    """db/seed.py hashes independently of app.core.security and needs its own check."""
    source = (Path(__file__).resolve().parents[1] / "db" / "seed.py").read_text()
    assert "password_policy_errors" in source, \
        "seed.py must validate SEED_ADMIN_PASSWORD before bcrypt"


# --- the API path: "rejected with appropriate error messages" --------------

@pytest.fixture()
def admin():
    email = f"policy-{uuid.uuid4().hex[:8]}@threatsense.local"
    with SessionLocal() as db:
        row = Administrator(full_name="Policy Test", email=email,
                            password_hash=hash_password(COMPLIANT),
                            role=AdminRole.ADMIN)
        db.add(row)
        db.commit()
        admin_id = row.admin_id
    login_rate_limiter.reset()
    yield {"admin_id": admin_id, "email": email}
    login_rate_limiter.reset()
    with SessionLocal() as db:
        db.query(AuditLog).filter(AuditLog.admin_id == admin_id).delete()
        db.query(Administrator).filter(Administrator.admin_id == admin_id).delete()
        db.commit()


@pytest.mark.parametrize("label,password,expected_fragment", FAILS_ONE_CHECK,
                         ids=[c[0] for c in FAILS_ONE_CHECK])
def test_reset_endpoint_rejects_non_compliant_passwords(admin, label, password, expected_fragment):
    token = reset_token_store.issue(admin["admin_id"])
    with TestClient(app) as client:
        res = client.post("/api/auth/password-reset/confirm",
                          json={"token": token, "new_password": password})
    assert res.status_code == 422, label
    assert expected_fragment in res.json()["detail"].lower()


def test_rejection_detail_is_a_readable_string_not_a_pydantic_array():
    """frontend/src/api/client.js reads body.detail directly.

    A Pydantic Field constraint would emit a list of error objects here, which
    the React error banner renders as "[object Object]". The administrator
    must see the actual rule.
    """
    with TestClient(app) as client:
        res = client.post("/api/auth/password-reset/confirm",
                          json={"token": "irrelevant", "new_password": "weak"})
    assert res.status_code == 422
    assert isinstance(res.json()["detail"], str)


def test_reset_endpoint_accepts_a_compliant_password(admin):
    new_password = "Rotated1Pass!"
    token = reset_token_store.issue(admin["admin_id"])
    with TestClient(app) as client:
        res = client.post("/api/auth/password-reset/confirm",
                          json={"token": token, "new_password": new_password})
        assert res.status_code == 200

        login = client.post("/api/auth/login",
                            json={"email": admin["email"], "password": new_password})
        assert login.status_code == 200


def test_policy_is_published_for_the_client_side():
    """The React validator fetches this so both sides show the same wording."""
    with TestClient(app) as client:
        res = client.get("/api/auth/password-policy")
    assert res.status_code == 200
    assert res.json()["min_length"] == MIN_LENGTH


# --- "validated on both the client side and the server side" ---------------

def test_client_and_server_policies_agree():
    """Pin the React validator's constants against this module.

    NFR-11 requires validation on both sides. Two independent implementations
    can drift; this reads the JS and checks the numbers and character class
    still match Python.
    """
    js_path = (Path(__file__).resolve().parents[2]
               / "frontend" / "src" / "lib" / "passwordPolicy.js")
    if not js_path.exists():
        pytest.skip("frontend/src not present in this checkout")

    js = js_path.read_text()

    min_length_match = re.search(r"MIN_LENGTH\s*=\s*(\d+)", js)
    assert min_length_match, "passwordPolicy.js must declare MIN_LENGTH"
    assert int(min_length_match.group(1)) == MIN_LENGTH

    for required in ["[A-Z]", "[a-z]", "[0-9]"]:
        assert required in js, f"client validator is missing the {required} check"
    assert "SPECIAL" in js, "client validator is missing the special-character check"
