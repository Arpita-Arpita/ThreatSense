"""Auth routes: login / logout / me (task 1.4, UC 4.1)."""
from __future__ import annotations

import ipaddress
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from ..config import settings
from ..core.password_policy import POLICY_DESCRIPTION, password_policy_errors
from ..database import get_db
from ..middleware.auth import get_current_admin
from ..middleware.rate_limit import LoginRateLimitExceeded, check_login_rate
from ..core.security import hash_password, verify_password
from ..models import Administrator, AuditAction, AuditLog
from ..schemas.auth import (AdminOut, LoginRequest, PasswordChange,
                            PasswordResetConfirm, PasswordResetRequest,
                            SetupRequest, SetupStatus)
from ..services.auth.service import AccountLocked, InvalidCredentials, authenticate
from ..services.auth.reset import confirm_reset, request_reset, send_reset_link
from ..services.auth.setup import (SetupAlreadyComplete,
                                   create_first_administrator, setup_required)

router = APIRouter(prefix="/api/auth", tags=["auth"])
logger = logging.getLogger("threatsense.auth")


def _client_ip(request: Request) -> str | None:
    """Return the client IP only if it is a valid INET value, else None.

    Used for audit_logs.ip_address, which is a PostgreSQL INET column and will
    reject anything that is not a real address.
    """
    host = request.client.host if request.client else None
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return None


def _rate_limit_key(request: Request) -> str:
    """Return a stable per-client key for the NFR-05 login window.

    Deliberately NOT _client_ip(): rate limiting needs a stable identifier for
    the caller, not a storable INET value. Starlette's TestClient reports the
    host as the literal string "testclient", and a proxied deployment may
    report a hostname — both must still be throttled. Unidentifiable clients
    share one bucket rather than escaping the limit entirely.
    """
    host = request.client.host if request.client else None
    return host or "unknown-client"


@router.post("/login", response_model=AdminOut)
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> Administrator:
    # Table 11, NFR-05: "five login attempts per IP within a 15-minute window
    # ... Exceeding limits returns HTTP 429."
    # Checked BEFORE authenticate() so that every attempt counts against the
    # window, including attempts against emails that match no account.
    try:
        check_login_rate(_rate_limit_key(request))
    except LoginRateLimitExceeded as exc:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many login attempts. Try again in {exc.retry_after_seconds} seconds.",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        )

    ip = _client_ip(request)
    try:
        admin, token = authenticate(db, payload.email, payload.password, ip)
    except AccountLocked as exc:
        # Mirrors the 429 above: a lockout the administrator cannot see the
        # end of is indistinguishable from a broken account, which is what
        # made the previous permanent lockout so awkward to operate.
        minutes = max(1, round(exc.retry_after_seconds / 60))
        raise HTTPException(
            status.HTTP_423_LOCKED,
            "Account locked after too many failed attempts. "
            f"Try again in about {minutes} minute{'s' if minutes != 1 else ''}.",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        )
    except InvalidCredentials:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_expiry_minutes * 60,
        path="/",
    )
    return admin


@router.post("/logout")
def logout(response: Response, _: Administrator = Depends(get_current_admin)) -> dict:
    response.delete_cookie(settings.cookie_name, path="/")
    return {"status": "logged out"}


@router.get("/me", response_model=AdminOut)
def me(admin: Administrator = Depends(get_current_admin)) -> Administrator:
    return admin


@router.post("/password-reset/request")
def password_reset_request(payload: PasswordResetRequest, db: Session = Depends(get_db)) -> dict:
    """Issue a reset token and email the link (Section 2.1).

    The raw token is a bearer credential for this account for 15 minutes. It
    is handed straight to the mailer and never logged, returned, or included
    in the response — an earlier build logged the full link at WARNING for
    local testing, which put a live credential into every log sink.

    The response is identical whether or not the address matches an account,
    and whether or not delivery succeeded, so this endpoint cannot be used to
    enumerate administrators.
    """
    raw = request_reset(db, payload.email)
    if raw is not None:
        send_reset_link(payload.email, raw)
    return {"message": "If that account exists, a password reset link has been sent."}


@router.get("/password-policy")
def password_policy() -> dict:
    """Publish the NFR-11 rules so the client-side validator cannot drift.

    Table 11, NFR-11: "Passwords must be validated on both the client side and
    the server side before acceptance." The React form carries its own regex
    (the requirement asks for one), but fetching the human-readable rules from
    the server keeps the message shown to the administrator identical to the
    one the server would return on rejection.
    """
    from ..core.password_policy import MIN_LENGTH
    return {"min_length": MIN_LENGTH, "description": POLICY_DESCRIPTION}


@router.post("/password-reset/confirm")
def password_reset_confirm(payload: PasswordResetConfirm, db: Session = Depends(get_db)) -> dict:
    # Table 11, NFR-11: "The system must enforce strong password policies: a
    # minimum of 8 characters, with at least one uppercase letter, one
    # lowercase letter, one digit, and one special character."
    # hash_password() enforces this too (immediately before bcrypt, per the
    # measurement column). It is repeated here so the administrator gets a
    # readable list of what is missing instead of a 500 from deeper in the
    # stack, satisfying "rejected with appropriate error messages".
    errors = password_policy_errors(payload.new_password)
    if errors:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, " ".join(errors))

    if not confirm_reset(db, payload.token, payload.new_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired reset token")
    return {"message": "Password has been reset. You can now log in."}


@router.get("/setup-status", response_model=SetupStatus)
def get_setup_status(db: Session = Depends(get_db)) -> SetupStatus:
    """Whether the system still needs its first administrator.

    Public by necessity: the login screen calls it before anyone can
    authenticate, to decide whether to show the Initial Setup link. Figure 3:
    "Available only before the first administrator account is created."

    It discloses only whether any account exists, which an unconfigured
    system reveals anyway by having none.
    """
    return SetupStatus(setup_required=setup_required(db))


@router.post("/setup", response_model=AdminOut, status_code=status.HTTP_201_CREATED)
def initial_setup(payload: SetupRequest, request: Request,
                  db: Session = Depends(get_db)) -> Administrator:
    """Create the initial administrator (Section 2.1).

        "Direct registration is available only for the initial administrator.
         Additional accounts are created by an authenticated SUPER_ADMIN
         through a controlled account-management workflow"

    Public, because nobody can authenticate before the first account exists.
    "Exactly one" is therefore the whole security boundary, and it is enforced
    by a partial unique index rather than a count-then-insert check — two
    simultaneous requests both read zero administrators and would both
    succeed. See db/migrations/002_single_initial_admin.sql.

    The account is SUPER_ADMIN because Section 2.1 reserves account creation
    for that role: a first account with any lesser role could never create
    the second.

    Returns 409 once setup is complete. Deliberately not 403: there is no
    authorisation question here, the operation simply no longer applies.
    """
    # Availability first. Validating the password before checking whether
    # setup is still open made the response depend on the password: a strong
    # one got 409, a weak one got 422, on a system where neither could ever
    # create an account. The route's contract is "409 once setup is
    # complete", so answer that first.
    #
    # create_first_administrator re-checks under the unique index; this is a
    # fast path for the common case, not the boundary.
    if not setup_required(db):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Setup has already been completed. Ask a SUPER_ADMIN to create "
            "your account.")

    # NFR-11 server-side, before bcrypt. Repeated here rather than left to
    # hash_password so the response lists exactly what the password is
    # missing — "rejected with appropriate error messages".
    errors = password_policy_errors(payload.password)
    if errors:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, " ".join(errors))

    try:
        return create_first_administrator(
            db, full_name=payload.full_name, email=payload.email,
            password=payload.password, ip=_client_ip(request))
    except SetupAlreadyComplete:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Setup has already been completed. Ask a SUPER_ADMIN to create "
            "your account.")


@router.post("/change-password")
def change_password(payload: PasswordChange, request: Request,
                    db: Session = Depends(get_db),
                    admin: Administrator = Depends(get_current_admin)) -> dict:
    """Change your own password (Section 2.1).

    Distinct from the reset flow, which is for someone who cannot sign in.
    This is for someone already signed in, so it verifies the CURRENT password
    first — otherwise an unattended unlocked screen is a permanent account
    takeover rather than a temporary one.

    The new password goes through the same NFR-11 policy as every other entry
    point, and the change is written to audit_logs (Section 2.7).
    """
    if not verify_password(payload.current_password, admin.password_hash):
        # Deliberately not "wrong password" vs "no such account": the caller
        # is already authenticated, so the only useful detail is that the
        # current password did not match.
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Your current password is not correct.")

    errors = password_policy_errors(payload.new_password)
    if errors:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, " ".join(errors))

    admin.password_hash = hash_password(payload.new_password)
    db.add(AuditLog(admin_id=admin.admin_id, action=AuditAction.CONFIG_CHANGE,
                    details="password changed by the account holder",
                    ip_address=_client_ip(request)))
    db.commit()
    return {"message": "Your password has been changed."}
