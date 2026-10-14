"""Administrator account management (Section 2.1).

Section 2.1, verbatim:

    "Direct registration is available only for the initial administrator.
     Additional accounts are created by an authenticated SUPER_ADMIN through
     a controlled account-management workflow"

Initial setup covered the first half. This module is the second: the workflow
by which a SUPER_ADMIN creates the ADMIN and VIEWER accounts that follow.

Without it the three-role design was unreachable in practice — a VIEWER
account could only be produced by inserting a row into PostgreSQL by hand,
which is neither a controlled workflow nor something an SMB operator could do.

SCOPE. Listing and creating accounts only.

DELETION IS DELIBERATELY ABSENT. audit_logs.admin_id references
administrators without ON DELETE CASCADE or SET NULL, and every successful
login writes a LOGIN row — so any account that has actually been used cannot
be deleted, and the attempt fails with a foreign-key violation. That is the
schema working as intended: Section 2.3 describes audit_logs as append-only,
and silently discarding an administrator's audit trail to allow a delete
button would defeat it.

Offering a Remove control that fails for every account that has ever signed in
is worse than offering none. Account lifecycle management, when it is added,
should be a status flag (ACTIVE / DISABLED) that preserves the audit history,
not a physical delete. Section 2.1 requires controlled CREATION of additional
accounts, which this module provides; it does not require deletion.

Role changes and password resets on behalf of another user are out of scope
for the same reason: each needs its own safeguards, and a half-built version
is worse than an absent one.
"""
from __future__ import annotations

import ipaddress
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..core.password_policy import password_policy_errors
from ..core.security import hash_password
from ..database import get_db
from ..middleware.rbac import require_super_admin
from ..models import AdminRole, Administrator, AuditAction, AuditLog
from ..schemas.account import AccountCreate, AccountOut

router = APIRouter(prefix="/api/accounts", tags=["accounts"])
logger = logging.getLogger("threatsense.accounts")


def _client_ip(request: Request) -> str | None:
    """Return the client IP only if it is a valid INET value, else None.

    audit_logs.ip_address is a PostgreSQL INET column and rejects anything
    that is not a real address. A proxy or test client can present a hostname
    rather than an address, and losing the audit row entirely because the IP
    was unparseable would be the wrong trade. Same guard as routers/auth.py.
    """
    host = request.client.host if request.client else None
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    return host


@router.get("", response_model=list[AccountOut])
def list_accounts(db: Session = Depends(get_db),
                  admin: Administrator = Depends(require_super_admin)
                  ) -> list[Administrator]:
    """Every administrator account. SUPER_ADMIN only.

    Deliberately not open to ADMIN: knowing who else holds an account, and
    with what role, is reconnaissance for anyone who has compromised a lesser
    account.
    """
    return list(db.scalars(
        select(Administrator).order_by(Administrator.created_at)).all())


@router.post("", response_model=AccountOut, status_code=status.HTTP_201_CREATED)
def create_account(payload: AccountCreate, request: Request,
                   db: Session = Depends(get_db),
                   admin: Administrator = Depends(require_super_admin)
                   ) -> Administrator:
    """Create an ADMIN or VIEWER account. SUPER_ADMIN only.

    The role is restricted to ADMIN and VIEWER by the schema. Creating another
    SUPER_ADMIN is not offered here: it is a privilege escalation worth doing
    deliberately rather than through a dropdown, and the proposal does not ask
    for it.

    The password is set by the creating administrator and must satisfy the
    same NFR-11 policy as every other entry point. In a production deployment
    the new user would be expected to change it; that flow already exists on
    the Account Settings page.
    """
    errors = password_policy_errors(payload.password)
    if errors:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, " ".join(errors))

    email = payload.email.strip().lower()
    if db.scalar(select(func.count()).select_from(Administrator)
                 .where(func.lower(Administrator.email) == email)):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "An account with that email address already exists.")

    account = Administrator(
        full_name=payload.full_name.strip(),
        email=email,
        password_hash=hash_password(payload.password),
        role=AdminRole(payload.role),
    )
    db.add(account)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "An account with that email address already exists.")

    db.add(AuditLog(
        admin_id=admin.admin_id, action=AuditAction.CONFIG_CHANGE,
        details=f"created account {account.email} with role {account.role.value}",
        ip_address=_client_ip(request)))
    db.commit()
    db.refresh(account)
    logger.info("account %s created by %s", account.email, admin.email)
    return account
