"""Initial administrator setup (Section 2.1, NFR-08).

Section 2.1, verbatim:

    "Direct registration is available only for the initial administrator.
     Additional accounts are created by an authenticated SUPER_ADMIN through
     a controlled account-management workflow"

and Figure 3's login mock-up shows an Initial Setup link "Available only
before the first administrator account is created".

WHY THIS EXISTS
---------------
There was no setup workflow at all. The only way to obtain an account was to
run db/seed.py, which creates admin@threatsense.local with a hard-coded
password printed in a warning. That is fine for a development fixture and
wrong as the product's first-run experience.

It also made NFR-08 unmeasurable. Table 11 asks that "a first-time
administrator with basic IT knowledge must be able to complete initial setup
or sign in, configure a Syslog source, and view their first detection result
within 15 minutes of initial access, without consulting external
documentation" — there was no initial setup to complete, so the clock could
not start.

THE ONE-ACCOUNT RULE
--------------------
The endpoint is public, because by definition nobody can authenticate before
the first account exists. That makes "exactly one" the entire security
boundary, so it is enforced at the DATABASE, not by a Python check:

    create_first_administrator() inserts and relies on the partial unique
    index in db/migrations/002_single_initial_admin.sql to reject a second
    concurrent insert.

A count-then-insert check is not sufficient. Two requests arriving together
both see zero administrators, both proceed, and both create an account —
which would hand a second SUPER_ADMIN to whoever raced the real operator. The
index makes that impossible regardless of timing; the count below is only a
fast path for the common case.
"""
from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...core.password_policy import validate_password
from ...core.security import hash_password
from ...models import (
    AdminRole, Administrator, AuditAction, AuditLog, DetectionSettings,
)

logger = logging.getLogger("threatsense.auth.setup")

# The trained model shipped with the capstone repository.  Initial setup must
# leave a fresh installation immediately usable by the detection engine rather
# than requiring the operator to discover and run the development seed script.
DEFAULT_ACTIVE_MODEL_VERSION = "IF_v1.0"


class SetupAlreadyComplete(Exception):
    """Raised when an administrator already exists."""


def setup_required(db: Session) -> bool:
    """True while no administrator exists.

    Read by the login screen to decide whether to show the Initial Setup
    link (Figure 3). Deliberately public and deliberately minimal: it reveals
    only whether the system has been configured, which an unconfigured
    system announces anyway by having no accounts.
    """
    return db.scalar(select(func.count()).select_from(Administrator)) == 0


def create_first_administrator(db: Session, *, full_name: str, email: str,
                               password: str, ip: str | None = None) -> Administrator:
    """Create the initial SUPER_ADMIN. Raises SetupAlreadyComplete otherwise.

    The role is SUPER_ADMIN because Section 2.1 reserves account management
    for that role: if the first account were an ADMIN, nobody could ever
    create the second one.
    """
    if not setup_required(db):
        # Fast path. Not the security boundary — see the module docstring.
        raise SetupAlreadyComplete()

    validate_password(password)          # NFR-11, before bcrypt

    admin = Administrator(
        full_name=full_name.strip(),
        email=email.strip().lower(),
        password_hash=hash_password(password),
        role=AdminRole.SUPER_ADMIN,
        # The flag the partial unique index guards. This is what makes a
        # concurrent second setup fail in the database rather than in Python.
        is_initial_admin=True,
    )
    db.add(admin)
    try:
        db.flush()
    except IntegrityError:
        # Either the unique index on "one administrator" fired (a concurrent
        # setup won) or the email is taken. Both mean: do not create.
        db.rollback()
        raise SetupAlreadyComplete()

    # A fresh schema has no detection_settings row, but the detection engine
    # cannot run without the singleton global configuration (Table 7).  Create
    # it in the SAME transaction as the first administrator: if either write
    # fails, neither half of the first-run bootstrap is allowed to survive.
    db.add(DetectionSettings(
        sensitivity_threshold=0.75,
        active_model_version=DEFAULT_ACTIVE_MODEL_VERSION,
        detection_interval_seconds=60,
        updated_by=admin.admin_id,
    ))
    db.add(AuditLog(
        admin_id=admin.admin_id,
        action=AuditAction.CONFIG_CHANGE,
        details=(f"initial administrator setup: {admin.email} (SUPER_ADMIN); "
                 f"detection settings initialised: threshold 0.75, "
                 f"model {DEFAULT_ACTIVE_MODEL_VERSION}, interval 60s"),
        ip_address=ip,
    ))
    try:
        db.commit()
    except Exception:
        # db.flush() above has not committed the administrator.  Rolling back
        # here therefore removes the account too, avoiding a half-configured
        # system where setup is closed but the detection engine cannot run.
        db.rollback()
        raise
    db.refresh(admin)
    logger.info("initial administrator created: %s", admin.email)
    return admin
