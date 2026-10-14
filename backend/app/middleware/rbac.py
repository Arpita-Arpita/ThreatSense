"""Role-based authorisation (Section 2.1).

Section 2.1 states that each administrator holds "one of three roles
(SUPER_ADMIN, ADMIN, or VIEWER) that determines their access permissions
across the system", and that additional accounts are "created by an
authenticated SUPER_ADMIN through a controlled account-management workflow".

Until now the roles existed in the model and in the JWT and were enforced
nowhere: get_current_admin authenticated the caller but never authorised the
action, so a VIEWER could add sources, change the shared detection threshold,
run scans, send test email, acknowledge detections and generate AI reports.
The three-role design was decorative.

POLICY

    SUPER_ADMIN   everything ADMIN can do, plus account management
    ADMIN         full operational administration
    VIEWER        read-only: may inspect, may not change state, trigger an
                  external send, or incur LLM cost

The proposal does not enumerate per-endpoint permissions, so the split below
is the least-privilege reading: reads open to all three, and every mutation,
upload, scan, test send, acknowledgement and report generation restricted to
the operator roles.

TWO SEPARATE CHECKS

Role answers "what actions may this account perform"; ownership answers "on
whose data". They are deliberately independent, and SUPER_ADMIN does NOT
bypass ownership — the per-admin scoping in the routers stays exactly as it
was, so one administrator still cannot read another's sources, detections or
reports regardless of role. Making SUPER_ADMIN organisation-wide would be a
change to the approved design, not an implementation detail.

STATUS CODES

    401  no session, or the session is invalid or expired
    403  authenticated, but this role may not perform this action
    404  the object does not exist within this account's ownership scope

403 and 404 must not be conflated: 404 for a wrong-owner object is
deliberate (it does not confirm the object exists), while 403 for a
role failure is safe because the caller already knows their own role.

AUTHORITY IS THE DATABASE ROW, NOT THE TOKEN

get_current_admin loads the Administrator from the database on every request,
and these dependencies read admin.role from that row. The JWT still carries
role because Section 2.1 asks for it, but it is not the authorisation
authority: if a SUPER_ADMIN demotes an ADMIN to VIEWER, the demotion takes
effect on the next request rather than lingering for the remaining lifetime
of a 60-minute token.
"""
from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, status

from ..models import AdminRole, Administrator
from .auth import get_current_admin

# Read-only monitoring and reporting.
READ_ROLES = (AdminRole.SUPER_ADMIN, AdminRole.ADMIN, AdminRole.VIEWER)
# Anything that changes state, uploads data, runs the engine, sends email or
# spends OpenAI quota.
OPERATOR_ROLES = (AdminRole.SUPER_ADMIN, AdminRole.ADMIN)
# Account management (Section 2.1). No endpoint uses this yet; it is defined
# here so the account-management workflow has one obvious place to attach.
SUPER_ADMIN_ONLY = (AdminRole.SUPER_ADMIN,)


def require_roles(*allowed: AdminRole) -> Callable[..., Administrator]:
    """Dependency factory: authenticate, then authorise against the DB role.

    Returns the Administrator so routes can keep using it for ownership
    scoping — this replaces Depends(get_current_admin) rather than sitting
    alongside it, which means a route cannot accidentally end up with the
    authorisation check attached but the unauthorised admin object in hand.
    """
    allowed_set = frozenset(allowed)

    def dependency(
        admin: Administrator = Depends(get_current_admin),
    ) -> Administrator:
        if admin.role not in allowed_set:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Your role does not permit this action.",
            )
        return admin

    # Tagged so the policy is machine-readable. tests/test_rbac.py walks every
    # registered route, reads this attribute and asserts the whole matrix in
    # one place — which catches a new route added with the wrong dependency,
    # or with none at all, without anyone remembering to write a test for it.
    dependency.allowed_roles = allowed_set          # type: ignore[attr-defined]
    dependency.__name__ = "require_" + "_".join(
        sorted(r.value.lower() for r in allowed_set))
    return dependency


# Pre-built dependencies. Routes use these rather than calling require_roles
# inline, so the permitted set for a route is visible at a glance and a typo
# cannot silently widen access.
require_read = require_roles(*READ_ROLES)
require_operator = require_roles(*OPERATOR_ROLES)
require_super_admin = require_roles(*SUPER_ADMIN_ONLY)
