"""
Password policy enforcement (NFR-11).

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

The requirement names five checks. Each is implemented as its own predicate
below so a caller can report exactly which class is missing, rather than a
single opaque "password too weak" — that is what "appropriate error messages"
in the measurement column asks for.

The client-side mirror of this module is frontend/src/lib/passwordPolicy.js.
The two MUST stay in step; test_password_policy.py::test_special_character_set
_matches_the_documented_set pins the character set on this side.
"""
from __future__ import annotations

import string

# NFR-11: "a minimum of 8 characters"
MIN_LENGTH = 8

# NFR-11: "one special character". The requirement does not enumerate which
# characters count, so this fixes the set explicitly rather than leaving it to
# a reader's assumption: the 32 ASCII punctuation marks, i.e. Python's
# string.punctuation -> !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
# Whitespace is deliberately NOT a special character: a trailing space is a
# typing accident, not a deliberate strengthening choice.
SPECIAL_CHARACTERS = frozenset(string.punctuation)

# Human-readable statement of the policy, shown to the administrator on
# rejection and reused as the helper text on the reset screen.
POLICY_DESCRIPTION = (
    f"Password must be at least {MIN_LENGTH} characters and include an "
    "uppercase letter, a lowercase letter, a digit, and a special character."
)


class PasswordPolicyError(ValueError):
    """Raised when a password fails one or more NFR-11 checks.

    `errors` holds one message per failed check, so the caller can surface all
    of them at once instead of making the administrator fix them one at a time.
    """

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(" ".join(errors))


def password_policy_errors(password: str) -> list[str]:
    """Return one message per failed NFR-11 check; empty list means compliant."""
    if not isinstance(password, str):
        return ["Password must be text."]

    errors: list[str] = []

    # NFR-11 check 1 of 5: "a minimum of 8 characters"
    if len(password) < MIN_LENGTH:
        errors.append(f"Password must be at least {MIN_LENGTH} characters long.")

    # NFR-11 check 2 of 5: "at least one uppercase letter"
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter.")

    # NFR-11 check 3 of 5: "one lowercase letter"
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter.")

    # NFR-11 check 4 of 5: "one digit"
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit.")

    # NFR-11 check 5 of 5: "one special character"
    if not any(c in SPECIAL_CHARACTERS for c in password):
        errors.append("Password must contain at least one special character.")

    return errors


def is_compliant(password: str) -> bool:
    """True when the password satisfies all five NFR-11 checks."""
    return not password_policy_errors(password)


def validate_password(password: str) -> None:
    """Raise PasswordPolicyError unless the password satisfies NFR-11.

    Called from every bcrypt hashing site so that no code path — API, reset
    flow, or seed script — can store a non-compliant password. See
    app/core/security.py::hash_password and db/seed.py.
    """
    errors = password_policy_errors(password)
    if errors:
        raise PasswordPolicyError(errors)
