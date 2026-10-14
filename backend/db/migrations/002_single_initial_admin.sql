-- 002_single_initial_admin.sql
--
-- Section 2.1: "Direct registration is available only for the initial
-- administrator. Additional accounts are created by an authenticated
-- SUPER_ADMIN through a controlled account-management workflow"
--
-- POST /api/auth/setup has to be public — nobody can authenticate before the
-- first account exists — so "there must be exactly one initial administrator"
-- is the whole security boundary for that endpoint. A count-then-insert check
-- in Python cannot hold it: two requests arriving together both read zero
-- administrators, both proceed, and both create a SUPER_ADMIN. Whoever raced
-- the real operator would own the system.
--
-- This index makes the second insert fail regardless of timing. It permits at
-- most one row carrying is_initial_admin = TRUE, which the setup path sets and
-- nothing else does. Later accounts created by a SUPER_ADMIN leave the column
-- FALSE and are unaffected.
--
-- Idempotent: safe to re-run against a database that already has it.

ALTER TABLE administrators
    ADD COLUMN IF NOT EXISTS is_initial_admin BOOLEAN NOT NULL DEFAULT FALSE;

-- Partial unique index: at most one TRUE, any number of FALSE.
CREATE UNIQUE INDEX IF NOT EXISTS ux_administrators_single_initial
    ON administrators (is_initial_admin)
    WHERE is_initial_admin;

COMMENT ON COLUMN administrators.is_initial_admin IS
    'TRUE only for the account created by POST /api/auth/setup. Enforced '
    'unique by ux_administrators_single_initial so a concurrent second '
    'setup request cannot succeed.';
