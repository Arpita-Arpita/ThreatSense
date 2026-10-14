-- 001_source_name_unique.sql
-- Task 4.1 follow-up: enforce unique source names per administrator.
--
-- Duplicate names make the Log Sources table ambiguous, and audit_logs records
-- the source NAME rather than its id, so duplicates make the audit trail
-- ambiguous too.
--
-- Existing databases may already contain duplicates (they were legal until
-- now), and ALTER TABLE ... ADD CONSTRAINT would simply fail on them. So this
-- renames the older duplicates first, keeping the OLDEST row's name intact and
-- suffixing the rest: "branch-fw", "branch-fw (2)", "branch-fw (3)".
--
-- Safe to run more than once.
--
--   psql "$DATABASE_URL" -f db/migrations/001_source_name_unique.sql
--
-- Rollback:
--   ALTER TABLE data_sources DROP CONSTRAINT uq_data_sources_admin_name;
--   (renamed sources keep their new names — rename them back by hand if needed)

BEGIN;

-- 1. Show what is about to change, so it appears in the psql output.
SELECT admin_id, name, count(*) AS copies
FROM   data_sources
GROUP  BY admin_id, name
HAVING count(*) > 1;

-- 2. Suffix every duplicate except the oldest of each name.
WITH ranked AS (
    SELECT source_id,
           name,
           row_number() OVER (PARTITION BY admin_id, name
                              ORDER BY created_at, source_id) AS n
    FROM   data_sources
)
UPDATE data_sources AS d
SET    name = left(r.name, 90) || ' (' || r.n || ')'
FROM   ranked AS r
WHERE  d.source_id = r.source_id
  AND  r.n > 1;

-- 3. Add the constraint (IF NOT EXISTS is not available for constraints, so
--    check the catalogue first and skip when it is already present).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_data_sources_admin_name'
    ) THEN
        ALTER TABLE data_sources
            ADD CONSTRAINT uq_data_sources_admin_name UNIQUE (admin_id, name);
    END IF;
END $$;

COMMIT;

-- 4. Confirm: this should return no rows.
SELECT admin_id, name, count(*)
FROM   data_sources
GROUP  BY admin_id, name
HAVING count(*) > 1;
