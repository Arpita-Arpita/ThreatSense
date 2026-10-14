# NFR-10 Restore Drill

**Requirement (Proposal Section 3, Table 11, NFR-10, verbatim):**

> Foreign-key constraints must protect all relevant relationships across the nine
> application tables. Daily automated `pg_dump` backups must run at 02:00 AEST, be
> retained for seven days, and be validated through restoration tests.

**Measurement / Metric (verbatim):**

> Schema inspection for foreign-key constraints; backup-job logs; scheduled
> restoration drill to a test database.

The measurement column names three separate pieces of evidence. This runbook
produces all three. Work through it in order and capture the output at each
**EVIDENCE** marker.

---

## Part 1 — Foreign-key constraints across the nine tables

```bash
docker exec -it threatsense-db psql -U threatsense -d threatsense -c "
SELECT
    tc.table_name,
    tc.constraint_name,
    kcu.column_name,
    ccu.table_name  AS references_table,
    ccu.column_name AS references_column
FROM information_schema.table_constraints tc
JOIN information_schema.key_column_usage kcu
  ON tc.constraint_name = kcu.constraint_name
JOIN information_schema.constraint_column_usage ccu
  ON tc.constraint_name = ccu.constraint_name
WHERE tc.constraint_type = 'FOREIGN KEY'
  AND tc.table_schema = 'public'
ORDER BY tc.table_name;"
```

Then confirm the table count matches the requirement's "nine application tables":

```bash
docker exec -it threatsense-db psql -U threatsense -d threatsense -c "
SELECT count(*) AS table_count FROM information_schema.tables
WHERE table_schema = 'public' AND table_type = 'BASE TABLE';"
```

**PASS:** `table_count` is 9, and every foreign-key relationship declared in
`db/schema.sql` appears in the first query's output.

> **EVIDENCE 1** — screenshot both query results.

It is worth also proving a constraint actually *bites*, rather than merely
existing. This attempts to insert a detection against a non-existent source:

```bash
docker exec -it threatsense-db psql -U threatsense -d threatsense -c "
INSERT INTO detections (source_id, source_ip, destination_ip, anomaly_score,
                        severity, threat_type, model_version)
VALUES ('00000000-0000-0000-0000-000000000000', '10.0.0.1', '10.0.0.2', 0.9,
        'HIGH', 'PORT_SCAN', 'IF_v1.0');"
```

**PASS:** PostgreSQL rejects it with a `violates foreign key constraint` error.

> **EVIDENCE 2** — screenshot the rejection.

---

## Part 2 — Backup job logs

The daily job is `scripts/backup_db.sh`, scheduled by
`scripts/com.threatsense.backup.plist`. Install it once (see the comment block
at the top of the plist — the three `CHANGE_ME` paths must be edited to
absolute paths first, because `launchd` does not expand `~`).

Force a run without waiting for 02:00:

```bash
launchctl start com.threatsense.backup
sleep 5
tail -n 20 backend/var/backup.log
ls -lh backend/var/backups/
```

**PASS:** `backup.log` shows a `START` line followed by `OK` and `DONE`, and a
`threatsense-<timestamp>.sql.gz` file exists with a non-trivial size.

> **EVIDENCE 3** — screenshot the log tail and the directory listing.

**Also capture a failure**, because a log that only ever shows successes does
not demonstrate that failures would be noticed. Stop the container and run
again:

```bash
docker stop threatsense-db
bash backend/scripts/backup_db.sh
tail -n 3 backend/var/backup.log
docker start threatsense-db
```

**PASS:** the log shows `FAIL  container 'threatsense-db' is not running`, and
**no** archive file was created for that run.

> **EVIDENCE 4** — screenshot the FAIL line.

### Retention

The requirement says seven days. The script prunes archives older than
`THREATSENSE_BACKUP_RETENTION_DAYS` (default 7) on every run. To demonstrate it
without waiting a week, plant an artificially old file:

```bash
touch -t "$(date -v-8d '+%Y%m%d0200')" backend/var/backups/threatsense-old-test.sql.gz
bash backend/scripts/backup_db.sh
grep PRUNE backend/var/backup.log | tail -n 3
```

**PASS:** a `PRUNE removed threatsense-old-test.sql.gz` line appears, and the
final `DONE` line reports the retained count.

> **EVIDENCE 5** — screenshot the PRUNE line.

---

## Part 3 — Restoration drill to a test database

This is the "validated through restoration tests" clause. Restore into a
**separate** database so the live one is never at risk.

```bash
# 1. Pick the most recent archive.
LATEST=$(ls -t backend/var/backups/threatsense-*.sql.gz | head -1)
echo "Restoring from: $LATEST"

# 2. Create a scratch database.
docker exec -i threatsense-db psql -U threatsense -d postgres \
  -c "DROP DATABASE IF EXISTS threatsense_restore_test;"
docker exec -i threatsense-db psql -U threatsense -d postgres \
  -c "CREATE DATABASE threatsense_restore_test OWNER threatsense;"

# 3. Restore into it.
gunzip -c "$LATEST" | docker exec -i threatsense-db \
  psql -U threatsense -d threatsense_restore_test

# 4. Verify structure: nine tables, foreign keys intact.
docker exec -it threatsense-db psql -U threatsense -d threatsense_restore_test -c "
SELECT count(*) AS tables FROM information_schema.tables
WHERE table_schema='public' AND table_type='BASE TABLE';"

docker exec -it threatsense-db psql -U threatsense -d threatsense_restore_test -c "
SELECT count(*) AS foreign_keys FROM information_schema.table_constraints
WHERE constraint_type='FOREIGN KEY' AND table_schema='public';"
```

Verify content, not just structure. A restore that produces nine empty tables
has technically succeeded and is practically worthless, so compare row counts
against the live database:

```bash
for DB in threatsense threatsense_restore_test; do
  echo "--- $DB ---"
  docker exec -i threatsense-db psql -U threatsense -d "$DB" -t -c "
  SELECT 'administrators', count(*) FROM administrators
  UNION ALL SELECT 'data_sources',     count(*) FROM data_sources
  UNION ALL SELECT 'network_logs',     count(*) FROM network_logs
  UNION ALL SELECT 'detections',       count(*) FROM detections
  UNION ALL SELECT 'alerts',           count(*) FROM alerts
  UNION ALL SELECT 'incident_reports', count(*) FROM incident_reports
  UNION ALL SELECT 'audit_logs',       count(*) FROM audit_logs;"
done
```

**PASS:** the restored database reports 9 tables, the same foreign-key count as
live, and row counts matching the live database as of the backup timestamp.

> Rows created *after* the backup ran will be missing from the restore. That is
> correct behaviour, not a failure — note the backup timestamp alongside the
> counts so the difference is explained rather than looking like data loss.

> **EVIDENCE 6** — screenshot the side-by-side row counts.

### Clean up

```bash
docker exec -i threatsense-db psql -U threatsense -d postgres \
  -c "DROP DATABASE threatsense_restore_test;"
```

---

## Drill record

Fill this in each time you run the drill. This table is the artefact to paste
into the NIT3004 report.

| Date run | Archive restored | Tables | FKs | Row counts match | Result | Notes |
|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |
