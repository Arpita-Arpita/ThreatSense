#!/usr/bin/env bash
#
# ThreatSense database backup — NFR-10.
#
# Proposal Section 3, Table 11, NFR-10 — Requirement (verbatim):
#   "Foreign-key constraints must protect all relevant relationships across
#   the nine application tables. Daily automated pg_dump backups must run at
#   02:00 AEST, be retained for seven days, and be validated through
#   restoration tests."
#
# Proposal Section 3, Table 11, NFR-10 — Measurement / Metric (verbatim):
#   "Schema inspection for foreign-key constraints; backup-job logs; scheduled
#   restoration drill to a test database."
#
# This script covers the "daily automated pg_dump" and "retained for seven
# days" clauses, and produces the "backup-job logs" the measurement column
# asks for. The "validated through restoration tests" clause is docs/
# restore_drill.md, which you run by hand.
#
# Scheduling is scripts/com.threatsense.backup.plist (launchd, 02:00 local).
# Run it manually any time with:
#     ./scripts/backup_db.sh
#
set -uo pipefail

BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="${THREATSENSE_BACKUP_DIR:-$BACKEND_DIR/var/backups}"
LOG_FILE="${THREATSENSE_BACKUP_LOG:-$BACKEND_DIR/var/backup.log}"
CONTAINER="${THREATSENSE_DB_CONTAINER:-threatsense-db}"
DB_NAME="${THREATSENSE_DB_NAME:-threatsense}"
DB_USER="${THREATSENSE_DB_USER:-threatsense}"
RETENTION_DAYS="${THREATSENSE_BACKUP_RETENTION_DAYS:-7}"

mkdir -p "$BACKUP_DIR" "$(dirname "$LOG_FILE")"

log() {
  # ISO-8601 with offset, so a log line read months later is unambiguous
  # about whether it was written under AEST or AEDT.
  printf '%s  %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$1" >> "$LOG_FILE"
}

STAMP="$(date '+%Y%m%d-%H%M%S')"
TARGET="$BACKUP_DIR/threatsense-$STAMP.sql.gz"

log "START backup -> $(basename "$TARGET")"

# --- preflight -------------------------------------------------------------
# A backup job that silently writes a 0-byte file is worse than one that
# fails: the failure is visible, the empty file is not. Docker Desktop is
# often not running when a laptop wakes, so check before dumping.
if ! command -v docker > /dev/null 2>&1; then
  log "FAIL  docker command not found on PATH"
  exit 1
fi

if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
  log "FAIL  container '$CONTAINER' is not running (Docker Desktop asleep or stopped)"
  exit 1
fi

# --- dump ------------------------------------------------------------------
if docker exec "$CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" 2>>"$LOG_FILE" | gzip > "$TARGET"; then
  # PIPESTATUS[0] is pg_dump's exit code; the `if` above only sees gzip's, so
  # a pg_dump failure piped into a successful gzip would otherwise look fine.
  if [ "${PIPESTATUS[0]}" -ne 0 ]; then
    log "FAIL  pg_dump exited non-zero; removing partial archive"
    rm -f "$TARGET"
    exit 1
  fi
else
  log "FAIL  dump pipeline failed"
  rm -f "$TARGET"
  exit 1
fi

SIZE_BYTES="$(wc -c < "$TARGET" | tr -d ' ')"
if [ "$SIZE_BYTES" -lt 1000 ]; then
  log "FAIL  archive is only ${SIZE_BYTES}B — treating as a failed dump"
  rm -f "$TARGET"
  exit 1
fi

log "OK    wrote $(basename "$TARGET") (${SIZE_BYTES} bytes)"

# --- retention: "retained for seven days" ----------------------------------
PRUNED=0
while IFS= read -r old; do
  rm -f "$old"
  log "PRUNE removed $(basename "$old") (older than ${RETENTION_DAYS} days)"
  PRUNED=$((PRUNED + 1))
done < <(find "$BACKUP_DIR" -name 'threatsense-*.sql.gz' -type f -mtime "+${RETENTION_DAYS}")

REMAINING="$(find "$BACKUP_DIR" -name 'threatsense-*.sql.gz' -type f | wc -l | tr -d ' ')"
log "DONE  pruned=${PRUNED} retained=${REMAINING}"
exit 0
