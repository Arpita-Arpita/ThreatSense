# ThreatSense — Final Local Validation

What was actually run, where, and with what result. Nothing here is inferred;
every line is the output of a command.

Environment: Ubuntu 24.04 container, Python 3.12, PostgreSQL 16 installed and
seeded locally. Date: 3 September 2026. Revision: post-review corrections.

---

## Commands run and results

| # | Command | Result |
|---|---|---|
| 1 | `python -m compileall -q app tests` | **Pass** — exit 0 |
| 2 | `pip install -r requirements.txt` | **Pass** |
| 3 | `psql -f db/schema.sql` | **Pass** — 9 tables, 10 foreign keys |
| 4 | `python -m db.seed` | **Pass** |
| 5 | `pytest tests/ -q` | **472 passed, 0 failed** in 177.31s |
| 6 | `npm ci` | **Pass** |
| 7 | `npm run build` | **Pass** — 77 modules; JS 422.63 kB (135.32 kB gzip), CSS 41.84 kB (9.02 kB gzip) |
| 8 | Extract ZIP to a clean directory, rerun 5 and 7 from the extraction | **Pass** — see "Archive verification" |

```
472 passed, 23 warnings in 177.31s (0:02:57)
```

Warnings only. They are third-party deprecations (`HTTP_422_UNPROCESSABLE_ENTITY`
in Starlette, a NumPy 2.5 notice from joblib, an intentional `TLSv1_1`
reference in the TLS refusal test) plus one scikit-learn version notice, all
described under "Environment notes".

### Tests added — 43 across three new modules

`backend/tests/` contains **26 `test_*.py` modules** plus `conftest.py` and
`__init__.py`. Three of those modules are new in this work:

| File | Tests | Covers |
|---|---|---|
| `tests/test_source_status.py` | 13 | Effective source status: boundaries at 59.999s / 60s / 61s, traffic resuming, freshly created sources, ERROR never overridden, naive timestamps, configurability, Dashboard and Log Sources agreeing on one count |
| `tests/test_source_resolution.py` | 15 | Ambiguous sender addresses rejected rather than guessed; ambiguity clearing on reconfiguration; single-source fallback scoped to address-less sources; stale-source records dropped without failing their batch; endpoint revalidation — IP reconfiguration TOCTOU, transport mismatch, port mismatch, unconfigured fields not enforced, mismatched record not blocking valid siblings, and `offer()` carrying the resolution evidence |
| `tests/test_report_scope.py` | 15 | Window start derived from the detection's calendar-minute bucket; preceding-bucket traffic excluded; post-detection traffic excluded; empty summaries safe; `GET /api/reports` returning detection context, newest-first ordering, ownership isolation, session requirement, paging |

21 of these need no database and run anywhere.

---

## Corrections made in this revision

### 1. Related-log window now derived from the detection's minute bucket

**The defect.** The previous fix narrowed the scope from fifteen minutes to a
rolling `detection.timestamp - 1 minute`. That is not the detection's window.
`ml/features.py::group_windows` buckets records with
`timestamp.replace(second=0, microsecond=0)`, and `Detection.timestamp` is the
**last** log timestamp inside that bucket. For a detection at 12:30:20 the
rolling scope spanned 12:29:20–12:30:20, so forty seconds of the *preceding*
bucket — traffic scored as a different detection — was still summarised into
the report.

**The fix.** `prompt.py::detection_window_start()` mirrors `group_windows`
exactly. Scope now runs from the start of the detection's own calendar minute
up to and including the detection timestamp. Traffic arriving after the
detection is excluded because the model never scored it.

**Regressions added.** Detection at 12:30:20: 12:29:50 excluded, 12:30:00
included, 12:30:05 included, 12:30:20 included, 12:30:45 excluded.

### 2. Endpoint revalidation at the write boundary

**The defect.** `_write()` only asked whether the `source_id` still existed.
Resolution happens when a message is buffered and the write happens up to five
seconds later, so an administrator could repoint a source at a different
address in between. The source still existed, so the record was accepted and
landed under a source that no longer claimed the endpoint it came from.
Separately, `data_sources.transport` and `.port` took no part in attribution
at all.

**The fix.** `offer()` now carries `_sender_ip`, `_transport` and
`_listener_port` on each buffered record (buffer-lifetime only; not columns).
`_still_matches()` revalidates each record inside the write transaction against
the freshly fetched source: configured IP must still equal the sender address,
configured transport must match the listener that received the message,
configured port must match that listener. Unset fields are not enforced, so an
address-less single-collector deployment is unaffected. A failing record is
**dropped**, never reassigned to whichever source now owns the address, and
valid records in the same batch still commit. Drops are counted separately as
`dropped_endpoint_mismatch` and surfaced in `var/ingestion_stats.json`.

**What is still not solved:** two sources legitimately claiming the same
address at the same time. `KNOWN_LIMITATIONS.md` §1 states this and no longer
implies the rest is complete.

### 3. Source timeout boundary made literal

`effective_status()` used `>` so exactly 60.000s still read ACTIVE. Use Case
4.2 step 5a says "if no messages arrive within 60 seconds", so the boundary is
now `>=`: 59.999s reads ACTIVE, 60.000s reads INACTIVE. Tests updated.

### 4. Fixture clocks pinned

Deriving the scope from a calendar minute exposed a latent flakiness in three
fixtures that used `datetime.now(timezone.utc)` and placed log records a few
seconds earlier. Whenever the suite ran near the top of a minute, those records
fell into the preceding bucket and the test failed for reasons unrelated to the
code. `test_reports.py` and `test_traffic_summary.py` now pin their clock to
`:50` within the minute and `test_report_scope.py` uses a fixed `:40`. The
assertions are unchanged.

### Pre-existing tests updated — 3 assertions across 2 files

Narrowing the window broke three assertions that had encoded the old
fifteen-minute scope. The fixtures were corrected, not the assertions weakened:
`test_reports.py` placed six records at one-minute intervals *before* the
detection, and `test_traffic_summary.py` did the same and asserted
`window_minutes == 15`. Both now place traffic inside the detection's own
minute; the substantive assertions (`events == 6`, `distinct_dst_ports == 6`,
`protocols == {"TCP": 6}`) are untouched.

**Behaviour change worth noting:** `GET /api/detections/{id}/traffic` shares the
aggregate query with the report prompt by design, so the View Traffic panel is
also scoped to the detection's minute. Deliberate — screen and report describe
the same traffic — but visible in the interface and in the demonstration.

---

## Archive verification

The ZIP was extracted into an empty directory and the suite and build were run
**from that extraction**, not from the working tree:

```
472 passed, 23 warnings in 177.31s
✓ 77 modules transformed — built in 3.98s
```

Archive contents:

| Check | Result |
|---|---|
| Root entries | exactly one: `ThreatSense/` |
| `__MACOSX/` entries | 0 |
| `._*` AppleDouble entries | 0 |
| `.DS_Store` entries | 0 |
| `.git/`, `node_modules`, `.venv`, `__pycache__`, `.pytest_cache` | 0 |
| `.env` files | 0 — only `*.env.example` templates |
| API keys (`sk-…`, `SG.…` patterns) | 0 across the whole tree |
| Total entries | see the delivery message for the exact figure |

**On the `__MACOSX` finding.** The archive I produced was built with Linux
`zip` in a container that has never touched macOS, and it contained zero
`__MACOSX`, `._*` or `.DS_Store` entries — verified before delivery and again
now. An archive containing a `__MACOSX/` tree and roughly double the entry
count is one that has been round-tripped through macOS Finder (extracted and
re-compressed) after leaving here. Worth knowing because it will recur with any
file re-zipped on the Mac before submission. The regeneration command now also
passes `-X` and explicit exclusions so the property holds even if the archive
is rebuilt on macOS.

---

## Environment notes

**scikit-learn version.** `ml/models/IF_v1.0.joblib` was trained with 1.9.0;
this container resolved 1.8.0, producing an `InconsistentVersionWarning` on
load. The model loads and scores correctly, and
`tests/test_detection_batching.py` confirms batched scores match per-window
scores numerically. This warning does not appear on the development Mac.

**TLS.** The suite ran with `SYSLOG_TLS_ENABLED=false` because
`backend/certs/` is excluded from the submission. The TLS listener tests
generate their own ephemeral context and passed regardless.

---

## Steps performed on the delivery machine

### 1. Confirm the test count

```bash
cd ~/threatsense/backend && source .venv/bin/activate && pytest tests/ -q
```

Confirmed on the delivery machine: **472 passed, 0 failed** (157.94s). The
baseline before this package was 429; the 43 tests added here account for the
difference. This is the figure carried in the Technical Implementation
Document.

### 2. Confirm the production build

```bash
cd ~/threatsense/frontend && npm run build
```

Confirmed on the delivery machine: build succeeded, **77 modules transformed**.

### 3. Check your source rows before the demonstration

This one is new and it matters. Endpoint revalidation now enforces
`data_sources.transport` and `.port` **when they are set**. If a source row in
your database says TLS/6514 but you demonstrate over UDP/1514, its records will
be dropped and counted as `dropped_endpoint_mismatch`.

```bash
docker exec -it threatsense-db psql -U threatsense -d threatsense \
  -c "SELECT name, ip_address, transport, port, status FROM data_sources;"
```

If `transport`/`port` do not match the listener you actually demonstrate on,
either update the row on the Log Sources screen or clear those fields — unset
fields are not enforced.

### 4. Live validation I cannot perform

Running the five processes together; Kali rsyslog over TLS to 6514;
`nmap -sS -p 1-1000`; `hping3 -S --flood`; SendGrid delivery; OpenAI report
generation; screenshot capture.

### 5. TLS certificates — confirmed excluded

`backend/certs/` stays out; `scripts/generate_dev_cert.sh` regenerates the pair
and the User Manual will document it as a setup step.
