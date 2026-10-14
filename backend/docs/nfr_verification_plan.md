# Phase 6.1 — NFR Verification Plan

Every non-functional requirement in Proposal Section 3, Table 11, with the exact
command to run it, what "pass" means against the literal wording, and where the
evidence goes.

Work through in order. NFR-08 needs participants booked in advance — read the
note under it **today**, not when you reach it.

Fill in the results table at the bottom as you go; that table is the artefact to
paste into the NIT3004 report.

---

## Before you start

```bash
cd ~/threatsense
docker ps                      # threatsense-db must be running
cd backend && source .venv/bin/activate
pytest tests/ -q               # expect 159 passed
mkdir -p var
```

Run the API with a **single worker** throughout. The NFR-05 login window lives
in process memory, so `--workers N` multiplies the effective limit by N and
invalidates the NFR-05 evidence:

```bash
uvicorn app.main:app --reload --port 8000
```

---

## NFR-01 — Ingestion throughput

> **Requirement:** The data ingestion pipeline must process a minimum of 1,000
> Syslog entries per second under normal operating conditions without data loss
> or queue overflow. A stretch target of 5,000 entries per second will be
> evaluated during load testing.
>
> **Measurement:** Load testing with synthetic Syslog streams at increasing
> volumes (500, 1,000, 2,000, 5,000 msgs/sec); throughput logged per batch and
> verified against the 1,000/s baseline threshold.

Per your decision, this targets the **Docker/bridge path**, not loopback — the
topology you will demo and the one Phase 5's Kali traffic used.

```bash
# Terminal 1 — listener under test
cd backend && source .venv/bin/activate
python -m app.services.ingestion.listener

# Terminal 2 — load harness
cd backend && source .venv/bin/activate
python scripts/nfr01_syslog_load.py --host 192.168.64.1 --port 1514
```

Substitute the address your listener actually binds on the UTM bridge. The
script warns if you point it at loopback.

**PASS:** at 1,000 msgs/sec, delivered rows match sent datagrams within 1%.
The 5,000/sec figure is a stretch target — report it, but it is not a pass
condition.

The harness reports **sent** and **delivered** separately. UDP does not
acknowledge, so the gap between them *is* the "data loss or queue overflow"
the requirement asks about. Report both numbers; a run that sends 5,000/sec
and lands 3,100/sec is an honest finding about where the ceiling sits.

> **EVIDENCE** — screenshot the summary table.

---

## NFR-02 — Detection latency

> **Requirement:** The Isolation Forest detection engine must complete analysis
> of each one-minute feature vector batch within 10 seconds, ensuring
> near-real-time detection capability.
>
> **Measurement:** Server-side timing of detection cycle starts and completion
> timestamps; the 95th percentile across 100 consecutive test cycles must be
> ≤ 10 seconds.

```bash
cd backend && source .venv/bin/activate
python scripts/nfr02_latency_harness.py
```

Runs the full 100 cycles Table 11 specifies. Uses nearest-rank p95, stated
explicitly in the output because percentile methods differ and an examiner may
recompute from the raw figures.

**PASS:** 95th percentile ≤ 10.0 s across 100 timed cycles.

Cost is driven by the **number of distinct source IPs**, not the log count —
`run_cycle()` groups by `(source_id, src_ip, minute)`, so windows are what get
scored. The default of 25 hosts emitting into a one-minute window approximates
an edge firewall. Say which `--hosts` and `--logs-per-cycle` you used when you
report the number; the figure is meaningless without them.

Also run it at the engine's per-cycle ceiling, since that is the worst case the
engine can actually encounter:

```bash
python scripts/nfr02_latency_harness.py --cycles 100 --logs-per-cycle 5000 --hosts 200
```

Ignore the detection counts. Uniform-random synthetic traffic trips the
anomaly threshold far more often than real traffic; NFR-02 measures **timing**
only. Detection accuracy is Phase 5's validation report, already done.

> **EVIDENCE** — screenshot both summary blocks (default and 5,000-log runs).

### Read this before writing NFR-01 and NFR-02 up together

`_MAX_LOGS_PER_CYCLE = 5000` in `app/services/detection/engine.py` caps each
cycle at 5,000 rows. At the NFR-01 baseline of 1,000 msgs/sec sustained, one
minute of traffic is **60,000 rows** — twelve times what a single cycle can
consume. The engine would fall permanently behind, and the backlog would grow
by roughly 55,000 rows every minute.

Both NFRs still pass as written: NFR-01 measures ingestion, NFR-02 measures
per-cycle time, and neither says the engine must keep pace with the ingest
ceiling. But they cannot both be sustained simultaneously, and an examiner
reading the two rows together may well ask.

The honest framing, which is also the accurate one: 1,000 msgs/sec is a burst
capacity for the ingestion pipeline, while the detection engine is sized for a
steady-state rate around 80 rows/sec. Name the cap, give the arithmetic, and
list raising `_MAX_LOGS_PER_CYCLE` with parallel window scoring as future work.
Do not quietly report both numbers and hope the question does not come up.

---

## NFR-03 — Dashboard load time

> **Requirement:** Dashboard pages must achieve Largest Contentful Paint within
> 2.5 seconds and Total Blocking Time below 200 milliseconds under standard
> test conditions.
>
> **Measurement:** Measured using Chrome DevTools Lighthouse across five test
> runs; average Largest Contentful Paint must be ≤ 2.5 seconds and Total
> Blocking Time must be < 200 milliseconds.

You run this by hand in Chrome.

```bash
cd frontend && npm run build && npm run preview
```

**Build first — do not audit the dev server.** Vite's dev build ships unminified
modules and a HMR client, which will fail LCP for reasons that have nothing to
do with your application.

Then, in Chrome:

1. Open the preview URL in an **Incognito** window (extensions distort TBT).
2. DevTools → Lighthouse → Performance only → Desktop.
3. Log in first, then audit `/` (Dashboard) with data on screen.
4. Run **five times**, recording LCP and TBT each time.

**PASS:** mean LCP ≤ 2.5 s **and** mean TBT < 200 ms across five runs. Table 11
says average, so report the mean — but record all five, since a single outlier
run is worth explaining rather than hiding.

Audit the Dashboard at minimum. Detection Detail and Log Sources are worth
running too if time allows, since they carry heavier tables.

> **EVIDENCE** — screenshot each of the five Lighthouse summaries, plus your
> table of the five LCP/TBT pairs and their means.

---

## NFR-04 — Encryption, hashing, cookies

> **Requirement:** All web application, API, and external-service traffic must
> be encrypted using TLS 1.2 or higher. Syslog over TLS on TCP port 6514 must be
> used where supported. Standard Syslog ports 514 and 1514 may be used only
> within the isolated testing environment. Passwords must be hashed with bcrypt
> (cost factor ≥ 12). JWTs must expire after 60 minutes and be returned using
> HttpOnly, Secure, SameSite=Strict cookies.
>
> **Measurement:** SSL Labs scan (minimum A rating); verification of
> Syslog-over-TLS configuration where enabled; inspection of the bcrypt cost
> factor in source code; validation of JWT cookie attributes during integration
> testing.

Four separate clauses. Three are verifiable now; the fourth is task 6.2.

### bcrypt cost factor

```bash
grep -n "bcrypt_cost_factor" backend/app/config.py
grep -n "gensalt" backend/app/core/security.py backend/db/seed.py
```

**PASS:** cost factor is 12, which satisfies "≥ 12".

### JWT expiry and cookie attributes

```bash
grep -n "jwt_expiry_minutes" backend/app/config.py
grep -n "set_cookie" backend/app/routers/auth.py
```

Then observe them live — the measurement column says "during integration
testing", so source inspection alone is not the whole clause. Log in with
DevTools open, then Application → Cookies → `ts_session`.

**PASS:** `HttpOnly` ✓, `SameSite=Strict` ✓, expiry 60 minutes, and `Secure`
set when `ENV=production`.

**Expect `Secure` to be absent in local dev, and say so in the write-up.**
`app/config.py` sets it from the environment because a `Secure` cookie is not
stored over plain HTTP — Chrome would silently drop it and local login would
break. Show the conditional in the source alongside the DevTools screenshot.

### Syslog over TLS on 6514

**Not yet implemented — this is task 6.2.** `app/services/ingestion/listener.py`
uses `create_datagram_endpoint`, so it is UDP-only; there is no TCP path at
all, even though `data_sources` accepts TLS/TCP/UDP as transport values. 6.2 is
"add TCP *and* TLS", not "add TLS to an existing TCP listener".

Mark this clause **deferred to 6.2** in the results table rather than failing it.

### SSL Labs

Not applicable to a localhost MVP — SSL Labs scans public hostnames. Record it
as not applicable, with the self-signed local certificate from 6.2 as the
substitute evidence.

> **EVIDENCE** — the three greps, the DevTools cookie panel, and a note on the
> two clauses deferred to 6.2.

---

## NFR-05 — Rate limiting

> **Requirement:** Rate limiting: five login attempts per IP within a 15-minute
> window; ten report generations per administrator per hour. Exceeding limits
> returns HTTP 429.
>
> **Measurement:** Test scripts (automated) to send requests in rapid succession
> and check for HTTP 429 response at specified thresholds.

The automated suite Table 11 asks for already exists:

```bash
cd backend && source .venv/bin/activate
pytest tests/test_login_rate_limit.py -v      # login clause, 11 tests
pytest tests/test_reports.py -v -k rate       # report clause
```

**PASS:** all tests green. Each of the three literal parameters — the count of
five, the per-IP scope, and the 15-minute window — has its own test, so a
failure points at a specific clause.

Also demonstrate it live against the running API, because "in rapid succession"
reads more naturally as a manual demonstration than a unit test:

```bash
for i in $(seq 1 6); do
  printf "attempt %d: " "$i"
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://localhost:8000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"nobody@threatsense.local","password":"WrongPassw0rd!"}'
done
```

**PASS:** attempts 1–5 return 401, attempt 6 returns 429.

Restart the API afterwards to clear the window, or your next five logins are
already spent.

**Note in the write-up** that successful logins consume quota too. NFR-05 says
"login attempts", not "failed login attempts", and reading in an exemption
would be a divergence from Table 11.

**Also note the account lockout as defence-in-depth beyond the requirement.**
Per-IP sliding-window 429 is the NFR-05 control; the per-account 423 lockout
defends a different surface — one attacker spreading attempts for a single
account across many IPs, which a per-IP window cannot see.
`test_account_lockout_survives_alongside_the_ip_window` demonstrates both
operating together.

> **EVIDENCE** — pytest output, plus the curl loop showing 401×5 then 429.

---

## NFR-06 — Availability

> **Requirement:** The deployed platform shall be accessible and responsive at
> all planned testing and demonstration periods. During the testing phase,
> unplanned downtime should remain below four hours per month.
>
> **Measurement:** Availability – tracked by server access logs and noted in the
> project diary. Any downtime – recorded with cause and resolution.

This is a **record-keeping requirement, not a test**. There is nothing to run.

What it needs:

1. **A downtime log** — a dated table in your project diary with one row per
   unplanned outage: date, duration, cause, resolution. An empty table is a
   valid and good result, but it must exist and be dated.
2. **Health-check evidence** — Section 3.1 names health-check endpoints:

```bash
curl -s http://localhost:8000/health
curl -s http://localhost:8000/api/system/health | python3 -m json.tool
```

3. **Access logs** — uvicorn writes request lines to stdout. Redirect them to a
file for the remainder of the project so the evidence exists when you need it:

```bash
uvicorn app.main:app --port 8000 2>&1 | tee -a var/uvicorn-access.log
```

**PASS:** health endpoints return 200, and the diary shows a maintained
downtime record with under four hours of unplanned outage for the month.

Start the log now. This is the one NFR you cannot reconstruct retrospectively —
if you begin logging the week before submission, you have a week of evidence
for a monthly claim.

> **EVIDENCE** — health endpoint output, a sample of the access log, and the
> diary downtime table.

---

## NFR-07 — Concurrency

> **Requirement:** The system shall support at least five concurrent
> administrator sessions without API response times increasing by more than 30%
> relative to the single-user baseline.
>
> **Measurement:** Load testing with Locust or k6 to simulate five concurrent
> sessions; API response times compared with the single-user baseline.

```bash
pip install locust

# Pass 1 — single-user baseline
locust -f scripts/nfr07_locustfile.py --headless \
       -u 1 -r 1 -t 3m --host http://localhost:8000 --csv=var/nfr07_baseline

# Restart uvicorn here, or wait 15 minutes (see below)

# Pass 2 — five concurrent sessions
locust -f scripts/nfr07_locustfile.py --headless \
       -u 5 -r 1 -t 3m --host http://localhost:8000 --csv=var/nfr07_concurrent

python scripts/nfr07_locustfile.py --compare
```

**PASS:** no endpoint's median response time increases by more than 30%.

**The NFR-05 interaction is the trap here.** Each simulated user logs in once,
so a 5-user run performs exactly 5 logins from one IP — precisely at the
NFR-05 limit. **Restart the API between the two passes**, or the second starts
with an exhausted window and every user 429s on login. The comparison script
warns if it sees failures, but restart rather than relying on the warning.

Do not raise `-u` above 5 without restarting first.

> **EVIDENCE** — screenshot the comparison table.

---

## NFR-08 — Usability

> **Requirement:** A first-time administrator with basic IT knowledge must be
> able to complete initial setup or sign in, configure a Syslog source, and view
> their first detection result within 15 minutes of initial access, without
> consulting external documentation.
>
> **Measurement:** Task-based usability testing with three to five
> representative users; task completion time and post-task System Usability
> Scale (SUS) score recorded.

**Book participants now.** This is the only NFR you cannot run alone at your
desk, and the constraints narrow the pool: participants need basic IT knowledge
and must **not** be people you have already walked through ThreatSense.
Classmates outside your unit work well. Three is the minimum Table 11 accepts;
five is better.

Budget 30 minutes per participant.

### Protocol

Give each participant the running application and this instruction, then stop
talking:

> "You are a network administrator who has just been given this tool. Sign in,
> connect it to a log source, and find the first threat it detects. I cannot
> answer questions while you work."

Start a timer at first access. Stop it when a detection is visible on screen.

**Answer nothing during the task.** The requirement says "without consulting
external documentation" — you are external documentation. Note where they get
stuck; that observation is worth more to Section 7 than the timing.

Credentials: `admin@threatsense.local` / your seeded password. Have a source
ready to configure, and either the Kali sandbox running or a log file ready to
upload so a detection can actually appear.

### After each participant

Administer the standard 10-item SUS questionnaire. Score it: subtract 1 from
odd-numbered items, subtract each even-numbered response from 5, sum, multiply
by 2.5. Range 0–100.

**PASS:** all participants complete the three tasks within 15 minutes. Record
the SUS score per participant and the mean. Table 11 sets no SUS threshold —
it says "recorded" — so report the number rather than claiming a pass against
an invented bar. For context, 68 is the conventional average.

> **EVIDENCE** — per-participant table (completion time, tasks completed, SUS
> score), the mean SUS, and your notes on where participants hesitated.

---

## NFR-09 — Alert delivery timing

> **Requirement:** The initial dispatch attempt for a critical alert must begin
> within 10 seconds of detection. If delivery fails, the system must retry three
> times using 2s, 4s, and 8s backoff delays before marking the alert FAILED.
>
> **Measurement:** Measure the time difference between detection created_at and
> the first delivery attempt. Verify retry timing and final status transitions
> through integration tests.

The retry half is already covered:

```bash
cd backend && source .venv/bin/activate
pytest tests/test_alert_worker.py -v
```

**PASS:** retry backoff of 2s/4s/8s and the PENDING → SENT / FAILED transitions
are all asserted.

For the timing half, query the live database after a real detection:

```bash
docker exec -it threatsense-db psql -U threatsense -d threatsense -c "
SELECT d.detection_id,
       d.severity,
       d.created_at                             AS detected_at,
       a.created_at                             AS alert_created,
       EXTRACT(EPOCH FROM (a.created_at - d.created_at)) AS dispatch_delay_seconds,
       a.status,
       a.retry_count
FROM detections d
JOIN alerts a ON a.detection_id = d.detection_id
WHERE d.severity = 'CRITICAL'
ORDER BY d.created_at DESC
LIMIT 20;"
```

**PASS:** `dispatch_delay_seconds` < 10 for every critical detection.

Confirm the configured values match the requirement literally:

```bash
grep -n "alert_poll_seconds\|alert_retry_backoff" backend/app/config.py
```

Expect `alert_poll_seconds: 5` and `alert_retry_backoff: "2,4,8"`.

Note the poll interval honestly: the worker polls every 5 seconds, so dispatch
begins within 5 seconds of the alert row appearing, comfortably inside the
10-second budget but not instantaneous. That is the mechanism, and stating it
is better than implying event-driven dispatch.

SendGrid (task 2.2) is still mock-first pending an API key. The mock path
exercises the same timing and retry logic; say which path produced the numbers.

> **EVIDENCE** — pytest output, the SQL result, and the config grep.

---

## NFR-10 — Data integrity

> **Requirement:** Foreign-key constraints must protect all relevant
> relationships across the nine application tables. Daily automated pg_dump
> backups must run at 02:00 AEST, be retained for seven days, and be validated
> through restoration tests.
>
> **Measurement:** Schema inspection for foreign-key constraints; backup-job
> logs; scheduled restoration drill to a test database.

Fully specified in **`backend/docs/restore_drill.md`** — work through that
document, which covers all three evidence types and has six evidence markers.

Summary of what it produces:

- FK inspection across all nine tables, plus a live constraint-violation test
- Backup job logs from `launchd`, including a deliberate failure run
- 7-day retention demonstrated without waiting a week
- Restoration into a scratch database with row counts compared against live

**PASS:** nine tables with FKs intact, `backup.log` showing successful runs and
pruning, and a restore reproducing structure and row counts.

Install the `launchd` job before you start — it needs three `CHANGE_ME`
absolute paths edited, since `launchd` does not expand `~`.

> **EVIDENCE** — the six markers in `restore_drill.md`.

---

## NFR-11 — Password policy

> **Requirement:** The system must enforce strong password policies: a minimum
> of 8 characters, with at least one uppercase letter, one lowercase letter, one
> digit, and one special character. Passwords must be validated on both the
> client side and the server side before acceptance.
>
> **Measurement:** Implementation: client-side regex validation on the
> registration form, and server-side validation immediately before bcrypt
> hashing. Testing: an automated test suite submitting passwords of varying
> complexity and verifying that non-compliant passwords are rejected with
> appropriate error messages.

```bash
cd backend && source .venv/bin/activate
pytest tests/test_password_policy.py -v       # 23 tests
```

**PASS:** all green. Each of the five character classes has a password that
fails only that check, so a regression is attributable to a specific clause.

Server-side enforcement sits at three points, because there are two bcrypt call
sites in the repo:

```bash
grep -n "validate_password\|password_policy_errors" \
  backend/app/routers/auth.py \
  backend/app/core/security.py \
  backend/db/seed.py
```

Demonstrate the client side in the browser: open `/reset-password`, type into
the password field, and show the five-rule checklist ticking green live.

**PASS:** the checklist responds as you type and the submit button stays
disabled until all five rules pass.

`test_client_and_server_policies_agree` reads the JavaScript validator and pins
its constants against the Python module, so the two cannot drift apart
silently.

### Declare this divergence rather than letting it be found

Table 11's implementation note says "client-side regex validation on the
**registration form**". There is no registration form and no Initial Setup
screen — Figure 3 shows a conditional Initial Setup link, but the destination
was never built. The client-side validation therefore lives on the
password-reset screen instead.

State this plainly: the control exists and is demonstrable, on the screen that
currently sets passwords. Decide before you write this up whether building
Initial Setup is in scope; if it is not, the divergence is defensible, but only
if you name it first.

> **EVIDENCE** — pytest output, the three-point grep, and a screen recording or
> screenshots of the live checklist.

---

## Results table

| NFR | Requirement (short) | Target | Measured | Result | Evidence |
|---|---|---|---|---|---|
| 01 | Ingestion throughput | 1,000 msgs/s, no loss |  |  |  |
| 02 | Detection latency | p95 ≤ 10 s over 100 cycles |  |  |  |
| 03 | Dashboard load | LCP ≤ 2.5 s, TBT < 200 ms |  |  |  |
| 04 | TLS / bcrypt / cookies | bcrypt ≥ 12, 60 min, HttpOnly+Strict |  | *TLS 6514 → 6.2* |  |
| 05 | Rate limiting | 5/IP/15 min → 429; 10 reports/hr |  |  |  |
| 06 | Availability | < 4 hrs unplanned/month |  |  |  |
| 07 | Concurrency | 5 sessions, ≤ +30% |  |  |  |
| 08 | Usability | 3 tasks < 15 min, SUS recorded |  |  |  |
| 09 | Alert timing | dispatch < 10 s; 2/4/8 s retries |  |  |  |
| 10 | Data integrity | FKs, daily backup, 7-day, restore |  |  |  |
| 11 | Password policy | 8 chars + 4 classes, both sides |  |  |  |

---

## Three things to declare rather than let an examiner find

1. **NFR-01 vs NFR-02.** `_MAX_LOGS_PER_CYCLE = 5000` against a 60,000-row
   minute at the NFR-01 baseline. Both pass as written; they cannot both be
   sustained at once. Give the arithmetic and list the fix as future work.
2. **NFR-04's Syslog-over-TLS clause** is task 6.2, and the listener currently
   has no TCP path at all.
3. **NFR-11's "registration form"** does not exist; client-side validation
   lives on the reset screen.

Each is defensible. None is defensible if the examiner spots it first.
