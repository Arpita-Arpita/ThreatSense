# ThreatSense — Known Limitations and Future Work

Every item below is a difference between the delivered system and the approved
NIT3003 proposal that has been identified, understood and left in place
deliberately. Each entry states what the specification asks for, what the
system does, why the difference exists, and what closing it would take.

Nothing here describes a broken feature. Every capability named is
implemented, tested and demonstrable; these are boundaries on how far each one
goes.

---

## 1. Two administrators registering the same sender address

**Specification.** Section 2.2 binds each ingested record to the data source
that produced it, through `network_logs.source_id`.

**Behaviour.** The listener maps a sender IP address to a source. Private
address ranges are not globally unique, so two administrators can each register
`192.168.1.1` for entirely different networks. When that happens, ThreatSense
now refuses to attribute traffic from that address: the address is removed from
the resolution map, the messages are dropped, counted under
`dropped_unknown_source`, and the operator is told which addresses are
contested and why.

**Why it is not resolved.** A syslog datagram carries no field that
distinguishes the two networks. Any attribution would be a guess, and a wrong
guess writes one administrator's network traffic into another administrator's
account — a worse outcome than dropping. Refusing is the only choice that
cannot leak across tenants.

**What closing it would require.** Per-source credentials rather than per-source
addresses: a distinct TLS client certificate for each collector (the listener
already supports `SYSLOG_TLS_REQUIRE_CLIENT_CERT`), or a dedicated listener
port per source. Both are architectural changes to the ingestion path.

**Related work that *was* completed.** Three neighbouring defects in the same
code path are fixed. The single-source fallback no longer accepts traffic from
an unregistered sender when the source declares an address. Records whose
source was deleted between buffering and the flush are dropped individually
instead of failing the insert and wedging every valid record queued behind
them. And each buffered record now carries the sender address, transport and
listener port that resolved it, so the write boundary revalidates the binding
rather than merely confirming the source id still exists — closing the
time-of-check/time-of-use case where an administrator repointed a source
between buffering and the flush and the record landed under a source that no
longer claimed that endpoint. Configured `transport` and `port` participate in
that check; fields left unset are not enforced, so address-less
single-collector deployments are unaffected.

**Scope of this entry.** What remains unsolved is only the case above: two
sources legitimately claiming the *same* address at the *same* time. Source
resolution is not "fully solved" in general — it is safe, and its remaining
gap is this one.

---

## 2. Algorithm 2 feature definitions

**Specification.** Section 6.2 defines ten window features and a rule
evaluation order.

**Behaviour.** Five of the ten differ materially. Packet and byte rates divide
by the observed window duration rather than a fixed 60 seconds; protocol
distribution is carried as a TCP ratio rather than TCP:UDP:ICMP; the SYN ratio
is computed against all records rather than against ACKs; the RST ratio against
all records rather than total flags. The rule layer evaluates PORT_SCAN,
BRUTE_FORCE, DDOS, C2 rather than PORT_SCAN, DDOS, C2, BRUTE_FORCE.

**Why it is not resolved.** `IF_v1.0` was trained on the current definitions.
Changing them invalidates the model, so correcting the specification gap means
retraining as `IF_v1.1`, regenerating every evaluation metric, and re-capturing
every piece of live validation evidence. That work cannot be done responsibly
in the time remaining before delivery, and a hurried retrain would leave the
detection evidence weaker than it is now.

**Effect on the delivered system.** None observable. The features are
internally consistent between training and inference because both import the
same module (`ml/features.py`), which is the property that actually matters for
correctness. Live validation against Nmap and hping3 traffic detects both
attack types correctly.

**What closing it would require.** Rewrite `ml/features.py`, retrain, re-run
`ml/evaluate.py`, re-run the full Kali validation sequence, update every
recorded metric.

---

## 3. Dashboard panel and endpoint alignment

**Specification.** Section 2.4 describes Network Health, Alert Timeline and
Traffic Analytics panels, served by `/api/dashboard/health`, `/alerts` and
`/analytics`, polled every 30 seconds.

**Behaviour.** All three endpoints exist, are tested and return the specified
shapes. The React dashboard polls the detections endpoints every 20 seconds
instead; its KPI cards report detection counts rather than network health, and
its charts show detection activity rather than traffic volume, protocol
distribution and top talkers. Parts of System Status render static defaults.

**Why it is not resolved.** This is presentation-layer rework on a screen that
is operational and has been demonstrated successfully. The backend half of the
requirement is complete; rewiring the front end late in the schedule risks a
working demonstration for no functional gain.

**What closing it would require.** Rewriting `Dashboard.jsx` and the panel
components against the existing endpoints. No backend work.

---

## 4. Session-expiry warning

**Specification.** Section 2.1 requires a warning two minutes before session
expiry, with an option to extend.

**Behaviour.** Not implemented. Sessions expire after the 60 minutes NFR-04
specifies and the user is returned to the login screen.

**Why it is not resolved.** Deprioritised against data-correctness work. It is
a convenience feature; its absence costs a re-login, not data.

**What closing it would require.** A client-side timer against the JWT expiry
plus a refresh endpoint. Roughly half a day.

---

## 5. RFC 5424 header field coverage

**Specification.** Section 2.2 lists facility, severity, timestamp, hostname,
application name and message body as extracted fields.

**Behaviour.** The parser validates the PRI, derives severity, extracts the
timestamp and all structured network fields, and preserves the complete raw
message. Facility, hostname and application name are not persisted as separate
structured columns — they remain available inside `raw_message`.

**Why it is not resolved.** None of the three is consumed by feature
extraction, the rule layer, the dashboard or the reports, so persisting them
adds schema surface with no reader. `db/schema.sql` is also the artefact behind
NFR-10's "nine tables, ten foreign keys" evidence.

**What closing it would require.** Three nullable columns, a migration, and
parser changes.

---

## 6. Alert dispatch latency under concurrent failure

**Specification.** NFR-09 requires the first dispatch attempt for every
critical alert to begin within 10 seconds of detection.

**Behaviour.** Measured detection-to-dispatch is 2.2 s and 4.7 s on successful
delivery, and automated tests verify the 2/4/8-second retry sequence and the
final FAILED state. However, the worker sleeps through a retry sequence
synchronously, so a second critical alert arriving while a first is failing
could have its own first attempt delayed past 10 seconds. That concurrent case
has not been measured.

**Why it is not resolved.** Fixing it means restructuring the worker into
concurrent per-alert tasks — a change to the delivery path that would need
fresh evidence for the whole of NFR-09, not just the new case.

**What closing it would require.** Per-alert asyncio tasks or a queue with
independent backoff timers, plus re-measurement.

---

## 7. Report generation quota semantics

**Specification.** The approved proposal contradicts itself. Table 11 and
Section 2.6 describe a limit of ten report *generation requests* per
administrator per hour; Use Case 4.4 alternate flow 3a states that a failed
OpenAI request does not consume quota.

**Behaviour.** The implementation follows the Use Case: quota counts stored
reports, so a failed generation costs the administrator nothing.

**Why it is not resolved.** It is a specification defect, not a code defect,
and the interpretation should be settled with the supervisor rather than
chosen unilaterally. The implemented reading is also the defensible one — a
user who received nothing usable should not be charged for it.

**What closing it would require.** A decision, then a one-line change to the
counter in `app/middleware/rate_limit.py` if the other reading is preferred.

---

## 8. Backup execution time

**Specification.** NFR-10 requires a daily `pg_dump` at 02:00 AEST with
seven-day retention and tested restoration.

**Behaviour.** The launchd job is scheduled for 02:00 and runs daily; retention
and restore are verified end to end. macOS does not wake a sleeping host to run
a scheduled job, so on a laptop the backup executes at the next wake instead.

**Why it is not resolved.** It is a property of the host operating system, not
of ThreatSense. The daily cadence, the retention window and the restore
procedure — the substance of the requirement — are all met.

**What closing it would require.** A host that stays awake, or a scheduler with
wake privileges (`pmset`), neither of which is a change to the application.

---

## 9. NFR-01 and NFR-02 sustained capacity

**Specification.** NFR-01 requires ingestion of 1,000 syslog entries per second
without loss. NFR-02 requires each detection cycle to finish within 10 seconds,
measured as the 95th percentile over 100 consecutive cycles.

**Behaviour.** NFR-01 is met independently: 85,002 sent and 85,002 delivered
across four rates, 0.00% loss. NFR-02 is met at typical and capped volumes
(4.748 s for 20,000 logs; p95 0.432 s). The two have not been demonstrated
simultaneously: at NFR-01's arrival rate, 60,000 records arrive per detection
window while the cycle is capped at 20,000, and raising the cap to 60,000 would
exceed NFR-02's budget.

**Why it is not resolved.** Sustaining both at once requires a structural
change to the detection pipeline — parallel window scoring, or decoupling
extraction from scoring. That is a redesign, not a tuning exercise.

**What closing it would require.** Pipeline restructuring plus a fresh
100-cycle p95 measurement at the full arrival rate.

---

## 10. Model evaluation dataset

**Specification.** Section 1.5 anticipated evaluation against CICIDS2017.

**Behaviour.** `IF_v1.0` is trained and evaluated on synthetic traffic from the
project's own generator (`ml/synth.py`). The precision, recall and F1 of 1.000
recorded in `ml/metrics/IF_v1.0.metrics.json` were obtained on held-out data
produced by that same generator and **must not be read as generalisable
real-world accuracy** — they measure separability within one synthetic
distribution.

**Why it is stated this way.** The meaningful evidence is the live validation:
an Nmap SYN scan produced 1,001 ingested records and one CRITICAL PORT_SCAN at
anomaly score 1.000 with `unique_dst_ports` of exactly 1000.0, and an hping3
SYN flood produced a CRITICAL DDOS detection. That is reported separately and
is the result the project stands on.

**What closing it would require.** Preparing CICIDS2017 through
`ml/prepare_data.py`, retraining and re-evaluating.

---

## Future enhancements

Declared in the proposal as secondary deliverables and not attempted:

- `.pcap` and `.pcapng` upload with magic-byte validation (the endpoint exists
  and returns HTTP 501 with an explanatory message)
- An autoencoder comparison model using reconstruction error
- SMS alerting through Twilio (schema fields are reserved: `alert_config.sms_enabled`,
  `sms_recipient`)
- A geographic threat map using MaxMind GeoLite2
- WebSocket dashboard updates driven by PostgreSQL LISTEN/NOTIFY
- Redis-backed caching for dashboard queries

Beyond the proposal, the natural next steps are per-source TLS client
certificates (which would resolve §1), `IF_v1.1` with proposal-exact feature
definitions (§2), and a concurrent alert dispatcher (§6).
