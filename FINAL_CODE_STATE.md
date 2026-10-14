# ThreatSense — Final Code State

Inventory of every major user-facing feature in the submitted tree, verified
against source rather than against filenames, task notes or Git history.

Verified: 3 September 2026, against the tree submitted as
`ThreatSense_Final_Code.zip`.

Status meanings:

- **PRESENT** — implemented, reachable by a user, covered by automated tests.
- **PARTIAL** — implemented and usable, but one literal aspect of the approved
  proposal is not met. Each PARTIAL entry names what is missing and points at
  `KNOWN_LIMITATIONS.md`.
- **MISSING** — not implemented.

---

## Authentication and accounts

| Feature | Status | Evidence in source |
|---|---|---|
| Login / logout | PRESENT | `app/routers/auth.py`, `app/services/auth/service.py`; JWT in an HttpOnly, SameSite=Strict cookie |
| bcrypt password verification (cost 12) | PRESENT | `app/core/security.py`; cost from `config.bcrypt_cost_factor` |
| Login rate limiting (5 per IP / 15 min) | PRESENT | `app/middleware/rate_limit.py`; returns 429 with `Retry-After` |
| Account lockout | PRESENT | `app/services/auth/service.py`; `tests/test_account_lockout.py` |
| Initial administrator setup | PRESENT | `app/services/auth/setup.py`; creates detection settings in the same transaction |
| Password reset by email | PRESENT | `app/services/auth/reset.py`; delivery via SendGrid, token never logged |
| Change password | PRESENT | `app/routers/accounts.py`, `frontend/src/pages/Account.jsx` |
| RBAC: SUPER_ADMIN / ADMIN / VIEWER | PRESENT | `app/middleware/rbac.py`; `require_operator` / `require_read` on every mutating endpoint |
| SUPER_ADMIN lists and creates accounts | PRESENT | `app/routers/accounts.py::list_accounts`, `::create_account` |
| Account deletion | Deliberately not exposed | `app/routers/accounts.py` header comment: `audit_logs.admin_id` has no CASCADE or SET NULL, so a physical delete would either fail or destroy an audit trail. Deactivation is the intended path. |
| Session-expiry warning (2 minutes) | MISSING | Section 2.1 specifies it. See `KNOWN_LIMITATIONS.md` §4. |

## Navigation and shell

| Feature | Status | Evidence in source |
|---|---|---|
| ThreatSense logo returns to Dashboard | PRESENT | `frontend/src/components/AppShell.jsx`, `<Link to="/">` with aria-label |
| Seven navigation destinations (Section 2.1) | PRESENT | `AppShell.jsx` `NAV`: Dashboard, Detections, Log Sources, Detection Settings, Alert Config, Incident Reports, Account Settings |
| Source count consistent across pages | PRESENT | `AppShell.jsx` fetches the count itself rather than taking it as a prop, so every page reports the same number; counts effectively-ACTIVE sources only |
| Notification bell (unacknowledged count) | PRESENT | `frontend/src/components/NotificationBell.jsx`, `context/AlertsContext.jsx` |

## Dashboard

| Feature | Status | Evidence in source |
|---|---|---|
| Dashboard renders | PRESENT | `frontend/src/pages/Dashboard.jsx` |
| Network health endpoint | PRESENT | `app/routers/dashboard.py::dashboard_health` |
| Alerts endpoint | PRESENT | `app/routers/dashboard.py::dashboard_alerts` |
| Analytics endpoint | PRESENT | `app/routers/dashboard.py::dashboard_analytics` |
| Manage button routes to Log Sources | PRESENT | `frontend/src/dashboard/Panels.jsx`, `<Link to="/sources">` |
| View All opens detection history | PRESENT | `frontend/src/dashboard/IncidentStream.jsx` |
| Hero alert card, KPI cards, system status | PRESENT | `frontend/src/dashboard/HeroAlert.jsx`, `Kpis.jsx`, `SystemStatus.jsx` |
| Dashboard consumes the three proposal endpoints | PARTIAL | The endpoints exist and are tested; the React dashboard polls the detections endpoints instead and its KPI cards report detection counts rather than Network Health. See `KNOWN_LIMITATIONS.md` §3. |

## Detections

| Feature | Status | Evidence in source |
|---|---|---|
| Full detections page (not a placeholder) | PRESENT | `frontend/src/pages/Detections.jsx`, 240 lines with filters, paging and acknowledge |
| Global detection search | PRESENT | `app/routers/detections.py::list_detections`; the `q` filter is applied in SQL **before** limit/offset, so the whole history is searched, not the loaded page. `tests/test_detection_search.py`, 12 tests |
| Detection detail | PRESENT | `frontend/src/pages/DetectionDetail.jsx` |
| View Traffic (traffic summary) | PRESENT | `app/routers/detections.py::detection_traffic`; shares one aggregate query with the report prompt so screen and report never disagree |
| Acknowledgement (PATCH) | PRESENT | `app/routers/detections.py::acknowledge_detection`; writes an ACKNOWLEDGE audit row |

## Log sources

| Feature | Status | Evidence in source |
|---|---|---|
| Source CRUD | PRESENT | `app/routers/sources.py` |
| Per-admin unique source names | PRESENT | `uq_data_sources_admin_name`; `tests/test_source_names.py` |
| Status ACTIVE → INACTIVE after 60 seconds | PRESENT | `app/core/source_status.py`; derived at read time from `last_received`. Boundary is inclusive — 60.000s of silence reads INACTIVE. Applied in both the sources router and the dashboard health card |
| Log file upload | PRESENT | `app/routers/sources.py::upload_logs` (text/syslog; PCAP returns 501 as a declared enhancement) |

## Ingestion

| Feature | Status | Evidence in source |
|---|---|---|
| UDP listener (1514) | PRESENT | `app/services/ingestion/listener.py::start_udp` |
| TCP listener (1601, diagnostics) | PRESENT | `::start_tcp` |
| TLS listener (6514, RFC 5425) | PRESENT | `::start_tls`, `app/services/ingestion/tls.py`; `tests/test_tls_listener.py` |
| RFC 6587 octet-counted framing | PRESENT | `app/services/ingestion/framing.py`; `tests/test_syslog_framing.py` |
| Parser adapters | PRESENT | `app/services/ingestion/parsers/` (rfc5424, iptables, default) |
| Buffered flush (500 records / 5 seconds) | PRESENT | `listener.py::flush`; durable — the buffer prefix is removed only after a confirmed commit |
| In-batch deduplication | PRESENT | `parsers/base.py::fingerprint`, applied in `offer()` |
| Ambiguous sender address handling | PRESENT | `listener.py::refresh_sources`; an address claimed by two sources is dropped rather than attributed by row order |
| Single-source fallback scoped | PRESENT | `listener.py::refresh_sources`; the fallback applies only when the lone source has no `ip_address` configured |
| Stale-source records dropped, batch survives | PRESENT | `listener.py::_write`; source ids are revalidated inside the write transaction. `tests/test_source_resolution.py`, 9 tests |
| Endpoint revalidated at the write boundary | PRESENT | `listener.py::_still_matches`; each buffered record carries its sender address, transport and listener port, and a source reconfigured mid-flight no longer absorbs it |
| Configured transport / port enforced on attribution | PRESENT | `_still_matches` checks `data_sources.transport` and `.port` when they are set; unset fields are not enforced, so address-less single-collector setups keep working |
| Automatic attribution when multiple sources share one sender IP | NOT SUPPORTED | Contested traffic is safely **rejected** rather than assigned to the wrong tenant. ThreatSense does not disambiguate; it detects ambiguity and refuses. See `KNOWN_LIMITATIONS.md` §1. |
| RFC 5424 facility / hostname / app-name persisted | PARTIAL | PRI and severity are parsed; those three are not stored as structured columns. See `KNOWN_LIMITATIONS.md` §5. |

## Detection engine

| Feature | Status | Evidence in source |
|---|---|---|
| Feature extraction (10 window features) | PRESENT | `ml/features.py`, imported by both training and inference so they cannot drift |
| Isolation Forest inference | PRESENT | `app/services/detection/model.py`, `ml/models/IF_v1.0.joblib` (200 trees) |
| Vectorised batch scoring | PRESENT | `app/services/detection/engine.py`; one `score_samples` call for all windows |
| Rule-based threat classification | PRESENT | `app/services/detection/rules.py`, `app/core/thresholds.py` |
| Severity banding | PRESENT | `app/services/detection/severity.py` |
| 60-second scheduled cycle | PRESENT | `app/services/detection/engine.py` |
| Manual scan | PRESENT | `app/routers/settings.py`, `frontend/src/pages/DetectionSettings.jsx` |
| Feature definitions match Algorithm 2 literally | PARTIAL | Five of ten differ from the approved pseudocode. Correcting them requires retraining. See `KNOWN_LIMITATIONS.md` §2. |

## Alerting

| Feature | Status | Evidence in source |
|---|---|---|
| Alert configuration CRUD | PRESENT | `app/routers/alerts.py`, `frontend/src/pages/AlertConfig.jsx` |
| SendGrid delivery | PRESENT | `app/services/alerting/sendgrid_client.py`, `sender.py` |
| Async alert worker | PRESENT | `app/services/alerting/worker.py` |
| Severity threshold | PRESENT | `worker.py`, `config_cache.py` |
| Quiet hours | PRESENT | `worker.py` |
| Five-minute duplicate suppression | PRESENT | `worker.py` |
| Retry 2 / 4 / 8 s then FAILED | PRESENT | `worker.py`; `tests/test_alert_worker.py` |
| Test alert | PRESENT | `app/routers/alerts.py` |
| Concurrent-failure dispatch latency | PARTIAL | The worker sleeps a retry sequence synchronously. See `KNOWN_LIMITATIONS.md` §6. |

## AI incident reports

| Feature | Status | Evidence in source |
|---|---|---|
| Report generation (4 fixed sections) | PRESENT | `app/services/reporting/generator.py`, `prompt.py`, `llm_client.py` |
| Data minimisation (no raw logs to OpenAI) | PRESENT | `prompt.py::summarise_related_logs` returns aggregates only; asserted in `tests/test_reports.py` |
| Related-log window is the detection's own minute bucket | PRESENT | `prompt.py::detection_window_start` mirrors `ml/features.py::group_windows`; scope runs from the start of that calendar minute to the detection timestamp, and the prompt text, the TrafficSummary schema and the Detection Detail label all describe it that way. `tests/test_report_scope.py` |
| Immutable storage / regenerate history | PRESENT | `generator.py` only ever INSERTs |
| Per-detection report history | PRESENT | `app/routers/reports.py::report_history` |
| Incident Reports history page | PRESENT | `app/routers/reports.py::all_reports`, `frontend/src/pages/IncidentReports.jsx` |
| PDF export | PRESENT | `app/services/reporting/pdf.py`, `app/routers/reports.py::export_report_pdf` |
| Report quota counts attempts | PARTIAL | Counts stored reports; the approved specification contradicts itself. See `KNOWN_LIMITATIONS.md` §7. |

## Operations

| Feature | Status | Evidence in source |
|---|---|---|
| Database schema (9 tables, 10 FKs) | PRESENT | `backend/db/schema.sql` |
| Seed script | PRESENT | `backend/db/seed.py` |
| Docker / PostgreSQL 16 configuration | PRESENT | `docker-compose.yml` |
| Automated backup, 7-day retention | PRESENT | `backend/scripts/backup_db.sh` |
| Restore drill | PRESENT | `backend/docs/restore_drill.md` |
| Scheduled backup at exactly 02:00 | PARTIAL | macOS defers a job on a sleeping host. See `KNOWN_LIMITATIONS.md` §8. |
| Cross-process liveness heartbeats | PRESENT | `app/services/heartbeat.py`; surfaced on `/health` |
| Ingestion telemetry | PRESENT | `listener.py::write_stats` → `var/ingestion_stats.json` |
