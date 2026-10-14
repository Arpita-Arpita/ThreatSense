"""Application settings, loaded from environment / backend/.env (task 1.3)."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Read backend/.env; ignore the many keys not needed yet (SendGrid, OpenAI, …).
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Core
    database_url: str = "postgresql+psycopg://threatsense:change_me_local_dev@localhost:5432/threatsense"
    env: str = "development"
    log_level: str = "info"

    # CORS — the React dev server origin (credentials carry the auth cookie).
    frontend_origin: str = "http://localhost:5173"

    # Auth / JWT (task 1.4)
    jwt_secret: str = "dev-insecure-change-me"
    jwt_expiry_minutes: int = 60
    bcrypt_cost_factor: int = 12
    cookie_name: str = "ts_session"
    cookie_secure: bool = False          # True in production (HTTPS)
    cookie_samesite: str = "strict"
    max_failed_attempts: int = 5         # account lockout threshold (423), NOT NFR-05    # How long an account stays locked after max_failed_attempts is reached.
    # Matched to login_rate_window_minutes below on purpose: 15 minutes is the
    # only lockout-style window Table 11 names (NFR-05), so aligning the two
    # means an operator has one number to reason about rather than two.
    # Before this existed the lockout never expired and could only be cleared
    # by a successful password reset or by hand in SQL.
    account_lockout_minutes: int = 15

    # Login rate limiting (task 1.4, NFR-05) ----------------------------------
    # Table 11, NFR-05: "five login attempts per IP within a 15-minute window
    # ... Exceeding limits returns HTTP 429." Leave these at the defaults when
    # capturing NFR-05 evidence — they are the numbers being certified.
    login_rate_limit: int = 5
    login_rate_window_minutes: int = 15

    # Syslog ingestion worker (task 1.6)
    syslog_host: str = "0.0.0.0"
    syslog_port: int = 1514              # non-privileged (>1024), no sudo needed
    syslog_flush_seconds: int = 5        # Algorithm 1: time-based flush trigger
    syslog_flush_batch: int = 500        # Algorithm 1: size-based flush trigger

    # Syslog over TLS (task 6.2, NFR-04) --------------------------------------
    # Table 11, NFR-04: "Syslog over TLS on TCP port 6514 must be used where
    # supported. Standard Syslog ports 514 and 1514 may be used only within
    # the isolated testing environment."
    #
    # 6514 is the IANA-assigned port for syslog-tls (RFC 5425). The UDP
    # listener on 1514 above stays available for the sandbox, which is what
    # the requirement's second sentence permits — but production traffic is
    # expected here.
    syslog_tls_enabled: bool = True
    syslog_tls_port: int = 6514
    syslog_tls_certfile: str = "certs/threatsense.crt"
    syslog_tls_keyfile: str = "certs/threatsense.key"
    syslog_tls_min_version: str = "TLSv1_2"     # NFR-04 floor; or TLSv1_3
    # RFC 5425 s4.2.1 mutual auth. Off by default — no CA exists for the MVP.
    syslog_tls_require_client_cert: bool = False
    syslog_tls_ca_file: str = ""

    # Plaintext TCP syslog (RFC 6587). Off by default: it is neither the
    # encrypted path NFR-04 wants nor the UDP path the sandbox uses, and
    # exists only for diagnosing whether a failure is TLS-related or not.
    syslog_tcp_enabled: bool = False
    syslog_tcp_port: int = 1601
    # Upper bound on a single framed message. RFC 5425 s4.3.1 sets no limit;
    # this caps memory per connection.
    syslog_max_frame_bytes: int = 64 * 1024

    # Use Case 4.2: a source moves to INACTIVE when no valid message has been
    # received for 60 seconds, and back to ACTIVE when traffic resumes. The
    # stored status column records the last WRITE (set ACTIVE on every flush
    # that touched the source); the timeout is applied when the status is READ,
    # so no background sweeper process is required and Dashboard and Log
    # Sources cannot disagree about the same source.
    source_inactive_after_seconds: int = 60

    # Maximum network_logs rows one detection cycle will pull. NFR-02 allows a
    # cycle to take up to 10 seconds; this is the knob that keeps it there.
    # Held at 5000 while each window was scored individually. The engine now
    # scores every window in one vectorised call, so the ceiling is set by
    # database fetch and feature extraction rather than by the model.
    # Measured figures are in tests/test_detection_batching.py.
    detection_max_logs_per_cycle: int = 20000

    # Ingestion telemetry surfaced on /health -----------------------------------
    # The listener and the API are separate processes, so the drop counters
    # held in IngestionService cannot be read directly by the /health handler.
    # The listener writes them to this file once per flush cycle and /health
    # reads it. A file rather than a table on purpose: db/schema.sql is the
    # artefact behind NFR-10's "nine application tables ... ten foreign keys",
    # and a tenth table would invalidate that evidence for telemetry that is
    # not itself a Table 11 requirement.
    ingestion_stats_path: str = "var/ingestion_stats.json"
    # Age beyond which /health reports the listener as stale rather than up.
    # Must exceed syslog_flush_seconds or a healthy listener reads as stale.
    ingestion_stats_stale_seconds: int = 30

    # Cross-process liveness heartbeats (Phase 6.3). The detection engine and
    # alert worker write here; /health reads them. See services/heartbeat.py.
    heartbeat_dir: str = "var"
    # Must exceed the SLOWEST background cycle or a healthy process reads as
    # stale. The engine runs on detection_settings.detection_interval_seconds
    # (60s by default) and the worker on alert_poll_seconds (5s), so 180s
    # leaves room for an operator raising the detection interval.
    heartbeat_stale_seconds: int = 180

    # Alerting (task 2.1) — alert_config cache staleness bound. The API refreshes
    # its own cache on save; this TTL is what lets the separate alert-worker
    # process pick up a settings change without a per-detection query.
    alert_config_cache_ttl_seconds: int = 30

    # Alert worker (task 2.3, Section 2.5 / Algorithm 3 / NFR-09) ---------------
    # Poll cadence. NFR-09 wants the first dispatch attempt inside 10s of a
    # detection, so this must stay comfortably under that.
    alert_poll_seconds: int = 5
    alert_batch_size: int = 200            # detections evaluated per cycle
    alert_dedup_minutes: int = 5           # same source_ip + threat_type window
    alert_retry_backoff: str = "2,4,8"     # seconds; initial attempt + 3 retries
    # Where the worker remembers how far it has read. Detections that are
    # suppressed, below threshold or in quiet hours never produce an alerts row,
    # so the join alone cannot tell "not yet seen" from "seen and skipped".
    alert_worker_state_path: str = "var/alert_worker_state.json"
    # On a first-ever run, ignore detections older than this (0 = start from now).
    alert_initial_lookback_minutes: int = 0
    # Proposal Algorithm 3 notifies every admin with email enabled. Phase 1 made
    # sources admin-owned, so the default here notifies the owning admin only.
    # Set true for the literal Algorithm 3 fan-out.
    alert_fanout_all_admins: bool = False
    # alert_config stores bare TIME values. Set this (e.g. Australia/Sydney)
    # when the host runs UTC but quiet hours must match local working hours.
    alert_quiet_hours_tz: str = ""

    # Email delivery
    sendgrid_api_key: str = ""             # empty -> mock sender (task 2.2 pending)
    alert_from_email: str = "alerts@threatsense.local"
    alert_from_name: str = "ThreatSense"
    alert_email_sender: str = "auto"       # auto | mock | sendgrid
    dashboard_url: str = "http://localhost:5173"

    # Incident reports (task 3.2, Section 2.6 / Algorithm 5 / UC 4.4) ----------
    openai_api_key: str = ""               # empty -> mock LLM client (task 3.1 pending)
    openai_model: str = "gpt-4o-mini"
    openai_timeout_seconds: int = 15       # hard budget per Algorithm 5
    report_llm_client: str = "auto"        # auto | mock | openai
    report_max_completion_tokens: int = 1200
    report_rate_limit: int = 10            # successful reports per admin ...
    report_rate_window_minutes: int = 60   # ... per rolling window -> 429

    # File-upload ingestion (task 1.8)
    max_upload_bytes: int = 25 * 1024 * 1024   # 25 MiB cap on uploaded log files


settings = Settings()
