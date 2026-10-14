-- ============================================================================
-- ThreatSense · PostgreSQL 16 schema  ·  Task 1.1  (proposal-aligned, rev 3)
-- Matches Section 2 / 2.7 per the proposal-diff corrections.
-- UUID PKs via gen_random_uuid() (built into PostgreSQL 13+). Idempotent.
-- ============================================================================

-- ---- ENUM types ------------------------------------------------------------
DO $$ BEGIN CREATE TYPE admin_role AS ENUM ('SUPER_ADMIN','ADMIN','VIEWER');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE audit_action AS ENUM ('LOGIN','CONFIG_CHANGE','ACKNOWLEDGE','REPORT_GENERATED','REPORT_GENERATION_FAILED','EXPORT');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE transport_type AS ENUM ('TLS','TCP','UDP');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE source_type AS ENUM ('PCAP','SYSLOG');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE source_status AS ENUM ('ACTIVE','INACTIVE','ERROR');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE severity_level AS ENUM ('LOW','MEDIUM','HIGH','CRITICAL');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE threat_type AS ENUM ('PORT_SCAN','DDOS','C2','BRUTE_FORCE','UNKNOWN_ANOMALY');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE alert_channel AS ENUM ('EMAIL','SMS','IN_APP');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE alert_status AS ENUM ('PENDING','SENT','FAILED');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE alert_severity_threshold AS ENUM ('CRITICAL','HIGH','MEDIUM','ALL');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ---- 1. administrators -----------------------------------------------------
CREATE TABLE IF NOT EXISTS administrators (
    admin_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    full_name           VARCHAR(150) NOT NULL,
    email               VARCHAR(255) NOT NULL UNIQUE,
    password_hash       VARCHAR(255) NOT NULL,
    role                admin_role   NOT NULL DEFAULT 'ADMIN',
    last_login          TIMESTAMPTZ,
    failed_attempts     INTEGER      NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- TRUE only for the account created by POST /api/auth/setup (Section 2.1,
    -- "Direct registration is available only for the initial administrator").
    -- ux_administrators_single_initial below permits at most one such row, so
    -- two simultaneous setup requests cannot both create a SUPER_ADMIN. Not
    -- in the proposal's Table 2; recorded as a declared deviation.
    is_initial_admin    BOOLEAN      NOT NULL DEFAULT FALSE
);

-- ---- 2. audit_logs ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    log_id      BIGSERIAL PRIMARY KEY,
    admin_id    UUID NOT NULL REFERENCES administrators(admin_id),
    action      audit_action NOT NULL,
    details     TEXT,
    ip_address  INET,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---- 3. data_sources -------------------------------------------------------
CREATE TABLE IF NOT EXISTS data_sources (
    source_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id        UUID NOT NULL REFERENCES administrators(admin_id) ON DELETE CASCADE,
    name            VARCHAR(100) NOT NULL,
    type            source_type NOT NULL,
    transport       transport_type,
    ip_address      INET,
    port            INTEGER CHECK (port BETWEEN 1 AND 65535),
    status          source_status NOT NULL DEFAULT 'ACTIVE',
    last_received   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_data_sources_admin_name UNIQUE (admin_id, name)
);

-- ---- 4. network_logs -------------------------------------------------------
CREATE TABLE IF NOT EXISTS network_logs (
    log_id              BIGSERIAL PRIMARY KEY,
    source_id           UUID NOT NULL REFERENCES data_sources(source_id) ON DELETE CASCADE,
    batch_id            UUID NOT NULL,
    src_ip              INET NOT NULL,
    dst_ip              INET NOT NULL,
    src_port            INTEGER CHECK (src_port BETWEEN 0 AND 65535),  -- retained: see note
    dst_port            INTEGER CHECK (dst_port BETWEEN 0 AND 65535),  -- retained: feature "unique dst ports"
    protocol            VARCHAR(10) NOT NULL,
    packet_size         INTEGER NOT NULL,
    flags               VARCHAR(20),
    connection_outcome  VARCHAR(20),
    syslog_severity     INTEGER,
    raw_message         TEXT,
    "timestamp"         TIMESTAMPTZ NOT NULL,
    is_analysed         BOOLEAN NOT NULL DEFAULT FALSE,
    ingested_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---- 5. detections ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS detections (
    detection_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id           UUID NOT NULL REFERENCES data_sources(source_id),
    source_ip           INET NOT NULL,
    destination_ip      INET NOT NULL,
    "timestamp"         TIMESTAMPTZ NOT NULL,
    anomaly_score       FLOAT NOT NULL CHECK (anomaly_score BETWEEN 0 AND 1),
    severity            severity_level NOT NULL,
    threat_type         threat_type NOT NULL DEFAULT 'UNKNOWN_ANOMALY',
    model_version       VARCHAR(20) NOT NULL,
    model_type          VARCHAR(20) NOT NULL,             -- ISOLATION_FOREST | AUTOENCODER
    feature_vector      JSONB NOT NULL,
    is_acknowledged     BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_by     UUID REFERENCES administrators(admin_id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---- 6. detection_settings -------------------------------------------------
CREATE TABLE IF NOT EXISTS detection_settings (
    settings_id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sensitivity_threshold       FLOAT NOT NULL DEFAULT 0.75 CHECK (sensitivity_threshold BETWEEN 0.50 AND 0.99),
    active_model_version        VARCHAR(20) NOT NULL,
    detection_interval_seconds  INTEGER NOT NULL DEFAULT 60 CHECK (detection_interval_seconds > 0),
    updated_by                  UUID NOT NULL REFERENCES administrators(admin_id),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---- 7. alert_config -------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_config (
    config_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id            UUID NOT NULL UNIQUE REFERENCES administrators(admin_id) ON DELETE CASCADE,
    email_enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    sms_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    email_recipient     VARCHAR(255),
    sms_recipient       VARCHAR(20),
    severity_threshold  alert_severity_threshold NOT NULL DEFAULT 'HIGH',
    quiet_start         TIME,
    quiet_end           TIME,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---- 8. alerts -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    alert_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id    UUID NOT NULL REFERENCES detections(detection_id) ON DELETE CASCADE,
    channel         alert_channel NOT NULL,
    recipient       VARCHAR(255) NOT NULL,
    status          alert_status NOT NULL DEFAULT 'PENDING',
    retry_count     INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT,
    sent_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---- 9. incident_reports ---------------------------------------------------
CREATE TABLE IF NOT EXISTS incident_reports (
    report_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id    UUID NOT NULL REFERENCES detections(detection_id) ON DELETE CASCADE,
    generated_by    UUID NOT NULL REFERENCES administrators(admin_id),
    report_text     TEXT NOT NULL,
    model_used      VARCHAR(30) NOT NULL,
    token_count     INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- Indexes (Section 2.7) — exact list.
-- ============================================================================
CREATE UNIQUE INDEX IF NOT EXISTS ux_administrators_single_initial
    ON administrators (is_initial_admin) WHERE is_initial_admin;
CREATE INDEX IF NOT EXISTS ix_administrators_email          ON administrators (email);
CREATE INDEX IF NOT EXISTS ix_detection_settings_updated_at ON detection_settings (updated_at);
CREATE INDEX IF NOT EXISTS ix_network_logs_source_ts        ON network_logs (source_id, "timestamp");
CREATE INDEX IF NOT EXISTS ix_network_logs_unanalysed       ON network_logs (is_analysed) WHERE is_analysed = FALSE;
CREATE INDEX IF NOT EXISTS ix_detections_ts_severity        ON detections ("timestamp", severity);
CREATE INDEX IF NOT EXISTS ix_detections_srcip_threat_ts    ON detections (source_ip, threat_type, "timestamp");
CREATE INDEX IF NOT EXISTS ix_alerts_detection_created      ON alerts (detection_id, created_at);
CREATE INDEX IF NOT EXISTS ix_alerts_created                ON alerts (created_at);
