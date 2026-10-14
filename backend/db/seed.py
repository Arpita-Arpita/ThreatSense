"""
ThreatSense · Task 1.2 · Database seed script.

Creates the minimum data the system needs to boot and the detection engine
needs to chew on:
  • the first SUPER_ADMIN (bcrypt cost-12 password hash)
  • the singleton detection_settings row (threshold 0.75, interval 60s)
  • a default alert_config for that admin
  • one sample SYSLOG data_source
  • a handful of sample network_logs (is_analysed = FALSE)

Idempotent: re-running it will NOT create duplicates.  If the product's
Initial Setup has already created any administrator, the seed helper reuses
that account instead of manufacturing a second privileged account.

Run it from the backend/ directory once your DB is up:
    cd backend
    python3.12 -m venv .venv && source .venv/bin/activate
    pip install "sqlalchemy>=2.0" "psycopg[binary]" bcrypt
    python db/seed.py
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Make `app.models` importable when run as `python db/seed.py` from backend/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bcrypt
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.core.password_policy import password_policy_errors
from app.models import (
    Administrator, AdminRole, DetectionSettings, AlertConfig,
    AlertSeverityThreshold, DataSource, SourceType, TransportType,
    SourceStatus, NetworkLog,
)

# --- Config (override via environment) --------------------------------------
SEED_ADMIN_EMAIL = os.environ.get("SEED_ADMIN_EMAIL", "admin@threatsense.local")
SEED_ADMIN_NAME = os.environ.get("SEED_ADMIN_NAME", "ThreatSense Admin")
SEED_ADMIN_PASSWORD = os.environ.get("SEED_ADMIN_PASSWORD", "ChangeMe123!")
ACTIVE_MODEL_VERSION = os.environ.get("ACTIVE_MODEL_VERSION", "IF_v1.0")


def get_database_url() -> str:
    """env DATABASE_URL → backend/.env → local compose default."""
    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    env_file = Path(__file__).resolve().parents[1] / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("DATABASE_URL=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip()
    return "postgresql+psycopg://threatsense:change_me_local_dev@localhost:5432/threatsense"


def hash_password(plain: str) -> str:
    """Bcrypt-hash the seed password, enforcing NFR-11 first.

    This is the SECOND bcrypt call site in the codebase (the other is
    app/core/security.py). It is intentionally standalone so the seed script
    can run without the FastAPI app importable — which means it needs its own
    copy of the Table 11, NFR-11 guard, "server-side validation immediately
    before bcrypt hashing", or SEED_ADMIN_PASSWORD would be the one way to get
    a non-compliant password into administrators.
    """
    errors = password_policy_errors(plain)
    if errors:
        raise SystemExit(
            "  ✗  SEED_ADMIN_PASSWORD does not meet the NFR-11 password policy:\n"
            + "".join(f"       - {e}\n" for e in errors)
            + "     Set a compliant SEED_ADMIN_PASSWORD and re-run."
        )
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def seed(session: Session) -> None:
    # 1) Administrator -------------------------------------------------------
    # This is a DEVELOPMENT data helper, not an account-registration path.
    # After Initial Setup there may already be a SUPER_ADMIN with a different
    # email.  Creating admin@threatsense.local in that case would bypass the
    # Section 2.1 controlled SUPER_ADMIN account-management workflow and, with
    # the default seed password, introduce an unnecessary privileged account.
    admin = session.scalar(
        select(Administrator).where(Administrator.email == SEED_ADMIN_EMAIL)
    )
    if admin is None:
        admin = session.scalar(
            select(Administrator)
            .order_by(Administrator.created_at, Administrator.admin_id)
            .limit(1)
        )

    if admin is None:
        admin = Administrator(
            full_name=SEED_ADMIN_NAME,
            email=SEED_ADMIN_EMAIL,
            password_hash=hash_password(SEED_ADMIN_PASSWORD),
            role=AdminRole.SUPER_ADMIN,
        )
        session.add(admin)
        session.flush()  # populate admin.admin_id (RETURNING)
        print(f"  + development SUPER_ADMIN created: {SEED_ADMIN_EMAIL}")
    else:
        print(f"  = using existing administrator: {admin.email}")

    # 2) detection_settings (singleton) -------------------------------------
    if session.scalar(select(DetectionSettings)) is None:
        session.add(DetectionSettings(
            sensitivity_threshold=0.75,
            active_model_version=ACTIVE_MODEL_VERSION,
            detection_interval_seconds=60,
            updated_by=admin.admin_id,
        ))
        print("  + detection_settings created (threshold 0.75, interval 60s)")
    else:
        print("  = detection_settings already present")

    # 3) alert_config for the admin -----------------------------------------
    if session.scalar(select(AlertConfig).where(AlertConfig.admin_id == admin.admin_id)) is None:
        session.add(AlertConfig(
            admin_id=admin.admin_id,
            email_enabled=True,
            email_recipient=admin.email,
            severity_threshold=AlertSeverityThreshold.HIGH,
        ))
        print("  + alert_config created (email, threshold HIGH)")
    else:
        print("  = alert_config already present")

    # 4) sample data_source --------------------------------------------------
    source = session.scalar(select(DataSource).where(DataSource.admin_id == admin.admin_id))
    if source is None:
        source = DataSource(
            admin_id=admin.admin_id,
            name="sample-edge-firewall",
            type=SourceType.SYSLOG,
            transport=TransportType.UDP,
            ip_address="192.168.1.1",
            port=514,
            status=SourceStatus.ACTIVE,
        )
        session.add(source)
        session.flush()
        print("  + data_source created: sample-edge-firewall")
    else:
        print(f"  = data_source already present: {source.name}")

    # 5) sample network_logs (only if this source has none) -----------------
    existing_logs = session.scalar(select(NetworkLog).where(NetworkLog.source_id == source.source_id))
    if existing_logs is None:
        batch = uuid.uuid4()
        now = datetime.now(timezone.utc)
        protocols = ["TCP", "UDP", "ICMP"]
        rows = []
        for i in range(20):
            rows.append(NetworkLog(
                source_id=source.source_id,
                batch_id=batch,
                src_ip=f"10.0.0.{10 + (i % 5)}",
                dst_ip=f"192.168.1.{20 + (i % 7)}",
                src_port=40000 + i,
                dst_port=(22, 80, 443, 53, 3389)[i % 5],
                protocol=protocols[i % 3],
                packet_size=64 + (i * 23) % 1400,
                flags="SYN" if i % 4 == 0 else "ACK",
                connection_outcome="ESTABLISHED" if i % 3 else "REJECTED",
                syslog_severity=6,
                raw_message=f"sample syslog record #{i}",
                timestamp=now - timedelta(seconds=i * 3),
                is_analysed=False,
            ))
        session.add_all(rows)
        print(f"  + {len(rows)} sample network_logs created (batch {batch})")
    else:
        print("  = network_logs already present for this source")


def main() -> None:
    url = get_database_url()
    safe = url.split("@")[-1]
    print(f"Seeding ThreatSense DB @ {safe}")
    engine = create_engine(url, echo=False)
    with Session(engine) as session:
        seed(session)
        session.commit()
    print("Seed complete.")
    if SEED_ADMIN_PASSWORD == "ChangeMe123!":
        print("\n  ⚠  Default admin password in use ('ChangeMe123!'). "
              "Change it after first login, or set SEED_ADMIN_PASSWORD before seeding.")


if __name__ == "__main__":
    main()
