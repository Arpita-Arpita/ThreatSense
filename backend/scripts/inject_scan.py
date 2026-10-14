"""Inject one port-scan window of unanalysed logs for demoing the engine (task 1.12).

    python scripts/inject_scan.py        # adds 120 scan logs under the first source

Then run the engine (python -m app.services.detection.engine) and a CRITICAL
detection should appear for src 10.0.9.5.
"""
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select

from app.database import SessionLocal
from app.models import DataSource, NetworkLog

with SessionLocal() as s:
    src = s.scalar(select(DataSource))
    if src is None:
        raise SystemExit("No data source found — run db/seed.py first.")
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    for i in range(120):
        s.add(NetworkLog(
            source_id=src.source_id, batch_id=uuid.uuid4(),
            src_ip="10.0.9.5", dst_ip="192.168.1.10", dst_port=1 + i,
            protocol="TCP", packet_size=44, flags="SYN",
            timestamp=now.replace(second=i % 60), is_analysed=False,
        ))
    s.commit()
    print(f"Injected 120 port-scan logs under source '{src.name}' ({src.source_id}).")
