"""Data Sources CRUD + file-upload ingestion (task 1.8, UC 4.2).

Sources are admin-scoped: an admin only sees and manages their own. The upload
endpoint attaches an uploaded log file to an EXISTING source (records inherit
its source_id). PCAP is a planned enhancement — text/syslog files work now.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..core.source_status import effective_status
from ..middleware.rbac import require_operator, require_read
from ..models import (
    Administrator, AuditAction, AuditLog, DataSource, NetworkLog, SourceStatus,
)
from ..schemas.source import SourceCreate, SourceOut, SourceUpdate, UploadResult
from ..services.ingestion.parsers import parse_lines
from ..services.ingestion.parsers.base import fingerprint

router = APIRouter(prefix="/api/sources", tags=["sources"])

_BATCH = 500

# uq_data_sources_admin_name. Audit entries record the source NAME, not the id,
# so duplicates make the audit trail ambiguous as well as the UI.
_DUPLICATE_NAME = ("You already have a source named '{}'. "
                   "Source names must be unique so they can be told apart in "
                   "the sources table and in the audit log.")


def _out(src: DataSource) -> SourceOut:
    """Serialise a source with its EFFECTIVE status (Use Case 4.2).

    The stored status column only ever records the last write. The 60-second
    INACTIVE transition is applied here, at read time, so every screen that
    lists or fetches a source agrees. See core/source_status.py.
    """
    out = SourceOut.model_validate(src)
    out.status = effective_status(src.status, src.last_received,
                                  created_at=src.created_at)
    return out


def _owned(db: Session, source_id: uuid.UUID, admin: Administrator) -> DataSource:
    src = db.get(DataSource, source_id)
    if src is None or src.admin_id != admin.admin_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source not found")
    return src


@router.post("", response_model=SourceOut, status_code=status.HTTP_201_CREATED)
def create_source(payload: SourceCreate, db: Session = Depends(get_db),
                  admin: Administrator = Depends(require_operator)) -> SourceOut:
    src = DataSource(admin_id=admin.admin_id, **payload.model_dump())
    db.add(src)
    db.add(AuditLog(admin_id=admin.admin_id, action=AuditAction.CONFIG_CHANGE,
                    details=f"create source '{payload.name}'"))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, _DUPLICATE_NAME.format(payload.name))
    db.refresh(src)
    return _out(src)


@router.get("", response_model=list[SourceOut])
def list_sources(db: Session = Depends(get_db),
                 admin: Administrator = Depends(require_read)) -> list[SourceOut]:
    rows = db.scalars(
        select(DataSource).where(DataSource.admin_id == admin.admin_id)
        .order_by(DataSource.created_at.desc())
    ).all()
    return [_out(src) for src in rows]


@router.get("/{source_id}", response_model=SourceOut)
def get_source(source_id: uuid.UUID, db: Session = Depends(get_db),
               admin: Administrator = Depends(require_read)) -> SourceOut:
    return _out(_owned(db, source_id, admin))


@router.patch("/{source_id}", response_model=SourceOut)
def update_source(source_id: uuid.UUID, payload: SourceUpdate,
                  db: Session = Depends(get_db),
                  admin: Administrator = Depends(require_operator)) -> SourceOut:
    src = _owned(db, source_id, admin)
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(src, key, value)
    db.add(AuditLog(admin_id=admin.admin_id, action=AuditAction.CONFIG_CHANGE,
                    details=f"update source '{src.name}'"))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, _DUPLICATE_NAME.format(src.name))
    db.refresh(src)
    return _out(src)


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_source(source_id: uuid.UUID, db: Session = Depends(get_db),
                  admin: Administrator = Depends(require_operator)) -> None:
    src = _owned(db, source_id, admin)
    name = src.name
    try:
        db.delete(src)  # network_logs cascade; detections (RESTRICT) block deletion
        db.add(AuditLog(admin_id=admin.admin_id, action=AuditAction.CONFIG_CHANGE,
                        details=f"delete source '{name}'"))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Source has linked detections and cannot be deleted")


@router.post("/{source_id}/upload", response_model=UploadResult)
async def upload_logs(source_id: uuid.UUID, file: UploadFile = File(...),
                      db: Session = Depends(get_db),
                      admin: Administrator = Depends(require_operator)) -> UploadResult:
    src = _owned(db, source_id, admin)
    content = await file.read()
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File too large")

    name = (file.filename or "").lower()
    if name.endswith((".pcap", ".pcapng")):
        # Planned enhancement — PCAP is binary, not line-based text.
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED,
                            "PCAP parsing is a planned enhancement; upload a text-based "
                            "syslog/log file for now")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "File is not valid UTF-8 text (binary formats like PCAP are "
                            "not yet supported)")

    records, skipped = parse_lines(text)

    # Section 2.2 puts deduplication under "Preprocessing (all formats)", not
    # under the listener alone, so the upload path applies the same rule with
    # the same fingerprint the listener uses — one definition, so the two
    # cannot drift. Every row here shares one source_id, and the whole batch
    # is one file, so the batch IS the dedup window.
    seen: set = set()
    deduped = []
    for r in records:
        r["source_id"] = src.source_id
        fp = fingerprint(r)
        if fp is not None:
            if fp in seen:
                continue
            seen.add(fp)
        deduped.append(r)
    duplicates = len(records) - len(deduped)
    records = deduped

    batch_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    rows = [
        NetworkLog(
            source_id=src.source_id, batch_id=batch_id,
            src_ip=r["src_ip"], dst_ip=r["dst_ip"],
            src_port=r["src_port"], dst_port=r["dst_port"],
            protocol=r["protocol"], packet_size=r["packet_size"],
            flags=r["flags"], connection_outcome=r["connection_outcome"],
            syslog_severity=r["syslog_severity"], raw_message=r["raw_message"],
            timestamp=r.get("event_time") or now, is_analysed=False,
        )
        for r in records
    ]
    for i in range(0, len(rows), _BATCH):
        db.add_all(rows[i:i + _BATCH])
        db.flush()
    if rows:
        src.last_received = now
        src.status = SourceStatus.ACTIVE
    db.add(AuditLog(admin_id=admin.admin_id, action=AuditAction.CONFIG_CHANGE,
                    details=f"upload {len(rows)} records to '{src.name}'"))
    db.commit()
    # Duplicates count as skipped: from the caller's point of view they are
    # lines that did not become rows, same as unparseable ones.
    return UploadResult(source_id=src.source_id, batch_id=batch_id,
                        parsed=len(rows), skipped=skipped + duplicates)
