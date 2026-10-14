"""Incident report generation (task 3.2, Section 2.6, Use Case 4.4, Algorithm 5).

Flow: fetch detection → aggregate related-log summary → build minimum-metadata
prompt → LLM call (15s timeout) → sanitise → validate the four fixed sections →
INSERT into incident_reports → audit.

Storage is immutable by construction: this module only ever INSERTs. Regenerate
calls generate_report() again and produces a new row; nothing here can UPDATE
or DELETE an incident_reports row.

Audit contract (Section 2.6): success writes REPORT_GENERATED, every failure —
transport or validation — writes REPORT_GENERATION_FAILED. Transport failures
raise LLMError (retryable, never counted against the rate limit); content that
fails validation raises ReportValidationError (also uncounted: the admin got
nothing usable, so it would be unfair to charge their quota for it).
"""
from __future__ import annotations

import logging
import re

from sqlalchemy.orm import Session

from ...models import Administrator, AuditAction, AuditLog, Detection, IncidentReport
from .llm_client import LLMClient, LLMError, REPORT_SECTIONS, get_llm_client
from .prompt import SYSTEM_PROMPT, build_user_prompt, summarise_related_logs

logger = logging.getLogger("threatsense.reporting.generator")

MAX_REPORT_CHARS = 20_000     # hard ceiling on stored report text
MIN_SECTION_CHARS = 20        # a section shorter than this is not a report


class ReportValidationError(Exception):
    """The LLM answered, but not with a complete, usable four-section report."""

    kind = "validation"
    retryable = True


# --- sanitisation -----------------------------------------------------------

_TAG_RE = re.compile(r"<[^>\n]{0,200}>")                    # strip HTML/script tags
_FENCE_RE = re.compile(r"^```[a-zA-Z0-9_-]*\s*$", re.M)     # ``` fence lines
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # control chars (keep \n \t)
# Heading variants models produce for the fixed titles: "## Executive Summary",
# "**Executive Summary**", "1. Executive Summary:", "EXECUTIVE SUMMARY" …
_HEADING_VARIANT = (
    r"^\s{{0,3}}(?:#{{1,6}}\s*)?(?:\*\*)?(?:\d+[.)]\s*)?({title})\s*(?:\*\*)?\s*:?\s*$"
)


def sanitise(text: str) -> str:
    """Normalise a completion into the canonical stored form.

    Removes markup that must never reach the dashboard or the PDF (tags, code
    fences, control characters) and rewrites any recognisable variant of the
    four fixed headings to the canonical `## Title` line, so parsing and
    validation don't depend on the model's markdown mood.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CTRL_RE.sub("", text)
    text = _FENCE_RE.sub("", text)
    text = _TAG_RE.sub("", text)
    for title in REPORT_SECTIONS:
        pattern = re.compile(_HEADING_VARIANT.format(title=re.escape(title)),
                             re.M | re.IGNORECASE)
        text = pattern.sub(f"## {title}", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text[:MAX_REPORT_CHARS]


def split_sections(text: str) -> dict[str, str]:
    """Canonical text → {title: body}. Raises if any section is missing/empty."""
    positions = []
    for title in REPORT_SECTIONS:
        match = re.search(rf"^## {re.escape(title)}$", text, re.M)
        if not match:
            raise ReportValidationError(f"missing section: {title}")
        positions.append((match.start(), match.end(), title))
    if [p[2] for p in sorted(positions)] != list(REPORT_SECTIONS):
        raise ReportValidationError("sections out of order")

    positions.sort()
    sections: dict[str, str] = {}
    for i, (_, end, title) in enumerate(positions):
        stop = positions[i + 1][0] if i + 1 < len(positions) else len(text)
        body = text[end:stop].strip()
        if len(body) < MIN_SECTION_CHARS:
            raise ReportValidationError(f"section too short: {title}")
        sections[title] = body
    return sections


# --- audit ------------------------------------------------------------------

def _audit(db: Session, admin_id, action: AuditAction, detail: str) -> None:
    db.add(AuditLog(admin_id=admin_id, action=action, details=detail[:2000]))


# --- entry point ------------------------------------------------------------

def generate_report(
    db: Session,
    detection: Detection,
    admin: Administrator,
    client: LLMClient | None = None,
) -> IncidentReport:
    """Generate + store one immutable report. Commits on success and failure
    (the failure commit persists the REPORT_GENERATION_FAILED audit row).

    Rate limiting is the router's job (middleware/rate_limit.py) and happens
    before this function runs; because failures raise before any
    incident_reports row exists, a failed attempt can never consume quota.
    """
    client = client or get_llm_client()
    log_summary = summarise_related_logs(db, detection)
    user_prompt = build_user_prompt(detection, log_summary)

    try:
        result = client.complete(SYSTEM_PROMPT, user_prompt)
        text = sanitise(result.text)
        split_sections(text)  # validation gate — raises ReportValidationError
    except (LLMError, ReportValidationError) as exc:
        kind = getattr(exc, "kind", "api_error")
        _audit(db, admin.admin_id, AuditAction.REPORT_GENERATION_FAILED,
               f"detection {detection.detection_id}: {kind} via {client.name}: {exc}")
        db.commit()
        logger.warning("report generation failed (%s) for detection %s",
                       kind, detection.detection_id)
        raise

    report = IncidentReport(
        detection_id=detection.detection_id,
        generated_by=admin.admin_id,
        report_text=text,
        model_used=result.model[:30],
        token_count=result.token_count,
    )
    db.add(report)
    db.flush()  # populate report_id for the audit detail
    _audit(db, admin.admin_id, AuditAction.REPORT_GENERATED,
           f"report {report.report_id} for detection {detection.detection_id} "
           f"via {report.model_used}")
    db.commit()
    db.refresh(report)
    logger.info("report %s stored for detection %s", report.report_id,
                detection.detection_id)
    return report
