"""Server-side PDF export of an incident report (task 3.3, UC 4.4 / Figure 7).

WeasyPrint renders HTML + CSS, so the export inherits the dashboard's palette
and type from a template that mirrors frontend/src/styles/theme.css instead of
a second, hand-coded visual language. Same template pattern as the Phase 2
alert email (services/alerting/renderer.py): brace-safe {token} substitution,
no template engine dependency.

Two deliberate constraints:

  * The renderer is offline. _no_network() is installed as WeasyPrint's URL
    fetcher, so a stylesheet, image or font reference that ever appears in the
    template — or is smuggled in through report text — cannot cause an
    outbound request from the API host.
  * Report text is escaped before it becomes markup. generator.sanitise()
    already strips tags at write time; escaping again here means a report row
    written before that guard existed still cannot inject markup into the PDF.
"""
from __future__ import annotations

import html
import logging
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from ...models import Detection, IncidentReport, SeverityLevel
from .generator import ReportValidationError, split_sections
from .llm_client import REPORT_SECTIONS

logger = logging.getLogger("threatsense.reporting.pdf")

_TEMPLATE = Path(__file__).parent / "templates" / "incident_report.html"

# Dashboard severity palette — frontend/src/styles/theme.css (--crit/--high/
# --med/--low). NOTE: alerting/renderer.py uses a different set for email;
# see the task 3.3 note in the README.
_COLOURS = {
    SeverityLevel.LOW: "#2f80ed",
    SeverityLevel.MEDIUM: "#ffb020",
    SeverityLevel.HIGH: "#ff7a45",
    SeverityLevel.CRITICAL: "#f5365c",
}
_WASHES = {
    SeverityLevel.LOW: "#eaf2fd",
    SeverityLevel.MEDIUM: "#fff6e6",
    SeverityLevel.HIGH: "#fff0e9",
    SeverityLevel.CRITICAL: "#feebef",
}

_THREAT_LABELS = {
    "PORT_SCAN": "Port scan",
    "DDOS": "DDoS activity",
    "C2": "Command-and-control traffic",
    "BRUTE_FORCE": "Brute-force attempt",
    "UNKNOWN_ANOMALY": "Unclassified anomaly",
}

# Long-form names for the model_type codes stored on a detection, so the
# export does not read "IF IF_v1.0" to a non-technical audience.
_MODEL_LABELS = {"IF": "Isolation Forest", "ISOLATION_FOREST": "Isolation Forest"}


def model_label(model_type: str) -> str:
    """Human-readable model name. Unknown codes degrade to title case rather
    than shouting SNAKE_CASE at a non-technical reader."""
    code = str(model_type)
    return _MODEL_LABELS.get(code, code.replace("_", " ").title())

_BULLET_RE = re.compile(r"^\s*(?:[-*\u2022]|\d+[.)])\s+(.*)$")
_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")


class PDFUnavailable(RuntimeError):
    """WeasyPrint could not be imported or its system libraries are missing."""


def _no_network(url: str):
    """URL fetcher that refuses every resource. The template is self-contained."""
    raise ValueError(f"external resources are not permitted in report PDFs: {url}")


@lru_cache(maxsize=1)
def _template() -> str:
    return _TEMPLATE.read_text(encoding="utf-8")


def _value(enum_or_str) -> str:
    return getattr(enum_or_str, "value", str(enum_or_str))


def threat_label(threat_type) -> str:
    key = _value(threat_type)
    return _THREAT_LABELS.get(key, key.replace("_", " ").title())


def _fill(template: str, values: dict[str, str]) -> str:
    """Literal {token} substitution — brace-safe, so the CSS block is untouched."""
    for key, value in values.items():
        template = template.replace("{" + key + "}", str(value))
    return template


def _inline(text: str) -> str:
    """Escape one line, then re-admit **bold** only."""
    escaped = html.escape(text, quote=False)
    return _BOLD_RE.sub(r"<strong>\1</strong>", escaped)


def _body_html(body: str) -> str:
    """Section body → paragraphs and lists.

    Models drift between prose and bullets for Recommended Actions, so both
    render properly rather than collapsing a list into one run-on paragraph.
    """
    out: list[str] = []
    bullets: list[str] = []

    def flush() -> None:
        if bullets:
            items = "".join(f"<li>{_inline(b)}</li>" for b in bullets)
            out.append(f"<ul>{items}</ul>")
            bullets.clear()

    for block in re.split(r"\n\s*\n", body.strip()):
        lines = [ln for ln in block.splitlines() if ln.strip()]
        if not lines:
            continue
        if all(_BULLET_RE.match(ln) for ln in lines):
            bullets.extend(_BULLET_RE.match(ln).group(1) for ln in lines)
            flush()
            continue
        flush()
        out.append("<p>" + _inline(" ".join(ln.strip() for ln in lines)) + "</p>")
    flush()
    return "\n".join(out)


def _sections_html(report: IncidentReport) -> str:
    """The four fixed sections, in order. Falls back to a single block if a
    stored row somehow fails to split, so export can never 500 on old data."""
    try:
        sections = split_sections(report.report_text)
    except ReportValidationError:
        logger.warning("report %s does not split into sections; exporting raw",
                       report.report_id)
        return "<section>" + _body_html(report.report_text) + "</section>"

    parts = []
    for title in REPORT_SECTIONS:
        parts.append(
            f"<section><h2>{html.escape(title)}</h2>\n"
            f"{_body_html(sections[title])}</section>"
        )
    return "\n".join(parts)


def _fmt(moment: datetime | None) -> str:
    if moment is None:
        return "unknown"
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC")


def build_html(report: IncidentReport, detection: Detection,
               generated_by: str = "ThreatSense administrator") -> str:
    """Assemble the full HTML document. Separated from rendering so the markup
    is unit-testable without invoking WeasyPrint."""
    severity = detection.severity
    if not isinstance(severity, SeverityLevel):
        severity = SeverityLevel(_value(severity))

    return _fill(_template(), {
        "report_id": str(report.report_id),
        "report_short": str(report.report_id)[:8],
        "detection_id": str(detection.detection_id),
        "severity": _value(severity),
        "severity_colour": _COLOURS.get(severity, "#515a72"),
        "severity_wash": _WASHES.get(severity, "#f4f6fc"),
        "threat_label": html.escape(threat_label(detection.threat_type)),
        "threat_type": _value(detection.threat_type),
        "anomaly_score": f"{float(detection.anomaly_score):.2f}",
        "source_ip": html.escape(str(detection.source_ip)),
        "destination_ip": html.escape(str(detection.destination_ip)),
        "detected_at": _fmt(detection.timestamp or detection.created_at),
        "ack_status": "Acknowledged" if detection.is_acknowledged else "Open — not yet acknowledged",
        "model_label": html.escape(
            f"{model_label(detection.model_type)} ({detection.model_version})"),
        "model_used": html.escape(str(report.model_used)),
        "generated_at": _fmt(report.created_at),
        "generated_by": html.escape(generated_by),
        "sections_html": _sections_html(report),
    })


def pdf_filename(report: IncidentReport, detection: Detection) -> str:
    """Stable, sortable, safe for a Content-Disposition header."""
    created = report.created_at or datetime.now(timezone.utc)
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    stamp = created.astimezone(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return (f"threatsense-incident-report-{_value(detection.threat_type).lower()}"
            f"-{str(detection.detection_id)[:8]}-{stamp}.pdf")


def render_report_pdf(report: IncidentReport, detection: Detection,
                      generated_by: str = "ThreatSense administrator") -> bytes:
    """Render one stored report to PDF bytes.

    Raises PDFUnavailable when WeasyPrint cannot load — on macOS that is
    almost always the Homebrew dylib path, not a broken install. See README.
    """
    try:
        from weasyprint import HTML
    except (ImportError, OSError) as exc:  # OSError = missing pango/cairo libs
        raise PDFUnavailable(
            "PDF export needs WeasyPrint and its system libraries. "
            "Install with: brew install pango && pip install weasyprint, and on "
            "Apple Silicon export DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib. "
            f"Underlying error: {type(exc).__name__}: {exc}"
        ) from exc

    document = build_html(report, detection, generated_by)
    pdf = HTML(string=document, base_url=None, url_fetcher=_no_network).write_pdf()
    logger.info("rendered PDF for report %s (%d bytes)", report.report_id, len(pdf))
    return pdf
