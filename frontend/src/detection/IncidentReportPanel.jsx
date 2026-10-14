// Incident report panel for the Detection Detail screen (task 3.4, UC 4.4).
//
// Owns everything about the AI report: generating it, showing the four fixed
// sections, the Export PDF / Copy / Regenerate actions, and the Report History
// tab. The parent page owns the detection itself.
//
// Two behaviours are load-bearing and easy to lose in a refactor:
//   * storage is insert-only server-side, so Regenerate ADDS to history and
//     the newest report is simply the one on top — nothing is overwritten;
//   * a failed generation (timeout, API error, incomplete report) does not
//     consume the 10/hour quota, so its error state offers Retry, while a
//     429 does not.
import {
  forwardRef, useCallback, useEffect, useImperativeHandle, useState,
} from "react";
import {
  describeReportError, downloadReportPdf, generateReport, reportHistory,
} from "../api/reports";
import {
  IconCopy, IconDownload, IconHistory, IconRefresh, IconSparkle,
} from "../components/icons";
import { useAuth } from "../context/AuthContext";

const SECTIONS = [
  "Executive Summary",
  "Threat Details",
  "Risk Assessment",
  "Recommended Actions",
];

function when(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

/** Sections come pre-split from the API; fall back to raw text if a legacy
    row ever fails to split so the panel still shows something useful. */
function sectionsOf(report) {
  const s = report?.sections || {};
  const present = SECTIONS.filter((t) => s[t]);
  if (present.length === SECTIONS.length) return { ordered: SECTIONS, map: s };
  return { ordered: [], map: {}, raw: report?.report_text || "" };
}

/* forwardRef so the page header can own the Figure 7 "Generate Incident
   Report" action while the panel keeps all the report state. */
const IncidentReportPanel = forwardRef(function IncidentReportPanel(
  { detectionId, onStatus }, ref,
) {
  // VIEWER may read existing reports and export the PDF, but not generate a
  // new one: that writes a row and spends OpenAI quota (Sections 2.1, 2.6).
  const { canWrite } = useAuth();
  const [history, setHistory] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [tab, setTab] = useState("report");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [toast, setToast] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await reportHistory(detectionId);
      setHistory(data.items || []);
      setSelectedId((prev) => prev || data.items?.[0]?.report_id || null);
    } catch (err) {
      setError(describeReportError(err));
    } finally {
      setLoading(false);
    }
  }, [detectionId]);

  useEffect(() => { load(); }, [load]);

  // Keep the page header's action label and disabled state in sync.
  useEffect(() => {
    onStatus?.({ count: history.length, busy, loading });
  }, [history.length, busy, loading, onStatus]);

  // Auto-clear the transient confirmation, but never the error state —
  // errors stay until the admin acts on them.
  useEffect(() => {
    if (!toast) return undefined;
    const t = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(t);
  }, [toast]);

  const selected =
    history.find((r) => r.report_id === selectedId) || history[0] || null;
  const isLatest = selected && history[0] && selected.report_id === history[0].report_id;

  async function onGenerate() {
    setBusy(true);
    setError(null);
    try {
      const created = await generateReport(detectionId);
      setHistory((prev) => [created, ...prev]);
      setSelectedId(created.report_id);
      setTab("report");
      setToast(history.length ? "New report generated." : "Report generated.");
    } catch (err) {
      setError(describeReportError(err));
    } finally {
      setBusy(false);
    }
  }

  async function onExport() {
    if (!selected) return;
    setError(null);
    try {
      await downloadReportPdf(selected.report_id);
      setToast("PDF downloaded.");
    } catch (err) {
      setError(describeReportError(err));
    }
  }

  async function onCopy() {
    if (!selected) return;
    try {
      await navigator.clipboard.writeText(selected.report_text);
      setToast("Report copied to clipboard.");
    } catch {
      setError({
        kind: "clipboard",
        retryable: false,
        message: "Your browser blocked clipboard access. Select the text and copy manually.",
      });
    }
  }

  useImperativeHandle(ref, () => ({ generate: onGenerate }), [detectionId, history.length]);

  if (loading) {
    return (
      <div className="card dd-report">
        <div className="dd-rhead"><h3>Incident Report</h3></div>
        <div className="dd-skel" /><div className="dd-skel" /><div className="dd-skel short" />
      </div>
    );
  }

  return (
    <div className="card dd-report">
      <div className="dd-rhead">
        <h3>Incident Report</h3>
        {history.length > 0 && (
          <div className="dd-tabs" role="tablist">
            <button
              role="tab" aria-selected={tab === "report"}
              className={tab === "report" ? "on" : ""}
              onClick={() => setTab("report")}
            >
              Report
            </button>
            <button
              role="tab" aria-selected={tab === "history"}
              className={tab === "history" ? "on" : ""}
              onClick={() => setTab("history")}
            >
              <IconHistory /> History <span className="dd-count">{history.length}</span>
            </button>
          </div>
        )}
      </div>

      {error && (
        <div className="dd-banner bad" role="alert">
          <span>{error.message}</span>
          {canWrite && error.retryable && (
            <button className="b b-line sm" onClick={onGenerate} disabled={busy}>
              Retry
            </button>
          )}
        </div>
      )}
      {toast && <div className="dd-banner ok" role="status">{toast}</div>}

      {history.length === 0 && (
        <div className="dd-empty">
          <p>
            No incident report yet. Generating one sends detection metadata —
            never raw log lines — to the AI service and writes a plain-English
            report in four sections.
          </p>
          {canWrite && (
            <button className="b b-primary" onClick={onGenerate} disabled={busy}>
              <IconSparkle /> {busy ? "Generating…" : "Generate Incident Report"}
            </button>
          )}
        </div>
      )}

      {history.length > 0 && tab === "report" && selected && (
        <>
          <div className="dd-ractions">
            <button className="b b-line sm" onClick={onExport}>
              <IconDownload /> Export PDF
            </button>
            <button className="b b-line sm" onClick={onCopy}>
              <IconCopy /> Copy
            </button>
            {canWrite && (
              <button className="b b-line sm" onClick={onGenerate} disabled={busy}>
                <IconRefresh /> {busy ? "Regenerating…" : "Regenerate"}
              </button>
            )}
            <span className="dd-rmeta">
              {isLatest ? "Latest" : "Earlier version"} · {when(selected.created_at)} ·{" "}
              <span className="mono">{selected.model_used}</span>
            </span>
          </div>

          <ReportBody report={selected} />
        </>
      )}

      {history.length > 0 && tab === "history" && (
        <ul className="dd-history">
          {history.map((r, i) => (
            <li key={r.report_id}>
              <button
                className={r.report_id === selectedId ? "on" : ""}
                onClick={() => { setSelectedId(r.report_id); setTab("report"); }}
              >
                <span className="dd-hver">{i === 0 ? "Latest" : `v${history.length - i}`}</span>
                <span className="dd-hwhen">{when(r.created_at)}</span>
                <span className="dd-hmodel mono">{r.model_used}</span>
                {r.token_count != null && (
                  <span className="dd-htok">{r.token_count} tokens</span>
                )}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
});

export default IncidentReportPanel;

function ReportBody({ report }) {
  const { ordered, map, raw } = sectionsOf(report);
  if (!ordered.length) {
    return <div className="dd-section"><p>{raw}</p></div>;
  }
  return (
    <div className="dd-sections">
      {ordered.map((title) => (
        <section key={title} className="dd-section">
          <h4>{title}</h4>
          {map[title].split(/\n\s*\n/).map((para, i) => (
            <p key={i}>{para.replace(/\n/g, " ")}</p>
          ))}
        </section>
      ))}
      <p className="dd-provenance">
        Written by {report.model_used} from detection metadata only. Raw log
        lines were never sent. Verify against the detection data before acting
        on it or sharing it externally.
      </p>
    </div>
  );
}
