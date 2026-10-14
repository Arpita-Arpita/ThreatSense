/**
 * Incident Reports — the top-level report history (Section 2.1).
 *
 * Section 2.1 lists seven navigation destinations; Incident Reports was the
 * one with no route behind it. Report history already existed, but only per
 * detection (GET /api/detections/{id}/reports), reachable from the detection
 * detail screen — so there was no way to answer "what has been generated
 * across all my detections", which is exactly what a navigation destination
 * called Incident Reports should answer.
 *
 * Deliberately a navigation and history screen only. Generation stays on the
 * detection detail screen (IncidentReportPanel), so the rate limit, the 502
 * retry semantics and the regenerate-inserts-a-new-row behaviour all keep one
 * implementation. This page opens a report in the context of its detection
 * rather than duplicating the renderer.
 *
 * Reuses the dt-* table styles from the Detections screen so it matches the
 * rest of the interface without adding CSS.
 */
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import AppShell from "../components/AppShell";
import { IconDownload, IconHistory, IconRefresh } from "../components/icons";
import {
  describeReportError, downloadReportPdf, listAllReports,
} from "../api/reports";

const PAGE = 25;

function label(v = "") {
  return v.replace(/_/g, " ").toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());
}

function when(ts) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString(undefined, {
    day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit",
  });
}

export default function IncidentReports() {
  const navigate = useNavigate();

  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await listAllReports({ limit: PAGE, offset: page * PAGE });
      setRows(data.items || []);
      setTotal(data.total ?? (data.items || []).length);
    } catch (e) {
      setError(describeReportError(e).message);
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => { load(); }, [load]);

  async function onExport(e, reportId) {
    e.stopPropagation();                       // don't open the detection
    setBusyId(reportId);
    setError("");
    try {
      await downloadReportPdf(reportId);
    } catch (err) {
      setError(describeReportError(err).message);
    } finally {
      setBusyId(null);
    }
  }

  const lastPage = Math.max(0, Math.ceil(total / PAGE) - 1);
  const from = total === 0 ? 0 : page * PAGE + 1;
  const to = Math.min(total, page * PAGE + rows.length);

  return (
    <AppShell
      title="Incident Reports"
      subtitle="Every AI-assisted report generated from your detections"
    >
      <div className="card dt-card">
        <div className="dt-bar">
          <div className="dt-filters">
            <span className="dt-page">
              {total === 0
                ? "No reports generated yet"
                : `${total} report${total === 1 ? "" : "s"} in history`}
            </span>
          </div>
          <button className="b b-line sm" onClick={load} disabled={loading}>
            <IconRefresh /> {loading ? "Loading…" : "Refresh"}
          </button>
        </div>

        {error && <div className="dt-error" role="alert">{error}</div>}

        <div className="dt-wrap">
          <table className="dt">
            <thead>
              <tr>
                <th>Generated</th>
                <th>Threat</th>
                <th>Severity</th>
                <th>Source</th>
                <th>Detection time</th>
                <th>Model</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {loading && rows.length === 0 && (
                <tr><td colSpan={7} className="dt-empty">Loading reports…</td></tr>
              )}
              {!loading && rows.length === 0 && (
                <tr><td colSpan={7} className="dt-empty">
                  <IconHistory /> No incident reports yet. Open a detection and
                  choose Generate Incident Report to create one.
                </td></tr>
              )}
              {rows.map((r) => (
                <tr key={r.report_id}
                    onClick={() => navigate(`/detections/${r.detection_id}`)}
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") navigate(`/detections/${r.detection_id}`);
                    }}>
                  <td className="dt-time">{when(r.created_at)}</td>
                  <td className="dt-threat">{label(r.threat_type)}</td>
                  <td>
                    <span className={`sev sev-${(r.severity || "").toLowerCase()}`}>
                      {label(r.severity)}
                    </span>
                  </td>
                  <td className="mono">{r.source_ip || "—"}</td>
                  <td className="dt-time">{when(r.detection_timestamp)}</td>
                  <td className="mono">{r.model_used}</td>
                  <td className="dt-act">
                    <button className="b b-line sm"
                            onClick={(e) => onExport(e, r.report_id)}
                            disabled={busyId === r.report_id}>
                      <IconDownload /> {busyId === r.report_id ? "…" : "PDF"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="dt-foot">
          <span>{total === 0 ? "No reports" : `Showing ${from}–${to} of ${total}`}</span>
          <div className="dt-pages">
            <button className="b b-line sm" disabled={page === 0}
                    onClick={() => setPage(page - 1)}>← Previous</button>
            <span className="dt-page">Page {page + 1} of {lastPage + 1}</span>
            <button className="b b-line sm" disabled={page >= lastPage}
                    onClick={() => setPage(page + 1)}>Next →</button>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
