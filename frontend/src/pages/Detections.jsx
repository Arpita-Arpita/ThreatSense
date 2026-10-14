/**
 * Detections — the full history table (Section 2.4).
 *
 * This route was a placeholder reading "Full detections table — Task 1.17",
 * which meant the sidebar's second item led nowhere. The backend already
 * supported severity, threat-type, acknowledgement and source filtering plus
 * limit/offset paging, so this page is the missing front end for an API that
 * was already complete.
 */
import { useCallback, useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import AppShell from "../components/AppShell";
import { IconCheck, IconRefresh, IconShield } from "../components/icons";
import { acknowledgeDetection, listDetections } from "../api/detections";
import { useAuth } from "../context/AuthContext";

const PAGE = 25;

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const THREATS = ["PORT_SCAN", "DDOS", "C2_BEACONING", "BRUTE_FORCE", "UNKNOWN_ANOMALY"];

function label(v = "") {
  return v.replace(/_/g, " ").toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());
}

function when(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return d.toLocaleString(undefined, {
    day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit",
  });
}

export default function Detections() {
  const navigate = useNavigate();
  const { canWrite } = useAuth();
  const [params, setParams] = useSearchParams();

  const severity = params.get("severity") || "";
  const threat = params.get("threat_type") || "";
  const ack = params.get("acknowledged") || "";
  const q = (params.get("q") || "").trim().toLowerCase();
  const page = Math.max(0, Number(params.get("page") || 0));

  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState(null);

  // The search now queries the API, so the box is debounced rather than firing
  // a request on every keystroke. It seeds from the URL so a search arriving
  // from the header box shows its term.
  const [draft, setDraft] = useState(q);
  useEffect(() => { setDraft(q); }, [q]);
  useEffect(() => {
    const t = setTimeout(() => {
      if (draft.trim().toLowerCase() !== q) setParam("q", draft.trim());
    }, 300);
    return () => clearTimeout(t);
  }, [draft]);          // eslint-disable-line react-hooks/exhaustive-deps

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await listDetections({
        severity: severity || undefined,
        threat_type: threat || undefined,
        acknowledged: ack === "" ? undefined : ack === "yes",
        q: q || undefined,
        limit: PAGE,
        offset: page * PAGE,
      });
      setRows(data.items || data.detections || []);
      setTotal(data.total ?? (data.items || []).length);
    } catch (e) {
      setError(e?.message || "Could not load detections.");
    } finally {
      setLoading(false);
    }
  }, [severity, threat, ack, q, page]);

  useEffect(() => { load(); }, [load]);

  // Search is applied by the API across the whole detection history, so the
  // total and page count describe the filtered set. Filtering here instead
  // would search only the page already loaded and could report no match while
  // one sat on the next page.
  const visible = rows;

  function setParam(key, value) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value); else next.delete(key);
    if (key !== "page") next.delete("page");   // any filter change resets paging
    setParams(next, { replace: true });
  }

  async function onAck(e, id) {
    e.stopPropagation();                        // don't open the row
    setBusyId(id);
    try {
      await acknowledgeDetection(id);
      await load();
    } catch (err) {
      setError(err?.message || "Could not acknowledge that detection.");
    } finally {
      setBusyId(null);
    }
  }

  const lastPage = Math.max(0, Math.ceil(total / PAGE) - 1);
  const from = total === 0 ? 0 : page * PAGE + 1;
  const to = Math.min(total, page * PAGE + rows.length);

  return (
    <AppShell title="Detections" subtitle="Every anomaly the engine has recorded">
      <div className="card dt-card">
        <div className="dt-bar">
          <div className="dt-filters">
            <input
              className="input dt-search"
              type="search"
              placeholder="Search all detections by IP, threat or severity…"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              aria-label="Search detections"
            />
            <select className="input dt-select" value={severity}
                    onChange={(e) => setParam("severity", e.target.value)}
                    aria-label="Filter by severity">
              <option value="">All severities</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{label(s)}</option>)}
            </select>
            <select className="input dt-select" value={threat}
                    onChange={(e) => setParam("threat_type", e.target.value)}
                    aria-label="Filter by threat type">
              <option value="">All threat types</option>
              {THREATS.map((t) => <option key={t} value={t}>{label(t)}</option>)}
            </select>
            <select className="input dt-select" value={ack}
                    onChange={(e) => setParam("acknowledged", e.target.value)}
                    aria-label="Filter by acknowledgement">
              <option value="">Any status</option>
              <option value="no">Unacknowledged</option>
              <option value="yes">Acknowledged</option>
            </select>
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
                <th>Time</th>
                <th>Severity</th>
                <th>Threat</th>
                <th>Source</th>
                <th>Destination</th>
                <th className="num">Score</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {loading && rows.length === 0 && (
                <tr><td colSpan={8} className="dt-empty">Loading detections…</td></tr>
              )}
              {!loading && visible.length === 0 && (
                <tr><td colSpan={8} className="dt-empty">
                  <IconShield /> No detections match these filters.
                </td></tr>
              )}
              {visible.map((d) => (
                <tr key={d.detection_id}
                    onClick={() => navigate(`/detections/${d.detection_id}`)}
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") navigate(`/detections/${d.detection_id}`);
                    }}>
                  <td className="dt-time">{when(d.detected_at || d.window_start)}</td>
                  <td>
                    <span className={`sev sev-${(d.severity || "").toLowerCase()}`}>
                      {label(d.severity)}
                    </span>
                  </td>
                  <td className="dt-threat">{label(d.threat_type)}</td>
                  <td className="mono">{d.source_ip || "—"}</td>
                  <td className="mono">{d.destination_ip || "—"}</td>
                  <td className="num mono">{Number(d.anomaly_score ?? 0).toFixed(3)}</td>
                  <td>
                    {d.is_acknowledged
                      ? <span className="dt-ack">Acknowledged</span>
                      : <span className="dt-open">Open</span>}
                  </td>
                  <td className="dt-act">
                    {canWrite && !d.is_acknowledged && (
                      <button className="b b-line sm"
                              onClick={(e) => onAck(e, d.detection_id)}
                              disabled={busyId === d.detection_id}>
                        <IconCheck /> {busyId === d.detection_id ? "…" : "Acknowledge"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="dt-foot">
          <span>{total === 0 ? "No detections" : `Showing ${from}–${to} of ${total}`}</span>
          <div className="dt-pages">
            <button className="b b-line sm" disabled={page === 0}
                    onClick={() => setParam("page", String(page - 1))}>← Previous</button>
            <span className="dt-page">Page {page + 1} of {lastPage + 1}</span>
            <button className="b b-line sm" disabled={page >= lastPage}
                    onClick={() => setParam("page", String(page + 1))}>Next →</button>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
