// Detection Detail + Incident Report screen (task 3.4, Figure 7, UC 4.4).
//
// Left column is the detection as the engine recorded it: identity, scoring,
// the traffic behind it, and the raw feature vector. Right column is the AI
// report. The two top-level actions from Figure 7 — Generate Incident Report
// and Acknowledge Alert — sit in the header.
//
// NOTE: element inventory follows the implementation guide's task 3.4 brief;
// the arrangement is inferred and should be reconciled against Figure 7 in
// the proposal before submission.
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import AppShell from "../components/AppShell";
import IncidentReportPanel from "../detection/IncidentReportPanel";
import {
  acknowledgeDetection, detectionTraffic, getDetection,
} from "../api/detections";
import { IconBack, IconCheck, IconSparkle } from "../components/icons";
import { score100, sevClass, sevLabel, threatLabel, timeAgo } from "../lib/format";
import { useAuth } from "../context/AuthContext";

function when(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

/** Protocol counts as proportional bars. Reads faster than a table and needs
    no chart library for what is usually two or three protocols. */
function ProtocolBars({ protocols }) {
  const entries = Object.entries(protocols || {});
  if (!entries.length) return <p className="dd-none">No matching traffic in the window.</p>;
  const total = entries.reduce((sum, [, n]) => sum + n, 0);
  return (
    <div className="dd-protos">
      {entries.map(([proto, n]) => {
        const pct = Math.round((n / total) * 100);
        return (
          <div className="dd-proto" key={proto}>
            <span className="dd-plabel mono">{proto}</span>
            <span className="dd-ptrack"><i style={{ width: `${pct}%` }} /></span>
            <span className="dd-ppct">{pct}% <small>({n})</small></span>
          </div>
        );
      })}
    </div>
  );
}

export default function DetectionDetail() {
  // VIEWER may read the detection and any existing reports, but not
  // acknowledge or generate a new report — the latter also spends OpenAI
  // quota (Section 2.6 rate limit). Section 2.1.
  const { canWrite } = useAuth();
  const { detectionId } = useParams();
  const navigate = useNavigate();
  const [detection, setDetection] = useState(null);
  const [traffic, setTraffic] = useState(null);
  const [error, setError] = useState(null);
  const [acking, setAcking] = useState(false);
  const [reportStatus, setReportStatus] = useState({ count: 0, busy: false, loading: true });
  const reportRef = useRef(null);
  const onStatus = useCallback((s) => setReportStatus(s), []);

  const load = useCallback(async () => {
    try {
      const det = await getDetection(detectionId);
      setDetection(det);
      // Traffic is supplementary — a detection with no surviving logs must
      // still render, so this failure is swallowed rather than fatal.
      try {
        setTraffic(await detectionTraffic(detectionId));
      } catch {
        setTraffic(null);
      }
    } catch (err) {
      setError(err.status === 404
        ? "That detection does not exist, or it belongs to another administrator."
        : err.message);
    }
  }, [detectionId]);

  useEffect(() => { load(); }, [load]);

  async function onAcknowledge() {
    setAcking(true);
    try {
      setDetection(await acknowledgeDetection(detectionId));
    } catch (err) {
      setError(err.message);
    } finally {
      setAcking(false);
    }
  }

  if (error) {
    return (
      <AppShell title="Detection" subtitle="Detail and incident report">
        <div className="card dd-error">
          <p>{error}</p>
          <button className="b b-line" onClick={() => navigate("/")}>Back to dashboard</button>
        </div>
      </AppShell>
    );
  }

  if (!detection) {
    return (
      <AppShell title="Detection" subtitle="Detail and incident report">
        <div className="card"><div className="dd-skel" /><div className="dd-skel" /></div>
      </AppShell>
    );
  }

  const d = detection;
  const fv = d.feature_vector || {};

  return (
    <AppShell
      title={threatLabel(d.threat_type)}
      subtitle={`Detected ${timeAgo(d.timestamp || d.created_at)} · ${d.source_ip} → ${d.destination_ip}`}
    >
      <div className="dd-bar">
        <Link className="b b-line sm" to="/"><IconBack /> Back</Link>
        <span className={`stag ${sevClass(d.severity)}`}>{sevLabel(d.severity)}</span>
        <span className={`stag ${d.is_acknowledged ? "ack" : ""}`}>
          {d.is_acknowledged ? "Acknowledged" : "Open"}
        </span>
        <div className="dd-spacer" />
        {canWrite && (
          <button
            className="b b-line sm"
            onClick={() => reportRef.current?.generate()}
            disabled={reportStatus.busy || reportStatus.loading}
          >
            <IconSparkle />
            {reportStatus.busy
              ? "Generating…"
              : reportStatus.count ? "Regenerate Report" : "Generate Incident Report"}
          </button>
        )}
        {canWrite && !d.is_acknowledged && (
          <button className="b b-primary sm" onClick={onAcknowledge} disabled={acking}>
            <IconCheck /> {acking ? "Acknowledging…" : "Acknowledge Alert"}
          </button>
        )}
      </div>

      <div className="dd-grid">
        <div className="dd-left">
          <div className="card">
            <div className="chead"><h3>Detection</h3></div>
            <div className="drow"><span className="k">Threat category</span><span className="v">{threatLabel(d.threat_type)}</span></div>
            <div className="drow"><span className="k">Severity</span><span className="v">{sevLabel(d.severity)}</span></div>
            <div className="drow"><span className="k">Risk score</span><span className="v mono">{score100(d.anomaly_score)} / 100</span></div>
            <div className="drow"><span className="k">Anomaly score</span><span className="v mono">{Number(d.anomaly_score).toFixed(4)}</span></div>
            <div className="drow"><span className="k">Source IP</span><span className="v mono">{d.source_ip}</span></div>
            <div className="drow"><span className="k">Destination IP</span><span className="v mono">{d.destination_ip}</span></div>
            <div className="drow"><span className="k">Detected at</span><span className="v">{when(d.timestamp)}</span></div>
            <div className="drow"><span className="k">Model</span><span className="v mono">{d.model_type} · {d.model_version}</span></div>
            <div className="drow"><span className="k">Status</span><span className="v">{d.is_acknowledged ? "Acknowledged" : "Open"}</span></div>
          </div>

          {/* id anchors the dashboard's View Logs link, which deep-links here. */}
          <div className="card" id="traffic">
            <div className="chead">
              <h3>Traffic</h3>
              {traffic?.events > 0 && (
                <span className="dd-sub">
                  {traffic.events} events · detection minute
                </span>
              )}
            </div>
            <ProtocolBars protocols={traffic?.protocols} />
            {traffic?.events > 0 && (
              <>
                <div className="drow"><span className="k">Distinct destination ports</span><span className="v mono">{traffic.distinct_dst_ports}</span></div>
                <div className="drow"><span className="k">Distinct destination IPs</span><span className="v mono">{traffic.distinct_dst_ips}</span></div>
                <div className="drow">
                  <span className="k">Most contacted ports</span>
                  <span className="v mono">{traffic.top_dst_ports.join(", ") || "—"}</span>
                </div>
                <div className="drow">
                  <span className="k">Packet size min/avg/max</span>
                  <span className="v mono">
                    {traffic.packet_size_bytes.min}/{traffic.packet_size_bytes.avg}/{traffic.packet_size_bytes.max} B
                  </span>
                </div>
              </>
            )}
          </div>

          <div className="card">
            <div className="chead"><h3>Model features</h3></div>
            <div className="dd-fv">
              {Object.entries(fv).map(([k, v]) => (
                <div className="dd-fvrow" key={k}>
                  <span className="fk mono">{k}</span>
                  <span className="fvv mono">{typeof v === "number" ? v.toFixed(3) : String(v)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="dd-right">
          <IncidentReportPanel ref={reportRef} detectionId={detectionId} onStatus={onStatus} />
        </div>
      </div>
    </AppShell>
  );
}
