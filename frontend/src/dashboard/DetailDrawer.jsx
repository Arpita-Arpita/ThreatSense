import { Fragment } from "react";
import { Link } from "react-router-dom";
import { threatLabel, sevLabel, score100, timeAgo } from "../lib/format";
import { IconClose, IconCheck } from "../components/icons";
import { useAuth } from "../context/AuthContext";

export default function DetailDrawer({ detection, onClose, onAck }) {
  // VIEWER is read-only (Section 2.1); backend still enforces with 403.
  const { canWrite } = useAuth();
  if (!detection) return null;
  const d = detection;
  const fv = d.feature_vector || {};
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Detection detail">
        <div className="dh">
          <div>
            <h3>{threatLabel(d.threat_type)}</h3>
            <div style={{ color: "var(--ink2)", fontSize: ".82rem", marginTop: ".2rem" }}>{timeAgo(d.created_at)}</div>
          </div>
          <button className="xbtn" onClick={onClose}><IconClose /></button>
        </div>

        <div className="drow"><span className="k">Severity</span><span className="v">{sevLabel(d.severity)}</span></div>
        <div className="drow"><span className="k">Risk score</span><span className="v mono">{score100(d.anomaly_score)} / 100</span></div>
        <div className="drow"><span className="k">Source IP</span><span className="v mono">{d.source_ip}</span></div>
        <div className="drow"><span className="k">Destination IP</span><span className="v mono">{d.destination_ip}</span></div>
        <div className="drow"><span className="k">Model</span><span className="v mono">{d.model_version} · {d.model_type}</span></div>
        <div className="drow"><span className="k">Anomaly score</span><span className="v mono">{Number(d.anomaly_score).toFixed(4)}</span></div>
        <div className="drow"><span className="k">Status</span><span className="v">{d.is_acknowledged ? "Acknowledged" : "Open"}</span></div>

        <div className="fvtitle">Feature vector</div>
        <div className="fv">
          {Object.entries(fv).map(([k, v]) => (
            <Fragment key={k}>
              <span className="fk">{k}</span>
              <span className="fvv">{typeof v === "number" ? v.toFixed(3) : String(v)}</span>
            </Fragment>
          ))}
        </div>

        <Link className="b b-line" to={`/detections/${d.detection_id}`}
              style={{ marginTop: "1.4rem", width: "100%", justifyContent: "center" }}>
          Open full detail &amp; incident report
        </Link>

        {canWrite && !d.is_acknowledged && (
          <button className="b b-primary" style={{ marginTop: ".6rem", width: "100%", justifyContent: "center" }} onClick={() => onAck(d)}>
            <IconCheck /> Acknowledge detection
          </button>
        )}
      </aside>
    </>
  );
}
