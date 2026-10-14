import { Link } from "react-router-dom";
import { threatLabel, sevLabel, score100, timeAgo } from "../lib/format";
import { IconCheck, IconSearch, IconLogs } from "../components/icons";
import { useAuth } from "../context/AuthContext";

// deterministic-ish probe bars derived from the detection score
function ProbeBars({ score }) {
  const seed = [2, 1, 3, 2, 4, 3, 5, 6, 8, 7, 9, 8, 9, 7, 8, 6, 5, 4, 3, 2, 3, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7, 6, 5, 4, 3, 2];
  const k = 0.5 + score; // scale by score
  return (
    <div className="bars">
      {seed.map((hgt, i) => <span key={i} style={{ height: `${Math.min(100, 20 + hgt * 8 * k)}%` }} />)}
    </div>
  );
}

export default function HeroAlert({ detection, onAcknowledge, onDetails }) {
  // VIEWER is read-only (Section 2.1). Presentation only — the backend
  // refuses the call with 403 regardless of what is rendered here.
  const { canWrite } = useAuth();
  if (!detection) {
    return (
      <div className="hero calm">
        <span className="ebrow eyebrow"><i /> All clear</span>
        <div className="htitle"><h2>No active threats</h2></div>
        <p className="hdesc">No unacknowledged critical or high-severity detections right now. The engine is monitoring all sources in real time.</p>
      </div>
    );
  }
  const s = score100(detection.anomaly_score);
  return (
    <div className="hero">
      <div className="htop">
        <div>
          <span className="ebrow eyebrow"><i /> Active threat detected</span>
          <div className="htitle">
            <h2>{threatLabel(detection.threat_type)}</h2>
            <span className="chip">{sevLabel(detection.severity)}</span>
          </div>
          <p className="hdesc">
            Anomalous traffic on <span className="mono">{detection.destination_ip}</span> from{" "}
            <span className="mono">{detection.source_ip}</span> — flagged by{" "}
            <span className="mono">{detection.model_version}</span> {timeAgo(detection.created_at)}.
          </p>
        </div>
        <div className="ring">
          <svg width="118" height="118">
            <circle cx="59" cy="59" r="50" fill="none" stroke="rgba(255,255,255,.1)" strokeWidth="9" />
            <circle cx="59" cy="59" r="50" fill="none" stroke="url(#hg)" strokeWidth="9" strokeLinecap="round"
              strokeDasharray="314" strokeDashoffset={314 - (314 * s) / 100} />
            <defs><linearGradient id="hg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#ff7a45" /><stop offset="1" stopColor="#f5365c" /></linearGradient></defs>
          </svg>
          <div className="c"><div className="n">{s}</div><div className="l">Risk</div></div>
        </div>
      </div>
      <div className="probe">
        <div className="pl"><span>Probe activity · window</span><span className="mono">score {Number(detection.anomaly_score).toFixed(2)}</span></div>
        <ProbeBars score={Number(detection.anomaly_score) || 0} />
      </div>
      <div className="hbtns">
        {canWrite && (
          <button className="b b-primary" onClick={() => onAcknowledge(detection)}><IconCheck /> Acknowledge</button>
        )}
        <button className="b b-ghost" onClick={() => onDetails(detection)}><IconSearch /> Investigate</button>
        {/* Opens the detection detail page at its traffic summary, which is
            where the log lines behind this detection are shown. It previously
            had no handler at all. */}
        <Link className="b b-ghost"
              to={`/detections/${detection.detection_id}#traffic`}>
          <IconLogs /> View Logs
        </Link>
      </div>
    </div>
  );
}
