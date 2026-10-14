import { Link } from "react-router-dom";
import { ThreatIcon, IconCheck } from "../components/icons";
import { threatLabel, sevLabel, sevClass, timeAgo } from "../lib/format";
import { useAuth } from "../context/AuthContext";

const FILTERS = [
  { key: "all", label: "All" },
  { key: "unack", label: "Unacknowledged" },
  { key: "CRITICAL", label: "Critical" },
  { key: "HIGH", label: "High" },
];

function Incident({ d, onAck, onOpen }) {
  // VIEWER is read-only (Section 2.1); backend still enforces with 403.
  const { canWrite } = useAuth();
  const cls = sevClass(d.severity);
  return (
    <div className={`inc ${cls}`} onClick={() => onOpen(d)}>
      <div className="ic"><ThreatIcon type={d.threat_type} /></div>
      <div className="bd">
        <div className="t">{threatLabel(d.threat_type)}</div>
        <div className="m">
          <span className="mono">{d.source_ip} → {d.destination_ip}</span>
          <span>{timeAgo(d.created_at)}</span>
          {d.is_acknowledged
            ? <span className="stag ack">Acknowledged</span>
            : <span className={`stag ${cls}`}>{sevLabel(d.severity)}</span>}
          <span className="mono">{Number(d.anomaly_score).toFixed(2)}</span>
        </div>
      </div>
      <div className="ac" onClick={(e) => e.stopPropagation()}>
        {canWrite && !d.is_acknowledged && (
          <button className="b sm b-soft" onClick={() => onAck(d)}><IconCheck /> Acknowledge</button>
        )}
        <button className="b sm b-line" onClick={() => onOpen(d)}>Details</button>
      </div>
    </div>
  );
}

export default function IncidentStream({ items = [], total = 0, loading, filter, setFilter, onAck, onOpen }) {
  return (
    <div className="card">
      <div className="chead">
        <h3>Live Incident Stream</h3>
        <div className="filterchips">
          {FILTERS.map((f) => (
            <button key={f.key} className={`chipf ${filter === f.key ? "on" : ""}`} onClick={() => setFilter(f.key)}>{f.label}</button>
          ))}
        </div>
      </div>
      {/* Eight skeletons, matching the slice in Dashboard.jsx, so the card is
          already its loaded height before the rows arrive. A single "Loading…"
          line here was the second-largest contributor to CLS 0.158. */}
      {loading && Array.from({ length: 8 }, (_, i) => (
        <div className="inc-skel" key={`skel-${i}`} aria-hidden="true" />
      ))}
      {loading && <span className="sr-only" role="status">Loading detections…</span>}
      {!loading && items.length === 0 && <div className="empty">No detections match this filter.</div>}
      {!loading && items.map((d) => <Incident key={d.detection_id} d={d} onAck={onAck} onOpen={onOpen} />)}
      {!loading && (
        <Link className="allbtn" to="/detections">
          {total > items.length ? `View all ${total} detections →` : "View full detection history →"}
        </Link>
      )}
    </div>
  );
}
