import { Link } from "react-router-dom";
import { timeAgo } from "../lib/format";

const SEVS = [
  { key: "CRITICAL", label: "Critical", color: "var(--crit)" },
  { key: "HIGH", label: "High", color: "var(--high)" },
  { key: "MEDIUM", label: "Medium", color: "var(--med)" },
  { key: "LOW", label: "Low", color: "var(--low)" },
];

export function SeverityBreakdown({ bySeverity }) {
  const data = bySeverity || {};
  const total = SEVS.reduce((a, s) => a + (data[s.key] || 0), 0) || 1;
  return (
    <div className="card">
      <div className="chead"><h3>Severity Breakdown</h3></div>
      <div className="segbar">
        {SEVS.map((s) => {
          const w = ((data[s.key] || 0) / total) * 100;
          return w > 0 ? <div key={s.key} style={{ width: `${w}%`, background: s.color }} /> : null;
        })}
      </div>
      <div className="seglegend">
        {SEVS.map((s) => (
          <div className="sl" key={s.key}>
            <span className="nm"><span className="sw" style={{ background: s.color }} />{s.label}</span>
            <span className="vv">{data[s.key] || 0}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function LogSourcesPanel({ sources = [] }) {
  return (
    <div className="card">
      <div className="chead"><h3>Log Sources</h3>
        <Link className="link" to="/sources">Manage →</Link></div>
      {sources.length === 0 && <div className="empty">No sources configured</div>}
      {sources.map((s) => (
        <div className="src" key={s.source_id}>
          <span className={`sd ${s.status === "ACTIVE" ? "on" : "off"}`} />
          <div className="nf"><div className="n">{s.name}</div><div className="d">{s.type} · {s.transport || "—"}</div></div>
          <span className="w">{s.last_received ? timeAgo(s.last_received) : "never"}</span>
        </div>
      ))}
    </div>
  );
}
