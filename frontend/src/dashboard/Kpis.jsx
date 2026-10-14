import Sparkline from "./Sparkline";
import { IconUp } from "../components/icons";

function Kpi({ label, value, color, foot, spark, sparkColor }) {
  return (
    <div className="card kpi">
      <h4>{label}</h4>
      <div className="num" style={color ? { color } : undefined}>{value}</div>
      <div className="foot">
        {foot}
        <Sparkline points={spark} color={sparkColor} />
      </div>
    </div>
  );
}

export default function Kpis({ stats }) {
  const s = stats || {};
  return (
    <div className="grid r-kpi">
      <Kpi label="Total Detections" value={s.total ?? "—"}
        foot={<span className="delta up"><IconUp /> all time</span>}
        spark={[3, 4, 3, 5, 6, 5, 7, 8]} sparkColor="#2b54ff" />
      <Kpi label="Unacknowledged" value={s.unacknowledged ?? "—"}
        foot={<span className="delta flat">awaiting review</span>}
        spark={[5, 4, 6, 5, 4, 5, 4, 3]} sparkColor="#ffb020" />
      <Kpi label="Last 24 Hours" value={s.last_24h ?? "—"}
        foot={<span className="delta up"><IconUp /> recent</span>}
        spark={[2, 3, 2, 4, 3, 5, 4, 6]} sparkColor="#2b54ff" />
      <Kpi label="Critical" value={s.by_severity?.CRITICAL ?? 0} color="var(--crit)"
        foot={<span className="delta dn">needs attention</span>}
        spark={[0, 1, 1, 2, 1, 3, 2, 4]} sparkColor="#f5365c" />
    </div>
  );
}
