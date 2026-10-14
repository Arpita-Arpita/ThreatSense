import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip,
} from "chart.js";
import { threatLabel } from "../lib/format";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip);

const THREAT_COLORS = {
  PORT_SCAN: "#2b54ff", UNKNOWN_ANOMALY: "#9aa3b8", DDOS: "#f5365c",
  BRUTE_FORCE: "#ff7a45", C2: "#8b5cf6",
};

function DetectionActivity({ buckets, labels, f1 = "0.99" }) {
  const data = {
    labels: labels || ["00", "03", "06", "09", "12", "15", "18", "21", "24"],
    datasets: [{
      data: buckets || [1, 0, 2, 3, 2, 5, 4, 7, 3],
      borderColor: "#2b54ff",
      backgroundColor: (ctx) => {
        const { ctx: c, chartArea } = ctx.chart;
        if (!chartArea) return "rgba(43,84,255,.15)";
        const g = c.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
        g.addColorStop(0, "rgba(43,84,255,.22)"); g.addColorStop(1, "rgba(43,84,255,0)");
        return g;
      },
      fill: true, tension: 0.42, borderWidth: 2.5,
      pointBackgroundColor: "#fff", pointBorderColor: "#2b54ff", pointBorderWidth: 2,
      pointRadius: 3, pointHoverRadius: 5,
    }],
  };
  const opts = {
    plugins: { legend: { display: false } }, maintainAspectRatio: false,
    scales: {
      y: { beginAtZero: true, grid: { color: "#eef1f9" }, border: { display: false }, ticks: { precision: 0 } },
      x: { grid: { display: false }, border: { display: false } },
    },
  };
  return (
    <div className="card">
      <div className="chead">
        <div>
          <h3>Detection Activity</h3>
          <div style={{ fontSize: ".82rem", color: "var(--ink2)", marginTop: ".2rem" }}>
            Last 24 hours · model F1 <b style={{ color: "var(--accent-deep)" }}>{f1}</b>{" "}
            <span style={{ color: "var(--faint)" }}>(synthetic eval)</span>
          </div>
        </div>
      </div>
      <div style={{ position: "relative", height: 226 }}><Line data={data} options={opts} /></div>
    </div>
  );
}

function ThreatsByType({ byType, total }) {
  const entries = Object.entries(byType || {})
    .map(([k, v]) => ({ type: k, label: threatLabel(k), count: v, color: THREAT_COLORS[k] || "#9aa3b8" }))
    .filter((e) => e.count > 0)
    .sort((a, b) => b.count - a.count);
  const max = entries.length ? entries[0].count : 1;
  const tot = total || entries.reduce((a, e) => a + e.count, 0);
  return (
    <div className="card">
      <div className="chead"><h3>Threats by Type</h3><span className="mono" style={{ fontSize: ".78rem", color: "var(--faint)" }}>{tot} total</span></div>
      {entries.length === 0 && <div className="empty">No detections yet</div>}
      {entries.map((e) => (
        <div className="tbar" key={e.type}>
          <div className="tl"><span className="nm">{e.label}</span><span className="vv">{e.count} · {Math.round((e.count / tot) * 100)}%</span></div>
          <div className="tk"><div className="tf" style={{ width: `${(e.count / max) * 100}%`, background: e.color }} /></div>
        </div>
      ))}
    </div>
  );
}

export default function Analytics({ stats, activity }) {
  return (
    <div className="grid r-an">
      <DetectionActivity buckets={activity?.buckets} labels={activity?.labels} />
      <ThreatsByType byType={stats?.by_threat_type} total={stats?.total} />
    </div>
  );
}
