import Sparkline from "./Sparkline";

export default function SystemStatus({ settings = {}, eventCount }) {
  const {
    engine = "Running", ingestion = "Running",
    model = "IF_v1.0", threshold = "0.75", interval = "60s", lastScan = "—",
  } = settings;
  return (
    <div className="card">
      <div className="chead"><h3>System Status</h3><span className="badge">Operational</span></div>
      <div className="srow"><span className="k"><span className="dok" />Detection Engine</span><span className="v">{engine}</span></div>
      <div className="srow"><span className="k"><span className="dok" />Syslog Ingestion</span><span className="v">{ingestion}</span></div>
      <div className="srow"><span className="k">Active Model</span><span className="v mono">{model}</span></div>
      <div className="srow"><span className="k">Sensitivity</span><span className="v mono">{threshold}</span></div>
      <div className="srow"><span className="k">Scan Interval</span><span className="v mono">{interval}</span></div>
      <div className="srow"><span className="k"><span className="dok" />Last Scan</span><span className="v mono">{lastScan}</span></div>
      <div className="eventtile">
        <div>
          <div className="lab">Detections · 24h</div>
          <div className="big">{(eventCount ?? 0).toLocaleString()}</div>
        </div>
        <Sparkline points={[6, 7, 6, 8, 7, 9, 8, 9]} color="#2b54ff" w={84} h={36} />
      </div>
    </div>
  );
}
