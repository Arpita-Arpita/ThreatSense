import { useCallback, useEffect, useMemo, useState } from "react";
import AppShell from "../components/AppShell";
import HeroAlert from "../dashboard/HeroAlert";
import SystemStatus from "../dashboard/SystemStatus";
import Kpis from "../dashboard/Kpis";
import Analytics from "../dashboard/Analytics";
import IncidentStream from "../dashboard/IncidentStream";
import { SeverityBreakdown, LogSourcesPanel } from "../dashboard/Panels";
import DetailDrawer from "../dashboard/DetailDrawer";
import { listDetections } from "../api/detections";
import { useAlerts } from "../context/AlertsContext";
import { listSources } from "../api/sources";
import { SEV_ORDER } from "../lib/format";

const POLL_MS = 20000;

function buildActivity(detections) {
  // 8 buckets of 3h across the last 24h
  const now = Date.now(), span = 24 * 3600 * 1000, n = 8;
  const buckets = new Array(n).fill(0);
  for (const d of detections) {
    const age = now - new Date(d.created_at).getTime();
    if (age < 0 || age > span) continue;
    const idx = Math.min(n - 1, Math.floor(((span - age) / span) * n));
    buckets[idx] += 1;
  }
  const labels = ["", "", "", "", "", "", "", "now"];
  return { buckets, labels };
}

export default function Dashboard() {
  const [all, setAll] = useState([]);
  // stats comes from AlertsContext so the KPI and the bell read one object
  // (task 4.3). Fetching it here too would let them drift apart.
  const { stats, acknowledge } = useAlerts();
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("all");
  const [selected, setSelected] = useState(null);

  const load = useCallback(async () => {
    try {
      const [list, src] = await Promise.all([
        listDetections({ limit: 100 }),
        listSources(),
      ]);
      setAll(list.items || []);
      setSources(src || []);
    } catch {
      /* unauthorized handled by ProtectedRoute */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, POLL_MS);
    return () => clearInterval(id);
  }, [load]);

  const hero = useMemo(() => {
    const open = all.filter((d) => !d.is_acknowledged);
    if (!open.length) return null;
    return [...open].sort((a, b) =>
      (SEV_ORDER[b.severity] - SEV_ORDER[a.severity]) ||
      (new Date(b.created_at) - new Date(a.created_at))
    )[0];
  }, [all]);

  const stream = useMemo(() => {
    let rows = all;
    if (filter === "unack") rows = rows.filter((d) => !d.is_acknowledged);
    else if (filter === "CRITICAL" || filter === "HIGH") rows = rows.filter((d) => d.severity === filter);
    return rows.slice(0, 8);
  }, [all, filter]);

  const streamTotal = useMemo(() => {
    if (filter === "all") return stats?.total ?? all.length;
    if (filter === "unack") return stats?.unacknowledged ?? all.filter((d) => !d.is_acknowledged).length;
    return stats?.by_severity?.[filter] ?? all.filter((d) => d.severity === filter).length;
  }, [filter, stats, all]);

  const ack = useCallback(async (d) => {
    setAll((prev) => prev.map((x) => x.detection_id === d.detection_id
      ? { ...x, is_acknowledged: true } : x));
    setSelected((s) => (s && s.detection_id === d.detection_id
      ? { ...s, is_acknowledged: true } : s));
    // Delegates to the shared context, so the bell count drops at the same
    // moment this row greys out (task 4.3).
    await acknowledge(d.detection_id);
    load();
  }, [load, acknowledge]);

  const activity = useMemo(() => buildActivity(all), [all]);
  const activeSources = sources.filter((s) => s.status === "ACTIVE").length;

  return (
    <AppShell title="Dashboard" subtitle="AI-driven network threat detection & response" sources={activeSources}>
      <div className="grid r-hero">
        <HeroAlert detection={hero} onAcknowledge={ack} onDetails={setSelected} />
        <SystemStatus eventCount={stats?.last_24h ?? 0} settings={{ lastScan: "live" }} />
      </div>

      <Kpis stats={stats} />

      <Analytics stats={stats} activity={activity} />

      <div className="grid r-op">
        <IncidentStream
          items={stream} total={streamTotal} loading={loading}
          filter={filter} setFilter={setFilter} onAck={ack} onOpen={setSelected}
        />
        <div className="col">
          <SeverityBreakdown bySeverity={stats?.by_severity} />
          <LogSourcesPanel sources={sources} />
        </div>
      </div>

      <div className="note">ThreatSense — Command Deck · live data from /api/detections, /stats, /sources</div>

      {selected && <DetailDrawer detection={selected} onClose={() => setSelected(null)} onAck={ack} />}
    </AppShell>
  );
}
