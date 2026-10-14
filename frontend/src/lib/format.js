// Display helpers for the dashboard (task 1.16)

export function timeAgo(iso) {
  if (!iso) return "—";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

const SEV_CLASS = { CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low" };
export const sevClass = (s) => SEV_CLASS[s] || "low";

const SEV_LABEL = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low" };
export const sevLabel = (s) => SEV_LABEL[s] || s;

const THREAT_LABEL = {
  PORT_SCAN: "Port Scan",
  DDOS: "DDoS Flood",
  BRUTE_FORCE: "Brute Force",
  C2: "C2 Beacon",
  UNKNOWN_ANOMALY: "Unknown Anomaly",
};
export const threatLabel = (t) => THREAT_LABEL[t] || t;

export const score100 = (score) => Math.round((Number(score) || 0) * 100);

export const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
