// Shared unacknowledged-alert state (task 4.3, Use Case 4.6).
//
// The brief requires the bell count and the dashboard's "Unacknowledged"
// metric to derive from the same source. The reliable way to guarantee that
// is for both to read the SAME object, not to make two components run the
// same query and hope they agree — two independent polls drift apart the
// moment one of them fails or lands a second later.
//
// So this provider owns:
//   * detection stats (/api/detections/stats)
//   * the five most recent unacknowledged detections
//   * acknowledge(), which updates both optimistically then reconciles
//
// The Dashboard reads `stats` from here rather than fetching its own.
import {
  createContext, useCallback, useContext, useEffect, useMemo, useState,
} from "react";
import { acknowledgeDetection, detectionStats, listDetections } from "../api/detections";

const POLL_MS = 20000;
const RECENT = 5;

const AlertsContext = createContext(null);

export function AlertsProvider({ children }) {
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);
  const [error, setError] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [s, list] = await Promise.all([
        detectionStats(),
        listDetections({ acknowledged: false, limit: RECENT }),
      ]);
      setStats(s);
      setRecent(list.items || []);
      setError(false);
    } catch {
      // Keep the last good numbers on screen rather than flashing zeros —
      // a bell that reads 0 during a blip is worse than a slightly stale one.
      setError(true);
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, POLL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  const acknowledge = useCallback(async (detectionId) => {
    // Optimistic: the count and the list move together, immediately.
    setRecent((list) => list.filter((d) => d.detection_id !== detectionId));
    setStats((s) => (s ? { ...s, unacknowledged: Math.max(0, s.unacknowledged - 1) } : s));
    try {
      await acknowledgeDetection(detectionId);
    } finally {
      // Reconcile against the server either way: on success this pulls the
      // next unacknowledged detection into the list of five; on failure it
      // puts the count back to the truth.
      refresh();
    }
  }, [refresh]);

  const value = useMemo(() => ({
    stats,
    recent,
    error,
    unacknowledged: stats?.unacknowledged ?? 0,
    refresh,
    acknowledge,
  }), [stats, recent, error, refresh, acknowledge]);

  return <AlertsContext.Provider value={value}>{children}</AlertsContext.Provider>;
}

export function useAlerts() {
  const ctx = useContext(AlertsContext);
  if (!ctx) throw new Error("useAlerts must be used inside <AlertsProvider>");
  return ctx;
}
