// Detection settings API (task 4.2, Figure 8).
import { api } from "./client";

export const getSettings = () => api.get("/api/settings");
export const saveSettings = (payload) => api.patch("/api/settings", payload);
export const listModels = () => api.get("/api/settings/models");

/** Metrics for a threshold. Omit `threshold` for the saved one; pass a value
    to preview a slider position before committing the change. */
export const getMetrics = (threshold) =>
  api.get(threshold == null
    ? "/api/settings/metrics"
    : `/api/settings/metrics?threshold=${threshold.toFixed(2)}`);

export const runManualScan = () => api.post("/api/settings/scan");
