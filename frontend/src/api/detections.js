import { api } from "./client";

export function listDetections(params = {}) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") q.append(k, v);
  });
  const qs = q.toString();
  return api.get(`/api/detections${qs ? `?${qs}` : ""}`);
}
export const getDetection = (id) => api.get(`/api/detections/${id}`);
export const detectionStats = () => api.get("/api/detections/stats");
export const detectionTraffic = (id) => api.get(`/api/detections/${id}/traffic`);
// PATCH per Section 2.4 and Figure 2c. Changed with the backend route in the
// same commit — leaving this as POST would 405 and break the Acknowledge button.
export const acknowledgeDetection = (id) => api.patch(`/api/detections/${id}/acknowledge`);
