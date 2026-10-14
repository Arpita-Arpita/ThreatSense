// Data sources API (task 1.8 endpoints, consumed by the Log Sources screen 4.1).
import { api } from "./client";

const BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export const listSources = () => api.get("/api/sources");
export const getSource = (id) => api.get(`/api/sources/${id}`);
export const createSource = (payload) => api.post("/api/sources", payload);
export const updateSource = (id, payload) => api.patch(`/api/sources/${id}`, payload);
export const deleteSource = (id) => api.del(`/api/sources/${id}`);

/**
 * Attach a log file to an existing source.
 *
 * Not routed through api.post: this is multipart/form-data, and setting
 * Content-Type by hand would omit the boundary the server needs to parse it.
 * Letting fetch set the header is the fix.
 */
export async function uploadLogs(sourceId, file) {
  const body = new FormData();
  body.append("file", file);
  const res = await fetch(`${BASE}/api/sources/${sourceId}/upload`, {
    method: "POST",
    credentials: "include",
    body,
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error(data?.detail || `Upload failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return data;
}
