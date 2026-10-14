// Fetch client with credentials:"include" so the HttpOnly session cookie
// (ts_session) rides along. No tokens in localStorage (task 1.15).
const BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

async function request(path, options = {}) {
  let res;
  try {
    res = await fetch(`${BASE}${path}`, {
      credentials: "include",
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      ...options,
    });
  } catch {
    const err = new Error("Cannot reach the server. Is the backend running?");
    err.status = 0;
    throw err;
  }
  const isJson = res.headers.get("content-type")?.includes("application/json");
  const body = isJson ? await res.json() : null;
  if (!res.ok) {
    const err = new Error(body?.detail || res.statusText || "Request failed");
    err.status = res.status;
    err.body = body;
    // Exposed by the backend's CORS config; used by the report rate limit UI.
    err.retryAfter = res.headers.get("retry-after") || null;
    throw err;
  }
  return body;
}

export const api = {
  get: (p) => request(p),
  post: (p, data) => request(p, { method: "POST", body: data ? JSON.stringify(data) : undefined }),
  patch: (p, data) => request(p, { method: "PATCH", body: data ? JSON.stringify(data) : undefined }),
  del: (p) => request(p, { method: "DELETE" }),
};
