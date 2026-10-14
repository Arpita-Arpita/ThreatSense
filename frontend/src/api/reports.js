// Incident report API (tasks 3.2-3.4, UC 4.4).
import { api } from "./client";

const BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

/** Generate (or regenerate) a report. Every call inserts a new row server-side. */
export const generateReport = (detectionId) =>
  api.post(`/api/detections/${detectionId}/reports`);

/** Full history for a detection, newest first (Report History tab). */
export const reportHistory = (detectionId) =>
  api.get(`/api/detections/${detectionId}/reports`);

/**
 * Every report the signed-in administrator owns, newest first.
 * Backs the Incident Reports navigation destination (Section 2.1).
 */
export const listAllReports = ({ limit = 100, offset = 0 } = {}) =>
  api.get(`/api/reports?limit=${limit}&offset=${offset}`);

export const getReport = (reportId) => api.get(`/api/reports/${reportId}`);

/**
 * Download the server-rendered PDF.
 *
 * Deliberately not routed through api.get: the response is binary, and the
 * filename lives in Content-Disposition, which the backend adds to the CORS
 * expose list. Falls back to a generated name if the header is unreadable.
 */
export async function downloadReportPdf(reportId) {
  const res = await fetch(`${BASE}/api/reports/${reportId}/pdf`, {
    credentials: "include",
  });
  if (!res.ok) {
    let detail = `Export failed (${res.status})`;
    try {
      const body = await res.json();
      if (body?.detail) detail = body.detail;
    } catch {
      /* non-JSON error body — keep the status message */
    }
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }

  const disposition = res.headers.get("content-disposition") || "";
  const match = /filename="?([^"]+)"?/.exec(disposition);
  const filename = match ? match[1] : `threatsense-report-${reportId}.pdf`;

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoking immediately can cancel the download in Safari; one tick is enough.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return filename;
}

/**
 * Turn an API error into something an admin can act on.
 *
 * 429 carries Retry-After, but the server's message already contains the
 * wait in seconds, so the countdown still works if the header is stripped
 * by a proxy. 502 is always retryable and never consumed quota — that
 * distinction is the whole point of the copy here.
 */
export function describeReportError(err) {
  if (err.status === 429) {
    const header = Number(err.retryAfter);
    const parsed = /in (\d+)s/.exec(err.message || "");
    const seconds = header || (parsed ? Number(parsed[1]) : null);
    return {
      kind: "rate_limit",
      retryable: false,
      seconds,
      message: seconds
        ? `Report limit reached — 10 per hour. Try again in ${seconds} seconds.`
        : "Report limit reached — 10 per hour. Try again shortly.",
    };
  }
  if (err.status === 502) {
    const reason = err.body?.reason;
    const detail =
      reason === "timeout"
        ? "The AI service did not respond within 15 seconds."
        : reason === "validation"
        ? "The AI service returned an incomplete report."
        : "The AI service could not be reached.";
    return {
      kind: reason || "api_error",
      retryable: true,
      message: `${detail} This attempt did not count against your limit — you can retry now.`,
    };
  }
  if (err.status === 503) {
    return { kind: "pdf_unavailable", retryable: false, message: err.message };
  }
  return {
    kind: "error",
    retryable: err.status === 0,
    message: err.message || "Something went wrong.",
  };
}
