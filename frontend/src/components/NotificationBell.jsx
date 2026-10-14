// Notification bell (task 4.3, Use Case 4.6).
//
// Shows the unacknowledged count and the five most recent unacknowledged
// detections. Count and list both come from AlertsContext, which is the same
// object the dashboard's "Unacknowledged" KPI reads — so the two can never
// disagree, which is the requirement the brief is actually testing.
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAlerts } from "../context/AlertsContext";
import { IconBell, IconCheck } from "./icons";
import { sevClass, sevLabel, threatLabel, timeAgo } from "../lib/format";
import { useAuth } from "../context/AuthContext";

export default function NotificationBell() {
  // VIEWER is read-only (Section 2.1); backend still enforces with 403.
  const { canWrite } = useAuth();
  const { unacknowledged, recent, acknowledge, error } = useAlerts();
  const [open, setOpen] = useState(false);
  const wrap = useRef(null);
  const navigate = useNavigate();

  // Close on outside click and on Escape — a dropdown that traps the page is
  // an accessibility failure as much as a usability one.
  useEffect(() => {
    if (!open) return undefined;
    const onDown = (e) => { if (!wrap.current?.contains(e.target)) setOpen(false); };
    const onKey = (e) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const label = unacknowledged === 0
    ? "Notifications: no unacknowledged alerts"
    : `Notifications: ${unacknowledged} unacknowledged alert${unacknowledged === 1 ? "" : "s"}`;

  return (
    <div className="nbell" ref={wrap}>
      <button
        className="ibtn" onClick={() => setOpen((v) => !v)}
        aria-label={label} aria-expanded={open} aria-haspopup="true"
      >
        <IconBell />
        {unacknowledged > 0 && (
          <span className="nbadge" aria-hidden="true">
            {unacknowledged > 99 ? "99+" : unacknowledged}
          </span>
        )}
      </button>

      {open && (
        <div className="npanel" role="dialog" aria-label="Recent unacknowledged alerts">
          <div className="nhead">
            <strong>Unacknowledged alerts</strong>
            <span className="ncount">{unacknowledged}</span>
          </div>

          {error && (
            <p className="nempty">
              Could not reach the API. Showing the last known state.
            </p>
          )}

          {!recent.length && !error && (
            <p className="nempty">Nothing waiting. Every detection has been acknowledged.</p>
          )}

          <ul className="nlist">
            {recent.map((d) => (
              <li key={d.detection_id}>
                <button
                  className="nitem"
                  onClick={() => { setOpen(false); navigate(`/detections/${d.detection_id}`); }}
                >
                  <span className={`stag ${sevClass(d.severity)}`}>{sevLabel(d.severity)}</span>
                  <span className="nmain">
                    <span className="ntitle">{threatLabel(d.threat_type)}</span>
                    <span className="nmeta mono">{d.source_ip} → {d.destination_ip}</span>
                  </span>
                  <span className="nwhen">{timeAgo(d.timestamp || d.created_at)}</span>
                </button>
                {canWrite && (
                  <button
                    className="nack" onClick={() => acknowledge(d.detection_id)}
                    aria-label={`Acknowledge ${threatLabel(d.threat_type)} from ${d.source_ip}`}
                    title="Acknowledge"
                  >
                    <IconCheck />
                  </button>
                )}
              </li>
            ))}
          </ul>

          {unacknowledged > recent.length && (
            <p className="nmore">
              +{unacknowledged - recent.length} more not shown
            </p>
          )}

          <button className="nall" onClick={() => { setOpen(false); navigate("/"); }}>
            View all on the dashboard
          </button>
        </div>
      )}
    </div>
  );
}
