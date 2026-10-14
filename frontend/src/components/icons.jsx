// Inline SVG icon set (task 1.16). All stroke-based, inherit currentColor.

const S = { fill: "none", strokeWidth: 1.9, strokeLinecap: "round", strokeLinejoin: "round" };

export const IconDashboard = () => (
  <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}>
    <rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" />
    <rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" />
  </svg>
);
export const IconShield = () => (
  <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}><path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" /></svg>
);
export const IconSources = () => (
  <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}>
    <rect x="3" y="4" width="18" height="5" rx="1.5" /><rect x="3" y="13" width="18" height="5" rx="1.5" />
    <circle cx="7" cy="6.5" r="0.7" /><circle cx="7" cy="15.5" r="0.7" />
  </svg>
);
export const IconSettings = () => (
  <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}>
    <circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2" />
  </svg>
);
export const IconBell = () => (
  <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}><path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.7 21a2 2 0 01-3.4 0" /></svg>
);
export const IconSearch = () => (
  <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></svg>
);
export const IconLogout = () => (
  <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" /><path d="M16 17l5-5-5-5M21 12H9" /></svg>
);
export const IconCheck = () => (
  <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}><path d="M20 6L9 17l-5-5" /></svg>
);
export const IconClose = () => (
  <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}><path d="M18 6L6 18M6 6l12 12" /></svg>
);
export const IconLogs = () => (
  <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}><path d="M4 4h16v16H4z" /><path d="M8 9h8M8 13h5" /></svg>
);
export const IconUp = () => (
  <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" fill="none" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round"><path d="M7 14l5-5 5 5" /></svg>
);

// threat-type glyphs
export function ThreatIcon({ type }) {
  switch (type) {
    case "PORT_SCAN":
      return <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></svg>;
    case "DDOS":
      return <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}><path d="M3 12h4l2-7 4 14 2-7h6" /></svg>;
    case "BRUTE_FORCE":
      return <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}><rect x="4" y="11" width="16" height="9" rx="2" /><path d="M8 11V8a4 4 0 018 0v3" /></svg>;
    case "C2":
      return <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}><circle cx="12" cy="12" r="2.5" /><circle cx="12" cy="12" r="7" /><circle cx="12" cy="12" r="11" opacity=".4" /></svg>;
    default:
      return <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" stroke="currentColor" {...S}><path d="M12 2L2 7v6c0 5 4 8 10 9 6-1 10-4 10-9V7L12 2z" /><path d="M12 8v4M12 16v.5" /></svg>;
  }
}

/* --- Detection Detail + Incident Report (task 3.4, Figure 7) --- */
const s = { "aria-hidden": "true", focusable: "false", width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.9, strokeLinecap: "round", strokeLinejoin: "round" };

export const IconBack = () => (
  <svg aria-hidden="true" focusable="false" {...s}><path d="M15 18l-6-6 6-6" /></svg>
);
export const IconDownload = () => (
  <svg aria-hidden="true" focusable="false" {...s}><path d="M12 3v12" /><path d="M7 11l5 5 5-5" /><path d="M4 20h16" /></svg>
);
export const IconCopy = () => (
  <svg aria-hidden="true" focusable="false" {...s}><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" /></svg>
);
export const IconRefresh = () => (
  <svg aria-hidden="true" focusable="false" {...s}><path d="M20 12a8 8 0 1 1-2.6-5.9" /><path d="M20 4v5h-5" /></svg>
);
export const IconSparkle = () => (
  <svg aria-hidden="true" focusable="false" {...s}><path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z" /><path d="M18 16l.8 2.2L21 19l-2.2.8L18 22l-.8-2.2L15 19l2.2-.8z" /></svg>
);
export const IconHistory = () => (
  <svg aria-hidden="true" focusable="false" {...s}><path d="M3 12a9 9 0 1 0 3-6.7" /><path d="M3 4v5h5" /><path d="M12 8v4l3 2" /></svg>
);

export const IconPlus = () => (
  <svg aria-hidden="true" focusable="false" {...s}><path d="M12 5v14" /><path d="M5 12h14" /></svg>
);

// Account Settings nav item and the avatar link in the sidebar footer.
export const IconUser = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <circle cx="12" cy="8" r="3.4" stroke="currentColor" strokeWidth="1.8" />
    <path d="M4.5 20c0-3.6 3.4-5.6 7.5-5.6s7.5 2 7.5 5.6"
          stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
  </svg>
);
