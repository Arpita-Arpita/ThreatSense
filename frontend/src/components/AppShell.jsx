import { useEffect, useRef, useState } from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";

import { useAuth } from "../context/AuthContext";
import { listSources } from "../api/sources";
import {
  IconDashboard, IconShield, IconSources, IconSettings, IconBell, IconSearch,
  IconLogout, IconUser, IconHistory,
} from "./icons";
import NotificationBell from "./NotificationBell";

const NAV = [
  { to: "/", label: "Dashboard", Icon: IconDashboard, end: true },
  { to: "/detections", label: "Detections", Icon: IconShield },
  { to: "/sources", label: "Log Sources", Icon: IconSources },
  { to: "/settings", label: "Detection Settings", Icon: IconSettings },
  { to: "/alerts", label: "Alert Config", Icon: IconBell },
  // Section 2.1 names Incident Reports as one of the seven navigation
  // destinations. Report history existed only per detection until now.
  { to: "/reports", label: "Incident Reports", Icon: IconHistory },
  { to: "/account", label: "Account Settings", Icon: IconUser },
];

function initials(name = "") {
  return name.split(/\s+/).map((w) => w[0]).slice(0, 2).join("").toUpperCase() || "TS";
}

export default function AppShell({ title, subtitle, sources, children }) {
  const { admin, logout } = useAuth();
  const navigate = useNavigate();
  const searchRef = useRef(null);
  const [term, setTerm] = useState("");

  // The source count used to be a prop, so only the Dashboard passed it and
  // every other page showed "0 sources" — the same system reporting two
  // different numbers depending on which tab you were on. The shell now fetches
  // it itself; the prop remains an override for a page that already has the
  // list loaded, so we do not fetch it twice.
  const [count, setCount] = useState(sources ?? null);
  useEffect(() => {
    if (sources !== undefined) { setCount(sources); return; }
    let cancelled = false;
    listSources()
      .then((rows) => {
        if (cancelled) return;
        const list = Array.isArray(rows) ? rows : (rows?.items ?? []);
        // ACTIVE only: the badge says "Live", so counting a source that has
        // gone quiet would overstate what is actually reporting.
        setCount(list.filter((s) => s.status === "ACTIVE").length);
      })
      .catch(() => { if (!cancelled) setCount(null); });
    return () => { cancelled = true; };
  }, [sources]);

  // Cmd/Ctrl+K focuses the search box, which the old placeholder advertised
  // without implementing.
  useEffect(() => {
    function onKey(e) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        searchRef.current?.focus();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  function onSearch(e) {
    e.preventDefault();
    const q = term.trim();
    if (!q) return;
    // Everything searchable is a detection attribute, so search resolves to a
    // filtered detections list rather than a separate results page.
    navigate(`/detections?q=${encodeURIComponent(q)}`);
  }

  return (
    <div className="app">
      {/* First tab stop on every screen (WCAG 2.4.1) — lets a keyboard user
          jump the sidebar instead of tabbing through every nav item. */}
      <a className="skip" href="#main">Skip to main content</a>
      <aside className="side" aria-label="Main navigation">
        {/* The wordmark is a link home: it is what users try first when they
            want to get back, and it did nothing before. */}
        <Link to="/" className="brand brand-link" aria-label="ThreatSense — go to dashboard">
          <div className="m">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
              <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="rgba(255,255,255,.25)" stroke="#fff" strokeWidth="1.6" strokeLinejoin="round" />
              <path d="M8.5 12l2.3 2.3L15.5 9.5" stroke="#fff" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <h1>Threat<span>Sense</span></h1>
        </Link>
        <div className="navlabel eyebrow">Main menu</div>
        <nav className="nav">
          {NAV.map(({ to, label, Icon, end }) => (
            <NavLink key={to} to={to} end={end} className={({ isActive }) => (isActive ? "active" : "")}>
              <Icon /> {label}
            </NavLink>
          ))}
        </nav>
        <div className="sfoot">
          <Link to="/account" className="av" title="Account settings">{initials(admin?.full_name)}</Link>
          <div className="who">{admin?.full_name || "Administrator"}<small>{admin?.role}</small></div>
          <button className="logout" onClick={logout} title="Sign out"><IconLogout /></button>
        </div>
      </aside>

      <main id="main" tabIndex={-1} className="main">
        <div className="top">
          <div>
            <h2>{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          <div className="tact">
            <form className="search" onSubmit={onSearch} role="search">
              <IconSearch />
              <input
                ref={searchRef}
                type="search"
                value={term}
                onChange={(e) => setTerm(e.target.value)}
                placeholder="Search detections by IP, threat…"
                aria-label="Search detections"
              />
              <span className="kbd" aria-hidden="true">⌘K</span>
            </form>
            <div className="livepill">
              <i /> Live · {count === null ? "—" : count} source{count === 1 ? "" : "s"}
            </div>
            <NotificationBell />
          </div>
        </div>
        {children}
      </main>
    </div>
  );
}
