import { useEffect, useState } from "react";
import { useNavigate, Navigate, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { getSetupStatus } from "../api/auth";
import "../styles/password.css";

/** "12 minutes" / "45 seconds" — a raw second count reads as noise at 15 min. */
function formatWait(seconds) {
  if (seconds < 60) return `${seconds} second${seconds === 1 ? "" : "s"}`;
  const minutes = Math.ceil(seconds / 60);
  return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}

export default function Login() {
  const { admin, login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  // Figure 3: the Initial Setup link is "Available only before the first
  // administrator account is created". Defaults to hidden, so a failed or
  // slow status call shows no link rather than advertising a setup route on
  // a configured system.
  const [setupRequired, setSetupRequired] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getSetupStatus()
      .then((s) => { if (!cancelled) setSetupRequired(Boolean(s.setup_required)); })
      .catch(() => { /* leave hidden */ });
    return () => { cancelled = true; };
  }, []);

  if (admin) return <Navigate to="/" replace />;

  async function onSubmit(e) {
    e.preventDefault();
    setError(""); setBusy(true);
    try {
      await login(email.trim(), password);
      navigate("/", { replace: true });
    } catch (err) {
      if (err.status === 401) setError("Invalid email or password.");
      else if (err.status === 423) setError("Account locked after too many attempts. Try again later.");
      // NFR-05: five attempts per IP per 15 minutes. The backend sends
      // Retry-After, exposed to JS by the CORS config in app/main.py, so the
      // wait can be stated rather than left vague.
      else if (err.status === 429) {
        const seconds = Number(err.retryAfter);
        setError(Number.isFinite(seconds) && seconds > 0
          ? `Too many login attempts from this network. Try again in ${formatWait(seconds)}.`
          : "Too many login attempts from this network. Try again shortly.");
      }
      else if (err.status === 0) setError("Cannot reach the server. Is the backend running?");
      else setError(err.message || "Login failed.");
    } finally { setBusy(false); }
  }

  return (
    <div className="login-wrap">
      <div className="login-grid" />
      <div className="login-card">
        <div className="login-brand">
          <div className="m">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
              <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="rgba(255,255,255,.25)" stroke="#fff" strokeWidth="1.6" strokeLinejoin="round" />
              <path d="M8.5 12l2.3 2.3L15.5 9.5" stroke="#fff" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <h1>Threat<span>Sense</span></h1>
        </div>
        <p className="login-sub">AI-driven network threat detection</p>

        {error && <div className="login-error">{error}</div>}

        <form onSubmit={onSubmit}>
          <div className="field">
            <label htmlFor="email">Email</label>
            <input id="email" className="input" type="email" autoComplete="username"
              value={email} onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@threatsense.local" required autoFocus />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <input id="password" className="input" type="password" autoComplete="current-password"
              value={password} onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••" required />
          </div>

          {/* Figure 3 / task 1.15 specify a password-recovery link on the
              auth card. It previously had no destination; /forgot-password
              is now that destination. */}
          <div className="login-link-row">
            <Link className="login-link" to="/forgot-password">Forgot your password?</Link>
          </div>

          {/* Section 2.1: "Direct registration is available only for the
              initial administrator." Figure 3 shows this link present only
              before that account exists, with the caption below it. */}
          {setupRequired && (
            <div className="login-link-row">
              <Link className="login-link" to="/setup">Initial Setup</Link>
              <span className="login-hint">
                Available only before the first administrator account is created
              </span>
            </div>
          )}

          <button className="login-btn" type="submit" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <div className="login-foot">Authorized administrators only</div>
      </div>
    </div>
  );
}
