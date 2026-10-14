import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { confirmPasswordReset } from "../api/auth";
import { evaluate, isCompliant } from "../lib/passwordPolicy";
import "../styles/password.css";

/**
 * Set a new password from a reset link — the client-side half of NFR-11.
 *
 * Proposal Section 3, Table 11, NFR-11 (verbatim):
 *   "Passwords must be validated on both the client side and the server side
 *   before acceptance."
 *
 * The validation here is a convenience layer, never a security control: the
 * server re-checks every rule in app/core/password_policy.py, and the submit
 * button being disabled only saves the administrator a round trip. Anyone
 * calling the API directly still hits the server-side guard.
 *
 * Reached at /reset-password?token=... — the token is emailed in production;
 * in dev, routers/auth.py logs the link at WARNING level.
 */
export default function ResetPassword() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const token = params.get("token") || "";

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const rules = useMemo(() => evaluate(password), [password]);
  const compliant = isCompliant(password);
  const matches = confirm.length > 0 && password === confirm;
  const canSubmit = Boolean(token) && compliant && matches && !busy;

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    if (!canSubmit) return;
    setBusy(true);
    try {
      await confirmPasswordReset(token, password);
      setDone(true);
      setTimeout(() => navigate("/login", { replace: true }), 2500);
    } catch (err) {
      // The server returns a single readable string in `detail` (see the note
      // in backend/app/schemas/auth.py about why Field(min_length=...) was
      // removed), so this renders the actual rule rather than [object Object].
      if (err.status === 422) setError(err.message);
      else if (err.status === 400) setError("This reset link is invalid or has expired. Request a new one.");
      else if (err.status === 0) setError("Cannot reach the server. Is the backend running?");
      else setError(err.message || "Could not reset the password.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <div className="login-grid" />
      <div className="login-card">
        <div className="login-brand">
          <div className="m">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="rgba(255,255,255,.25)" stroke="#fff" strokeWidth="1.6" strokeLinejoin="round" />
              <path d="M8.5 12l2.3 2.3L15.5 9.5" stroke="#fff" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <h1>Threat<span>Sense</span></h1>
        </div>
        <p className="login-sub">Choose a new password</p>

        {done && (
          <div className="login-notice" role="status">
            Password updated. Redirecting you to sign in…
          </div>
        )}
        {error && <div className="login-error" role="alert">{error}</div>}
        {!token && !done && (
          <div className="login-error" role="alert">
            This page needs a reset token. Open the link from your reset email,
            or <Link className="login-link" to="/forgot-password">request a new one</Link>.
          </div>
        )}

        {!done && (
          <form onSubmit={onSubmit}>
            <div className="field">
              <label htmlFor="new-password">New password</label>
              <input
                id="new-password"
                className="input"
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                aria-describedby="pw-rules"
                required
                autoFocus
              />
            </div>

            {/* NFR-11 checklist. Each rule reports its own state so the
                administrator can see exactly what is outstanding — the
                "appropriate error messages" the measurement column asks for,
                shown before submission rather than after. */}
            <ul className="pw-rules" id="pw-rules" aria-live="polite">
              <li className="pw-rules-title">Password must contain</li>
              {rules.map((rule) => (
                <li key={rule.id} className={`pw-rule ${rule.passed ? "is-met" : "is-unmet"}`}>
                  {/* Text marker as well as colour — severity/status must never
                      be conveyed by colour alone (Section 7.7). */}
                  <span className="pw-rule-mark" aria-hidden="true">{rule.passed ? "✓" : "○"}</span>
                  <span>{rule.label}</span>
                  <span className="sr-only">{rule.passed ? " — met" : " — not yet met"}</span>
                </li>
              ))}
            </ul>

            <div className="field">
              <label htmlFor="confirm-password">Confirm new password</label>
              <input
                id="confirm-password"
                className="input"
                type="password"
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                required
              />
            </div>

            {confirm.length > 0 && (
              <p className={`pw-match ${matches ? "is-match" : "is-mismatch"}`} aria-live="polite">
                {matches ? "Passwords match." : "Passwords do not match."}
              </p>
            )}

            <button className="login-btn" type="submit" disabled={!canSubmit}>
              {busy ? "Updating…" : "Update password"}
            </button>
          </form>
        )}

        <div className="login-foot">
          <Link className="login-link" to="/login">Back to sign in</Link>
        </div>
      </div>
    </div>
  );
}
