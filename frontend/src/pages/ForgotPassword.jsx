import { useState } from "react";
import { Link } from "react-router-dom";
import { requestPasswordReset } from "../api/auth";
import "../styles/password.css";

/**
 * Request a password-reset link (task 1.5, Section 2.1).
 *
 * This is where the Login screen's password-recovery link goes — Figure 3
 * specifies the link, and until now it had no destination.
 *
 * The backend deliberately returns the same generic response whether or not
 * the email matches an account (routers/auth.py: "Always generic, to avoid
 * account enumeration"), so this screen must NOT report whether the address
 * was found. Showing "no such account" here would undo that protection on the
 * client side.
 *
 * DEV NOTE: SendGrid delivery of the link is task 2.2, still pending an API
 * key. Until then the backend logs the reset URL at WARNING level — check the
 * uvicorn console for a line starting "PASSWORD RESET requested for".
 */
export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await requestPasswordReset(email.trim());
      setSent(true);
    } catch (err) {
      if (err.status === 0) setError("Cannot reach the server. Is the backend running?");
      else setError(err.message || "Could not send the reset link.");
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
        <p className="login-sub">Reset your password</p>

        {sent && (
          <div className="login-notice" role="status">
            If that account exists, a reset link has been sent. The link expires
            in 15 minutes.
          </div>
        )}
        {error && <div className="login-error" role="alert">{error}</div>}

        {!sent && (
          <form onSubmit={onSubmit}>
            <div className="field">
              <label htmlFor="reset-email">Email</label>
              <input
                id="reset-email"
                className="input"
                type="email"
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@threatsense.local"
                required
                autoFocus
              />
            </div>
            <button className="login-btn" type="submit" disabled={busy}>
              {busy ? "Sending…" : "Send reset link"}
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
