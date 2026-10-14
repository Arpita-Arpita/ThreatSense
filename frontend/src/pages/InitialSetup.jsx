/**
 * Initial administrator setup (Section 2.1, Figure 3, NFR-11).
 *
 * Section 2.1: "Direct registration is available only for the initial
 * administrator. Additional accounts are created by an authenticated
 * SUPER_ADMIN through a controlled account-management workflow."
 *
 * This screen is the "registration form" NFR-11 names as the site of
 * client-side validation:
 *
 *   "Implementation: client-side regex validation on the registration form,
 *    and server-side validation immediately before bcrypt hashing."
 *
 * Until now the form did not exist, so NFR-11's client-side evidence had to
 * be taken from the password-reset screen instead — a documented deviation
 * that this closes. The checklist below is the same component behaviour as
 * ResetPassword, drawing on the same lib/passwordPolicy.js regexes, so the
 * two screens cannot drift apart.
 *
 * The server re-validates regardless (POST /api/auth/setup returns 422 with
 * the specific failures); the client copy exists to tell the administrator
 * what is outstanding before they submit.
 */
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { getSetupStatus, initialSetup } from "../api/auth";
import { evaluate, isCompliant } from "../lib/passwordPolicy";

export default function InitialSetup() {
  const navigate = useNavigate();
  const [checking, setChecking] = useState(true);
  const [required, setRequired] = useState(false);
  // Distinct from "setup already done". Treating a failed status call as
  // "already configured" told a first-time operator that someone else had
  // set the system up, when in fact the backend was unreachable — the
  // opposite of NFR-08's "without consulting external documentation".
  const [statusError, setStatusError] = useState(false);
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  // Figure 3: the Initial Setup link is shown "only before the first
  // administrator account is created". Anyone reaching this URL directly
  // after setup is complete gets told so rather than a failing form.
  useEffect(() => {
    let cancelled = false;
    getSetupStatus()
      .then((s) => { if (!cancelled) setRequired(Boolean(s.setup_required)); })
      .catch(() => { if (!cancelled) setStatusError(true); })
      .finally(() => { if (!cancelled) setChecking(false); });
    return () => { cancelled = true; };
  }, []);

  const rules = evaluate(password);
  const matches = password.length > 0 && password === confirm;
  const canSubmit =
    fullName.trim().length > 0 &&
    email.trim().length > 0 &&
    isCompliant(password) &&
    matches &&
    !busy;

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await initialSetup(fullName, email, password);
      setDone(true);
      setTimeout(() => navigate("/login"), 1500);
    } catch (err) {
      setError(err?.message || "Setup failed. Please try again.");
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
        <p className="login-sub">Create the first administrator account</p>

        {done && (
          <div className="login-notice" role="status">
            Administrator created. Redirecting you to sign in…
          </div>
        )}
        {error && <div className="login-error" role="alert">{error}</div>}

        {!checking && statusError && !done && (
          <div className="login-error" role="alert">
            Unable to check setup status. Verify that the ThreatSense backend
            is running and reachable, then reload this page.
          </div>
        )}

        {!checking && !statusError && !required && !done && (
          <div className="login-error" role="alert">
            Setup has already been completed. Ask a SUPER_ADMIN to create your
            account, or <Link className="login-link" to="/login">sign in</Link>.
          </div>
        )}

        {!checking && !statusError && required && !done && (
          <form onSubmit={onSubmit}>
            <div className="field">
              <label htmlFor="full-name">Full name</label>
              <input id="full-name" className="input" type="text"
                     autoComplete="name" value={fullName}
                     onChange={(e) => setFullName(e.target.value)}
                     required autoFocus />
            </div>

            <div className="field">
              <label htmlFor="setup-email">Email address</label>
              <input id="setup-email" className="input" type="email"
                     autoComplete="email" value={email}
                     onChange={(e) => setEmail(e.target.value)}
                     required />
            </div>

            <div className="field">
              <label htmlFor="setup-password">Password</label>
              <input id="setup-password" className="input" type="password"
                     autoComplete="new-password" value={password}
                     onChange={(e) => setPassword(e.target.value)}
                     aria-describedby="pw-rules" required />
            </div>

            {/* NFR-11 checklist, identical in behaviour to the reset screen:
                each rule reports its own state so the administrator sees what
                is outstanding before submitting. Text markers as well as
                colour, since status must never be carried by colour alone
                (Section 7.7). */}
            <ul className="pw-rules" id="pw-rules" aria-live="polite">
              <li className="pw-rules-title">Password must contain</li>
              {rules.map((rule) => (
                <li key={rule.id} className={`pw-rule ${rule.passed ? "is-met" : "is-unmet"}`}>
                  <span className="pw-rule-mark" aria-hidden="true">{rule.passed ? "✓" : "○"}</span>
                  <span>{rule.label}</span>
                  <span className="sr-only">{rule.passed ? " — met" : " — not yet met"}</span>
                </li>
              ))}
            </ul>

            <div className="field">
              <label htmlFor="setup-confirm">Confirm password</label>
              <input id="setup-confirm" className="input" type="password"
                     autoComplete="new-password" value={confirm}
                     onChange={(e) => setConfirm(e.target.value)}
                     required />
            </div>

            {confirm.length > 0 && (
              <p className={`pw-match ${matches ? "is-match" : "is-mismatch"}`} aria-live="polite">
                {matches ? "Passwords match." : "Passwords do not match."}
              </p>
            )}

            <button className="login-btn" type="submit" disabled={!canSubmit}>
              {busy ? "Creating…" : "Create administrator"}
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
