/**
 * Account Settings (Section 2.1).
 *
 * The proposal lists Account Settings as one of the seven navigation
 * destinations. It did not exist, which meant a signed-in administrator had no
 * way to see their own details or change their password without going through
 * the forgotten-password email flow.
 */
import { useCallback, useEffect, useState } from "react";

import AppShell from "../components/AppShell";
import { changePassword, createAccount, listAccounts } from "../api/auth";
import { useAuth } from "../context/AuthContext";
import { evaluate, isCompliant } from "../lib/passwordPolicy";

const ROLE_DESC = {
  SUPER_ADMIN: "Full access, including creating and managing other accounts.",
  ADMIN: "Full operational access: sources, detection settings, alerts and reports.",
  VIEWER: "Read-only. Can view detections and configuration but cannot change anything.",
};

export default function Account() {
  const { admin, logout } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  const rules = evaluate(next);
  const matches = next.length > 0 && next === confirm;
  const canSubmit = current.length > 0 && isCompliant(next) && matches && !busy;

  async function onSubmit(e) {
    e.preventDefault();
    setError(""); setDone(false); setBusy(true);
    try {
      await changePassword(current, next);
      setDone(true);
      setCurrent(""); setNext(""); setConfirm("");
    } catch (err) {
      setError(err?.message || "Could not change your password.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppShell title="Account Settings" subtitle="Your profile and password">
      <div className="acct-grid">
        <div className="card acct-card">
          <div className="chead"><h3>Profile</h3></div>
          <dl className="acct-dl">
            <dt>Name</dt><dd>{admin?.full_name || "—"}</dd>
            <dt>Email</dt><dd className="mono">{admin?.email || "—"}</dd>
            <dt>Role</dt>
            <dd>
              <span className={`role-pill role-${(admin?.role || "").toLowerCase()}`}>
                {admin?.role || "—"}
              </span>
              <p className="acct-note">{ROLE_DESC[admin?.role] || ""}</p>
            </dd>
            <dt>Last sign-in</dt>
            <dd>{admin?.last_login ? new Date(admin.last_login).toLocaleString() : "This session"}</dd>
          </dl>
          <button className="b b-line" onClick={logout}>Sign out</button>
        </div>

        <div className="card acct-card">
          <div className="chead"><h3>Change password</h3></div>

          {done && <div className="acct-ok" role="status">Your password has been changed.</div>}
          {error && <div className="acct-err" role="alert">{error}</div>}

          <form onSubmit={onSubmit}>
            <div className="field">
              <label htmlFor="cur">Current password</label>
              <input id="cur" className="input" type="password" autoComplete="current-password"
                     value={current} onChange={(e) => setCurrent(e.target.value)} required />
            </div>
            <div className="field">
              <label htmlFor="new">New password</label>
              <input id="new" className="input" type="password" autoComplete="new-password"
                     value={next} onChange={(e) => setNext(e.target.value)}
                     aria-describedby="acct-rules" required />
            </div>

            {/* Same NFR-11 checklist component behaviour as setup and reset, from
                the one shared policy module, so the three screens cannot drift. */}
            <ul className="pw-rules" id="acct-rules" aria-live="polite">
              <li className="pw-rules-title">Password must contain</li>
              {rules.map((r) => (
                <li key={r.id} className={`pw-rule ${r.passed ? "is-met" : "is-unmet"}`}>
                  <span className="pw-rule-mark" aria-hidden="true">{r.passed ? "✓" : "○"}</span>
                  <span>{r.label}</span>
                  <span className="sr-only">{r.passed ? " — met" : " — not yet met"}</span>
                </li>
              ))}
            </ul>

            <div className="field">
              <label htmlFor="cnf">Confirm new password</label>
              <input id="cnf" className="input" type="password" autoComplete="new-password"
                     value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
            </div>
            {confirm.length > 0 && (
              <p className={`pw-match ${matches ? "is-match" : "is-mismatch"}`} aria-live="polite">
                {matches ? "Passwords match." : "Passwords do not match."}
              </p>
            )}

            <button className="b b-primary" type="submit" disabled={!canSubmit}>
              {busy ? "Changing…" : "Change password"}
            </button>
          </form>
        </div>
      </div>

      {admin?.role === "SUPER_ADMIN" && <UserManagement />}
    </AppShell>
  );
}

/**
 * SUPER_ADMIN-only account management (Section 2.1).
 *
 * "Additional accounts are created by an authenticated SUPER_ADMIN through a
 * controlled account-management workflow." Before this existed, a second
 * account could only be produced by inserting a row into PostgreSQL by hand.
 *
 * Rendered only for SUPER_ADMIN, but that is presentation: the backend
 * requires the role on every one of these endpoints and returns 403 otherwise.
 */
function UserManagement() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ full_name: "", email: "", password: "", role: "VIEWER" });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRows(await listAccounts());
      setError("");
    } catch (e) {
      setError(e?.message || "Could not load accounts.");
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => { load(); }, [load]);

  const canSubmit = form.full_name.trim() && form.email.trim()
    && isCompliant(form.password) && !busy;

  async function onCreate(e) {
    e.preventDefault();
    setBusy(true); setError(""); setNotice("");
    try {
      const created = await createAccount(form);
      setNotice(`Created ${created.email} as ${created.role}.`);
      setForm({ full_name: "", email: "", password: "", role: "VIEWER" });
      setOpen(false);
      await load();
    } catch (err) {
      setError(err?.message || "Could not create that account.");
    } finally {
      setBusy(false);
    }
  }

  const rules = evaluate(form.password);

  return (
    <div className="card acct-users">
      <div className="chead">
        <h3>User accounts</h3>
        <button className="b b-primary sm" onClick={() => setOpen((v) => !v)}>
          {open ? "Cancel" : "+ Add user"}
        </button>
      </div>

      {notice && <div className="acct-ok" role="status">{notice}</div>}
      {error && <div className="acct-err" role="alert">{error}</div>}

      {open && (
        <form className="acct-newuser" onSubmit={onCreate}>
          <div className="acct-row">
            <div className="field">
              <label htmlFor="nu-name">Full name</label>
              <input id="nu-name" className="input" value={form.full_name}
                     onChange={(e) => setForm({ ...form, full_name: e.target.value })} required />
            </div>
            <div className="field">
              <label htmlFor="nu-email">Email address</label>
              <input id="nu-email" className="input" type="email" value={form.email}
                     onChange={(e) => setForm({ ...form, email: e.target.value })} required />
            </div>
            <div className="field">
              <label htmlFor="nu-role">Role</label>
              <select id="nu-role" className="input" value={form.role}
                      onChange={(e) => setForm({ ...form, role: e.target.value })}>
                <option value="VIEWER">VIEWER — read only</option>
                <option value="ADMIN">ADMIN — full operational access</option>
              </select>
            </div>
          </div>
          <div className="field">
            <label htmlFor="nu-pass">Initial password</label>
            <input id="nu-pass" className="input" type="password" autoComplete="new-password"
                   value={form.password}
                   onChange={(e) => setForm({ ...form, password: e.target.value })}
                   aria-describedby="nu-rules" required />
          </div>
          <ul className="pw-rules" id="nu-rules" aria-live="polite">
            <li className="pw-rules-title">Password must contain</li>
            {rules.map((r) => (
              <li key={r.id} className={`pw-rule ${r.passed ? "is-met" : "is-unmet"}`}>
                <span className="pw-rule-mark" aria-hidden="true">{r.passed ? "✓" : "○"}</span>
                <span>{r.label}</span>
              </li>
            ))}
          </ul>
          <p className="acct-note">
            The new user can change this password themselves from this page after
            signing in. SUPER_ADMIN accounts cannot be created here, and accounts
            are not deleted: audit history references the administrator who
            performed each action, so removing one would break that record.
          </p>
          <button className="b b-primary" type="submit" disabled={!canSubmit}>
            {busy ? "Creating…" : "Create account"}
          </button>
        </form>
      )}

      <div className="dt-wrap">
        <table className="dt">
          <thead>
            <tr><th>Name</th><th>Email</th><th>Role</th><th>Last sign-in</th></tr>
          </thead>
          <tbody>
            {loading && <tr><td colSpan={4} className="dt-empty">Loading accounts…</td></tr>}
            {!loading && rows.map((r) => (
              <tr key={r.admin_id}>
                <td>{r.full_name}</td>
                <td className="mono">{r.email}</td>
                <td>
                  <span className={`role-pill role-${(r.role || "").toLowerCase()}`}>{r.role}</span>
                </td>
                <td className="dt-time">
                  {r.last_login ? new Date(r.last_login).toLocaleString() : "Never"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
