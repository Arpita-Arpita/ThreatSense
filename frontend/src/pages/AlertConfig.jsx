// Alert Configuration screen (task 2.4, Figure 6, Section 2.5).
// Backed by /api/alert-config from task 2.1; the test button calls the sender
// wired up in task 2.3, so it works against the mock sender before SendGrid.
import { useCallback, useEffect, useMemo, useState } from "react";
import AppShell from "../components/AppShell";
import { getAlertConfig, saveAlertConfig, sendTestAlert } from "../api/alertConfig";
import { useAuth } from "../context/AuthContext";

const THRESHOLDS = [
  { value: "CRITICAL", label: "Critical", desc: "0.95+" },
  { value: "HIGH", label: "High", desc: "0.85+" },
  { value: "MEDIUM", label: "Medium", desc: "0.70+" },
  { value: "ALL", label: "All", desc: "everything" },
];

// The API stores TIME as HH:MM:SS; <input type="time"> speaks HH:MM.
const toInput = (t) => (t ? String(t).slice(0, 5) : "");
const toApi = (t) => (t ? `${t}:00` : null);

const EMAIL_RE = /^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$/;

function formOf(cfg) {
  return {
    email_enabled: cfg.email_enabled,
    email_recipient: cfg.email_recipient || "",
    severity_threshold: cfg.severity_threshold,
    quiet_start: toInput(cfg.quiet_start),
    quiet_end: toInput(cfg.quiet_end),
  };
}

/* Mirrors the server's merged-state rules so the user sees problems before
   saving. The server remains the authority — it revalidates everything. */
function validate(f) {
  const e = {};
  const email = f.email_recipient.trim();
  if (f.email_enabled && !email) {
    e.email_recipient = "A recipient is required while email alerts are enabled.";
  } else if (email && !EMAIL_RE.test(email)) {
    e.email_recipient = "Enter a valid email address.";
  }
  if (Boolean(f.quiet_start) !== Boolean(f.quiet_end)) {
    e.quiet = "Set both a start and an end time, or clear both.";
  } else if (f.quiet_start && f.quiet_start === f.quiet_end) {
    e.quiet = "Start and end must differ. Clear both to disable quiet hours.";
  }
  return e;
}

function Switch({ on, onClick, disabled, label }) {
  return (
    <button type="button" role="switch" aria-checked={on} aria-label={label}
            disabled={disabled} onClick={onClick}
            className={`sw${on ? " on" : ""}`}><i /></button>
  );
}

function Banner({ kind, children, onClose }) {
  return (
    <div className={`ac-banner ${kind}`} role={kind === "bad" ? "alert" : "status"}>
      <div>{children}</div>
      {onClose && <button className="x" onClick={onClose} aria-label="Dismiss">×</button>}
    </div>
  );
}

export default function AlertConfig() {
  // VIEWER may read the notification configuration but not change it or
  // trigger an external send (Section 2.1). Values stay visible and the
  // inputs are disabled; Save and Send test alert are not rendered.
  const { canWrite } = useAuth();
  const [form, setForm] = useState(null);
  const [saved, setSaved] = useState(null);      // last persisted state
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");          // "save" | "test"
  const [msg, setMsg] = useState(null);          // { kind, text }

  useEffect(() => {
    let alive = true;
    getAlertConfig()
      .then((cfg) => {
        if (!alive) return;
        setForm(formOf(cfg));
        setSaved(formOf(cfg));
      })
      .catch((err) => alive && setMsg({ kind: "bad", text: err.message }))
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, []);

  const errors = useMemo(() => (form ? validate(form) : {}), [form]);
  const dirty = useMemo(
    () => Boolean(form && saved) && JSON.stringify(form) !== JSON.stringify(saved),
    [form, saved]
  );
  const invalid = Object.keys(errors).length > 0;

  const set = useCallback((patch) => {
    setForm((f) => ({ ...f, ...patch }));
    setMsg(null);
  }, []);

  async function onSave() {
    if (invalid || !dirty) return;
    setBusy("save");
    setMsg(null);
    try {
      const cfg = await saveAlertConfig({
        email_enabled: form.email_enabled,
        email_recipient: form.email_recipient.trim() || null,
        severity_threshold: form.severity_threshold,
        quiet_start: toApi(form.quiet_start),
        quiet_end: toApi(form.quiet_end),
      });
      setForm(formOf(cfg));
      setSaved(formOf(cfg));
      setMsg({ kind: "ok", text: "Alert settings saved." });
    } catch (err) {
      setMsg({ kind: "bad", text: err.message || "Could not save settings." });
    } finally {
      setBusy("");
    }
  }

  async function onTest() {
    setBusy("test");
    setMsg(null);
    try {
      const r = await sendTestAlert();
      setMsg(
        r.delivered
          ? {
              kind: "ok",
              text: r.sender === "mock"
                ? `Test alert accepted by the mock sender for ${r.recipient}. Add a SendGrid API key to deliver real email.`
                : `Test alert sent to ${r.recipient}.`,
            }
          : { kind: "bad", text: `Delivery failed: ${r.detail || "unknown error"}` }
      );
    } catch (err) {
      setMsg({ kind: "bad", text: err.message || "Could not send the test alert." });
    } finally {
      setBusy("");
    }
  }

  const shell = {
    title: "Alert Configuration",
    subtitle: "Choose how and when you are notified about detections",
  };

  if (loading) {
    return (
      <AppShell {...shell}>
        <div className="card"><div className="empty">Loading settings…</div></div>
      </AppShell>
    );
  }
  if (!form) {
    return (
      <AppShell {...shell}>
        <div className="card">
          <Banner kind="bad">{msg?.text || "Settings unavailable."}</Banner>
        </div>
      </AppShell>
    );
  }

  const emailOff = !form.email_enabled;

  return (
    <AppShell {...shell}>
      <div className="ac-wrap">
        {msg && <Banner kind={msg.kind} onClose={() => setMsg(null)}>{msg.text}</Banner>}

        {/* --- channels --- */}
        <section className="card">
          <div className="chead"><h3>Notification channels</h3></div>

          <div className="ac-row">
            <div>
              <div className="ac-lab">Email notifications</div>
              <div className="ac-hint">
                Send an email when a detection meets the severity threshold below.
              </div>
            </div>
            <Switch on={form.email_enabled} label="Email notifications"
                    disabled={!canWrite}
                    onClick={() => set({ email_enabled: !form.email_enabled })} />
          </div>

          <div className="ac-row is-off">
            <div>
              <div className="ac-lab">
                SMS notifications<span className="ac-tag">Planned enhancement</span>
              </div>
              <div className="ac-hint">
                Twilio delivery is reserved in the schema and is not part of the MVP.
              </div>
            </div>
            <Switch on={false} disabled label="SMS notifications (unavailable)" />
          </div>
        </section>

        {/* --- email settings --- */}
        <section className="card">
          <div className="chead"><h3>Email settings</h3></div>

          <div className="field">
            <label htmlFor="recipient">Recipient email</label>
            <input id="recipient" type="email" autoComplete="email"
                   className={`input${errors.email_recipient ? " bad" : ""}`}
                   placeholder="admin@yourcompany.com.au"
                   value={form.email_recipient}
                   aria-invalid={Boolean(errors.email_recipient)}
                   onChange={(e) => set({ email_recipient: e.target.value })}
                   disabled={!canWrite} />
            {errors.email_recipient && <div className="ac-err">{errors.email_recipient}</div>}
          </div>

          <div className="field" style={{ marginBottom: 0 }}>
            <label>Severity threshold</label>
            <div className="ac-seg" role="group" aria-label="Severity threshold">
              {THRESHOLDS.map((t) => (
                <button key={t.value} type="button" disabled={!canWrite}
                        aria-pressed={form.severity_threshold === t.value}
                        className={form.severity_threshold === t.value ? "on" : ""}
                        onClick={() => set({ severity_threshold: t.value })}>
                  {t.label}<span className="d">{t.desc}</span>
                </button>
              ))}
            </div>
            <p className="ac-sub">
              Detections at or above this level are emailed. Lower-severity
              detections still appear on the dashboard.
            </p>
          </div>
        </section>

        {/* --- quiet hours --- */}
        <section className="card">
          <div className="chead"><h3>Quiet hours</h3></div>
          <p className="ac-sub" style={{ marginTop: 0, marginBottom: "1rem" }}>
            Hold non-critical email during this window. Critical detections are
            always delivered. A window may cross midnight, for example 22:00 to 06:00.
          </p>

          <div className="ac-two">
            <div className="field" style={{ marginBottom: 0 }}>
              <label htmlFor="qstart">Start time</label>
              <input id="qstart" type="time" className={`input${errors.quiet ? " bad" : ""}`}
                     value={form.quiet_start}
                     onChange={(e) => set({ quiet_start: e.target.value })}
                     disabled={!canWrite} />
            </div>
            <div className="field" style={{ marginBottom: 0 }}>
              <label htmlFor="qend">End time</label>
              <input id="qend" type="time" className={`input${errors.quiet ? " bad" : ""}`}
                     value={form.quiet_end}
                     onChange={(e) => set({ quiet_end: e.target.value })}
                     disabled={!canWrite} />
            </div>
          </div>
          {errors.quiet && <div className="ac-err">{errors.quiet}</div>}
          {canWrite && (form.quiet_start || form.quiet_end) && !errors.quiet && (
            <button className="link" style={{ marginTop: ".7rem" }}
                    onClick={() => set({ quiet_start: "", quiet_end: "" })}>
              Clear quiet hours
            </button>
          )}
        </section>

        {/* --- actions --- */}
        <div className="ac-actions">
          {canWrite ? (
            <>
              <button className="b b-primary" disabled={!dirty || invalid || Boolean(busy)}
                      onClick={onSave}>
                {busy === "save" ? "Saving…" : "Save settings"}
              </button>
              <button className="b b-line" onClick={onTest}
                      disabled={emailOff || Boolean(busy) || Boolean(errors.email_recipient)}
                      title={emailOff ? "Enable email notifications first" : undefined}>
                {busy === "test" ? "Sending…" : "Send test alert"}
              </button>
            </>
          ) : <span className="ac-sub">Read-only access</span>}
          <span className="sp" />
          {dirty && !invalid && <span className="ac-sub">Unsaved changes</span>}
        </div>
      </div>
    </AppShell>
  );
}
