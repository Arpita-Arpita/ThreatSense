// Add / Edit Syslog Source modal (task 4.1, Figure 5, UC 4.2).
//
// Validation mirrors the server's SourceCreate schema so the admin sees a
// problem before a round trip; the server stays the authority and revalidates.
// The port helper text is deliberately opinionated: 6514 over TLS is the only
// combination fit for production, and saying so at the point of choice is
// worth more than a line in the docs nobody opens.
import { useEffect, useState } from "react";
import { IconClose } from "../components/icons";

const TRANSPORTS = [
  { value: "TLS", label: "TLS", hint: "Encrypted. The only production-safe choice." },
  { value: "TCP", label: "TCP", hint: "Plaintext, reliable delivery. Testing only." },
  { value: "UDP", label: "UDP", hint: "Plaintext, best-effort. Classic syslog; testing only." },
];

// Figure 5 specifies IPv4 validation. The API accepts any valid IP, so this is
// the stricter of the two rules and the one the brief asks for.
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

const BLANK = {
  name: "", type: "SYSLOG", transport: "TLS",
  ip_address: "", port: "6514", status: "ACTIVE",
};

function validate(f) {
  const e = {};
  if (!f.name.trim()) e.name = "Give the source a name.";
  else if (f.name.trim().length > 100) e.name = "Maximum 100 characters.";

  if (f.ip_address.trim() && !IPV4_RE.test(f.ip_address.trim())) {
    e.ip_address = "Enter a valid IPv4 address, e.g. 192.168.1.20.";
  }
  if (f.port !== "") {
    const p = Number(f.port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      e.port = "Port must be a whole number between 1 and 65535.";
    }
  }
  return e;
}

/** Warn where the transport/port pairing is defensible but not production-safe. */
function portNote(transport, port) {
  const p = Number(port);
  if (transport === "TLS" && p !== 6514) {
    return { kind: "warn", text: "TLS syslog is conventionally 6514. Change the port only if your collector differs." };
  }
  if (p === 514) {
    return { kind: "warn", text: "Port 514 needs root to bind. Use 1514 for local testing — that is what the listener defaults to." };
  }
  if (transport !== "TLS") {
    return { kind: "warn", text: "Plaintext transport. Acceptable for testing; use TLS on 6514 in production." };
  }
  return { kind: "ok", text: "TLS on 6514 — production configuration." };
}

export default function SourceModal({ source, onClose, onSaved, save }) {
  const editing = Boolean(source);
  const [form, setForm] = useState(BLANK);
  const [errors, setErrors] = useState({});
  const [busy, setBusy] = useState(false);
  const [serverError, setServerError] = useState(null);

  useEffect(() => {
    setForm(source ? {
      name: source.name || "",
      type: source.type || "SYSLOG",
      transport: source.transport || "TLS",
      ip_address: source.ip_address || "",
      port: source.port == null ? "" : String(source.port),
      status: source.status || "ACTIVE",
    } : BLANK);
    setErrors({});
    setServerError(null);
  }, [source]);

  // Escape closes, matching the drawer's behaviour elsewhere in the app.
  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const set = (patch) => { setForm((f) => ({ ...f, ...patch })); setServerError(null); };

  async function onSubmit() {
    const found = validate(form);
    setErrors(found);
    if (Object.keys(found).length) return;

    setBusy(true);
    setServerError(null);
    try {
      const saved = await save({
        name: form.name.trim(),
        type: form.type,
        transport: form.transport,
        ip_address: form.ip_address.trim() || null,
        port: form.port === "" ? null : Number(form.port),
        status: form.status,
      });
      onSaved(saved, editing);
    } catch (err) {
      setServerError(err.message || "Could not save the source.");
    } finally {
      setBusy(false);
    }
  }

  const note = portNote(form.transport, form.port);

  return (
    <>
      <div className="scrim" onClick={onClose} />
      <div className="ls-modal" role="dialog" aria-modal="true"
           aria-labelledby="ls-modal-title">
        <div className="ls-mhead">
          <h3 id="ls-modal-title">{editing ? "Edit Source" : "Add Syslog Source"}</h3>
          <button className="xbtn" onClick={onClose} aria-label="Close"><IconClose /></button>
        </div>

        {serverError && <div className="dd-banner bad" role="alert">{serverError}</div>}

        <div className="field">
          <label htmlFor="src-name">Source name</label>
          <input
            id="src-name" className={`input${errors.name ? " bad" : ""}`}
            value={form.name} placeholder="edge-firewall"
            onChange={(e) => set({ name: e.target.value })}
            aria-invalid={Boolean(errors.name)}
          />
          {errors.name && <span className="ac-err">{errors.name}</span>}
        </div>

        <div className="field">
          <label>Transport mode</label>
          <div className="ls-seg" role="radiogroup" aria-label="Transport mode">
            {TRANSPORTS.map((t) => (
              <button
                key={t.value} type="button" role="radio"
                aria-checked={form.transport === t.value}
                className={form.transport === t.value ? "on" : ""}
                onClick={() => set({
                  transport: t.value,
                  // Nudge the port to the convention for the chosen transport,
                  // but never clobber a port the admin typed deliberately.
                  port: form.port === "" || form.port === "6514" || form.port === "1514"
                    ? (t.value === "TLS" ? "6514" : "1514")
                    : form.port,
                })}
              >
                {t.label}
              </button>
            ))}
          </div>
          <span className="ac-hint">
            {TRANSPORTS.find((t) => t.value === form.transport)?.hint}
          </span>
        </div>

        <div className="ls-two">
          <div className="field">
            <label htmlFor="src-ip">IP address <span className="ls-opt">optional</span></label>
            <input
              id="src-ip" className={`input${errors.ip_address ? " bad" : ""}`}
              value={form.ip_address} placeholder="192.168.1.20"
              onChange={(e) => set({ ip_address: e.target.value })}
              aria-invalid={Boolean(errors.ip_address)}
            />
            {errors.ip_address
              ? <span className="ac-err">{errors.ip_address}</span>
              : <span className="ac-hint">Leave blank to accept from any address.</span>}
          </div>

          <div className="field">
            <label htmlFor="src-port">Port</label>
            <input
              id="src-port" className={`input${errors.port ? " bad" : ""}`}
              value={form.port} inputMode="numeric" placeholder="6514"
              onChange={(e) => set({ port: e.target.value.replace(/[^\d]/g, "") })}
              aria-invalid={Boolean(errors.port)}
            />
            {errors.port && <span className="ac-err">{errors.port}</span>}
          </div>
        </div>

        <p className={`ls-note ${note.kind}`}>{note.text}</p>

        <div className="ls-mfoot">
          <button className="b b-line" onClick={onClose}>Cancel</button>
          <button className="b b-primary" onClick={onSubmit} disabled={busy}>
            {busy ? "Saving…" : editing ? "Save changes" : "Add source"}
          </button>
        </div>
      </div>
    </>
  );
}
