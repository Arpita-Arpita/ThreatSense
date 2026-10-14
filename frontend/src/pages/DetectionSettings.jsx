// Detection Settings screen (task 4.2, Figure 8).
//
// Sensitivity slider (0.50-0.99), model-version selector, precision/recall/F1
// metric card from task 1.10's evaluation, and Run Manual Scan.
//
// The metric card reads the precomputed threshold sweep from
// ml/metrics/<version>.metrics.json, so dragging the slider shows what the
// model WOULD score at that sensitivity without saving anything and without
// running inference per request. If the artefact is missing the card says so
// and prints the command — it never shows a number it cannot source.
//
// NOTE: element inventory follows the task 4.2 brief; the arrangement is
// inferred and should be reconciled against Figure 8 in the proposal.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import AppShell from "../components/AppShell";
import {
  getMetrics, getSettings, listModels, runManualScan, saveSettings,
} from "../api/settings";
import { IconClose, IconRefresh } from "../components/icons";
import { useAuth } from "../context/AuthContext";

const MIN = 0.5;
const MAX = 0.99;
const DEFAULT = 0.75;

function pct(v) {
  return v == null ? "—" : `${(v * 100).toFixed(1)}%`;
}

function when(iso) {
  if (!iso) return "unknown";
  return new Date(iso).toLocaleString(undefined, {
    day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

/** Plain-language reading of what a sensitivity value means operationally. */
function sensitivityNote(v) {
  if (v <= 0.6) return "Very sensitive — catches more, expect more false positives.";
  if (v <= 0.72) return "Sensitive — errs towards flagging borderline traffic.";
  if (v <= 0.82) return "Balanced — the recommended starting point.";
  if (v <= 0.92) return "Conservative — fewer alerts, higher confidence in each.";
  return "Very conservative — only the most extreme anomalies are flagged.";
}

/** Precision/recall curve across the sweep, drawn from the same data as the
    metric card so the two can never disagree. */
function Curve({ sweep, threshold }) {
  if (!sweep?.length) return null;
  const W = 260;
  const H = 90;
  const PAD = 5;            // keep a line at 1.0 inside the viewBox, not on its edge
  const x = (t) => ((t - MIN) / (MAX - MIN)) * W;
  const y = (v) => PAD + (1 - v) * (H - 2 * PAD);
  const line = (key) => sweep.map((r, i) =>
    `${i ? "L" : "M"}${x(r.threshold).toFixed(1)},${y(r[key]).toFixed(1)}`).join(" ");

  return (
    <svg className="ds-curve" viewBox={`0 0 ${W} ${H}`} role="img"
         aria-label="Precision and recall across sensitivity thresholds">
      <line x1="0" y1={H} x2={W} y2={H} className="ds-axis" />
      <path d={line("recall")} className="ds-recall" />
      <path d={line("precision")} className="ds-precision" />
      <line x1={x(threshold)} y1="0" x2={x(threshold)} y2={H} className="ds-marker" />
    </svg>
  );
}

export default function DetectionSettings() {
  // VIEWER may inspect the configuration and the model metrics but not change
  // them (Section 2.1). Inputs are disabled rather than hidden so the current
  // values stay readable; the actions that would 403 are not rendered.
  const { canWrite } = useAuth();
  const [saved, setSaved] = useState(null);
  const [form, setForm] = useState(null);
  const [models, setModels] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(null);      // "save" | "scan" | null
  const [scan, setScan] = useState(null);
  const metricsSeq = useRef(0);

  const load = useCallback(async () => {
    try {
      const [cfg, mods] = await Promise.all([getSettings(), listModels()]);
      setSaved(cfg);
      setForm({
        sensitivity_threshold: cfg.sensitivity_threshold,
        active_model_version: cfg.active_model_version,
        detection_interval_seconds: cfg.detection_interval_seconds,
      });
      setModels(mods);
    } catch (err) {
      setMsg({ kind: "bad", text: err.message || "Could not load detection settings." });
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Preview metrics for the slider position. Sequence-guarded so a slow
  // response for an old position cannot overwrite a newer one.
  useEffect(() => {
    if (!form) return undefined;
    const seq = ++metricsSeq.current;
    const timer = setTimeout(async () => {
      try {
        const data = await getMetrics(form.sensitivity_threshold);
        if (seq === metricsSeq.current) setMetrics(data);
      } catch {
        if (seq === metricsSeq.current) setMetrics({ available: false });
      }
    }, 120);
    return () => clearTimeout(timer);
  }, [form?.sensitivity_threshold, form?.active_model_version]);

  useEffect(() => {
    if (!msg || msg.kind !== "ok") return undefined;
    const t = setTimeout(() => setMsg(null), 4000);
    return () => clearTimeout(t);
  }, [msg]);

  const dirty = useMemo(() => {
    if (!form || !saved) return false;
    return form.sensitivity_threshold !== saved.sensitivity_threshold
      || form.active_model_version !== saved.active_model_version
      || form.detection_interval_seconds !== saved.detection_interval_seconds;
  }, [form, saved]);

  async function onSave() {
    setBusy("save");
    setMsg(null);
    try {
      const cfg = await saveSettings(form);
      setSaved(cfg);
      setForm({
        sensitivity_threshold: cfg.sensitivity_threshold,
        active_model_version: cfg.active_model_version,
        detection_interval_seconds: cfg.detection_interval_seconds,
      });
      setMsg({ kind: "ok", text: "Detection settings saved and recorded in the audit log." });
    } catch (err) {
      setMsg({ kind: "bad", text: err.message || "Could not save settings." });
    } finally {
      setBusy(null);
    }
  }

  async function onScan() {
    setBusy("scan");
    setMsg(null);
    setScan(null);
    try {
      const result = await runManualScan();
      setScan(result);
    } catch (err) {
      setMsg({ kind: "bad", text: err.message || "Scan failed." });
    } finally {
      setBusy(null);
    }
  }

  if (!form) {
    return (
      <AppShell title="Detection Settings" subtitle="Engine sensitivity and model">
        <div className="card"><div className="dd-skel" /><div className="dd-skel short" /></div>
      </AppShell>
    );
  }

  const at = metrics?.at_threshold;
  const previewing = metrics?.available
    && Math.abs(metrics.threshold - saved.sensitivity_threshold) > 0.001;

  return (
    <AppShell title="Detection Settings" subtitle="Engine sensitivity and model">
      {msg && (
        <div className={`dd-banner ${msg.kind}`} role={msg.kind === "bad" ? "alert" : "status"}>
          <span>{msg.text}</span>
          <button className="xbtn sm" onClick={() => setMsg(null)} aria-label="Dismiss">
            <IconClose />
          </button>
        </div>
      )}

      <div className="ds-grid">
        <div className="ds-left">
          <div className="card">
            <div className="chead"><h3>Sensitivity</h3></div>
            <p className="ac-sub">
              The normalised anomaly score a traffic window must reach before it
              becomes a detection. Lower catches more and flags more harmless
              traffic; higher does the reverse.
            </p>

            <div className="ds-slider">
              <output className="ds-value">{form.sensitivity_threshold.toFixed(2)}</output>
              <input
                type="range" min={MIN} max={MAX} step="0.01"
                value={form.sensitivity_threshold}
                aria-label="Sensitivity threshold"
                aria-valuemin={MIN} aria-valuemax={MAX}
                aria-valuenow={form.sensitivity_threshold}
                onChange={(e) => setForm((f) => ({
                  ...f, sensitivity_threshold: Number(e.target.value),
                }))}
                disabled={!canWrite}
              />
              <div className="ds-ticks">
                <span>{MIN.toFixed(2)} more alerts</span>
                <span>{MAX} fewer alerts</span>
              </div>
              <p className="ds-note">{sensitivityNote(form.sensitivity_threshold)}</p>
              {canWrite && form.sensitivity_threshold !== DEFAULT && (
                <button className="ds-reset"
                        onClick={() => setForm((f) => ({ ...f, sensitivity_threshold: DEFAULT }))}>
                  Reset to default ({DEFAULT})
                </button>
              )}
            </div>
          </div>

          <div className="card">
            <div className="chead"><h3>Model</h3></div>
            <div className="field">
              <label htmlFor="ds-model">Active model version</label>
              <select
                id="ds-model" className="input"
                value={form.active_model_version}
                onChange={(e) => setForm((f) => ({
                  ...f, active_model_version: e.target.value,
                }))}
                disabled={!canWrite}
              >
                {models.map((m) => (
                  <option key={m.version} value={m.version}>
                    {m.version}{m.has_metrics ? "" : " — no evaluation"}
                  </option>
                ))}
              </select>
              <span className="ac-hint">
                Versions found in <span className="mono">ml/models/</span>. The engine
                loads the selected bundle on its next cycle.
              </span>
            </div>

            <div className="field">
              <label htmlFor="ds-interval">Detection interval (seconds)</label>
              <input
                id="ds-interval" className="input" inputMode="numeric"
                value={form.detection_interval_seconds}
                onChange={(e) => setForm((f) => ({
                  ...f,
                  detection_interval_seconds: Number(e.target.value.replace(/\D/g, "") || 0),
                }))}
                disabled={!canWrite}
              />
              <span className="ac-hint">How often the engine analyses unprocessed logs.</span>
            </div>
          </div>

          <div className="ds-actions">
            <p className="ds-audit">
              Configuration changes are recorded in the audit log with the previous
              and new values, and attributed to your account.
            </p>
            <div className="ds-btns">
              {dirty && (
                <button className="b b-line" onClick={() => setForm({
                  sensitivity_threshold: saved.sensitivity_threshold,
                  active_model_version: saved.active_model_version,
                  detection_interval_seconds: saved.detection_interval_seconds,
                })}>Discard</button>
              )}
              {canWrite && (
                <button className="b b-primary" onClick={onSave} disabled={!dirty || busy}>
                  {busy === "save" ? "Saving…" : "Save changes"}
                </button>
              )}
            </div>
          </div>
        </div>

        <div className="ds-right">
          <div className="card">
            <div className="chead">
              <h3>Model performance</h3>
              {previewing && <span className="ds-preview">preview</span>}
            </div>

            {!metrics?.available && (
              <div className="ds-nometrics">
                <p>{metrics?.message || "No evaluation results for this model yet."}</p>
                <code>cd ml &amp;&amp; python evaluate.py --json</code>
              </div>
            )}

            {metrics?.available && at && (
              <>
                <div className="ds-metrics">
                  <div className="ds-metric">
                    <span className="ds-mv">{pct(at.precision)}</span>
                    <span className="ds-mk">Precision</span>
                    <span className="ds-mh">of flagged windows were real attacks</span>
                  </div>
                  <div className="ds-metric">
                    <span className="ds-mv">{pct(at.recall)}</span>
                    <span className="ds-mk">Recall</span>
                    <span className="ds-mh">of attacks were caught</span>
                  </div>
                  <div className="ds-metric">
                    <span className="ds-mv">{pct(at.f1)}</span>
                    <span className="ds-mk">F1</span>
                    <span className="ds-mh">balance of the two</span>
                  </div>
                </div>

                <Curve sweep={metrics.sweep} threshold={metrics.threshold} />
                <div className="ds-legend">
                  <span><i className="k-p" /> Precision</span>
                  <span><i className="k-r" /> Recall</span>
                  <span><i className="k-m" /> Current</span>
                </div>

                <div className="drow"><span className="k">At threshold</span>
                  <span className="v mono">{metrics.threshold.toFixed(2)}</span></div>
                <div className="drow"><span className="k">Confusion (TP/FP/TN/FN)</span>
                  <span className="v mono">{at.tp}/{at.fp}/{at.tn}/{at.fn}</span></div>
                {Object.entries(metrics.recall_by_attack_kind || {}).map(([kind, v]) => (
                  <div className="drow" key={kind}>
                    <span className="k">Recall · {kind.replace(/_/g, " ")}</span>
                    <span className="v mono">{pct(v)}</span>
                  </div>
                ))}

                <p className="ds-caveat">
                  Measured against {metrics.dataset?.attack_windows ?? "—"} synthetic
                  attack windows and {metrics.dataset?.normal_windows ?? "—"} normal
                  windows generated by <span className="mono">ml/synth.py</span>, the
                  same process used to train the model. These figures show internal
                  consistency, not real-world accuracy — validation against live
                  attack traffic is a separate exercise.
                </p>
                <p className="ds-gen">
                  Evaluated {when(metrics.generated_at)}
                  {metrics.stale_days > 14 && (
                    <span className="ds-stale"> · {metrics.stale_days} days old — re-run
                      evaluate.py if the model has been retrained</span>
                  )}
                </p>
              </>
            )}
          </div>

          <div className="card">
            {/* The action sits in the card header, which is where a card's
                primary action belongs. It previously hung below the body copy
                with nothing aligning it, so it read as an afterthought. */}
            <div className="chead">
              <h3>Manual scan</h3>
              {canWrite && (
                <button className="b b-primary sm" onClick={onScan} disabled={Boolean(busy)}>
                  <IconRefresh /> {busy === "scan" ? "Scanning…" : "Run scan now"}
                </button>
              )}
            </div>
            <p className="ac-sub">
              Runs one detection cycle immediately over any logs not yet analysed,
              using the saved settings. Same code path as the scheduled engine,
              so the results are directly comparable.
            </p>

            {busy === "scan" && (
              <div className="ds-progress" role="status" aria-live="polite">
                <span className="ds-bar"><i /></span>
                <span>Analysing unprocessed logs…</span>
              </div>
            )}

            {scan && !busy && (
              <div className="ds-scan" role="status">
                <div className="drow"><span className="k">Logs analysed</span>
                  <span className="v mono">{scan.logs_processed}</span></div>
                <div className="drow"><span className="k">Detections created</span>
                  <span className="v mono">{scan.detections_created}</span></div>
                <div className="drow"><span className="k">Duration</span>
                  <span className="v mono">{scan.duration_ms} ms</span></div>
                {scan.logs_processed === 0 && (
                  <p className="ds-note">
                    Nothing to analyse — every ingested log has already been processed.
                  </p>
                )}
              </div>
            )}
          </div>

          {saved && (
            <p className="ds-updated">
              Last changed {when(saved.updated_at)}
              {saved.updated_by_name ? ` by ${saved.updated_by_name}` : ""}.
            </p>
          )}
        </div>
      </div>
    </AppShell>
  );
}
