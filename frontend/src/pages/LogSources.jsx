// Log Sources Management screen (task 4.1, Figure 5, UC 4.2).
//
// Table of configured sources with a live status indicator, plus Add / Edit /
// Delete and log-file upload. Everything here talks to the data_sources API
// built in task 1.8 — no new backend surface was needed.
//
// NOTE: the column set and the Add Syslog Source modal follow the task 4.1
// brief. Row actions (edit, upload, delete) come from Use Case 4.2 and the
// endpoints that already exist; reconcile the arrangement against Figure 5.
import { useCallback, useEffect, useRef, useState } from "react";
import AppShell from "../components/AppShell";
import SourceModal from "../sources/SourceModal";
import {
  createSource, deleteSource, listSources, updateSource, uploadLogs,
} from "../api/sources";
import { IconClose, IconLogs, IconPlus, IconSettings } from "../components/icons";
import { timeAgo } from "../lib/format";
import { useAuth } from "../context/AuthContext";

const STATUS_LABEL = { ACTIVE: "Active", INACTIVE: "Inactive", ERROR: "Error" };

/** A source is "live" if it has actually received something recently — the
    stored status alone can say ACTIVE for a collector that has gone quiet. */
function liveness(source) {
  if (source.status === "ERROR") return { dot: "err", text: "Error" };
  if (!source.last_received) return { dot: "off", text: "Never received" };
  const mins = (Date.now() - new Date(source.last_received).getTime()) / 60000;
  if (source.status !== "ACTIVE") return { dot: "off", text: STATUS_LABEL[source.status] };
  return mins <= 15
    ? { dot: "on", text: "Receiving" }
    : { dot: "idle", text: "Idle" };
}

export default function LogSources() {
  // VIEWER is read-only (Section 2.1). The table, statuses and last-received
  // times stay visible — inspection is exactly what the role is for — but the
  // controls that would 403 are not rendered. Backend remains the authority.
  const { canWrite } = useAuth();
  const [sources, setSources] = useState(null);
  const [modal, setModal] = useState(null);      // null | {source?}
  const [msg, setMsg] = useState(null);
  const [confirm, setConfirm] = useState(null);  // source pending deletion
  const [uploadingId, setUploadingId] = useState(null);
  const fileInput = useRef(null);
  const uploadTarget = useRef(null);

  const load = useCallback(async () => {
    try {
      setSources(await listSources());
    } catch (err) {
      setMsg({ kind: "bad", text: err.message || "Could not load sources." });
      setSources([]);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!msg || msg.kind !== "ok") return undefined;
    const t = setTimeout(() => setMsg(null), 4000);
    return () => clearTimeout(t);
  }, [msg]);

  function onSaved(saved, editing) {
    setSources((list) => (editing
      ? list.map((s) => (s.source_id === saved.source_id ? saved : s))
      : [saved, ...list]));
    setModal(null);
    setMsg({ kind: "ok", text: editing ? `Updated “${saved.name}”.` : `Added “${saved.name}”.` });
  }

  async function onDelete(source) {
    try {
      await deleteSource(source.source_id);
      setSources((list) => list.filter((s) => s.source_id !== source.source_id));
      setMsg({ kind: "ok", text: `Deleted “${source.name}”.` });
    } catch (err) {
      // 409 is the server refusing to orphan detections — surface it as the
      // meaningful constraint it is, not as a generic failure.
      setMsg({
        kind: "bad",
        text: err.status === 409
          ? `“${source.name}” has detections linked to it and cannot be deleted. Set it to Inactive instead.`
          : err.message || "Could not delete the source.",
      });
    } finally {
      setConfirm(null);
    }
  }

  function pickFile(source) {
    uploadTarget.current = source;
    fileInput.current?.click();
  }

  async function onFileChosen(e) {
    const file = e.target.files?.[0];
    const source = uploadTarget.current;
    e.target.value = "";               // allow re-picking the same file
    if (!file || !source) return;

    setUploadingId(source.source_id);
    setMsg(null);
    try {
      const result = await uploadLogs(source.source_id, file);
      setMsg({
        kind: "ok",
        text: `Ingested ${result.parsed} record${result.parsed === 1 ? "" : "s"} into “${source.name}”`
          + (result.skipped ? ` · ${result.skipped} line(s) skipped as unparseable.` : "."),
      });
      await load();                    // last_received and status have moved
    } catch (err) {
      setMsg({ kind: "bad", text: err.message || "Upload failed." });
    } finally {
      setUploadingId(null);
    }
  }

  return (
    <AppShell
      title="Log Sources"
      subtitle="Collectors feeding the detection engine"
      sources={sources?.filter((s) => s.status === "ACTIVE").length || 0}
    >
      <input ref={fileInput} type="file" hidden onChange={onFileChosen}
             accept=".log,.txt,.syslog,text/plain" />

      <div className="ls-bar">
        <p className="ls-count">
          {sources === null ? "Loading…"
            : `${sources.length} source${sources.length === 1 ? "" : "s"} configured`}
        </p>
        {canWrite && (
          <button className="b b-primary" onClick={() => setModal({})}>
            <IconPlus /> Add Source
          </button>
        )}
      </div>

      {msg && (
        <div className={`dd-banner ${msg.kind}`} role={msg.kind === "bad" ? "alert" : "status"}>
          <span>{msg.text}</span>
          <button className="xbtn sm" onClick={() => setMsg(null)} aria-label="Dismiss">
            <IconClose />
          </button>
        </div>
      )}

      <div className="card ls-card">
        {sources === null && <div className="dd-skel" />}

        {sources?.length === 0 && (
          <div className="dd-empty">
            <p>
              No log sources yet. Add one to tell ThreatSense where syslog will
              arrive from, or add a source and upload a log file to analyse
              traffic you have already captured.
            </p>
            {canWrite && (
              <button className="b b-primary" onClick={() => setModal({})}>
                <IconPlus /> Add Source
              </button>
            )}
          </div>
        )}

        {sources?.length > 0 && (
          <table className="ls-table">
            <thead>
              <tr>
                <th>Name</th><th>Type</th><th>Transport</th><th>IP address</th>
                <th>Status</th><th>Last received</th><th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {sources.map((s) => {
                const live = liveness(s);
                return (
                  <tr key={s.source_id}>
                    <td className="ls-name">{s.name}</td>
                    <td>{s.type}</td>
                    <td className="mono">{s.transport || "—"}</td>
                    <td className="mono">
                      {s.ip_address || "any"}{s.port ? `:${s.port}` : ""}
                    </td>
                    <td>
                      <span className="ls-status">
                        <i className={`ls-dot ${live.dot}`} aria-hidden="true" />
                        {live.text}
                      </span>
                    </td>
                    <td className="ls-when">
                      {s.last_received ? timeAgo(s.last_received) : "—"}
                    </td>
                    <td className="ls-actions">
                      {canWrite ? (
                        <>
                          <button className="b b-line sm" onClick={() => pickFile(s)}
                                  disabled={uploadingId === s.source_id}>
                            <IconLogs /> {uploadingId === s.source_id ? "Uploading…" : "Upload"}
                          </button>
                          <button className="b b-line sm" onClick={() => setModal({ source: s })}>
                            <IconSettings /> Edit
                          </button>
                          <button className="b b-line sm danger" onClick={() => setConfirm(s)}>
                            Delete
                          </button>
                        </>
                      ) : <span className="ls-when">Read only</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {modal && (
        <SourceModal
          source={modal.source}
          onClose={() => setModal(null)}
          onSaved={onSaved}
          save={(payload) => (modal.source
            ? updateSource(modal.source.source_id, payload)
            : createSource(payload))}
        />
      )}

      {confirm && (
        <>
          <div className="scrim" onClick={() => setConfirm(null)} />
          <div className="ls-modal sm" role="dialog" aria-modal="true">
            <div className="ls-mhead"><h3>Delete this source?</h3></div>
            <p className="ls-confirm">
              “{confirm.name}” and its ingested log records will be removed. Any
              detections already raised from it will block the deletion — set the
              source to Inactive instead if you only want to stop collecting.
            </p>
            <div className="ls-mfoot">
              <button className="b b-line" onClick={() => setConfirm(null)}>Cancel</button>
              <button className="b b-primary danger" onClick={() => onDelete(confirm)}>
                Delete source
              </button>
            </div>
          </div>
        </>
      )}
    </AppShell>
  );
}
