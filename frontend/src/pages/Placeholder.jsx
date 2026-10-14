import AppShell from "../components/AppShell";

export default function Placeholder({ title, note }) {
  return (
    <AppShell title={title} subtitle="Coming in a later task">
      <div className="card placeholder-page">
        <h3>{title}</h3>
        <p>{note || "This screen is part of a later task. The backend APIs are ready."}</p>
      </div>
    </AppShell>
  );
}
