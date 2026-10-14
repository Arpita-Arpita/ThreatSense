"""
NFR-07 concurrency load test.

Proposal Section 3, Table 11, NFR-07 — Requirement (verbatim):
    "The system shall support at least five concurrent administrator sessions
    without API response times increasing by more than 30% relative to the
    single-user baseline."

Proposal Section 3, Table 11, NFR-07 — Measurement / Metric (verbatim):
    "Load testing with Locust or k6 to simulate five concurrent sessions; API
    response times compared with the single-user baseline."

Locust is used rather than k6 because the venv is already Python — Table 11
names either.

HOW TO RUN — two passes, and the comparison is the whole point
--------------------------------------------------------------
    pip install locust

    # Pass 1 — the single-user BASELINE
    locust -f scripts/nfr07_locustfile.py --headless \
           -u 1 -r 1 -t 3m --host http://localhost:8000 \
           --csv=var/nfr07_baseline

    # Pass 2 — FIVE concurrent sessions
    locust -f scripts/nfr07_locustfile.py --headless \
           -u 5 -r 1 -t 3m --host http://localhost:8000 \
           --csv=var/nfr07_concurrent

Then compare:
    python scripts/nfr07_locustfile.py --compare

IMPORTANT — the NFR-05 interaction
----------------------------------
Each simulated user logs in once at start (on_start) and reuses the session
cookie, so a 5-user run performs 5 logins total. That is exactly at the
NFR-05 per-IP limit of 5 per 15 minutes, and all of them come from one IP.

Consequences:
  * Do NOT raise -u above 5 without restarting the API first, or the extra
    users will 429 on login and their failures will pollute the numbers.
  * Leave 15 minutes between the two passes, OR restart uvicorn between them
    (in-memory counters clear on restart). The second pass otherwise starts
    with an exhausted window.

Run the API with a SINGLE worker for this test, matching the NFR-05 evidence
conditions.
"""
from __future__ import annotations

import os
import sys

# --compare runs standalone, without Locust, so keep the import optional.
if "--compare" not in sys.argv:
    from locust import HttpUser, between, task

    ADMIN_EMAIL = os.getenv("NFR07_EMAIL", "admin@threatsense.local")
    ADMIN_PASSWORD = os.getenv("NFR07_PASSWORD", "ChangeMe123!")

    class AdministratorSession(HttpUser):
        """One administrator working through the dashboard.

        The task weights approximate a real session: the dashboard is polled
        often, detail views and reports are opened occasionally. Weighting
        matters — hammering one cheap endpoint would produce a flattering
        baseline that the concurrent run then trivially matches.
        """

        wait_time = between(1, 3)

        def on_start(self):
            """Authenticate once; the HttpOnly cookie rides on later requests."""
            with self.client.post("/api/auth/login",
                                  json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                                  catch_response=True) as res:
                if res.status_code == 429:
                    res.failure("429 from NFR-05 login limiter — restart the API "
                                "or wait 15 minutes between passes (see module docstring)")
                elif res.status_code != 200:
                    res.failure(f"login failed: {res.status_code}")

        @task(10)
        def dashboard_detections(self):
            self.client.get("/api/detections?limit=25", name="GET /api/detections")

        @task(6)
        def detection_stats(self):
            self.client.get("/api/detections/stats", name="GET /api/detections/stats")

        @task(4)
        def system_health(self):
            self.client.get("/health", name="GET /health")

        @task(3)
        def sources(self):
            self.client.get("/api/sources", name="GET /api/sources")

        @task(2)
        def settings_view(self):
            self.client.get("/api/settings", name="GET /api/settings")

        @task(1)
        def whoami(self):
            self.client.get("/api/auth/me", name="GET /api/auth/me")


def compare() -> None:
    """Compare the two CSV runs against the 30% threshold in Table 11."""
    import csv
    from pathlib import Path

    var = Path(__file__).resolve().parents[1] / "var"
    baseline_path = var / "nfr07_baseline_stats.csv"
    concurrent_path = var / "nfr07_concurrent_stats.csv"

    for p in (baseline_path, concurrent_path):
        if not p.exists():
            sys.exit(f"Missing {p}. Run both Locust passes first (see module docstring).")

    def load(path):
        rows = {}
        with open(path) as fh:
            for row in csv.DictReader(fh):
                if row["Name"] == "Aggregated":
                    continue
                rows[row["Name"]] = {
                    "median": float(row["Median Response Time"]),
                    "p95": float(row.get("95%", 0) or 0),
                    "requests": int(row["Request Count"]),
                    "failures": int(row["Failure Count"]),
                }
        return rows

    base, conc = load(baseline_path), load(concurrent_path)

    print("NFR-07 concurrency — 5 sessions vs single-user baseline")
    print("Threshold: response times must not increase by more than 30%\n")
    print(f"{'Endpoint':<36} {'Base ms':>9} {'5-user ms':>10} {'Change':>9}  Result")
    print("-" * 78)

    worst = 0.0
    any_failures = False
    for name in sorted(base):
        if name not in conc:
            continue
        b, c = base[name]["median"], conc[name]["median"]
        if b <= 0:
            continue
        change = (c - b) / b * 100
        worst = max(worst, change)
        if conc[name]["failures"] or base[name]["failures"]:
            any_failures = True
        print(f"{name:<36} {b:>9.0f} {c:>10.0f} {change:>+8.1f}%  "
              f"{'PASS' if change <= 30 else 'OVER'}")

    print("-" * 78)
    print(f"\nWorst-case increase: {worst:+.1f}%")
    print(f"NFR-07: {'PASS' if worst <= 30 else 'FAIL'} "
          f"(threshold +30%)")
    if any_failures:
        print("\nWARNING: some requests failed. Check for 429s from the NFR-05 "
              "login limiter before trusting these numbers.")
    print("\nScreenshot this table for the NFR-07 evidence.")


if __name__ == "__main__":
    if "--compare" in sys.argv:
        compare()
    else:
        print(__doc__)
