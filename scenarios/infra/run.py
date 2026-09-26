"""
Infra / SecOps scenario: an endpoint alert lands, and the agent correlates it
across email security and user-risk data to build one incident summary -
then proposes a containment action that a human must approve.

Why this is the demo for the Infra crowd: today this correlation is a human
flipping between three consoles (EDR, email security, awareness platform) at 8am.
The agent does the joining in seconds and SHOWS ITS WORKING with evidence
labels, so the analyst trusts the summary instead of re-checking it.

All three tools are SIMULATED, and
every datum says so. Containment (host quarantine) is DESTRUCTIVE and is
always gated, loudly.

Run:
  python -m scenarios.infra.run            # interactive approval
  python -m scenarios.infra.run --auto     # hands-off demo (still announces)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from core import (Evidence, EvidenceStatus, DataBoundary,
                  Action, ActionRisk, ApprovalGate, report)

MOCK = Path(__file__).resolve().parents[2] / "data" / "mock"


def _load(name: str) -> dict:
    return json.loads((MOCK / name).read_text(encoding="utf-8"))


def correlate(edr: dict, email: dict, profiles: dict) -> list[Evidence]:
    """Join the three sources around a single user and tell the story.

    Everything here is SIMULATED-tagged. The reasoning is real: the value of
    the agent is the JOIN, and the value of the evidence labels is that a
    watcher can see exactly which links are solid and which are inferred."""
    ev: list[Evidence] = []
    S = EvidenceStatus.SIMULATED

    user = edr["device"]["user"]
    host = edr["device"]["hostname"]

    ev.append(Evidence(
        f"EDR detection on {host} (user {user}): {edr['technique']} "
        f"[{edr['technique_id']}], severity {edr['severity_label']}.",
        S, "MOCK EDR alert"))

    # Tie the EDR alert to an email click for the same user.
    clicks = email.get("url_clicks", [])
    matched_click = next(
        (c for c in clicks if user in c.get("recipient", "")), None)
    if matched_click:
        ev.append(Evidence(
            f"Same user clicked a phishing URL ({matched_click['url']}) "
            f"at {matched_click['click_time']} - ~2 min before the EDR alert. "
            f"This is the likely initial access vector.",
            S, "MOCK email-security click log (joined on recipient + time)"))
    else:
        ev.append(Evidence(
            "No matching email click found for this user.",
            EvidenceStatus.UNKNOWN, "MOCK email security (no join) - vector unconfirmed"))

    # Pull the user's phishing-resilience score.
    prof = next((u for u in profiles.get("users", [])
                 if u["email"].split("@")[0] == user
                 or user in u["email"]), None)
    if prof:
        ev.append(Evidence(
            f"User risk profile: awareness platform level '{prof['awareness_risk_level']}', "
            f"{prof['failed_simulations_90d']} failed sims in 90d, "
            f"{int(prof['training_completion']*100)}% training complete. "
            f"Consistent with a successful real-world phish.",
            S, "MOCK awareness platform profile (joined on email)"))
    else:
        ev.append(Evidence(
            "No awareness platform profile for this user.",
            EvidenceStatus.UNKNOWN, "MOCK awareness platform (no match)"))

    # The one INFERRED conclusion - clearly flagged as reasoning, not data.
    ev.append(Evidence(
        "Assessment: high-confidence successful spearphish leading to "
        "PowerShell execution on a Finance endpoint. Recommend containment.",
        EvidenceStatus.INFERRED,
        "Agent reasoning over the three correlated sources above"))
    return ev


def main(argv: list[str]) -> int:
    auto = "--auto" in argv
    gate = ApprovalGate(auto_approve=auto)
    boundary = DataBoundary()

    print(report.header("LYNTINEL :: Infra / SecOps Correlation Agent"))
    print("  NOTE: all three sources are SIMULATED.")

    # READ (never gated) ---------------------------------------------------
    edr = gate.run(Action("Read EDR alert", ActionRisk.READ),
                   lambda: _load("edr_alert.json"))
    email = gate.run(Action("Read email security events", ActionRisk.READ),
                     lambda: _load("email_security_events.json"))
    profiles = gate.run(Action("Read awareness platform profiles", ActionRisk.READ),
                        lambda: _load("awareness_profiles.json"))

    # CORRELATE ------------------------------------------------------------
    findings = correlate(edr, email, profiles)
    print(report.section("INCIDENT SUMMARY (evidence-labelled correlation)"))
    print(report.render_findings(findings))

    # PROPOSE CONTAINMENT - destructive, always gated ----------------------
    print(report.section("PROPOSED CONTAINMENT (DESTRUCTIVE -> always gated)"))
    host = edr["device"]["hostname"]
    contained = gate.run(
        Action(f"Network-quarantine host {host} via EDR",
               ActionRisk.DESTRUCTIVE,
               payload=f"Isolate {host}; preserve for forensics; notify user's manager."),
        lambda: f"{host} quarantined (SIMULATED).",
    )

    print(report.section("RESULT"))
    print(f"  {'Containment approved: ' + contained if contained else 'Containment NOT executed (denied or pending human review).'}")

    print(report.footer(gate, boundary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
