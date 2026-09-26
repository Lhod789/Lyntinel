"""
Security-review preparation (design doc section 8).

Generates the one-pager a security engineer would otherwise hand-assemble before
a review meeting with developers: outstanding risks (prioritised), recent
changes to probe, and sharp questions to ask. It reuses the AppSec enrichment
pipeline so the "outstanding risks" are the same business-scored findings, not a
second, divergent list.

Run:
  python -m scenarios.review.run
"""

from __future__ import annotations

import sys
from core import (DataBoundary, Action, ActionRisk, ApprovalGate, report)
from scenarios.appsec import connectors
from scenarios.appsec.enrich import enrich_findings
from scenarios.appsec.assistant import owasp_category

APP = "payments-service"

# SIMULATED: in production these come from Cloud platform / git history for the app.
RECENT_CHANGES = [
    "Authentication middleware refactored (PR #412)",
    "New POST /payments endpoint deployed",
    "Dependency bump batch merged (14 packages)",
]


def build_questions(enriched) -> list[str]:
    qs = []
    for e in enriched:
        title = e.finding.get("title", "").lower()
        if "secret" in title or "key" in title:
            qs.append("The hardcoded credential: has it been rotated, and is the "
                      "old key confirmed revoked?")
        if "sql" in title:
            qs.append("SQL concatenation in user lookup: is it parameterised now, "
                      "and is there a regression test?")
    qs.append("Who can access privileged/admin endpoints, and is that access audited?")
    qs.append("Have regression tests been run against the auth changes since the "
              "middleware refactor?")
    # de-dup, preserve order
    seen, out = set(), []
    for q in qs:
        if q not in seen:
            seen.add(q); out.append(q)
    return out


def main(argv: list[str]) -> int:
    gate = ApprovalGate(auto_approve="--auto" in argv)
    boundary = DataBoundary()

    print(report.header(f"LYNTINEL :: Security Review Prep - {APP}"))

    tm = gate.run(Action("Read threat model", ActionRisk.READ),
                  connectors.fetch_threat_model)
    findings = gate.run(Action("Read AppSec scanner findings", ActionRisk.READ),
                        connectors.fetch_appsec_findings)
    assets = gate.run(Action("Read asset inventory", ActionRisk.READ),
                      connectors.fetch_asset_inventory)
    accepted = gate.run(Action("Read risk register", ActionRisk.READ),
                        connectors.fetch_accepted_risks)
    ticketing = gate.run(Action("Read Ticketing tickets", ActionRisk.READ),
                    connectors.fetch_tickets)
    exploit = gate.run(Action("Read exploit intel", ActionRisk.READ),
                       connectors.fetch_exploit_intel)

    enriched = enrich_findings(findings.data, assets=assets.data,
                               accepted=accepted.data, ticketing=ticketing.data,
                               exploit=exploit.data, live=findings.live)

    order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    outstanding = sorted(enriched, key=lambda e: order.get(e.score.priority, 9))

    print(report.section("OUTSTANDING RISKS (business-prioritised)"))
    for e in outstanding:
        f = e.finding
        flags = []
        if e.score.accepted_risk:
            flags.append("ACCEPTED")
        if e.linked_ticket:
            flags.append(f"tracked {e.linked_ticket['key']}")
        tag = f"  [{', '.join(flags)}]" if flags else ""
        print(f"  {e.score.priority}  {f.get('title','?')}  "
              f"({owasp_category(f)}){tag}")

    print(report.section("RECENT CHANGES (probe these - SIMULATED source)"))
    for c in RECENT_CHANGES:
        print(f"  - {c}")

    print(report.section("QUESTIONS FOR DEVELOPERS"))
    for q in build_questions(enriched):
        print(f"  - {q}")

    print(report.footer(gate, boundary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
