"""
AppSec pipeline: ingest -> triage -> enrich -> prioritise -> assist -> file.

This is the flagship scenario. It walks the design doc end to end for the AppSec
half:

  1. INGEST   (section 1) - read the threat model (GitHub) and findings (AppSec scanner).
  2. TRIAGE   (section 2) - evidence-label each finding vs the threat model, so a
               hallucinated "critical" cannot hide among the real ones.
  3. ENRICH   (section 2) - answer the business questions: internet-facing?
               deployed? active exploit? compensating control? accepted risk?
               linked ticket?  (from the simulated connectors)
  4. PRIORITISE (section 4) - composite business score -> P1-P4, showing its working.
  5. ASSIST   (section 5) - generate summary + remediation + Ticketing draft.
  6. FILE     - each ticket is a WRITE, so each stops at the approval gate; we
               refuse to file duplicates and never auto-file UNKNOWN/accepted.

Run:
  python -m scenarios.appsec.run            # interactive approval (demo this)
  python -m scenarios.appsec.run --auto     # hands-off (still announces every write)
"""

from __future__ import annotations

import sys
from core import (Evidence, EvidenceStatus, DataBoundary,
                  Action, ActionRisk, ApprovalGate, report)
from . import connectors
from .enrich import enrich_findings, Enriched
from . import assistant


def triage(findings: list[dict], threat_model: str, live: bool) -> list[Evidence]:
    """Turn raw findings into evidence-labelled conclusions.

    The rule that kills hallucination: a finding is only escalated to
    CONFIRMED-exploitable if BOTH the scanner says reachable AND the threat
    model names a matching threat. If the scanner is unsure, we say UNKNOWN -
    we never upgrade a guess to a fact.
    """
    tm = threat_model.lower()
    out: list[Evidence] = []
    base = EvidenceStatus.SIMULATED if not live else EvidenceStatus.CONFIRMED

    for f in findings:
        title = f.get("title", "untitled")
        sev = f.get("severity", "unknown")
        reachable = f.get("reachable")
        src = f"AppSec scanner {f.get('id','?')} ({f.get('file','?')})"

        keywords = {
            "SCA": ["dependency", "vuln", "disclosure"],
            "SAST": ["injection", "tampering", "sql"],
            "secret": ["credential", "key", "privilege", "spoofing"],
        }.get(f.get("type", ""), [])
        corroborated = any(k in tm for k in keywords)

        if reachable is True and corroborated:
            status = base
            claim = (f"{sev.upper()} - {title}: reachable AND matches a "
                     f"modelled threat. Triage: REAL, prioritise.")
        elif reachable is False:
            status = EvidenceStatus.INFERRED
            claim = (f"{sev.upper()} - {title}: scanner says not reachable. "
                     f"Triage: likely lower priority (matches an accepted risk).")
        elif reachable is None:
            status = EvidenceStatus.UNKNOWN
            claim = (f"{sev.upper()} - {title}: reachability not established. "
                     f"Triage: UNKNOWN - needs human review, not auto-filed.")
        else:
            status = EvidenceStatus.INFERRED
            claim = (f"{sev.upper()} - {title}: reachable but no matching "
                     f"threat in model. Triage: review threat model coverage.")

        out.append(Evidence(claim=claim, status=status, source=src))
    return out


def render_priority_table(enriched: list[Enriched]) -> str:
    """The design doc's section-4 table: sort by business priority, not CVSS."""
    order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    rows = sorted(enriched, key=lambda e: order.get(e.score.priority, 9))
    lines = ["  PRIORITY | TECH     | BUSINESS  | FINDING",
             "  ---------+----------+-----------+" + "-" * 40]
    for e in rows:
        f = e.finding
        title = f.get("title", "?")
        if len(title) > 40:
            title = title[:37] + "..."
        lines.append(
            f"  {e.score.priority:<8} | {e.score.technical_severity.upper():<8} | "
            f"{e.score.business_severity.upper():<9} | {title}")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    auto = "--auto" in argv
    gate = ApprovalGate(auto_approve=auto)
    boundary = DataBoundary()

    print(report.header("LYNTINEL :: AppSec Triage + Prioritisation Agent"))

    # 1. INGEST (never gated) ---------------------------------------------
    tm_res = gate.run(Action("Read threat model", ActionRisk.READ),
                      connectors.fetch_threat_model)
    find_res = gate.run(Action("Read AppSec scanner findings", ActionRisk.READ),
                        connectors.fetch_appsec_findings)
    assets_res = gate.run(Action("Read asset inventory", ActionRisk.READ),
                          connectors.fetch_asset_inventory)
    accepted_res = gate.run(Action("Read GRC platform risk register", ActionRisk.READ),
                            connectors.fetch_accepted_risks)
    ticket_res = gate.run(Action("Read existing Ticketing tickets", ActionRisk.READ),
                        connectors.fetch_tickets)
    exploit_res = gate.run(Action("Read exploit intel", ActionRisk.READ),
                           connectors.fetch_exploit_intel)

    print(report.section("SOURCES (every source labelled - never faked as real)"))
    for r in (tm_res, find_res, assets_res, accepted_res, ticket_res, exploit_res):
        tag = "LIVE" if r.live else "SIM "
        print(f"  [{tag}] {r.detail}")

    findings = find_res.data

    # 2. TRIAGE ------------------------------------------------------------
    conclusions = triage(findings, tm_res.data, find_res.live)
    print(report.section("TRIAGE (evidence-labelled - a guess can't hide as a fact)"))
    print(report.render_findings(conclusions))

    # 3. ENRICH + 4. PRIORITISE -------------------------------------------
    enriched = enrich_findings(
        findings,
        assets=assets_res.data, accepted=accepted_res.data,
        ticketing=ticket_res.data, exploit=exploit_res.data,
        live=find_res.live)

    print(report.section("PRIORITISATION (composite business score, not raw CVSS)"))
    print(render_priority_table(enriched))

    print(report.section("SCORING RATIONALE (every adjustment sourced)"))
    for e in enriched:
        print(f"  {e.finding.get('title','?')}")
        print(e.score.render())
        print()

    # 5. ASSIST + 6. FILE (each ticket gated) -----------------------------
    print(report.section("DEVELOPER ASSISTANT + TICKET FILING (WRITE -> gated)"))
    filed = 0
    for e, ev in zip(enriched, conclusions):
        f = e.finding
        title = f.get("title", "?")

        # Never auto-file the things a security engineer said not to.
        if ev.status == EvidenceStatus.UNKNOWN:
            print(f"\n  SKIP '{title}': triage is UNKNOWN -> route to human review.")
            continue
        if e.score.accepted_risk:
            print(f"\n  SKIP '{title}': formally accepted in the risk register -> "
                  f"surface only, do not file.")
            continue
        if e.linked_ticket:
            print(f"\n  SKIP '{title}': already tracked by {e.linked_ticket['key']} "
                  f"({e.linked_ticket['status']}) -> no duplicate filed.")
            continue

        print("\n  " + "-" * 54)
        print(assistant.summary(e).replace("\n", "\n  "))
        result = gate.run(
            Action(f"File Ticketing ticket: {title}", ActionRisk.WRITE,
                   payload=assistant.ticket_draft(e)),
            lambda e=e: assistant.ticket_draft(e),
        )
        if result is not None:
            filed += 1

    print(report.section("RESULT"))
    print(f"  {filed} ticket(s) approved and filed. Others were denied, "
          f"deduplicated, accepted, or routed to human review - by design.")

    print(report.footer(gate, boundary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
