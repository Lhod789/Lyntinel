"""
Threat-modelling assistant (design doc section 7).

Reads the threat model + architecture doc, extracts trust boundaries, and
suggests threats and concrete test cases - the way it would help a security
engineer prep a penetration test. Suggestions are labelled INFERRED (they are the
agent reasoning, not facts); anything read verbatim from the docs is labelled
from the source. It proposes; the human disposes.

Run:
  python -m scenarios.threatmodel.run
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from core import (Evidence, EvidenceStatus, DataBoundary,
                  Action, ActionRisk, ApprovalGate, report)

MOCK = Path(__file__).resolve().parents[2] / "data" / "mock"


def _read(name: str) -> str:
    return (MOCK / name).read_text(encoding="utf-8")


def extract_boundaries(arch: str) -> list[str]:
    """Pull 'X -> Y' data flows out of the architecture doc."""
    flows = []
    for line in arch.splitlines():
        m = re.search(r"([A-Za-z0-9_\-/ ]+?)\s*->\s*([A-Za-z0-9_\-/ ]+)", line)
        if m and ("flow" in arch.lower() or ":" in line or line.strip()[:1].isdigit()):
            src, dst = m.group(1).strip(" .").strip(), m.group(2).strip(" .").strip()
            # trim trailing description after a colon
            dst = dst.split(":")[0].strip()
            if src and dst:
                flows.append(f"{src} -> {dst}")
    # de-dup, keep order
    seen, out = set(), []
    for f in flows:
        if f not in seen:
            seen.add(f); out.append(f)
    return out


# Rule set: signal in the docs -> (threats, test cases). Deliberately small and
# auditable. Each rule fires only if its trigger text is present.
_RULES = [
    ("impersonat",
     ["Privilege escalation via impersonation if authorisation is bypassable",
      "Missing audit trail on impersonation"],
     ["Impersonation abuse: call /auth/impersonate as a non-admin",
      "Verify audit log entry is written for every impersonation",
      "Direct object reference: impersonate another user by id manipulation"]),
    ("jwt", "token", "bearer",
     ["Token replay / theft", "JWT tampering (alg=none, weak signature)"],
     ["Replay a captured JWT after logout / expiry",
      "JWT manipulation: modify claims, strip signature, test acceptance"]),
    ("rate limit", "no rate limiting",
     ["Credential stuffing / brute force on login", "Auth endpoint DoS"],
     ["Send N rapid /auth/login attempts; confirm throttling/lockout"]),
    ("pii", "card", "patient", "sensitive",
     ["Sensitive-data exposure if access control fails"],
     ["Attempt cross-tenant / IDOR access to records containing sensitive data"]),
]


def suggest(arch: str, tm: str) -> tuple[list[Evidence], list[Evidence]]:
    text = (arch + "\n" + tm).lower()
    threats: list[Evidence] = []
    tests: list[Evidence] = []
    I = EvidenceStatus.INFERRED
    seen_t, seen_c = set(), set()
    for rule in _RULES:
        *triggers, rule_threats, rule_tests = rule
        if any(t in text for t in triggers):
            src = f"inferred from docs (trigger: '{triggers[0]}')"
            for t in rule_threats:
                if t not in seen_t:
                    seen_t.add(t); threats.append(Evidence(t, I, src))
            for c in rule_tests:
                if c not in seen_c:
                    seen_c.add(c); tests.append(Evidence(c, I, src))
    return threats, tests


def main(argv: list[str]) -> int:
    gate = ApprovalGate(auto_approve="--auto" in argv)
    boundary = DataBoundary()

    print(report.header("LYNTINEL :: Threat-Modelling Assistant"))
    print("  Reads architecture + threat model, proposes threats & test cases.")
    print("  Every suggestion is INFERRED - a prompt for the engineer, not a verdict.")

    arch = gate.run(Action("Read architecture doc", ActionRisk.READ),
                    lambda: _read("architecture.md"))
    tm = gate.run(Action("Read threat model", ActionRisk.READ),
                  lambda: _read("threat_model.md"))

    boundaries = extract_boundaries(arch)
    print(report.section("TRUST BOUNDARIES (extracted from data flows)"))
    for b in boundaries:
        print(f"  - {b}")

    threats, tests = suggest(arch, tm)
    print(report.section("SUGGESTED THREATS (INFERRED - review before acting)"))
    print(report.render_findings(threats))

    print(report.section("SUGGESTED TEST CASES"))
    print(report.render_findings(tests))

    print(report.footer(gate, boundary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
