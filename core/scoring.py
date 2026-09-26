"""
scoring.py - composite, business-aware risk scoring (design doc section 4).

The design doc's key insight: sorting by CVSS is wrong. A "High" CVSS on an
internal-only service with a compensating control and an accepted risk is not a
High to the business. So instead of one number we compute a *business severity*
by starting from the technical severity and applying transparent, sourced
adjustments - then map that to a P1-P4 priority.

Design principle carried over from safety.py: the score SHOWS ITS WORKING.
Every adjustment is a (delta, reason, source) triple, so a security engineer
can audit exactly why a finding moved up or down - no black-box number.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Base points by the scanner's technical severity.
_BASE = {"critical": 40, "high": 30, "medium": 15, "low": 5, "unknown": 15}

# Business-severity bands -> (label, priority). Higher score = more urgent.
_BANDS = [
    (80, "Critical", "P1"),
    (60, "High", "P2"),
    (35, "Medium", "P3"),
    (0, "Low", "P4"),
]


@dataclass
class Adjustment:
    delta: int
    reason: str
    source: str

    def render(self) -> str:
        sign = f"+{self.delta}" if self.delta >= 0 else str(self.delta)
        return f"    {sign:>4}  {self.reason}  ({self.source})"


@dataclass
class ScoreResult:
    technical_severity: str
    business_severity: str
    priority: str
    score: int
    adjustments: list[Adjustment] = field(default_factory=list)
    accepted_risk: bool = False   # formally accepted in the risk register

    def render(self) -> str:
        head = (f"    technical={self.technical_severity.upper()} -> "
                f"business={self.business_severity.upper()} "
                f"[{self.priority}]  (score {self.score})")
        lines = [head] + [a.render() for a in self.adjustments]
        if self.accepted_risk:
            lines.append("    note: formally ACCEPTED in the risk register - "
                         "do not auto-file; surface for awareness only.")
        return "\n".join(lines)


def score_finding(technical_severity: str, context: dict) -> ScoreResult:
    """Compute a business-aware priority from technical severity + context.

    `context` is the enriched business context for one finding, e.g.:
        {
          "internet_facing": True,
          "deployed": True,
          "active_exploit": False,
          "data_classification": "PII+PCI",
          "regulatory_scope": ["PCI-DSS"],
          "asset_criticality": "tier1",
          "control_covers": True,       # a compensating control applies
          "reachable": True,
          "accepted_risk": False,
        }
    Missing keys are treated as "unknown" and simply don't move the score,
    which keeps the model honest: absence of evidence is not a downgrade.
    """
    sev = (technical_severity or "unknown").lower()
    score = _BASE.get(sev, _BASE["unknown"])
    adj: list[Adjustment] = []

    def bump(delta: int, reason: str, source: str) -> None:
        nonlocal score
        score += delta
        adj.append(Adjustment(delta, reason, source))

    # --- exposure ---------------------------------------------------------
    if context.get("internet_facing") is True:
        bump(+20, "internet-facing service", "asset inventory")
    elif context.get("internet_facing") is False:
        bump(-10, "internal-only service", "asset inventory")

    # --- exploitability ---------------------------------------------------
    if context.get("active_exploit") is True:
        bump(+25, "active exploit observed in the wild", "exploit intel (KEV)")

    if context.get("reachable") is False:
        bump(-25, "scanner reports code path not reachable", "AppSec scanner reachability")
    elif context.get("deployed") is False:
        bump(-20, "component not currently deployed", "asset inventory")

    # --- data / regulatory ------------------------------------------------
    data = (context.get("data_classification") or "").upper()
    if any(tag in data for tag in ("PII", "PHI", "PCI")):
        bump(+20, f"handles sensitive data ({data})", "asset inventory")
    if context.get("regulatory_scope"):
        scope = ", ".join(context["regulatory_scope"])
        bump(+10, f"in regulatory scope ({scope})", "asset inventory")

    # --- asset criticality ------------------------------------------------
    crit = (context.get("asset_criticality") or "").lower()
    if crit == "tier1":
        bump(+15, "tier-1 (business-critical) asset", "asset inventory")
    elif crit == "tier2":
        bump(+8, "tier-2 asset", "asset inventory")

    # --- compensating controls -------------------------------------------
    if context.get("control_covers") is True:
        bump(-15, "compensating control mitigates this class", "GRC platform controls")

    # --- formal risk acceptance ------------------------------------------
    accepted = context.get("accepted_risk") is True
    if accepted:
        bump(-30, "risk formally accepted in the register", "GRC platform risk register")

    score = max(0, score)
    label, priority = _band(score)
    return ScoreResult(
        technical_severity=sev,
        business_severity=label,
        priority=priority,
        score=score,
        adjustments=adj,
        accepted_risk=accepted,
    )


def _band(score: int) -> tuple[str, str]:
    for threshold, label, priority in _BANDS:
        if score >= threshold:
            return label, priority
    return "Low", "P4"
