"""
enrich.py - context enrichment (design doc section 2) + prioritisation (section 4).

A raw scanner finding is just "CVE-x, CVSS 7.5, Spring". The design doc says the
value is in what the agent asks *next*:

  - Is this product internet facing?
  - Is this component actually deployed?
  - Is there an active exploit?
  - Is it covered by a compensating control?
  - Is there a linked Ticketing ticket?
  - Is it accepted in the risk register?

This module answers those from the (simulated) connectors, attaches an evidence
trail, and hands the assembled context to core.scoring for a business-aware
P1-P4. Nothing here guesses: a question we can't answer stays "unknown" and the
scorer simply doesn't move the number for it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from core import Evidence, EvidenceStatus, score_finding, ScoreResult

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


@dataclass
class Enriched:
    finding: dict
    context: dict
    score: ScoreResult
    evidence: list[Evidence] = field(default_factory=list)
    linked_ticket: dict | None = None
    cve: str | None = None


def _cve_of(finding: dict) -> str | None:
    m = _CVE_RE.search(finding.get("title", "") or "")
    return m.group(0).upper() if m else None


def enrich_findings(findings: list[dict], *, assets: dict, accepted: dict,
                    ticketing: list[dict], exploit: dict, live: bool) -> list[Enriched]:
    base = EvidenceStatus.CONFIRMED if live else EvidenceStatus.SIMULATED
    out: list[Enriched] = []

    accepted_by_cve = {
        r.get("matches", {}).get("cve"): r
        for r in accepted.get("accepted_risks", [])
        if r.get("matches", {}).get("cve")
    }

    for f in findings:
        repo = f.get("repo", "?")
        asset = assets.get(repo, {})
        cve = _cve_of(f)
        ev: list[Evidence] = []
        ctx: dict = {"reachable": f.get("reachable")}

        # Q: internet facing? deployed? data class? criticality? controls?
        if asset:
            ctx["internet_facing"] = asset.get("internet_facing")
            ctx["deployed"] = "prod" in asset.get("environments_deployed", [])
            ctx["data_classification"] = asset.get("data_classification")
            ctx["regulatory_scope"] = asset.get("regulatory_scope", [])
            ctx["asset_criticality"] = asset.get("asset_criticality")
            ev.append(Evidence(
                f"{repo}: internet_facing={asset.get('internet_facing')}, "
                f"data={asset.get('data_classification')}, "
                f"criticality={asset.get('asset_criticality')}, "
                f"controls={asset.get('compensating_controls')}",
                base, f"asset inventory: {repo}"))
        else:
            ev.append(Evidence(
                f"No asset-inventory entry for repo '{repo}' - business context "
                f"could not be established.",
                EvidenceStatus.UNKNOWN, "asset inventory (no match)"))

        # Q: does a compensating control cover this finding's class?
        ctx["control_covers"] = _control_covers(f, asset)
        if ctx["control_covers"]:
            ev.append(Evidence(
                f"A compensating control ({', '.join(asset.get('compensating_controls', []))}) "
                f"plausibly mitigates this finding class.",
                EvidenceStatus.INFERRED, "asset inventory controls (inferred by class)"))

        # Q: active exploit in the wild?
        if cve and cve in exploit:
            rec = exploit[cve]
            ctx["active_exploit"] = bool(rec.get("kev"))
            ev.append(Evidence(
                f"{cve}: KEV={rec.get('kev')}, EPSS={rec.get('epss')}. {rec.get('note','')}",
                base, "exploit intel (KEV/EPSS)"))
        elif cve:
            ctx["active_exploit"] = None
            ev.append(Evidence(
                f"{cve}: not found in the exploit-intel feed - exploitation status unknown.",
                EvidenceStatus.UNKNOWN, "exploit intel (no record)"))

        # Q: formally accepted in the risk register?
        acc = accepted_by_cve.get(cve) if cve else None
        ctx["accepted_risk"] = acc is not None
        if acc:
            ev.append(Evidence(
                f"Risk formally accepted: {acc['risk_id']} by {acc['accepted_by']} "
                f"(review {acc['review_date']}). Rationale: {acc['rationale']}",
                base, f"GRC platform {acc['risk_id']}"))

        # Q: is there already a linked Ticketing ticket?
        linked = _linked_ticket(f, cve, ticketing)
        if linked:
            ev.append(Evidence(
                f"Existing ticket {linked['key']} ({linked['status']}) already "
                f"tracks this - do NOT file a duplicate.",
                base, f"Ticketing {linked['key']}"))

        score = score_finding(f.get("severity", "unknown"), ctx)
        out.append(Enriched(finding=f, context=ctx, score=score,
                            evidence=ev, linked_ticket=linked, cve=cve))
    return out


# Very small keyword map from finding -> control class it would be mitigated by.
# Deliberately conservative: only claims coverage when a matching control is
# actually present on the asset. Anything else stays False (no coverage claimed).
_CONTROL_HINTS = {
    "WAF": ["sql", "injection", "ssrf", "xss", "redirect"],
}


def _control_covers(finding: dict, asset: dict) -> bool:
    title = (finding.get("title", "") + " " + finding.get("type", "")).lower()
    controls = asset.get("compensating_controls", [])
    for control, keywords in _CONTROL_HINTS.items():
        if control in controls and any(k in title for k in keywords):
            return True
    return False


def _linked_ticket(finding: dict, cve: str | None, ticketing: list[dict]) -> dict | None:
    for t in ticketing:
        links = t.get("links", {})
        if cve and links.get("cve", "").upper() == cve:
            return t
    return None
