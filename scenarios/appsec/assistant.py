"""
assistant.py - developer assistant (design doc section 5).

When a finding is prioritised, a developer still has to understand it and fix
it. This turns an enriched finding into three developer-ready artefacts:

  1. Summary        - where, what the risk is, the affected code, OWASP class.
  2. Remediation    - concrete recommended actions.
  3. Ticketing draft     - description, risk statement, repro steps, acceptance
                      criteria. FILING it is a gated WRITE (see run.py), and we
                      refuse to file if a linked ticket already exists.

The generation here is deterministic template-fill, not an LLM call - so the
demo is offline and reproducible. The seam where an LLM would slot in is marked;
in production the enriched context would be handed to the model, but the safety
gate and duplicate check would sit exactly where they do now.
"""

from __future__ import annotations

from .enrich import Enriched

# Keyword -> OWASP Top 10 (2021) category. Small and auditable on purpose.
_OWASP = [
    (["sql", "injection", "command"], "A03 Injection"),
    (["secret", "credential", "key", "password", "token"],
     "A07 Identification & Authentication Failures / A05 Misconfiguration"),
    (["ssrf"], "A10 Server-Side Request Forgery"),
    (["access", "authorization", "authorisation", "impersonat", "idor", "privilege"],
     "A01 Broken Access Control"),
    (["prototype pollution", "deserial", "dependency", "cve", "outdated"],
     "A06 Vulnerable & Outdated Components"),
    (["redirect"], "A01 Broken Access Control (open redirect)"),
]


def owasp_category(finding: dict) -> str:
    text = (finding.get("title", "") + " " + finding.get("type", "")).lower()
    for keywords, category in _OWASP:
        if any(k in text for k in keywords):
            return category
    return "Unmapped - assign during review"


def summary(e: Enriched) -> str:
    f = e.finding
    loc = f.get("file", "?")
    return (
        f"Issue: {f.get('title','?')}\n"
        f"  Where:   {f.get('repo','?')}  {loc}\n"
        f"  Risk:    {_risk_statement(e)}\n"
        f"  OWASP:   {owasp_category(f)}\n"
        f"  Priority: {e.score.business_severity.upper()} [{e.score.priority}] "
        f"(technical {e.score.technical_severity.upper()})"
    )


def remediation(e: Enriched) -> list[str]:
    f = e.finding
    steps = [f.get("fix") or "Propose a fix during review."]
    ftype = f.get("type", "")
    title = f.get("title", "").lower()
    if ftype == "secret" or "secret" in title or "key" in title:
        steps += ["Rotate the exposed credential immediately.",
                  "Purge it from git history (e.g. git filter-repo).",
                  "Move to a secrets manager; add pre-commit secret scanning."]
    if "sql" in title or ftype == "SAST":
        steps += ["Add a unit/integration test proving the injection is closed.",
                  "Review sibling queries in the same module for the same pattern."]
    if ftype == "SCA" or "cve" in title:
        steps += ["Confirm no breaking changes in the upgrade; run the test suite.",
                  "Check whether the vulnerable path is actually reachable before rushing."]
    return steps


def ticket_draft(e: Enriched) -> str:
    f = e.finding
    steps = "\n".join(f"    - {s}" for s in remediation(e))
    return (
        f"[{e.score.priority}] {f.get('title','?')}\n"
        f"  Project: SEC   Component: {f.get('repo','?')}\n"
        f"  Description:\n"
        f"    {f.get('title','?')} in {f.get('repo','?')} ({f.get('file','?')}).\n"
        f"  Risk statement:\n"
        f"    {_risk_statement(e)}\n"
        f"  Reproduction:\n"
        f"    - Scanner: {f.get('id','?')} flagged {f.get('file','?')}.\n"
        f"    - Reachability: {f.get('reachable')}.\n"
        f"  Recommended actions:\n{steps}\n"
        f"  Acceptance criteria:\n"
        f"    - Finding no longer reported by AppSec scanner on the next scan.\n"
        f"    - Regression test added covering this class.\n"
        f"    - Change reviewed by a second engineer.\n"
        f"  OWASP: {owasp_category(f)}"
    )


def _risk_statement(e: Enriched) -> str:
    ctx = e.context
    bits = []
    if ctx.get("internet_facing") is True:
        bits.append("on an internet-facing service")
    elif ctx.get("internet_facing") is False:
        bits.append("on an internal-only service")
    data = ctx.get("data_classification")
    if data and any(t in data.upper() for t in ("PII", "PHI", "PCI")):
        bits.append(f"processing sensitive data ({data})")
    if ctx.get("active_exploit") is True:
        bits.append("with an active exploit in the wild")
    if ctx.get("accepted_risk") is True:
        bits.append("(NOTE: currently an accepted risk)")
    context_phrase = ", ".join(bits) if bits else "in this component"
    return (f"If exploited, {e.finding.get('title','this issue')} could be abused "
            f"{context_phrase}.")
