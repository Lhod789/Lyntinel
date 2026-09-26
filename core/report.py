"""
report.py - shared rendering helpers so both scenarios produce comparable,
skimmable output. Structure comes from here; only content varies per run.
"""

from __future__ import annotations

from .safety import Evidence, DataBoundary, ApprovalGate


def header(title: str) -> str:
    bar = "=" * 60
    return f"\n{bar}\n  {title}\n{bar}"


def section(title: str) -> str:
    return f"\n--- {title} " + "-" * max(0, 52 - len(title))


def render_findings(findings: list[Evidence]) -> str:
    if not findings:
        return "  (no findings - this is a valid, evidenced result)"
    return "\n".join(f"  {f.render()}" for f in findings)


def footer(gate: ApprovalGate, boundary: DataBoundary) -> str:
    out = [section("AUDIT TRAIL (every action, gated or not)")]
    out.append(gate.audit_trail())
    out.append(section("DATA BOUNDARY"))
    out.append("  " + boundary.summary().replace("\n", "\n  "))
    return "\n".join(out)
