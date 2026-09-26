"""
Trend analysis (design doc section 6): the agent as analyst, not scanner.

Aggregates the (simulated) scan history into a weekly summary a security lead
can read in 20 seconds: what moved, what's most common, and which teams carry
the backlog. All data is SIMULATED and labelled; the arithmetic is real.

Run:
  python -m scenarios.trends.run
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


def summarise(hist: dict) -> list[Evidence]:
    S = EvidenceStatus.SIMULATED
    ev: list[Evidence] = []
    weeks = hist.get("weeks", [])
    if len(weeks) >= 2:
        prev, cur = weeks[-2], weeks[-1]
        net = cur["remediated"] - cur["new"]
        arrow = "down" if net > 0 else ("up" if net < 0 else "flat")
        ev.append(Evidence(
            f"Week ending {cur['week_ending']}: {cur['apps_scanned']} apps scanned, "
            f"{cur['new']} new, {cur['remediated']} remediated "
            f"(net backlog {arrow} by {abs(net)}). "
            f"Open now {cur['open_at_week_end']} vs {prev['open_at_week_end']} last week.",
            S, "scan history (2-week delta)"))
    return ev


def render_top(hist: dict) -> str:
    cats = hist.get("current_open_by_category", {})
    ranked = sorted(cats.items(), key=lambda kv: kv[1], reverse=True)
    lines = ["  Most common open categories:"]
    for i, (name, n) in enumerate(ranked, 1):
        lines.append(f"    {i}. {name} ({n})")
    return "\n".join(lines)


def render_backlog(hist: dict) -> str:
    teams = sorted(hist.get("backlog_by_team", []),
                   key=lambda t: t["open"], reverse=True)
    lines = ["  Teams by backlog:",
             "    TEAM       OPEN  P1  OLDEST(d)",
             "    ---------- ----  --  ---------"]
    for t in teams:
        lines.append(f"    {t['team']:<10} {t['open']:>4}  {t['p1']:>2}  {t['oldest_days']:>9}")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    gate = ApprovalGate(auto_approve="--auto" in argv)
    boundary = DataBoundary()

    print(report.header("LYNTINEL :: Trend Analysis (weekly security summary)"))
    print("  NOTE: scan history is SIMULATED. The aggregation logic is real.")

    hist = gate.run(Action("Read scan history", ActionRisk.READ),
                    lambda: _load("scan_history.json"))

    print(report.section("HEADLINE (this week vs last)"))
    print(report.render_findings(summarise(hist)))

    print(report.section("MOST COMMON"))
    print(render_top(hist))

    print(report.section("BACKLOG OWNERS (where to point remediation effort)"))
    print(render_backlog(hist))

    print(report.footer(gate, boundary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
