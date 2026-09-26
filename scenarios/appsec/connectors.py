"""
connectors.py - data sources for the AppSec scenario.

Every source in this demo reads labelled mock data from data/mock/. Each one
returns the same SourceResult shape and says loudly that it is SIMULATED, so
mock data can never be mistaken for real data: not in the output, not in the
audit trail, and not in the evidence labels it produces downstream.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

MOCK_DIR = Path(__file__).resolve().parents[2] / "data" / "mock"


@dataclass
class SourceResult:
    data: object
    live: bool         # always False in this demo: every source is simulated
    detail: str        # human-readable note for the audit trail


def _load_mock(name: str) -> object:
    return json.loads((MOCK_DIR / name).read_text(encoding="utf-8"))


def _simulated(data: object, detail: str) -> SourceResult:
    return SourceResult(data, False, detail)


def fetch_threat_model() -> SourceResult:
    """The threat model that findings are checked against."""
    text = (MOCK_DIR / "threat_model.md").read_text(encoding="utf-8")
    return _simulated(text, "GitHub SIMULATED (threat model from mock data)")


def fetch_appsec_findings() -> SourceResult:
    """SAST, SCA and secret findings from the AppSec scanner."""
    issues = _load_mock("appsec_findings.json").get("issues", [])
    return _simulated(issues, f"AppSec scanner SIMULATED ({len(issues)} finding(s))")


def fetch_asset_inventory() -> SourceResult:
    """Business context per service: internet-facing, data class, criticality,
    controls."""
    data = _load_mock("asset_inventory.json").get("assets", {})
    return _simulated(data, f"Asset inventory SIMULATED ({len(data)} assets)")


def fetch_accepted_risks() -> SourceResult:
    """The GRC platform's risk register and controls. Used to avoid
    re-escalating a formally accepted risk."""
    data = _load_mock("grc_risks.json")
    n = len(data.get("accepted_risks", []))
    return _simulated(data, f"GRC platform SIMULATED ({n} accepted risk(s))")


def fetch_tickets() -> SourceResult:
    """Existing security tickets, so the agent can spot a linked ticket and
    avoid filing a duplicate."""
    data = _load_mock("tickets.json").get("issues", [])
    return _simulated(data, f"Ticketing SIMULATED ({len(data)} existing ticket(s))")


def fetch_exploit_intel() -> SourceResult:
    """Active-exploit intel keyed by CVE, kept offline so runs are
    deterministic."""
    data = _load_mock("exploit_intel.json").get("known_exploited", {})
    return _simulated(data, f"Exploit intel SIMULATED ({len(data)} CVE record(s))")
