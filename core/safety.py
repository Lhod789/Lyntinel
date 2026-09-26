"""
safety.py - The safety backbone for Lyntinel.

This module exists to answer, in code, the four objections a security
engineering team raises about AI agents:

  1. "It will take unsafe autonomous actions."   -> ApprovalGate
  2. "It will hallucinate findings."             -> Evidence / EvidenceStatus
  3. "Our data will leave the org."              -> DataBoundary
  4. "Securing the agent is itself a huge task." -> documented, not hand-waved

Design choice: every one of these is a *visible* runtime behaviour, not a
comment in a slide. When you demo, the team should SEE the gate fire and SEE
the evidence labels. A claim you can watch happen is worth ten you assert.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# Objection 2: hallucinated findings.
# Every claim the agent makes carries its evidence status. Inference is
# allowed; UNLABELLED inference is not. "UNKNOWN" (could not establish)
# is deliberately distinct from a confident answer - so a watcher can tell
# a fact from a guess without asking.
# ---------------------------------------------------------------------------
class EvidenceStatus(str, Enum):
    CONFIRMED = "CONFIRMED"      # backed by data the agent actually read
    INFERRED = "INFERRED"       # reasoned from confirmed facts, not directly seen
    UNKNOWN = "UNKNOWN"         # could not establish - explicitly NOT a guess
    SIMULATED = "SIMULATED"     # derived from mock data

    @property
    def marker(self) -> str:
        return {
            "CONFIRMED": "[CONFIRMED]",
            "INFERRED": "[INFERRED ]",
            "UNKNOWN": "[UNKNOWN  ]",
            "SIMULATED": "[SIMULATED]",
        }[self.value]


@dataclass
class Evidence:
    """A single claim plus where it came from and how much to trust it."""
    claim: str
    status: EvidenceStatus
    source: str  # e.g. "GitHub: threat-model.md L42", or "MOCK: edr alert"

    def render(self) -> str:
        return f"{self.status.marker} {self.claim}\n            source: {self.source}"


# ---------------------------------------------------------------------------
# Objection 3: data leaving the org.
# The boundary is explicit. Anything the agent reads is tagged with where it
# lives and whether sending it to an LLM would constitute egress. The demo
# version keeps everything local; the note explains what an org deployment
# would change. We do not pretend this is solved - we make it inspectable.
# ---------------------------------------------------------------------------
@dataclass
class DataBoundary:
    local_only: bool = True
    egress_log: list[str] = field(default_factory=list)

    def note_egress(self, what: str, destination: str) -> None:
        self.egress_log.append(f"{what} -> {destination}")

    def summary(self) -> str:
        if not self.egress_log:
            return ("Data boundary: NOTHING left this machine during the run. "
                    "All tool reads and processing were local.")
        lines = "\n".join(f"  - {e}" for e in self.egress_log)
        return f"Data boundary: the following left local scope:\n{lines}"


# ---------------------------------------------------------------------------
# Objection 1: unsafe autonomous actions.
# Read is free. Anything that WRITES, MODIFIES, or is DESTRUCTIVE must pass
# through a human. The gate is the product. In auto-approve demo mode it still
# PRINTS what it would have done and records it - so even unattended, the
# action is never silent.
# ---------------------------------------------------------------------------
class ActionRisk(str, Enum):
    READ = "READ"             # safe, never gated
    WRITE = "WRITE"           # creates/edits something - gated
    DESTRUCTIVE = "DESTRUCTIVE"  # deletes/quarantines/blocks - always gated, loudly


@dataclass
class Action:
    description: str
    risk: ActionRisk
    payload: Any = None


class ApprovalGate:
    """Human-in-the-loop gate. No WRITE/DESTRUCTIVE action executes without
    explicit approval. `auto_approve=True` is for hands-off demos: it does NOT
    skip the gate, it auto-answers yes AND announces every action so nothing
    is hidden."""

    def __init__(self, auto_approve: bool = False,
                 prompt_fn: Optional[Callable[[str], str]] = None):
        self.auto_approve = auto_approve
        self.prompt_fn = prompt_fn or input
        self.audit: list[str] = []

    def run(self, action: Action, execute: Callable[[], Any]) -> Any:
        if action.risk == ActionRisk.READ:
            self.audit.append(f"AUTO  | READ        | {action.description}")
            return execute()

        banner = "!! DESTRUCTIVE" if action.risk == ActionRisk.DESTRUCTIVE else "WRITE"
        print(f"\n  +-- APPROVAL REQUIRED [{banner}] " + "-" * 28)
        print(f"  | Action: {action.description}")
        if action.payload is not None:
            preview = str(action.payload)
            if len(preview) > 280:
                preview = preview[:280] + " ...(truncated)"
            print(f"  | Payload: {preview}")
        print("  +" + "-" * 52)

        if self.auto_approve:
            print("  > auto-approve mode: YES (recorded)")
            answer = "y"
        else:
            answer = self.prompt_fn("  > Approve this action? [y/N]: ").strip().lower()

        if answer in ("y", "yes"):
            self.audit.append(f"APPROVED | {action.risk.value:<11} | {action.description}")
            return execute()
        else:
            self.audit.append(f"DENIED   | {action.risk.value:<11} | {action.description}")
            print("  > denied - action NOT executed.\n")
            return None

    def audit_trail(self) -> str:
        if not self.audit:
            return "No actions recorded."
        return "\n".join(f"  {line}" for line in self.audit)
