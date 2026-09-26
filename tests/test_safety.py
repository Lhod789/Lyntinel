"""Tests for the approval gate, evidence labelling and data boundary.

These three are the product, not plumbing: they are the runtime answers to
"it will take unsafe autonomous actions", "it will hallucinate findings" and
"our data will leave the org". So they get the most exacting tests in the
suite - particularly the negative cases, where a silent failure would mean an
ungated action or an unlabelled guess.
"""

import io
import unittest
from contextlib import redirect_stdout

from core.safety import (
    Action, ActionRisk, ApprovalGate,
    DataBoundary, Evidence, EvidenceStatus,
)


def run_gated(gate, action, execute):
    """Run an action, swallowing the gate's console output.

    The gate prints its banner by design. Tests assert on behaviour and the
    audit trail, not on the printing, so stdout is captured and returned for
    the few tests that do care.
    """
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = gate.run(action, execute)
    return result, buf.getvalue()


class TestApprovalGateReads(unittest.TestCase):
    """READ is free. It must never prompt - a gate that interrupts on reads
    gets switched off by its users, which costs you the gate on writes too."""

    def test_read_executes_without_prompting(self):
        def boom(_):
            raise AssertionError("READ must never reach the prompt function")

        gate = ApprovalGate(prompt_fn=boom)
        result, _ = run_gated(gate, Action("Read findings", ActionRisk.READ),
                              lambda: "payload")
        self.assertEqual(result, "payload")

    def test_read_is_still_recorded(self):
        gate = ApprovalGate(prompt_fn=lambda _: "n")
        run_gated(gate, Action("Read findings", ActionRisk.READ), lambda: None)
        self.assertEqual(len(gate.audit), 1)
        self.assertIn("READ", gate.audit[0])
        self.assertIn("Read findings", gate.audit[0])


class TestApprovalGateWrites(unittest.TestCase):
    """The core claim: no WRITE or DESTRUCTIVE action runs without a yes."""

    def setUp(self):
        self.executed = []

    def _execute(self):
        self.executed.append(True)
        return "done"

    def test_write_denied_does_not_execute(self):
        gate = ApprovalGate(prompt_fn=lambda _: "n")
        result, _ = run_gated(gate, Action("File ticket", ActionRisk.WRITE),
                              self._execute)
        self.assertIsNone(result)
        self.assertEqual(self.executed, [], "denied action must not run")
        self.assertIn("DENIED", gate.audit[0])

    def test_write_approved_executes(self):
        gate = ApprovalGate(prompt_fn=lambda _: "y")
        result, _ = run_gated(gate, Action("File ticket", ActionRisk.WRITE),
                              self._execute)
        self.assertEqual(result, "done")
        self.assertEqual(self.executed, [True])
        self.assertIn("APPROVED", gate.audit[0])

    def test_destructive_denied_does_not_execute(self):
        gate = ApprovalGate(prompt_fn=lambda _: "n")
        result, _ = run_gated(gate, Action("Quarantine host", ActionRisk.DESTRUCTIVE),
                              self._execute)
        self.assertIsNone(result)
        self.assertEqual(self.executed, [])

    def test_destructive_is_announced_more_loudly_than_write(self):
        gate = ApprovalGate(prompt_fn=lambda _: "n")
        _, out = run_gated(gate, Action("Quarantine host", ActionRisk.DESTRUCTIVE),
                           self._execute)
        self.assertIn("DESTRUCTIVE", out)

    def test_only_explicit_yes_approves(self):
        """Anything that is not y/yes is a denial. Enter, whitespace, a
        stray keystroke or a misread must all fail closed."""
        for answer in ("", " ", "n", "no", "maybe", "Y no", "yeah", "1", "sure"):
            with self.subTest(answer=answer):
                self.executed.clear()
                gate = ApprovalGate(prompt_fn=lambda _, a=answer: a)
                run_gated(gate, Action("File ticket", ActionRisk.WRITE),
                          self._execute)
                self.assertEqual(self.executed, [],
                                 f"answer {answer!r} must not approve")

    def test_yes_is_accepted_case_insensitively_and_untrimmed(self):
        for answer in ("y", "Y", "yes", "YES", "  y  ", "Yes\n"):
            with self.subTest(answer=answer):
                self.executed.clear()
                gate = ApprovalGate(prompt_fn=lambda _, a=answer: a)
                run_gated(gate, Action("File ticket", ActionRisk.WRITE),
                          self._execute)
                self.assertEqual(self.executed, [True],
                                 f"answer {answer!r} should approve")


class TestAutoApprove(unittest.TestCase):
    """Break-glass / demo mode. It may skip the human, but it must never skip
    the announcement or the audit record - an unattended action is still a
    visible one."""

    def test_auto_approve_does_not_consult_the_human(self):
        def boom(_):
            raise AssertionError("auto-approve must not call the prompt function")

        gate = ApprovalGate(auto_approve=True, prompt_fn=boom)
        result, _ = run_gated(gate, Action("File ticket", ActionRisk.WRITE),
                              lambda: "done")
        self.assertEqual(result, "done")

    def test_auto_approve_still_announces_and_records(self):
        gate = ApprovalGate(auto_approve=True)
        _, out = run_gated(gate, Action("Quarantine host", ActionRisk.DESTRUCTIVE),
                           lambda: None)
        self.assertIn("APPROVAL REQUIRED", out)
        self.assertIn("auto-approve", out)
        self.assertIn("APPROVED", gate.audit[0])


class TestAuditTrail(unittest.TestCase):

    def test_every_action_lands_in_the_trail_in_order(self):
        gate = ApprovalGate(prompt_fn=lambda _: "n")
        run_gated(gate, Action("Read A", ActionRisk.READ), lambda: None)
        run_gated(gate, Action("Write B", ActionRisk.WRITE), lambda: None)
        run_gated(gate, Action("Destroy C", ActionRisk.DESTRUCTIVE), lambda: None)

        trail = gate.audit_trail()
        self.assertEqual(len(gate.audit), 3)
        self.assertLess(trail.index("Read A"), trail.index("Write B"))
        self.assertLess(trail.index("Write B"), trail.index("Destroy C"))
        self.assertIn("DENIED", trail)

    def test_empty_trail_says_so_rather_than_rendering_blank(self):
        self.assertEqual(ApprovalGate().audit_trail(), "No actions recorded.")


class TestPayloadPreview(unittest.TestCase):
    """The approver has to see what they are approving, but an enormous
    payload must not bury the prompt."""

    def test_payload_is_shown(self):
        gate = ApprovalGate(prompt_fn=lambda _: "n")
        action = Action("File ticket", ActionRisk.WRITE, payload="SEC-451 body")
        _, out = run_gated(gate, action, lambda: None)
        self.assertIn("SEC-451 body", out)

    def test_long_payload_is_truncated(self):
        gate = ApprovalGate(prompt_fn=lambda _: "n")
        action = Action("File ticket", ActionRisk.WRITE, payload="x" * 500)
        _, out = run_gated(gate, action, lambda: None)
        self.assertIn("truncated", out)
        self.assertNotIn("x" * 400, out)

    def test_absent_payload_prints_no_payload_line(self):
        gate = ApprovalGate(prompt_fn=lambda _: "n")
        _, out = run_gated(gate, Action("File ticket", ActionRisk.WRITE), lambda: None)
        self.assertNotIn("Payload:", out)


class TestEvidence(unittest.TestCase):
    """No hallucinated findings: every claim carries a status, and the four
    statuses stay visually distinct."""

    def test_all_statuses_have_a_marker(self):
        for status in EvidenceStatus:
            with self.subTest(status=status):
                self.assertTrue(status.marker.startswith("["))
                self.assertTrue(status.marker.endswith("]"))

    def test_markers_are_unique_and_equal_width(self):
        markers = [s.marker for s in EvidenceStatus]
        self.assertEqual(len(set(markers)), len(markers), "markers must be distinguishable")
        self.assertEqual(len(set(len(m) for m in markers)), 1,
                         "markers must align in column output")

    def test_unknown_is_distinct_from_inferred(self):
        """'Could not establish' and 'reasoned from facts' are different
        epistemic states. Collapsing them would let a guess read as a finding."""
        self.assertNotEqual(EvidenceStatus.UNKNOWN.marker,
                            EvidenceStatus.INFERRED.marker)

    def test_render_carries_claim_status_and_source(self):
        ev = Evidence("The key is still active.", EvidenceStatus.CONFIRMED,
                      "cloud IAM: key metadata")
        rendered = ev.render()
        self.assertIn("The key is still active.", rendered)
        self.assertIn("CONFIRMED", rendered)
        self.assertIn("cloud IAM: key metadata", rendered)


class TestDataBoundary(unittest.TestCase):

    def test_clean_run_states_nothing_left(self):
        summary = DataBoundary().summary()
        self.assertIn("NOTHING left this machine", summary)

    def test_egress_is_listed_with_destination(self):
        boundary = DataBoundary()
        boundary.note_egress("finding titles", "vendor LLM API")
        summary = boundary.summary()
        self.assertNotIn("NOTHING left this machine", summary)
        self.assertIn("finding titles", summary)
        self.assertIn("vendor LLM API", summary)

    def test_boundaries_do_not_share_state(self):
        """A mutable default here would leak one run's egress into the next."""
        first = DataBoundary()
        first.note_egress("a", "b")
        self.assertEqual(DataBoundary().egress_log, [])


if __name__ == "__main__":
    unittest.main()
